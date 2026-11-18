//! SCTP: finds S1AP / NGAP in DATA chunks and anonymizes addresses carried in
//! INIT / INIT-ACK / ASCONF parameters and HEARTBEAT info.

use crate::checksum::{self, get16};
use crate::engine::{Engine, Frag, PktMeta, SctpLoc};
use crate::net::IpInfo;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub fn process(eng: &mut Engine, d: &mut [u8], start: usize, end: usize, ip: &IpInfo, partial: bool, m: &mut PktMeta) {
    if end < start + 12 {
        return;
    }
    let sport = get16(d, start);
    let dport = get16(d, start + 2);
    let crc_ok = !partial && checksum::sctp_crc_ok(&d[start..end]);
    m.sctp = Some(SctpLoc { off: start, len: end - start, crc_ok });
    let port_proto = eng.proto_by_port(sport, dport);
    if port_proto.is_some() {
        m.signalling = true;
    }
    let assoc = {
        let mut h = DefaultHasher::new();
        (&ip.osrc, &ip.odst, sport, dport).hash(&mut h);
        h.finish()
    };

    let mut p = start + 12;
    while p + 4 <= end {
        let ctype = d[p];
        let flags = d[p + 1];
        let clen = get16(d, p + 2) as usize;
        if clen < 4 {
            return;
        }
        if p + clen > end {
            // chunk cut off by the capture snap length
            if ctype == 0 && clen >= 16 && p + 16 <= end {
                let ppid = u32::from_be_bytes([d[p + 12], d[p + 13], d[p + 14], d[p + 15]]);
                if let Some(proto) = eng.proto_by_ppid(ppid).or(port_proto) {
                    m.signalling = true;
                    m.error = true;
                    // a message start: anonymize whatever is fully captured
                    if flags & 0x02 != 0 {
                        eng.process_message_ext(proto, &mut d[p + 16..end], true);
                    }
                    eng.stats.error(
                        "S1AP/NGAP message truncated by the capture snap length (anonymized as far as captured)".into(),
                    );
                }
            }
            return;
        }
        match ctype {
            0 if clen >= 16 => {
                let tsn = u32::from_be_bytes([d[p + 4], d[p + 5], d[p + 6], d[p + 7]]);
                let sid = get16(d, p + 8);
                let ppid = u32::from_be_bytes([d[p + 12], d[p + 13], d[p + 14], d[p + 15]]);
                if let Some(proto) = eng.proto_by_ppid(ppid).or(port_proto) {
                    m.signalling = true;
                    let (b, e) = (flags & 0x02 != 0, flags & 0x01 != 0);
                    let (s, l) = (p + 16, clen - 16);
                    if b && e {
                        if !eng.process_message(proto, &mut d[s..s + l]) {
                            m.error = true;
                        }
                        m.sctp_dirty = true;
                    } else {
                        let key = assoc ^ ((sid as u64) << 48 | (sid as u64));
                        m.frags.push(Frag { key, tsn, first: b, last: e, off: s, len: l, proto });
                    }
                }
            }
            1 | 2 if clen >= 20 => {
                if addr_params(eng, d, p + 20, p + clen) {
                    m.sctp_dirty = true;
                }
            }
            4 | 5 => {
                if heartbeat_info(eng, d, p + 4, p + clen, ip) {
                    m.sctp_dirty = true;
                }
            }
            0xC1 if clen >= 8
                && addr_params(eng, d, p + 8, p + clen) => {
                    m.sctp_dirty = true;
                }
            _ => {}
        }
        p += (clen + 3) & !3;
    }
}

/// Walk SCTP parameters, mapping IPv4 (5) / IPv6 (6) address parameters, also
/// when wrapped in ASCONF add / delete / set-primary parameters.
fn addr_params(eng: &mut Engine, d: &mut [u8], mut q: usize, end: usize) -> bool {
    if !eng.cfg.anonymize.ip_addresses {
        return false;
    }
    let mut changed = false;
    while q + 4 <= end {
        let t = get16(d, q);
        let l = get16(d, q + 2) as usize;
        if l < 4 || q + l > end {
            break;
        }
        changed |= addr_param(eng, d, q, t, l);
        if matches!(t, 0xC001 | 0xC002 | 0xC004) && l >= 12 {
            let t2 = get16(d, q + 8);
            let l2 = get16(d, q + 10) as usize;
            if q + 8 + l2 <= q + l {
                changed |= addr_param(eng, d, q + 8, t2, l2);
            }
        }
        q += (l + 3) & !3;
    }
    changed
}

fn addr_param(eng: &mut Engine, d: &mut [u8], q: usize, t: u16, l: usize) -> bool {
    match (t, l) {
        (5, 8) => {
            crate::ap::map_v4(eng, d, q + 4);
            eng.stats.field("ip");
            true
        }
        (6, 20) => {
            crate::ap::map_v6(eng, d, q + 4);
            eng.stats.field("ip");
            true
        }
        _ => false,
    }
}

/// HEARTBEAT info is opaque, but common stacks (Linux) put the peer address in
/// it. Replace any copy of this packet's original addresses, or of any other
/// address already seen in the trace (e.g. another path of a multi-homed peer).
fn heartbeat_info(eng: &mut Engine, d: &mut [u8], s: usize, end: usize, ip: &IpInfo) -> bool {
    if !eng.cfg.anonymize.ip_addresses || end <= s {
        return false;
    }
    let n = ip.alen();
    // find all matches first, so a replacement is never matched again
    let mut hits: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut i = s;
    while i + n <= end {
        let w = &d[i..i + n];
        let new = if w == &ip.osrc[..n] {
            Some(ip.nsrc[..n].to_vec())
        } else if w == &ip.odst[..n] {
            Some(ip.ndst[..n].to_vec())
        } else {
            eng.ps.known_ip(w)
        };
        match new {
            Some(v) => {
                hits.push((i, v));
                i += n;
            }
            None => i += 1,
        }
    }
    let mut changed = false;
    for (at, new) in &hits {
        changed |= d[*at..*at + n] != new[..];
        d[*at..*at + n].copy_from_slice(new);
    }
    changed
}
