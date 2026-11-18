//! Link layer, IPv4/IPv6, ARP, ICMP and TCP/UDP checksum handling.

use crate::checksum::{self, adjust, get16, put16};
use crate::engine::{Engine, PktMeta};
use crate::sctp;

/// Original and anonymized addresses of the enclosing IP header.
#[derive(Clone, Copy)]
pub struct IpInfo {
    pub v6: bool,
    pub osrc: [u8; 16],
    pub odst: [u8; 16],
    pub nsrc: [u8; 16],
    pub ndst: [u8; 16],
}

impl IpInfo {
    pub fn alen(&self) -> usize {
        if self.v6 { 16 } else { 4 }
    }
    fn pseudo_old(&self) -> Vec<u8> {
        [&self.osrc[..self.alen()], &self.odst[..self.alen()]].concat()
    }
    fn pseudo_new(&self) -> Vec<u8> {
        [&self.nsrc[..self.alen()], &self.ndst[..self.alen()]].concat()
    }
}

pub fn process_packet(eng: &mut Engine, linktype: u32, d: &mut [u8], m: &mut PktMeta) {
    match linktype {
        1 => ethernet(eng, d, 0, m),
        12 | 14 | 101 | 228 | 229 => ip(eng, d, 0, m, 0),
        113 => sll(eng, d, m),
        276 => sll2(eng, d, m),
        0 | 108 => {
            if d.len() > 4 {
                ip(eng, d, 4, m, 0)
            }
        }
        _ => m.unsupported = true,
    }
}

fn map_mac_at(eng: &mut Engine, d: &mut [u8], at: usize) {
    if !eng.cfg.anonymize.mac_addresses || d.len() < at + 6 {
        return;
    }
    let mut a = [0u8; 6];
    a.copy_from_slice(&d[at..at + 6]);
    let n = eng.ps.mac(a);
    if n != a {
        d[at..at + 6].copy_from_slice(&n);
        eng.stats.field("mac");
    }
}

fn ethernet(eng: &mut Engine, d: &mut [u8], off: usize, m: &mut PktMeta) {
    if d.len() < off + 14 {
        return;
    }
    map_mac_at(eng, d, off);
    map_mac_at(eng, d, off + 6);
    let mut et = get16(d, off + 12);
    let mut p = off + 14;
    while matches!(et, 0x8100 | 0x88a8 | 0x9100) {
        if d.len() < p + 4 {
            return;
        }
        et = get16(d, p + 2);
        p += 4;
    }
    ethertype(eng, d, p, et, m);
}

fn ethertype(eng: &mut Engine, d: &mut [u8], mut p: usize, et: u16, m: &mut PktMeta) {
    match et {
        0x0800 | 0x86dd => ip(eng, d, p, m, 0),
        0x0806 => arp(eng, d, p),
        0x8847 | 0x8848 => {
            // MPLS label stack, then IP
            loop {
                if d.len() < p + 4 {
                    return;
                }
                let bos = d[p + 2] & 1;
                p += 4;
                if bos == 1 {
                    break;
                }
            }
            ip(eng, d, p, m, 0)
        }
        _ => {}
    }
}

/// Linux cooked capture v1 (16-byte header).
fn sll(eng: &mut Engine, d: &mut [u8], m: &mut PktMeta) {
    if d.len() < 16 {
        return;
    }
    if get16(d, 4) == 6 {
        map_mac_at(eng, d, 6);
    }
    let et = get16(d, 14);
    ethertype(eng, d, 16, et, m);
}

/// Linux cooked capture v2 (20-byte header).
fn sll2(eng: &mut Engine, d: &mut [u8], m: &mut PktMeta) {
    if d.len() < 20 {
        return;
    }
    if d[11] == 6 {
        map_mac_at(eng, d, 12);
    }
    let et = get16(d, 0);
    ethertype(eng, d, 20, et, m);
}

fn arp(eng: &mut Engine, d: &mut [u8], p: usize) {
    if d.len() < p + 28 || d[p + 4] != 6 || d[p + 5] != 4 || get16(d, p + 2) != 0x0800 {
        return;
    }
    map_mac_at(eng, d, p + 8);
    map_mac_at(eng, d, p + 18);
    if eng.cfg.anonymize.ip_addresses {
        map_v4_at(eng, d, p + 14);
        map_v4_at(eng, d, p + 24);
    }
}

fn map_v4_at(eng: &mut Engine, d: &mut [u8], at: usize) -> bool {
    let mut a = [0u8; 4];
    a.copy_from_slice(&d[at..at + 4]);
    let n = eng.ps.ipv4(a);
    d[at..at + 4].copy_from_slice(&n);
    if n != a {
        eng.stats.field("ip");
    }
    n != a
}

fn map_v6_at(eng: &mut Engine, d: &mut [u8], at: usize) -> bool {
    let mut a = [0u8; 16];
    a.copy_from_slice(&d[at..at + 16]);
    let n = eng.ps.ipv6(a);
    d[at..at + 16].copy_from_slice(&n);
    if n != a {
        eng.stats.field("ip");
    }
    n != a
}

pub fn ip(eng: &mut Engine, d: &mut [u8], off: usize, m: &mut PktMeta, depth: u8) {
    if d.len() <= off {
        return;
    }
    match d[off] >> 4 {
        4 => ipv4(eng, d, off, m, depth),
        6 => ipv6(eng, d, off, m, depth),
        _ => {}
    }
}

fn ipv4(eng: &mut Engine, d: &mut [u8], off: usize, m: &mut PktMeta, depth: u8) {
    if d.len() < off + 20 {
        return;
    }
    let ihl = (d[off] & 0x0F) as usize * 4;
    if ihl < 20 || d.len() < off + ihl {
        return;
    }
    let total = get16(d, off + 2) as usize;
    // total length 0 happens with TSO captures: use what was captured
    let (end, truncated) = if total >= ihl {
        ((off + total).min(d.len()), off + total > d.len())
    } else {
        (d.len(), false)
    };
    let proto = d[off + 9];
    let frag = get16(d, off + 6);
    let more = frag & 0x2000 != 0;
    let frag_off = frag & 0x1FFF;

    let mut info = IpInfo { v6: false, osrc: [0; 16], odst: [0; 16], nsrc: [0; 16], ndst: [0; 16] };
    info.osrc[..4].copy_from_slice(&d[off + 12..off + 16]);
    info.odst[..4].copy_from_slice(&d[off + 16..off + 20]);
    if eng.cfg.anonymize.ip_addresses {
        map_v4_at(eng, d, off + 12);
        map_v4_at(eng, d, off + 16);
    }
    info.nsrc[..4].copy_from_slice(&d[off + 12..off + 16]);
    info.ndst[..4].copy_from_slice(&d[off + 16..off + 20]);
    if eng.cfg.general.fix_checksums {
        checksum::ipv4_header(&mut d[off..off + ihl]);
    }

    if frag_off != 0 || more {
        if proto == 132 {
            m.ip_fragment = true;
        }
        if frag_off != 0 {
            return; // no transport header in this fragment
        }
    }
    l4(eng, d, off + ihl, end, proto, &info, truncated || more, m, depth);
}

fn ipv6(eng: &mut Engine, d: &mut [u8], off: usize, m: &mut PktMeta, depth: u8) {
    if d.len() < off + 40 {
        return;
    }
    let plen = get16(d, off + 4) as usize;
    let (end, truncated) = if plen > 0 {
        ((off + 40 + plen).min(d.len()), off + 40 + plen > d.len())
    } else {
        (d.len(), false)
    };
    let mut info = IpInfo { v6: true, osrc: [0; 16], odst: [0; 16], nsrc: [0; 16], ndst: [0; 16] };
    info.osrc.copy_from_slice(&d[off + 8..off + 24]);
    info.odst.copy_from_slice(&d[off + 24..off + 40]);
    if eng.cfg.anonymize.ip_addresses {
        map_v6_at(eng, d, off + 8);
        map_v6_at(eng, d, off + 24);
    }
    info.nsrc.copy_from_slice(&d[off + 8..off + 24]);
    info.ndst.copy_from_slice(&d[off + 24..off + 40]);

    let mut nh = d[off + 6];
    let mut p = off + 40;
    let mut partial = truncated;
    loop {
        match nh {
            0 | 43 | 60 => {
                if end < p + 8 {
                    return;
                }
                nh = d[p];
                p += (d[p + 1] as usize + 1) * 8;
            }
            44 => {
                if end < p + 8 {
                    return;
                }
                let next = d[p];
                let fo = get16(d, p + 2) >> 3;
                let mf = d[p + 3] & 1 == 1;
                p += 8;
                if fo != 0 || mf {
                    if next == 132 {
                        m.ip_fragment = true;
                    }
                    if fo != 0 {
                        return;
                    }
                    partial = true;
                }
                nh = next;
            }
            51 => {
                if end < p + 8 {
                    return;
                }
                nh = d[p];
                p += (d[p + 1] as usize + 2) * 4;
            }
            _ => break,
        }
        if p > end {
            return;
        }
    }
    l4(eng, d, p, end, nh, &info, partial, m, depth);
}

#[allow(clippy::too_many_arguments)]
fn l4(
    eng: &mut Engine,
    d: &mut [u8],
    start: usize,
    end: usize,
    proto: u8,
    ip: &IpInfo,
    partial: bool,
    m: &mut PktMeta,
    depth: u8,
) {
    if start > end {
        return;
    }
    let fix = eng.cfg.general.fix_checksums;
    match proto {
        6 => {
            if fix && end >= start + 18 {
                let c = adjust(get16(d, start + 16), &ip.pseudo_old(), &ip.pseudo_new());
                put16(d, start + 16, c);
            }
        }
        17 => {
            if fix && end >= start + 8 {
                let c0 = get16(d, start + 6);
                if c0 != 0 || ip.v6 {
                    let mut c = adjust(c0, &ip.pseudo_old(), &ip.pseudo_new());
                    if c == 0 {
                        c = 0xFFFF;
                    }
                    put16(d, start + 6, c);
                }
            }
        }
        132 => sctp::process(eng, d, start, end, ip, partial, m),
        1 => icmp4(eng, d, start, end, partial, depth),
        58 => icmp6(eng, d, start, end, ip, partial, depth),
        4 | 41 if depth < 3 => self::ip(eng, d, start, m, depth + 1),
        _ => {}
    }
}

/// Anonymize the IP header (plus transport checksum) quoted inside an ICMP error.
fn inner_ip_header(eng: &mut Engine, d: &mut [u8], p: usize, end: usize) {
    if !eng.cfg.anonymize.ip_addresses || p >= end {
        return;
    }
    match d[p] >> 4 {
        4 if end >= p + 20 => {
            let ihl = (d[p] & 0xF) as usize * 4;
            let old = d[p + 12..p + 20].to_vec();
            map_v4_at(eng, d, p + 12);
            map_v4_at(eng, d, p + 16);
            let new = d[p + 12..p + 20].to_vec();
            if ihl >= 20 && end >= p + ihl {
                checksum::ipv4_header(&mut d[p..p + ihl]);
                inner_l4_checksum(d, p + ihl, end, d[p + 9], &old, &new);
            }
        }
        6 if end >= p + 40 => {
            let old = d[p + 8..p + 40].to_vec();
            map_v6_at(eng, d, p + 8);
            map_v6_at(eng, d, p + 24);
            let new = d[p + 8..p + 40].to_vec();
            inner_l4_checksum(d, p + 40, end, d[p + 6], &old, &new);
        }
        _ => {}
    }
}

fn inner_l4_checksum(d: &mut [u8], s: usize, end: usize, proto: u8, old: &[u8], new: &[u8]) {
    let at = match proto {
        6 => s + 16,
        17 => s + 6,
        _ => return,
    };
    if end >= at + 2 {
        let c0 = get16(d, at);
        if proto == 17 && c0 == 0 {
            return;
        }
        put16(d, at, adjust(c0, old, new));
    }
}

fn icmp4(eng: &mut Engine, d: &mut [u8], s: usize, end: usize, partial: bool, depth: u8) {
    if end < s + 8 || depth > 0 {
        return;
    }
    let t = d[s];
    let mut changed = false;
    if t == 5 && eng.cfg.anonymize.ip_addresses {
        changed |= map_v4_at(eng, d, s + 4); // redirect gateway
    }
    if matches!(t, 3 | 4 | 5 | 11 | 12) && end > s + 8 {
        let before = d[s + 8..end].to_vec();
        inner_ip_header(eng, d, s + 8, end);
        changed |= before != d[s + 8..end];
    }
    if changed && eng.cfg.general.fix_checksums && !partial {
        put16(d, s + 2, 0);
        let c = checksum::finish(checksum::sum16(&d[s..end]));
        put16(d, s + 2, c);
    }
}

fn icmp6(eng: &mut Engine, d: &mut [u8], s: usize, end: usize, ip: &IpInfo, partial: bool, depth: u8) {
    if end < s + 8 {
        return;
    }
    let t = d[s];
    let before = d[s..end].to_vec();
    if depth == 0 {
        match t {
            1..=4 => inner_ip_header(eng, d, s + 8, end),
            133 => nd_options(eng, d, s + 8, end),
            134 => nd_options(eng, d, s + 16, end),
            135 | 136 => {
                if end >= s + 24 && eng.cfg.anonymize.ip_addresses {
                    map_v6_at(eng, d, s + 8);
                }
                nd_options(eng, d, s + 24, end);
            }
            137 => {
                if end >= s + 40 && eng.cfg.anonymize.ip_addresses {
                    map_v6_at(eng, d, s + 8);
                    map_v6_at(eng, d, s + 24);
                }
                nd_options(eng, d, s + 40, end);
            }
            _ => {}
        }
    }
    if !eng.cfg.general.fix_checksums {
        return;
    }
    let body_changed = before != d[s..end];
    if body_changed && !partial {
        // full recompute with the (new) pseudo header
        put16(d, s + 2, 0);
        let mut sum = checksum::sum16(&ip.nsrc) + checksum::sum16(&ip.ndst);
        sum += (end - s) as u64 + 58;
        sum += checksum::sum16(&d[s..end]);
        put16(d, s + 2, checksum::finish(sum));
    } else {
        let c = adjust(get16(d, s + 2), &ip.pseudo_old(), &ip.pseudo_new());
        put16(d, s + 2, c);
    }
}

/// IPv6 neighbour discovery options: link-layer addresses and prefixes.
fn nd_options(eng: &mut Engine, d: &mut [u8], mut p: usize, end: usize) {
    while p + 2 <= end {
        let t = d[p];
        let len = d[p + 1] as usize * 8;
        if len == 0 || p + len > end {
            return;
        }
        match t {
            1 | 2 if len >= 8 => map_mac_at(eng, d, p + 2),
            3 if len >= 32 && eng.cfg.anonymize.ip_addresses => {
                // prefix information: map like an address, then clear the host bits
                let plen = d[p + 2] as usize;
                map_v6_at(eng, d, p + 16);
                for bit in plen.min(128)..128 {
                    d[p + 16 + bit / 8] &= !(0x80 >> (bit % 8));
                }
            }
            _ => {}
        }
        p += len;
    }
}
