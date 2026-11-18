//! Building blocks shared by the S1AP and NGAP walkers.

use crate::engine::Engine;
use crate::per::Per;
use crate::pseudo::{Domain, NameKind};
use anyhow::Result;

/// PLMN identity: OCTET STRING (SIZE(3)). Only observed (MCC/MNC are kept).
pub fn plmn(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let pos = p.octets_fixed(3)?;
    let b = pos / 8;
    let v = [p.buf[b], p.buf[b + 1], p.buf[b + 2]];
    eng.ps.observe_plmn(&v);
    Ok(())
}

/// TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...)): IPv4 (32 bits),
/// IPv6 (128 bits) or both (160 bits).
pub fn tla(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let (pos, n) = p.bits_sized(1, 160, true)?;
    if !eng.cfg.anonymize.ip_in_signalling || pos % 8 != 0 {
        return Ok(());
    }
    let b = pos / 8;
    match n {
        32 => map_v4(eng, p.buf, b),
        128 => map_v6(eng, p.buf, b),
        160 => {
            map_v4(eng, p.buf, b);
            map_v6(eng, p.buf, b + 4);
        }
        _ => return Ok(()),
    }
    eng.stats.field("ip_in_signalling");
    Ok(())
}

pub fn map_v4(eng: &mut Engine, buf: &mut [u8], at: usize) {
    let mut a = [0u8; 4];
    a.copy_from_slice(&buf[at..at + 4]);
    let n = eng.ps.ipv4(a);
    buf[at..at + 4].copy_from_slice(&n);
}

pub fn map_v6(eng: &mut Engine, buf: &mut [u8], at: usize) {
    let mut a = [0u8; 16];
    a.copy_from_slice(&buf[at..at + 16]);
    let n = eng.ps.ipv6(a);
    buf[at..at + 16].copy_from_slice(&n);
}

fn name_enabled(eng: &Engine, kind: NameKind) -> bool {
    let f = &eng.cfg.anonymize;
    match kind {
        NameKind::Amf => f.amf_name,
        NameKind::Mme => f.mme_name,
        NameKind::Ran => f.ran_node_name,
    }
}

fn replace_name(eng: &mut Engine, buf: &mut [u8], s: usize, l: usize, kind: NameKind) {
    if !name_enabled(eng, kind) || l == 0 {
        return;
    }
    let orig = buf[s..s + l].to_vec();
    let new = eng.ps.name(kind, &orig);
    buf[s..s + l].copy_from_slice(&new);
    eng.stats.field(match kind {
        NameKind::Amf => "amf_name",
        NameKind::Mme => "mme_name",
        NameKind::Ran => "ran_node_name",
    });
}

/// PrintableString / VisibleString (SIZE(1..150, ...)) node name.
pub fn name(eng: &mut Engine, p: &mut Per, kind: NameKind) -> Result<()> {
    let (s, l) = p.char_string(1, 150, true)?;
    replace_name(eng, p.buf, s, l, kind);
    Ok(())
}

/// UTF8String node name: the size constraint is not PER-visible, so it is
/// encoded as an unconstrained length + octets.
pub fn name_utf8(eng: &mut Engine, p: &mut Per, kind: NameKind) -> Result<()> {
    let (s, l) = p.octets()?;
    replace_name(eng, p.buf, s, l, kind);
    Ok(())
}

/// Extended-AMFName / Extended-RANNodeName ::= SEQUENCE {
///   visibleString OPTIONAL, utf8String OPTIONAL, iE-Extensions OPTIONAL, ... }
pub fn extended_name(eng: &mut Engine, p: &mut Per, kind: NameKind) -> Result<()> {
    let s = p.seq(true, 3)?;
    if s.has(0) {
        name(eng, p, kind)?;
    }
    if s.has(1) {
        name_utf8(eng, p, kind)?;
    }
    Ok(())
}

/// eNB-ID / ng-eNB-ID bit string at `pos`.
pub fn enb_bits(eng: &mut Engine, p: &mut Per, pos: usize, n: usize) {
    let v = p.get(pos, n);
    eng.ps.learn_enb(n as u8, v);
    if eng.cfg.anonymize.enb_id {
        let nv = eng.ps.enb_id(n as u8, v);
        p.put(pos, n, nv);
        eng.stats.field("enb_id");
    }
}

/// gNB-ID bit string at `pos`.
pub fn gnb_bits(eng: &mut Engine, p: &mut Per, pos: usize, n: usize) {
    let v = p.get(pos, n);
    eng.ps.learn_gnb(n as u8, v);
    if eng.cfg.anonymize.gnb_id {
        let nv = eng.ps.gnb_id(n as u8, v);
        p.put(pos, n, nv);
        eng.stats.field("gnb_id");
    }
}

/// 28-bit E-UTRAN Cell Identity at `pos`.
pub fn eutra_cell_bits(eng: &mut Engine, p: &mut Per, pos: usize) {
    if eng.cfg.anonymize.cell_identity {
        let v = p.get(pos, 28);
        let nv = eng.ps.eutra_cell(v);
        p.put(pos, 28, nv);
        eng.stats.field("cell_identity");
    }
}

/// 36-bit NR Cell Identity at `pos`.
pub fn nr_cell_bits(eng: &mut Engine, p: &mut Per, pos: usize) {
    if eng.cfg.anonymize.cell_identity {
        let v = p.get(pos, 36);
        let nv = eng.ps.nr_cell(v);
        p.put(pos, 36, nv);
        eng.stats.field("cell_identity");
    }
}

/// 32-bit (M-/5G-)TMSI at `pos`.
pub fn tmsi_bits(eng: &mut Engine, p: &mut Per, pos: usize) {
    if eng.cfg.anonymize.tmsi {
        let v = p.get(pos, 32) as u32;
        let nv = eng.ps.tmsi(v);
        p.put(pos, 32, nv as u64);
        eng.stats.field("tmsi");
    }
}

/// Core network identifier bit field (AMF region/set/pointer, MME group/code).
pub fn cn_id_bits(eng: &mut Engine, p: &mut Per, pos: usize, n: usize, d: Domain) {
    let on = match d {
        Domain::AmfRegion | Domain::AmfSet | Domain::AmfPointer => eng.cfg.anonymize.amf_identifiers,
        Domain::MmeGroup | Domain::MmeCode => eng.cfg.anonymize.mme_identifiers,
        _ => false,
    };
    if on {
        let v = p.get(pos, n);
        let nv = eng.ps.uint(d, n as u32, v);
        p.put(pos, n, nv);
        eng.stats.field(match d {
            Domain::AmfRegion | Domain::AmfSet | Domain::AmfPointer => "amf_identifiers",
            _ => "mme_identifiers",
        });
    }
}

/// TraceActivation (identical layout in S1AP and NGAP):
/// SEQUENCE { traceID OCTET STRING(SIZE(8)), interfacesToTrace BIT STRING(SIZE(8)),
///            traceDepth ENUMERATED{6,...}, traceCollectionEntityIPAddress, iE-Ext OPT, ... }
pub fn trace_activation(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    p.octets_fixed(8)?;
    p.bits_fixed(8)?;
    p.enumerated(6, true)?;
    tla(eng, p)
}

/// Masked IMEISV ::= BIT STRING (SIZE(64)): the IMEISV digits with the last 4
/// SNR digits already masked (all ones). Mask the rest of the serial number too
/// (bytes 4..6 hold digits 9-14 in either nibble order), and the TAC if requested.
pub fn masked_imeisv(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let pos = p.bits_fixed(64)?;
    if eng.cfg.anonymize.imei && pos % 8 == 0 {
        let b = pos / 8;
        p.buf[b + 4..b + 7].fill(0xFF);
        if !eng.cfg.imei.keep_tac {
            p.buf[b..b + 4].fill(0xFF);
        }
        eng.stats.field("imei");
    }
    Ok(())
}

/// INTEGER (0..range-1, ...) with extension marker.
pub fn int_ext(p: &mut Per, range: u64) -> Result<u64> {
    if p.bit()? {
        let len = p.len_det()?;
        p.bits(len * 8)
    } else {
        p.cwn(range)
    }
}
