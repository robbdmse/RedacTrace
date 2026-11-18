//! Identity encodings shared by EPS and 5GS NAS (and S1AP paging IMSI).

use crate::ap;
use crate::engine::Engine;
use crate::per::{read_bits, write_bits};
use crate::pseudo::{plmn_digits, Domain};
use anyhow::Result;

#[derive(Clone, Copy)]
enum Kind {
    Imsi,
    Imei,
}

/// Nibble positions of a "mobile identity" digit string: digit 1 is the high
/// nibble of octet 1 (the low nibble holds odd/even + type), then octets 2..n
/// hold two digits each, low nibble first. A trailing 0xF is filler.
fn mi_positions(len: usize) -> Vec<(usize, bool)> {
    let mut v = vec![(0usize, true)];
    for i in 1..len {
        v.push((i, false));
        v.push((i, true));
    }
    v
}

/// TBCD: two digits per octet, low nibble first, 0xF filler.
fn tbcd_positions(len: usize) -> Vec<(usize, bool)> {
    let mut v = Vec::with_capacity(len * 2);
    for i in 0..len {
        v.push((i, false));
        v.push((i, true));
    }
    v
}

fn nib(b: &[u8], (i, hi): (usize, bool)) -> u8 {
    if hi { b[i] >> 4 } else { b[i] & 0xF }
}

fn set_nib(b: &mut [u8], (i, hi): (usize, bool), v: u8) {
    if hi {
        b[i] = (b[i] & 0x0F) | (v << 4);
    } else {
        b[i] = (b[i] & 0xF0) | (v & 0xF);
    }
}

/// Read the digits at the given nibble positions (stopping at a 0xF filler).
/// Returns None if a non-digit appears before the end.
fn read_digits(b: &[u8], pos: &[(usize, bool)]) -> Option<(String, usize)> {
    let mut s = String::new();
    for (k, p) in pos.iter().enumerate() {
        let d = nib(b, *p);
        if d == 0xF && k == pos.len() - 1 {
            break;
        }
        if d > 9 {
            return None;
        }
        s.push((b'0' + d) as char);
    }
    let n = s.len();
    Some((s, n))
}

fn write_digits(b: &mut [u8], pos: &[(usize, bool)], digits: &str) {
    for (p, c) in pos.iter().zip(digits.bytes()) {
        set_nib(b, *p, c - b'0');
    }
}

fn map_digits(eng: &mut Engine, b: &mut [u8], pos: &[(usize, bool)], kind: Kind) {
    let Some((digits, _)) = read_digits(b, pos) else { return };
    if digits.is_empty() {
        return;
    }
    let new = match kind {
        Kind::Imsi => {
            eng.stats.field("imsi");
            eng.ps.imsi(&digits)
        }
        Kind::Imei => {
            eng.stats.field("imei");
            eng.ps.imei(&digits)
        }
    };
    if new.len() == digits.len() {
        write_digits(b, pos, &new);
    }
}

/// IMSI as S1AP TBCD-STRING (paging).
pub fn tbcd_imsi(eng: &mut Engine, v: &mut [u8]) {
    let pos = tbcd_positions(v.len());
    map_digits(eng, v, &pos, Kind::Imsi);
}

fn mi_bcd(eng: &mut Engine, v: &mut [u8], kind: Kind) {
    let on = match kind {
        Kind::Imsi => eng.cfg.anonymize.imsi,
        Kind::Imei => eng.cfg.anonymize.imei,
    };
    if on && !v.is_empty() {
        let pos = mi_positions(v.len());
        map_digits(eng, v, &pos, kind);
    }
}

fn tmsi_at(eng: &mut Engine, v: &mut [u8], at: usize) {
    if eng.cfg.anonymize.tmsi && v.len() >= at + 4 {
        let t = u32::from_be_bytes([v[at], v[at + 1], v[at + 2], v[at + 3]]);
        let n = eng.ps.tmsi(t);
        v[at..at + 4].copy_from_slice(&n.to_be_bytes());
        eng.stats.field("tmsi");
    }
}

fn cn_bits(eng: &mut Engine, v: &mut [u8], bitpos: usize, n: usize, d: Domain) {
    let on = match d {
        Domain::AmfRegion | Domain::AmfSet | Domain::AmfPointer => eng.cfg.anonymize.amf_identifiers,
        _ => eng.cfg.anonymize.mme_identifiers,
    };
    if on && v.len() * 8 >= bitpos + n {
        let x = read_bits(v, bitpos, n);
        let y = eng.ps.uint(d, n as u32, x);
        write_bits(v, bitpos, n, y);
    }
}

/// Mobile identity, TS 24.008 10.5.1.4 (Identity Response, MS identity, IMEISV ...).
pub fn mobile_identity(eng: &mut Engine, v: &mut [u8]) -> Result<()> {
    if v.is_empty() {
        return Ok(());
    }
    match v[0] & 0x07 {
        1 => mi_bcd(eng, v, Kind::Imsi),
        2 | 3 => mi_bcd(eng, v, Kind::Imei),
        4 => tmsi_at(eng, v, 1),
        _ => {}
    }
    Ok(())
}

/// EPS mobile identity, TS 24.301 9.9.3.12 (IMSI / IMEI / GUTI).
pub fn eps_mobile_identity(eng: &mut Engine, v: &mut [u8]) -> Result<()> {
    if v.is_empty() {
        return Ok(());
    }
    match v[0] & 0x07 {
        1 => mi_bcd(eng, v, Kind::Imsi),
        3 => mi_bcd(eng, v, Kind::Imei),
        6 if v.len() >= 11 => {
            eng.ps.observe_plmn(&v[1..4]);
            cn_bits(eng, v, 4 * 8, 16, Domain::MmeGroup);
            cn_bits(eng, v, 6 * 8, 8, Domain::MmeCode);
            tmsi_at(eng, v, 7);
        }
        _ => {}
    }
    Ok(())
}

/// 5GS mobile identity, TS 24.501 9.11.3.4 (SUCI / 5G-GUTI / IMEI / 5G-S-TMSI / IMEISV / MAC).
pub fn fivegs_mobile_identity(eng: &mut Engine, v: &mut [u8]) -> Result<()> {
    if v.is_empty() {
        return Ok(());
    }
    match v[0] & 0x07 {
        1 => suci(eng, v),
        2 if v.len() >= 11 => {
            eng.ps.observe_plmn(&v[1..4]);
            cn_bits(eng, v, 4 * 8, 8, Domain::AmfRegion);
            cn_bits(eng, v, 5 * 8, 10, Domain::AmfSet);
            cn_bits(eng, v, 6 * 8 + 2, 6, Domain::AmfPointer);
            tmsi_at(eng, v, 7);
        }
        3 | 5 => mi_bcd(eng, v, Kind::Imei),
        4 if v.len() >= 7 => {
            cn_bits(eng, v, 8, 10, Domain::AmfSet);
            cn_bits(eng, v, 8 + 10, 6, Domain::AmfPointer);
            tmsi_at(eng, v, 3);
        }
        6 if v.len() >= 7 && eng.cfg.anonymize.mac_addresses => {
            let mut m = [0u8; 6];
            m.copy_from_slice(&v[1..7]);
            let n = eng.ps.mac(m);
            v[1..7].copy_from_slice(&n);
            eng.stats.field("mac");
        }
        _ => {}
    }
    Ok(())
}

/// SUCI with SUPI format IMSI: PLMN(3) routing indicator(2) scheme(1) HN key id(1)
/// scheme output. With the null scheme the output is the MSIN in TBCD.
fn suci(eng: &mut Engine, v: &mut [u8]) {
    let supi_format = (v[0] >> 4) & 0x07;
    if supi_format != 0 || v.len() < 9 {
        return;
    }
    let Some(plmn) = plmn_digits(&v[1..4]) else { return };
    eng.ps.observe_plmn_digits(&plmn);
    let scheme = v[6] & 0x0F;
    if scheme != 0 || !eng.cfg.anonymize.imsi {
        return; // ECIES-protected: the MSIN is not visible
    }
    let out = &mut v[8..];
    let pos = tbcd_positions(out.len());
    let Some((msin, _)) = read_digits(out, &pos) else { return };
    if msin.is_empty() {
        return;
    }
    let imsi = format!("{}{}", plmn, msin);
    let new = eng.ps.imsi_with_keep(&imsi, plmn.len());
    eng.stats.field("imsi");
    if new.len() == imsi.len() {
        write_digits(out, &pos, &new[plmn.len()..]);
    }
}

/// EPS PDN address (24.301 9.9.4.9) / 5GS PDU address (24.501 9.11.4.10) value.
pub fn ue_address(eng: &mut Engine, v: &mut [u8]) -> Result<()> {
    if !eng.cfg.anonymize.ue_ip_addresses || v.is_empty() {
        return Ok(());
    }
    let t = v[0] & 0x07;
    let si6lla = v[0] & 0x08 != 0;
    let mut mapped = false;
    match t {
        1 if v.len() >= 5 => {
            ap::map_v4(eng, v, 1);
            mapped = true;
        }
        2 | 3 if v.len() >= 9 => {
            let mut iid = [0u8; 8];
            iid.copy_from_slice(&v[1..9]);
            let n = eng.ps.ipv6_iid(iid);
            v[1..9].copy_from_slice(&n);
            if t == 3 && v.len() >= 13 {
                ap::map_v4(eng, v, 9);
            }
            let lla = if t == 3 { 13 } else { 9 };
            if si6lla && v.len() >= lla + 16 {
                ap::map_v6(eng, v, lla);
            }
            mapped = true;
        }
        _ => {}
    }
    if mapped {
        eng.stats.field("ue_ip_address");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mi_digit_layout() {
        // IMSI 001010000000001 (odd): 0x09 0x10 0x10 0x00 0x00 0x00 0x00 0x10
        let b = [0x09u8, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10];
        let (d, _) = read_digits(&b, &mi_positions(b.len())).unwrap();
        assert_eq!(d, "001010000000001");
        // IMEISV 16 digits (even): last nibble is filler
        let b = [0x33u8, 0x55, 0x99, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0];
        let (d, _) = read_digits(&b, &mi_positions(b.len())).unwrap();
        assert_eq!(d.len(), 16);
    }
}
