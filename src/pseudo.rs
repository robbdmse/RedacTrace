//! Pseudonym generation.
//!
//! Every identifier is replaced by a keyed-hash (HMAC-SHA256) derived value of
//! exactly the same size/format. Mappings are cached, so the same original always
//! gets the same pseudonym within a run (and across runs when a fixed secret is
//! configured), and they are collision free: two different originals never get
//! the same pseudonym.

use crate::config::{Config, IpMode};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io::Write;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameKind {
    Amf,
    Mme,
    Ran,
}

impl NameKind {
    fn prefix(self) -> &'static str {
        match self {
            NameKind::Amf => "amf",
            NameKind::Mme => "mme",
            NameKind::Ran => "ran",
        }
    }
    fn category(self) -> &'static str {
        match self {
            NameKind::Amf => "amf_name",
            NameKind::Mme => "mme_name",
            NameKind::Ran => "ran_node_name",
        }
    }
}

/// Integer identifier domains (each has its own collision-free table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    Tmsi,
    GnbId(u8),
    EnbId(u8),
    NrCell,
    EutraCell,
    AmfRegion,
    AmfSet,
    AmfPointer,
    MmeGroup,
    MmeCode,
}

impl Domain {
    fn label(self) -> String {
        format!("{:?}", self)
    }
    fn category(self) -> &'static str {
        match self {
            Domain::Tmsi => "tmsi",
            Domain::GnbId(_) => "gnb_id",
            Domain::EnbId(_) => "enb_id",
            Domain::NrCell => "nr_cell_identity",
            Domain::EutraCell => "eutra_cell_identity",
            Domain::AmfRegion => "amf_region_id",
            Domain::AmfSet => "amf_set_id",
            Domain::AmfPointer => "amf_pointer",
            Domain::MmeGroup => "mme_group_id",
            Domain::MmeCode => "mme_code",
        }
    }
    fn hex_width(self, bits: u32) -> usize {
        bits.div_ceil(4) as usize
    }
}

struct Table<T: Hash + Eq + Clone> {
    fwd: HashMap<T, T>,
    used: HashSet<T>,
}

impl<T: Hash + Eq + Clone> Default for Table<T> {
    fn default() -> Self {
        Table { fwd: HashMap::new(), used: HashSet::new() }
    }
}

impl<T: Hash + Eq + Clone> Table<T> {
    fn get(&self, k: &T) -> Option<T> {
        self.fwd.get(k).cloned()
    }
    fn insert(&mut self, k: T, v: T) {
        self.used.insert(v.clone());
        self.fwd.insert(k, v);
    }
}

pub struct Pseudo {
    base: HmacSha256,
    ip_mode: IpMode,
    keep_special: bool,
    keep_oui: bool,
    keep_tac: bool,
    default_mnc_len: usize,
    gnb_id_length: u8,
    enb_id_length: u8,
    map_gnb: bool,
    map_enb: bool,

    /// When true (learning pass) nothing is mapped; only facts are learned.
    pub learning: bool,

    mac: Table<[u8; 6]>,
    ipv4: Table<[u8; 4]>,
    ipv6: Table<[u8; 16]>,
    iid: Table<[u8; 8]>,
    imsi: Table<String>,
    imei: Table<String>,
    imei_recorded: HashSet<String>,
    names: Table<(NameKind, Vec<u8>)>,
    uints: HashMap<Domain, Table<u64>>,

    /// MCC+MNC digit strings seen in the trace (to know the MNC length of IMSIs).
    plmns: HashSet<String>,
    gnb_ids: HashSet<(u8, u64)>,
    enb_ids: HashSet<(u8, u64)>,

    mapping: Vec<(&'static str, String, String)>,
}

impl Pseudo {
    pub fn new(cfg: &Config, secret: &[u8]) -> Pseudo {
        Pseudo {
            base: HmacSha256::new_from_slice(secret).expect("hmac accepts any key length"),
            ip_mode: cfg.ip.mode,
            keep_special: cfg.ip.keep_special,
            keep_oui: cfg.mac.keep_oui,
            keep_tac: cfg.imei.keep_tac,
            default_mnc_len: cfg.imsi.default_mnc_length as usize,
            gnb_id_length: cfg.ran.gnb_id_length,
            enb_id_length: cfg.ran.enb_id_length,
            map_gnb: cfg.anonymize.gnb_id,
            map_enb: cfg.anonymize.enb_id,
            learning: false,
            mac: Table::default(),
            ipv4: Table::default(),
            ipv6: Table::default(),
            iid: Table::default(),
            imsi: Table::default(),
            imei: Table::default(),
            imei_recorded: HashSet::new(),
            names: Table::default(),
            uints: HashMap::new(),
            plmns: HashSet::new(),
            gnb_ids: HashSet::new(),
            enb_ids: HashSet::new(),
            mapping: Vec::new(),
        }
    }

    fn prf(&self, label: &str, data: &[u8], ctr: u32) -> [u8; 32] {
        let mut m = self.base.clone();
        m.update(label.as_bytes());
        m.update(&[0]);
        m.update(&ctr.to_be_bytes());
        m.update(data);
        m.finalize().into_bytes().into()
    }

    fn record(&mut self, cat: &'static str, orig: String, new: String) {
        self.mapping.push((cat, orig, new));
    }

    // ------------------------------------------------------------------ MAC

    pub fn mac(&mut self, m: [u8; 6]) -> [u8; 6] {
        if self.learning || m[0] & 1 == 1 || m == [0; 6] {
            return m; // multicast / broadcast / unset are not identifying
        }
        if let Some(v) = self.mac.get(&m) {
            return v;
        }
        let mut ctr = 0;
        let out = loop {
            let h = self.prf("mac", &m, ctr);
            ctr += 1;
            let c = if self.keep_oui {
                [m[0], m[1], m[2], h[0], h[1], h[2]]
            } else {
                // locally administered, unicast
                [(h[0] & 0xFC) | 0x02, h[1], h[2], h[3], h[4], h[5]]
            };
            if !self.mac.used.contains(&c) || ctr > 1000 {
                break c;
            }
        };
        self.mac.insert(m, out);
        self.record("mac", fmt_mac(&m), fmt_mac(&out));
        out
    }

    // ------------------------------------------------------------------- IP

    fn ipv4_special(a: [u8; 4]) -> bool {
        a == [0; 4] || a == [255; 4] || a[0] == 127 || a[0] >= 224
    }

    pub fn ipv4(&mut self, a: [u8; 4]) -> [u8; 4] {
        if self.learning || (self.keep_special && Self::ipv4_special(a)) {
            return a;
        }
        if let Some(v) = self.ipv4.get(&a) {
            return v;
        }
        let out = match self.ip_mode {
            IpMode::PrefixPreserving => {
                let v = self.prefix_preserve("ip4pp", u32::from_be_bytes(a) as u128, 32);
                (v as u32).to_be_bytes()
            }
            IpMode::Random => {
                let mut ctr = 0;
                loop {
                    let h = self.prf("ip4", &a, ctr);
                    ctr += 1;
                    let c = [h[0], h[1], h[2], h[3]];
                    let bad = self.keep_special && Self::ipv4_special(c);
                    if (!bad && !self.ipv4.used.contains(&c)) || ctr > 10000 {
                        break c;
                    }
                }
            }
        };
        self.ipv4.insert(a, out);
        self.record("ipv4", fmt_ipv4(&a), fmt_ipv4(&out));
        out
    }

    pub fn ipv6(&mut self, a: [u8; 16]) -> [u8; 16] {
        if self.learning {
            return a;
        }
        if self.keep_special
            && (a == [0; 16] || a[..15] == [0; 15] && a[15] == 1 || a[0] == 0xff) {
                return a;
            }
        if let Some(v) = self.ipv6.get(&a) {
            return v;
        }
        let mut out = a;
        if self.keep_special && a[0] == 0xfe && a[1] & 0xc0 == 0x80 {
            // link-local: keep fe80::/64, replace the interface identifier
            let mut iid = [0u8; 8];
            iid.copy_from_slice(&a[8..]);
            let n = self.iid_raw(iid);
            out[8..].copy_from_slice(&n);
        } else if a[..10] == [0; 10] && a[10] == 0xff && a[11] == 0xff {
            // IPv4-mapped
            let v4 = self.ipv4([a[12], a[13], a[14], a[15]]);
            out[12..].copy_from_slice(&v4);
        } else {
            match self.ip_mode {
                IpMode::PrefixPreserving => {
                    let v = self.prefix_preserve("ip6pp", u128::from_be_bytes(a), 128);
                    out = v.to_be_bytes();
                }
                IpMode::Random => {
                    let mut ctr = 0;
                    loop {
                        let h1 = self.prf("ip6", &a, ctr);
                        ctr += 1;
                        let mut c = [0u8; 16];
                        c.copy_from_slice(&h1[..16]);
                        if self.keep_special && c[0] == 0xff {
                            c[0] = 0x20;
                        }
                        if !self.ipv6.used.contains(&c) || ctr > 1000 {
                            out = c;
                            break;
                        }
                    }
                }
            }
        }
        self.ipv6.insert(a, out);
        self.record("ipv6", fmt_ipv6(&a), fmt_ipv6(&out));
        out
    }

    /// Pseudonym of an IPv4 (4 bytes) or IPv6 (16 bytes) address that was
    /// already mapped earlier in the trace; None if it was never seen.
    pub fn known_ip(&self, a: &[u8]) -> Option<Vec<u8>> {
        match a.len() {
            4 => self.ipv4.get(&[a[0], a[1], a[2], a[3]]).map(|v| v.to_vec()),
            16 => {
                let mut k = [0u8; 16];
                k.copy_from_slice(a);
                self.ipv6.get(&k).map(|v| v.to_vec())
            }
            _ => None,
        }
    }

    /// Prefix-preserving permutation (Crypto-PAn style, HMAC as PRF): output bit i
    /// is input bit i XOR PRF(first i input bits). Bijective by construction.
    fn prefix_preserve(&self, label: &str, addr: u128, nbits: u32) -> u128 {
        let mut out = 0u128;
        for i in 0..nbits {
            let prefix = if i == 0 { 0 } else { addr >> (nbits - i) };
            let mut data = [0u8; 17];
            data[0] = i as u8;
            data[1..].copy_from_slice(&prefix.to_be_bytes());
            let flip = (self.prf(label, &data, 0)[0] & 1) as u128;
            let bit = (addr >> (nbits - 1 - i)) & 1;
            out |= (bit ^ flip) << (nbits - 1 - i);
        }
        out
    }

    fn iid_raw(&mut self, iid: [u8; 8]) -> [u8; 8] {
        if let Some(v) = self.iid.get(&iid) {
            return v;
        }
        let mut ctr = 0;
        let out = loop {
            let h = self.prf("iid", &iid, ctr);
            ctr += 1;
            let mut c = [0u8; 8];
            c.copy_from_slice(&h[..8]);
            if !self.iid.used.contains(&c) || ctr > 1000 {
                break c;
            }
        };
        self.iid.insert(iid, out);
        out
    }

    /// IPv6 interface identifier (as found in NAS PDN/PDU addresses).
    pub fn ipv6_iid(&mut self, iid: [u8; 8]) -> [u8; 8] {
        if self.learning {
            return iid;
        }
        let known = self.iid.get(&iid).is_some();
        let out = self.iid_raw(iid);
        if !known {
            self.record("ipv6_iid", hex(&iid), hex(&out));
        }
        out
    }

    // ----------------------------------------------------------------- IMSI

    /// Remember a PLMN (3-octet MCC/MNC encoding) seen in the trace.
    pub fn observe_plmn(&mut self, p: &[u8]) {
        if let Some(s) = plmn_digits(p) {
            self.plmns.insert(s);
        }
    }

    pub fn observe_plmn_digits(&mut self, mcc_mnc: &str) {
        self.plmns.insert(mcc_mnc.to_string());
    }

    fn imsi_keep(&self, imsi: &str) -> usize {
        if imsi.len() >= 6 && self.plmns.contains(&imsi[..6]) {
            6
        } else if imsi.len() >= 5 && self.plmns.contains(&imsi[..5]) {
            5
        } else {
            3 + self.default_mnc_len
        }
    }

    /// Map an IMSI (ASCII digits). MCC+MNC are kept.
    pub fn imsi(&mut self, imsi: &str) -> String {
        let keep = self.imsi_keep(imsi);
        self.imsi_with_keep(imsi, keep)
    }

    pub fn imsi_with_keep(&mut self, imsi: &str, keep: usize) -> String {
        if self.learning || imsi.is_empty() {
            return imsi.to_string();
        }
        if let Some(v) = self.imsi.get(&imsi.to_string()) {
            return v;
        }
        let keep = keep.min(imsi.len());
        let mut ctr = 0;
        let out = loop {
            let h = self.prf("imsi", imsi.as_bytes(), ctr);
            ctr += 1;
            let mut s = String::with_capacity(imsi.len());
            s.push_str(&imsi[..keep]);
            for i in keep..imsi.len() {
                s.push((b'0' + h[i % 32] % 10) as char);
            }
            if !self.imsi.used.contains(&s) || ctr > 1000 {
                break s;
            }
        };
        self.imsi.insert(imsi.to_string(), out.clone());
        self.record("imsi", imsi.to_string(), out.clone());
        out
    }

    // ----------------------------------------------------------------- IMEI

    /// Map IMEI (15 digits) or IMEISV (16 digits). Other lengths are mapped digit-wise.
    pub fn imei(&mut self, d: &str) -> String {
        if self.learning || d.len() < 14 {
            return d.to_string();
        }
        let core = &d[..14];
        let new_core = match self.imei.get(&core.to_string()) {
            Some(v) => v,
            None => {
                let keep = if self.keep_tac { 8 } else { 0 };
                let mut ctr = 0;
                let out = loop {
                    let h = self.prf("imei", core.as_bytes(), ctr);
                    ctr += 1;
                    let mut s = String::from(&core[..keep]);
                    for b in &h[keep..14] {
                        s.push((b'0' + b % 10) as char);
                    }
                    if !self.imei.used.contains(&s) || ctr > 1000 {
                        break s;
                    }
                };
                self.imei.insert(core.to_string(), out.clone());
                out
            }
        };
        let mut out = new_core.clone();
        let tail = &d[14..];
        if d.len() == 15 {
            // check digit: recompute if the original carried a valid one, else keep (often '0')
            let cd = tail.as_bytes()[0];
            if cd == luhn(core) {
                out.push(luhn(&new_core) as char);
            } else {
                out.push(cd as char);
            }
        } else {
            out.push_str(tail); // IMEISV: software version kept
        }
        if self.imei_recorded.insert(d.to_string()) {
            self.record("imei", d.to_string(), out.clone());
        }
        out
    }

    // ---------------------------------------------------------------- names

    /// Same-length pseudonym for a node name, e.g. "open5gs-amf0" -> "amf-3f9c02ab".
    pub fn name(&mut self, kind: NameKind, orig: &[u8]) -> Vec<u8> {
        if self.learning || orig.is_empty() {
            return orig.to_vec();
        }
        let key = (kind, orig.to_vec());
        if let Some((_, v)) = self.names.get(&key) {
            return v;
        }
        let n = orig.len();
        let prefix = kind.prefix();
        let mut ctr = 0;
        let out = loop {
            let h = self.prf(prefix, orig, ctr);
            ctr += 1;
            let hexs: String = h.iter().map(|b| format!("{:02x}", b)).collect();
            let s = if n >= prefix.len() + 3 {
                let mut s = format!("{}-{}", prefix, hexs);
                while s.len() < n {
                    s.push_str(&hexs);
                }
                s.truncate(n);
                s
            } else {
                let mut s = hexs.clone();
                s.truncate(n);
                s
            };
            let cand = (kind, s.into_bytes());
            if !self.names.used.contains(&cand) || ctr > 1000 {
                break cand.1;
            }
        };
        self.names.insert(key, (kind, out.clone()));
        self.record(
            kind.category(),
            String::from_utf8_lossy(orig).into_owned(),
            String::from_utf8_lossy(&out).into_owned(),
        );
        out
    }

    // -------------------------------------------------------- integer ids

    pub fn uint(&mut self, d: Domain, bits: u32, v: u64) -> u64 {
        if self.learning || bits == 0 || bits > 64 {
            return v;
        }
        let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let v = v & mask;
        let t = self.uints.entry(d).or_default();
        if let Some(x) = t.get(&v) {
            return x;
        }
        let space: u128 = 1u128 << bits;
        let mut out = v;
        if (t.used.len() as u128) < space {
            let mut ctr = 0u32;
            loop {
                let h = self.prf(&d.label(), &v.to_be_bytes(), ctr);
                ctr += 1;
                let mut c = u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]) & mask;
                if ctr > 2000 {
                    // tiny, nearly full space: take the next free value
                    while self.uints[&d].used.contains(&c) {
                        c = (c + 1) & mask;
                    }
                }
                let forbidden = d == Domain::Tmsi && c == 0xFFFF_FFFF;
                if !forbidden && !self.uints[&d].used.contains(&c) {
                    out = c;
                    break;
                }
            }
        }
        self.uints.get_mut(&d).unwrap().insert(v, out);
        let w = d.hex_width(bits);
        self.record(d.category(), format!("{:0w$x}", v, w = w), format!("{:0w$x}", out, w = w));
        out
    }

    pub fn tmsi(&mut self, v: u32) -> u32 {
        self.uint(Domain::Tmsi, 32, v as u64) as u32
    }

    // ------------------------------------------------------ RAN node ids

    pub fn learn_gnb(&mut self, bits: u8, v: u64) {
        self.gnb_ids.insert((bits, v));
    }

    pub fn learn_enb(&mut self, bits: u8, v: u64) {
        self.enb_ids.insert((bits, v));
    }

    pub fn gnb_id(&mut self, bits: u8, v: u64) -> u64 {
        self.uint(Domain::GnbId(bits), bits as u32, v)
    }

    pub fn enb_id(&mut self, bits: u8, v: u64) -> u64 {
        self.uint(Domain::EnbId(bits), bits as u32, v)
    }

    /// NR Cell Identity (36 bits) = gNB-ID (22..32 bits) + local cell id.
    pub fn nr_cell(&mut self, nci: u64) -> u64 {
        if self.learning {
            return nci;
        }
        let gnb_len = if !self.map_gnb {
            None
        } else if self.gnb_id_length != 0 {
            Some(self.gnb_id_length)
        } else {
            (22..=32u8).rev().find(|b| self.gnb_ids.contains(&(*b, nci >> (36 - *b as u32))))
        };
        match gnb_len {
            Some(b) => {
                let shift = 36 - b as u32;
                let gnb = self.gnb_id(b, nci >> shift);
                (gnb << shift) | (nci & ((1u64 << shift) - 1))
            }
            None => self.uint(Domain::NrCell, 36, nci),
        }
    }

    /// E-UTRAN Cell Identity (28 bits) = eNB-ID (18/20/21/28 bits) + cell id.
    pub fn eutra_cell(&mut self, eci: u64) -> u64 {
        if self.learning {
            return eci;
        }
        if !self.map_enb {
            return self.uint(Domain::EutraCell, 28, eci);
        }
        let len = [20u8, 28, 21, 18]
            .into_iter()
            .find(|b| self.enb_ids.contains(&(*b, eci >> (28 - *b as u32))))
            .unwrap_or(self.enb_id_length);
        let shift = 28 - len as u32;
        let enb = self.enb_id(len, eci >> shift);
        let low = if shift == 0 { 0 } else { eci & ((1u64 << shift) - 1) };
        (enb << shift) | low
    }

    // -------------------------------------------------------------- export

    pub fn mapping_len(&self) -> usize {
        self.mapping.len()
    }

    pub fn write_mapping(&self, path: &Path) -> std::io::Result<()> {
        let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
        writeln!(f, "category,original,pseudonym")?;
        let mut rows: Vec<_> = self.mapping.iter().collect();
        rows.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
        for (c, o, n) in rows {
            writeln!(f, "{},{},{}", c, csv(o), csv(n))?;
        }
        f.flush()
    }
}

fn csv(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn luhn(digits14: &str) -> u8 {
    let mut sum = 0u32;
    for (i, c) in digits14.bytes().enumerate() {
        let mut d = (c - b'0') as u32;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    b'0' + ((10 - sum % 10) % 10) as u8
}

/// Decode a 3-octet PLMN identity into "MCC MNC" digits (5 or 6 chars).
pub fn plmn_digits(p: &[u8]) -> Option<String> {
    if p.len() < 3 {
        return None;
    }
    let d = [p[0] & 0xF, p[0] >> 4, p[1] & 0xF, p[2] & 0xF, p[2] >> 4, p[1] >> 4];
    let mut s = String::new();
    for (i, x) in d.iter().enumerate() {
        if *x == 0xF && i == 5 {
            break;
        }
        if *x > 9 {
            return None;
        }
        s.push((b'0' + x) as char);
    }
    Some(s)
}

pub fn fmt_mac(m: &[u8]) -> String {
    m.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

pub fn fmt_ipv4(a: &[u8; 4]) -> String {
    std::net::Ipv4Addr::from(*a).to_string()
}

pub fn fmt_ipv6(a: &[u8; 16]) -> String {
    std::net::Ipv6Addr::from(*a).to_string()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Pseudo {
        Pseudo::new(&Config::default(), b"test-secret")
    }

    #[test]
    fn imsi_keeps_plmn_and_length() {
        let mut ps = p();
        ps.observe_plmn_digits("001010");
        let a = ps.imsi("001010123456789");
        assert_eq!(a.len(), 15);
        assert_eq!(&a[..6], "001010");
        assert_ne!(a, "001010123456789");
        assert_eq!(ps.imsi("001010123456789"), a);
        let b = ps.imsi("206011234567890");
        assert_eq!(&b[..5], "20601");
    }

    #[test]
    fn prefix_preserving_shares_prefix() {
        let mut ps = p();
        let a = ps.ipv4([10, 1, 2, 3]);
        let b = ps.ipv4([10, 1, 2, 4]);
        let c = ps.ipv4([10, 1, 9, 9]);
        assert_eq!(a[..3], b[..3]);
        assert_eq!(a[..2], c[..2]);
        assert_ne!(a, [10, 1, 2, 3]);
        assert_eq!(ps.ipv4([127, 0, 0, 1]), [127, 0, 0, 1]);
    }

    #[test]
    fn names_keep_length() {
        let mut ps = p();
        let n = ps.name(NameKind::Amf, b"open5gs-amf0");
        assert_eq!(n.len(), 12);
        assert!(n.starts_with(b"amf-"));
        assert_eq!(ps.name(NameKind::Ran, b"g1").len(), 2);
    }

    #[test]
    fn small_space_is_collision_free() {
        let mut ps = p();
        let mut seen = HashSet::new();
        for v in 0..64u64 {
            assert!(seen.insert(ps.uint(Domain::AmfPointer, 6, v)));
        }
    }

    #[test]
    fn imei_check_digit() {
        let mut ps = p();
        let orig = "35693803564380"; // 14 digits
        let full = format!("{}{}", orig, luhn(orig) as char);
        let a = ps.imei(&full);
        assert_eq!(a.len(), 15);
        assert_eq!(&a[..8], &full[..8]);
        assert_eq!(a.as_bytes()[14], luhn(&a[..14]));
        let sv = ps.imei(&format!("{}{}", orig, "07"));
        assert_eq!(&sv[..14], &a[..14]);
        assert!(sv.ends_with("07"));
    }

    #[test]
    fn nci_follows_gnb_mapping() {
        let mut ps = p();
        ps.learn_gnb(22, 0x1);
        let nci = (0x1u64 << 14) | 0x5;
        let n = ps.nr_cell(nci);
        let g = ps.gnb_id(22, 0x1);
        assert_eq!(n >> 14, g);
        assert_eq!(n & 0x3fff, 0x5);
    }
}
