//! Internet checksum (RFC 1071 / RFC 1624) and SCTP CRC32c helpers.

// chunks_exact keeps the code buildable on older (pre as_chunks) toolchains
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
pub fn sum16(data: &[u8]) -> u64 {
    let mut s = 0u64;
    let mut it = data.chunks_exact(2);
    for c in &mut it {
        s += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    if let [b] = it.remainder() {
        s += (*b as u64) << 8;
    }
    s
}

pub fn fold(mut s: u64) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

pub fn finish(s: u64) -> u16 {
    !fold(s)
}

/// Incremental update after 16-bit-aligned bytes `old` were replaced by `new`
/// (RFC 1624: HC' = ~(~HC + ~m + m')).
pub fn adjust(csum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut s = (!csum) as u64;
    for (o, n) in old.chunks(2).zip(new.chunks(2)) {
        let ow = if o.len() == 2 { u16::from_be_bytes([o[0], o[1]]) } else { (o[0] as u16) << 8 };
        let nw = if n.len() == 2 { u16::from_be_bytes([n[0], n[1]]) } else { (n[0] as u16) << 8 };
        s += (!ow) as u64;
        s += nw as u64;
    }
    !fold(s)
}

pub fn get16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

pub fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// Recompute the IPv4 header checksum in place.
pub fn ipv4_header(h: &mut [u8]) {
    h[10] = 0;
    h[11] = 0;
    let c = finish(sum16(h));
    put16(h, 10, c);
}

const fn crc32c_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC32C: [u32; 256] = crc32c_table();

fn crc32c_update(mut c: u32, data: &[u8]) -> u32 {
    for &b in data {
        c = CRC32C[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c
}

/// CRC32c of an SCTP packet, computed with the checksum field taken as zero.
pub fn sctp_crc(pkt: &[u8]) -> u32 {
    let mut c = !0u32;
    c = crc32c_update(c, &pkt[..8]);
    c = crc32c_update(c, &[0, 0, 0, 0]);
    c = crc32c_update(c, &pkt[12..]);
    !c
}

pub fn sctp_crc_ok(pkt: &[u8]) -> bool {
    pkt.len() >= 12 && sctp_crc(pkt).to_le_bytes() == pkt[8..12]
}

pub fn sctp_fix(pkt: &mut [u8]) {
    let c = sctp_crc(pkt);
    pkt[8..12].copy_from_slice(&c.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_value() {
        let mut c = !0u32;
        c = crc32c_update(c, b"123456789");
        assert_eq!(!c, 0xE306_9283);
    }

    #[test]
    fn incremental_matches_full() {
        let mut d = vec![0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        ipv4_header(&mut d);
        let c0 = get16(&d, 10);
        let old = d[12..20].to_vec();
        d[12..20].copy_from_slice(&[192, 168, 1, 1, 172, 16, 0, 9]);
        let inc = adjust(c0, &old, &d[12..20]);
        ipv4_header(&mut d);
        assert_eq!(inc, get16(&d, 10));
    }
}
