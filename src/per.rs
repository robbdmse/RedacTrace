//! Minimal ALIGNED PER (X.691) cursor, just enough to walk S1AP / NGAP messages
//! and overwrite fields in place. Every anonymized value keeps its exact bit
//! length, so the encoding never needs to be regenerated.
//!
//! The cursor works on the whole message buffer with absolute bit positions;
//! nested open types / OCTET STRING (CONTAINING ...) are handled with `sub()`,
//! which restricts the end position but keeps absolute offsets.

use anyhow::{bail, Result};

pub struct Per<'a> {
    pub buf: &'a mut [u8],
    pos: usize, // bit position
    end: usize, // bit end (exclusive)
    /// best effort for messages cut by the capture snap length: open types
    /// longer than the remaining data are clamped instead of failing
    lenient: bool,
}

/// Preamble of a SEQUENCE: extension bit + bitmap of OPTIONAL components.
#[derive(Debug, Clone, Copy)]
pub struct Seq {
    pub ext: bool,
    opt: u32,
    n: usize,
}

impl Seq {
    /// Is the i-th OPTIONAL component (0-based, in definition order) present?
    pub fn has(&self, i: usize) -> bool {
        i < self.n && (self.opt >> (self.n - 1 - i)) & 1 == 1
    }
}

pub enum Choice {
    Root(u64),
    Ext(u64),
}

impl<'a> Per<'a> {
    pub fn new(buf: &'a mut [u8]) -> Per<'a> {
        let end = buf.len() * 8;
        Per { buf, pos: 0, end, lenient: false }
    }

    /// Cursor over bytes `start .. start+len` of `buf` (absolute positions).
    pub fn range(buf: &'a mut [u8], start: usize, len: usize) -> Result<Per<'a>> {
        if start + len > buf.len() {
            bail!("PER range out of bounds");
        }
        Ok(Per { buf, pos: start * 8, end: (start + len) * 8, lenient: false })
    }

    pub fn with_lenient(mut self, lenient: bool) -> Per<'a> {
        self.lenient = lenient;
        self
    }

    /// Nested cursor over bytes `start .. start+len` (typically an open type).
    pub fn sub(&mut self, start: usize, len: usize) -> Per<'_> {
        Per { buf: &mut *self.buf, pos: start * 8, end: (start + len) * 8, lenient: self.lenient }
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.end {
            bail!("PER: truncated (need {} bits at bit {}, end {})", n, self.pos, self.end);
        }
        Ok(())
    }

    /// Read `n` (<= 64) bits MSB-first.
    pub fn bits(&mut self, n: usize) -> Result<u64> {
        self.need(n)?;
        let v = read_bits(self.buf, self.pos, n);
        self.pos += n;
        Ok(v)
    }

    pub fn bit(&mut self) -> Result<bool> {
        Ok(self.bits(1)? == 1)
    }

    pub fn align(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }

    pub fn skip_bits(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }

    /// Byte position (cursor must be octet aligned).
    pub fn byte_pos(&self) -> usize {
        debug_assert!(self.pos.is_multiple_of(8));
        self.pos / 8
    }

    /// Constrained whole number with the given range (ub - lb + 1), X.691 10.5.
    /// Returns the offset from the lower bound.
    pub fn cwn(&mut self, range: u64) -> Result<u64> {
        if range <= 1 {
            return Ok(0);
        }
        if range <= 255 {
            let nbits = bits_for(range - 1);
            return self.bits(nbits);
        }
        if range == 256 {
            self.align();
            return self.bits(8);
        }
        if range <= 65536 {
            self.align();
            return self.bits(16);
        }
        // "indefinite length" case: length in octets as a constrained number
        // 1..max_octets, then the octet-aligned value.
        let max_octets = bits_for(range - 1).div_ceil(8);
        let len = self.cwn(max_octets as u64)? as usize + 1;
        self.align();
        if len > 8 {
            bail!("PER: integer too long");
        }
        self.bits(len * 8)
    }

    /// Unconstrained / semi-constrained length determinant (X.691 11.9.3.6-8).
    pub fn len_det(&mut self) -> Result<usize> {
        self.align();
        let b = self.bits(8)? as usize;
        if b & 0x80 == 0 {
            return Ok(b);
        }
        if b & 0xC0 == 0x80 {
            let b2 = self.bits(8)? as usize;
            return Ok(((b & 0x3F) << 8) | b2);
        }
        bail!("PER: fragmented length determinant not supported")
    }

    /// Length determinant of a SIZE(lb..ub) constrained type.
    pub fn constrained_len(&mut self, lb: u64, ub: u64) -> Result<usize> {
        if ub < 65536 {
            Ok((lb + self.cwn(ub - lb + 1)?) as usize)
        } else {
            self.len_det()
        }
    }

    /// Normally small non-negative whole number (X.691 11.6).
    pub fn nsnn(&mut self) -> Result<u64> {
        if !self.bit()? {
            self.bits(6)
        } else {
            let len = self.len_det()?;
            if len == 0 || len > 8 {
                bail!("PER: bad normally-small number");
            }
            self.bits(len * 8)
        }
    }

    /// Open type: returns (byte start, byte length) and moves past it.
    pub fn open_type(&mut self) -> Result<(usize, usize)> {
        let mut len = self.len_det()?;
        let start = self.byte_pos();
        if self.lenient {
            len = len.min(self.end.saturating_sub(self.pos) / 8);
        }
        self.skip_bits(len * 8)?;
        Ok((start, len))
    }

    /// SEQUENCE preamble.
    pub fn seq(&mut self, extensible: bool, n_opt: usize) -> Result<Seq> {
        let ext = if extensible { self.bit()? } else { false };
        let opt = if n_opt > 0 { self.bits(n_opt)? as u32 } else { 0 };
        Ok(Seq { ext, opt, n: n_opt })
    }

    /// CHOICE index. For an extension alternative the caller must read the open type.
    pub fn choice(&mut self, n_root: u64, extensible: bool) -> Result<Choice> {
        if extensible && self.bit()? {
            return Ok(Choice::Ext(self.nsnn()?));
        }
        let idx = self.cwn(n_root)?;
        if idx >= n_root {
            bail!("PER: choice index out of range");
        }
        Ok(Choice::Root(idx))
    }

    /// ENUMERATED value (root index or 1000+ext index).
    pub fn enumerated(&mut self, n_root: u64, extensible: bool) -> Result<u64> {
        if extensible && self.bit()? {
            return Ok(1000 + self.nsnn()?);
        }
        self.cwn(n_root)
    }

    /// Fixed-size OCTET STRING: returns the bit position where it starts.
    pub fn octets_fixed(&mut self, n: usize) -> Result<usize> {
        if n > 2 {
            self.align();
        }
        let p = self.pos;
        self.skip_bits(n * 8)?;
        Ok(p)
    }

    /// Fixed-size BIT STRING: returns the bit position where it starts.
    pub fn bits_fixed(&mut self, n: usize) -> Result<usize> {
        if n > 16 {
            self.align();
        }
        let p = self.pos;
        self.skip_bits(n)?;
        Ok(p)
    }

    /// Size-constrained BIT STRING (SIZE(lb..ub[, ...])): returns (bit pos, nbits).
    pub fn bits_sized(&mut self, lb: u64, ub: u64, extensible: bool) -> Result<(usize, usize)> {
        let n = if extensible && self.bit()? {
            self.len_det()?
        } else if lb == ub {
            return Ok((self.bits_fixed(lb as usize)?, lb as usize));
        } else {
            self.constrained_len(lb, ub)?
        };
        if n > 0 {
            self.align();
        }
        let p = self.pos;
        self.skip_bits(n)?;
        Ok((p, n))
    }

    /// Unconstrained OCTET STRING: returns (byte start, byte length).
    pub fn octets(&mut self) -> Result<(usize, usize)> {
        self.open_type()
    }

    /// Size-constrained OCTET STRING: returns (byte start, byte length).
    pub fn octets_sized(&mut self, lb: u64, ub: u64, extensible: bool) -> Result<(usize, usize)> {
        let n = if extensible && self.bit()? {
            self.len_det()?
        } else if lb == ub {
            let p = self.octets_fixed(lb as usize)?;
            if p % 8 != 0 {
                bail!("PER: unaligned octet string not supported here");
            }
            return Ok((p / 8, lb as usize));
        } else {
            self.constrained_len(lb, ub)?
        };
        self.align();
        let start = self.byte_pos();
        self.skip_bits(n * 8)?;
        Ok((start, n))
    }

    /// 8-bit known-multiplier character string (PrintableString / VisibleString /
    /// UTF8String) with SIZE(lb..ub, ...): returns (byte start, byte length).
    pub fn char_string(&mut self, lb: u64, ub: u64, extensible: bool) -> Result<(usize, usize)> {
        self.octets_sized(lb, ub, extensible)
    }

    /// Skip a ProtocolExtensionContainer (SIZE(1..65535) OF ProtocolExtensionField).
    pub fn skip_ext_container(&mut self) -> Result<()> {
        let n = self.cwn(65535)? + 1;
        for _ in 0..n {
            self.cwn(65536)?; // id
            self.bits(2)?; // criticality
            self.open_type()?;
        }
        Ok(())
    }

    /// Skip a ProtocolIE-SingleContainer / ProtocolIE-Field.
    pub fn skip_ie_field(&mut self) -> Result<()> {
        self.cwn(65536)?;
        self.bits(2)?;
        self.open_type()?;
        Ok(())
    }

    /// Skip SEQUENCE extension additions (present when the extension bit was set).
    pub fn skip_seq_extensions(&mut self, s: &Seq) -> Result<()> {
        if !s.ext {
            return Ok(());
        }
        // normally small length (n-1), then the presence bitmap, then open types
        let n = if !self.bit()? { self.bits(6)? as usize + 1 } else { self.len_det()? };
        let mut present = Vec::with_capacity(n);
        for _ in 0..n {
            present.push(self.bit()?);
        }
        for p in present {
            if p {
                self.open_type()?;
            }
        }
        Ok(())
    }

    /// Finish a SEQUENCE: skip its trailing iE-Extensions (if the given optional
    /// index is present) and any extension additions.
    pub fn finish_seq(&mut self, s: &Seq, ext_container_opt: Option<usize>) -> Result<()> {
        if let Some(i) = ext_container_opt {
            if s.has(i) {
                self.skip_ext_container()?;
            }
        }
        self.skip_seq_extensions(s)
    }

    pub fn get(&self, pos: usize, n: usize) -> u64 {
        read_bits(self.buf, pos, n)
    }

    pub fn put(&mut self, pos: usize, n: usize, v: u64) {
        write_bits(self.buf, pos, n, v)
    }
}

/// Number of bits needed to represent `v` (at least 1).
pub fn bits_for(v: u64) -> usize {
    (64 - v.leading_zeros() as usize).max(1)
}

pub fn read_bits(buf: &[u8], pos: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..n {
        let p = pos + i;
        let b = (buf[p / 8] >> (7 - (p % 8))) & 1;
        v = (v << 1) | b as u64;
    }
    v
}

pub fn write_bits(buf: &mut [u8], pos: usize, n: usize, v: u64) {
    for i in 0..n {
        let p = pos + i;
        let bit = ((v >> (n - 1 - i)) & 1) as u8;
        let mask = 1u8 << (7 - (p % 8));
        if bit == 1 {
            buf[p / 8] |= mask;
        } else {
            buf[p / 8] &= !mask;
        }
    }
}

// ---------------------------------------------------------------------------
// Common S1AP / NGAP framing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    Initiating,
    Successful,
    Unsuccessful,
}

pub struct ApHeader {
    pub pdu: PduType,
    pub procedure: u8,
    /// byte range of the message value (SEQUENCE { protocolIEs, ... })
    pub value: (usize, usize),
}

/// Parse `XXAP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome, ... }`.
pub fn parse_ap_header(p: &mut Per) -> Result<ApHeader> {
    let pdu = match p.choice(3, true)? {
        Choice::Root(0) => PduType::Initiating,
        Choice::Root(1) => PduType::Successful,
        Choice::Root(2) => PduType::Unsuccessful,
        _ => bail!("unsupported PDU choice"),
    };
    let procedure = p.cwn(256)? as u8;
    p.bits(2)?; // criticality
    let value = p.open_type()?;
    Ok(ApHeader { pdu, procedure, value })
}

/// IE of a ProtocolIE-Container: (id, byte start, byte length of the value).
pub type IeRef = (u16, usize, usize);

/// Parse `SEQUENCE { protocolIEs ProtocolIE-Container, ... }` at the cursor.
pub fn collect_ies(p: &mut Per) -> Result<Vec<IeRef>> {
    p.seq(true, 0)?;
    collect_container(p)
}

/// Parse a bare ProtocolIE-Container (SIZE(0..65535) OF ProtocolIE-Field).
pub fn collect_container(p: &mut Per) -> Result<Vec<IeRef>> {
    let n = p.cwn(65536)? as usize;
    let mut v = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        let r = (|| -> Result<IeRef> {
            let id = p.cwn(65536)? as u16;
            p.bits(2)?;
            let (s, l) = p.open_type()?;
            Ok((id, s, l))
        })();
        match r {
            Ok(ie) => v.push(ie),
            // truncated capture: keep the IEs that are (at least partly) present
            Err(_) if p.lenient => break,
            Err(e) => return Err(e),
        }
    }
    Ok(v)
}

/// Parse one ProtocolIE-SingleContainer at the cursor.
pub fn single_container(p: &mut Per) -> Result<IeRef> {
    let id = p.cwn(65536)? as u16;
    p.bits(2)?;
    let (s, l) = p.open_type()?;
    Ok((id, s, l))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_rw_roundtrip() {
        let mut b = [0u8; 4];
        write_bits(&mut b, 3, 10, 0x2AB);
        assert_eq!(read_bits(&b, 3, 10), 0x2AB);
        assert_eq!(b, [0x15, 0x58, 0, 0]);
    }

    #[test]
    fn printable_string_amf_name() {
        // value of AMFName "open5gs-amf0"
        let mut v = vec![0x05, 0x80];
        v.extend_from_slice(b"open5gs-amf0");
        let mut p = Per::new(&mut v);
        let (s, l) = p.char_string(1, 150, true).unwrap();
        assert_eq!((s, l), (2, 12));
    }

    #[test]
    fn gnb_id_bitstring() {
        // GlobalRANNodeID: globalGNB-ID, PLMN 02 f8 39, gNB-ID 32 bits 0x00000001
        let mut v = vec![0x00, 0x02, 0xf8, 0x39, 0x50, 0x00, 0x00, 0x00, 0x01];
        let mut p = Per::new(&mut v);
        let Choice::Root(0) = p.choice(4, false).unwrap() else { panic!() };
        p.seq(true, 1).unwrap();
        let _plmn = p.octets_fixed(3).unwrap();
        let Choice::Root(0) = p.choice(2, false).unwrap() else { panic!() };
        let (pos, n) = p.bits_sized(22, 32, false).unwrap();
        assert_eq!(n, 32);
        assert_eq!(p.get(pos, n), 1);
    }
}
