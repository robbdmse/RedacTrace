//! NAS (EPS: TS 24.301, 5GS: TS 24.501) message walkers.

pub mod eps;
pub mod fivegs;
pub mod ident;

use crate::engine::Engine;
use anyhow::{bail, Result};

/// An optional IE located by `walk_optional` (value byte range).
struct Ie {
    iei: u8,
    start: usize,
    len: usize,
}

/// Walk the optional part of a NAS message starting at `off`.
///
/// Formats (TS 24.007 11.2.4): IEI bit 8 set -> type 1/2 (one octet);
/// IEI 0x7X -> TLV-E (2-octet length); IEIs listed in `tv` -> TV with the given
/// total length; anything else -> TLV (1-octet length).
fn walk_optional(b: &[u8], mut off: usize, tv: &[(u8, usize)]) -> (Vec<Ie>, Option<anyhow::Error>) {
    let mut v = Vec::new();
    while off < b.len() {
        let iei = b[off];
        if iei & 0x80 != 0 {
            off += 1;
            continue;
        }
        if let Some(&(_, n)) = tv.iter().find(|(i, _)| *i == iei) {
            if off + n > b.len() {
                return (v, Some(anyhow::anyhow!("NAS: truncated TV IE {:#04x}", iei)));
            }
            v.push(Ie { iei, start: off + 1, len: n - 1 });
            off += n;
            continue;
        }
        let (start, len) = if iei & 0xF0 == 0x70 {
            if off + 3 > b.len() {
                return (v, Some(anyhow::anyhow!("NAS: truncated TLV-E IE {:#04x}", iei)));
            }
            (off + 3, u16::from_be_bytes([b[off + 1], b[off + 2]]) as usize)
        } else {
            if off + 2 > b.len() {
                return (v, Some(anyhow::anyhow!("NAS: truncated TLV IE {:#04x}", iei)));
            }
            (off + 2, b[off + 1] as usize)
        };
        if start + len > b.len() {
            return (v, Some(anyhow::anyhow!("NAS: IE {:#04x} exceeds message", iei)));
        }
        v.push(Ie { iei, start, len });
        off = start + len;
    }
    (v, None)
}

/// Call `f` for every optional TV/TLV/TLV-E IE of the message.
fn optional(
    eng: &mut Engine,
    b: &mut [u8],
    off: usize,
    tv: &[(u8, usize)],
    mut f: impl FnMut(&mut Engine, u8, &mut [u8]) -> Result<()>,
) -> Result<()> {
    let (ies, err) = walk_optional(b, off, tv);
    for ie in ies {
        f(eng, ie.iei, &mut b[ie.start..ie.start + ie.len])?;
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Mandatory LV IE at `o`: apply `f` to the value, return the offset after it.
fn lv(
    eng: &mut Engine,
    b: &mut [u8],
    o: usize,
    f: impl FnOnce(&mut Engine, &mut [u8]) -> Result<()>,
) -> Result<usize> {
    if o >= b.len() {
        bail!("NAS: missing mandatory LV IE");
    }
    let l = b[o] as usize;
    let s = o + 1;
    if s + l > b.len() {
        bail!("NAS: LV IE exceeds message");
    }
    f(eng, &mut b[s..s + l])?;
    Ok(s + l)
}

/// Mandatory LV-E IE (2-octet length) at `o`.
fn lve(
    eng: &mut Engine,
    b: &mut [u8],
    o: usize,
    f: impl FnOnce(&mut Engine, &mut [u8]) -> Result<()>,
) -> Result<usize> {
    if o + 2 > b.len() {
        bail!("NAS: missing mandatory LV-E IE");
    }
    let l = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
    let s = o + 2;
    if s + l > b.len() {
        bail!("NAS: LV-E IE exceeds message");
    }
    f(eng, &mut b[s..s + l])?;
    Ok(s + l)
}

fn skip_lv(b: &[u8], o: usize) -> Result<usize> {
    if o >= b.len() || o + 1 + b[o] as usize > b.len() {
        bail!("NAS: bad LV IE");
    }
    Ok(o + 1 + b[o] as usize)
}

fn skip_lve(b: &[u8], o: usize) -> Result<usize> {
    if o + 2 > b.len() {
        bail!("NAS: bad LV-E IE");
    }
    let e = o + 2 + u16::from_be_bytes([b[o], b[o + 1]]) as usize;
    if e > b.len() {
        bail!("NAS: bad LV-E IE");
    }
    Ok(e)
}

fn nothing(_: &mut Engine, _: &mut [u8]) -> Result<()> {
    Ok(())
}
