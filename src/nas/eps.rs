//! EPS NAS (TS 24.301): EMM and ESM messages carried in S1AP NAS-PDUs.

use super::ident::{eps_mobile_identity, mobile_identity, ue_address};
use super::{lv, lve, nothing, optional, skip_lv};
use crate::engine::{Dir, Engine};
use anyhow::Result;

pub fn process(eng: &mut Engine, b: &mut [u8], dir: Dir) -> Result<()> {
    nas(eng, b, dir, 0)
}

fn looks_plain(b: &[u8]) -> bool {
    if b.len() < 2 {
        return false;
    }
    if b[0] == 0x07 {
        return (0x41..=0x69).contains(&b[1]);
    }
    b[0] & 0x0F == 0x02 && b.len() >= 3 && (0xC1..=0xEF).contains(&b[2])
}

fn nas(eng: &mut Engine, b: &mut [u8], dir: Dir, depth: u8) -> Result<()> {
    if b.len() < 2 || depth > 3 {
        return Ok(());
    }
    match b[0] & 0x0F {
        7 => match b[0] >> 4 {
            0 => emm(eng, b, dir, depth),
            // integrity protected: header(1) MAC(4) SQN(1) + plain message
            1 | 3 if b.len() > 6 => nas(eng, &mut b[6..], dir, depth + 1),
            // integrity protected and ciphered: readable only with EEA0
            2 | 4 if b.len() > 6 => {
                if eng.nas_readable(looks_plain(&b[6..])) {
                    eng.stats.nas_null_ciphered += 1;
                    nas(eng, &mut b[6..], dir, depth + 1)
                } else {
                    eng.stats.nas_ciphered += 1;
                    Ok(())
                }
            }
            _ => Ok(()), // service request (12) and reserved
        },
        2 => esm(eng, b),
        _ => Ok(()),
    }
}

fn esm_container(eng: &mut Engine, v: &mut [u8]) -> Result<()> {
    if v.len() >= 3 && v[0] & 0x0F == 0x02 {
        esm(eng, v)
    } else {
        Ok(())
    }
}

/// Nested NAS message (Replayed NAS message container).
fn nested(eng: &mut Engine, v: &mut [u8], dir: Dir, depth: u8) -> Result<()> {
    if eng.nas_readable(looks_plain(v)) {
        nas(eng, v, dir, depth + 1)
    } else {
        Ok(())
    }
}

fn emm(eng: &mut Engine, b: &mut [u8], dir: Dir, depth: u8) -> Result<()> {
    match b[1] {
        // Attach request
        0x41 => {
            let o = lv(eng, b, 3, eps_mobile_identity)?;
            let o = skip_lv(b, o)?; // UE network capability
            let o = lve(eng, b, o, nothing)?; // ESM message container
            optional(eng, b, o, &[(0x19, 4), (0x52, 6), (0x5C, 3), (0x13, 6), (0x17, 2)], |eng, iei, v| {
                match iei {
                    0x50 => eps_mobile_identity(eng, v), // additional GUTI
                    _ => Ok(()),
                }
            })
        }
        // Attach accept
        0x42 => {
            let o = skip_lv(b, 4)?; // [2] result, [3] T3412, TAI list
            let o = lve(eng, b, o, esm_container)?;
            optional(eng, b, o, &[(0x13, 6), (0x53, 2), (0x17, 2), (0x59, 2)], |eng, iei, v| match iei {
                0x50 => eps_mobile_identity(eng, v), // GUTI
                0x23 => mobile_identity(eng, v),     // MS identity
                _ => Ok(()),
            })
        }
        // Attach complete
        0x43 => lve(eng, b, 2, esm_container).map(|_| ()),
        // Detach request (UE originating carries the EPS mobile identity)
        0x45 if dir == Dir::Ul => lv(eng, b, 3, eps_mobile_identity).map(|_| ()),
        // Tracking area update request
        0x48 => {
            let o = lv(eng, b, 3, eps_mobile_identity)?; // old GUTI
            optional(
                eng,
                b,
                o,
                &[(0x19, 4), (0x55, 5), (0x52, 6), (0x5C, 3), (0x13, 6), (0x17, 2)],
                |eng, iei, v| match iei {
                    0x50 => eps_mobile_identity(eng, v), // additional GUTI
                    _ => Ok(()),
                },
            )
        }
        // Tracking area update accept
        0x49 => optional(
            eng,
            b,
            3,
            &[(0x5A, 2), (0x13, 6), (0x53, 2), (0x17, 2), (0x59, 2)],
            |eng, iei, v| match iei {
                0x50 => eps_mobile_identity(eng, v),
                0x23 => mobile_identity(eng, v),
                _ => Ok(()),
            },
        ),
        // Extended service request: M-TMSI as mobile identity
        0x4C => lv(eng, b, 3, mobile_identity).map(|_| ()),
        // GUTI reallocation command
        0x50 => lv(eng, b, 2, eps_mobile_identity).map(|_| ()),
        // Identity response
        0x56 => lv(eng, b, 2, mobile_identity).map(|_| ()),
        // Security mode complete: IMEISV, replayed NAS message container
        0x5E => optional(eng, b, 2, &[], |eng, iei, v| match iei {
            0x23 => mobile_identity(eng, v),
            0x79 => nested(eng, v, Dir::Ul, depth),
            _ => Ok(()),
        }),
        _ => Ok(()),
    }
}

fn esm(eng: &mut Engine, b: &mut [u8]) -> Result<()> {
    if b.len() < 3 {
        return Ok(());
    }
    match b[2] {
        // Activate default EPS bearer context request: EPS QoS, APN, PDN address
        0xC1 => {
            let o = skip_lv(b, 3)?;
            let o = skip_lv(b, o)?;
            lv(eng, b, o, ue_address).map(|_| ())
        }
        _ => Ok(()),
    }
}
