//! 5GS NAS (TS 24.501): 5GMM and 5GSM messages carried in NGAP NAS-PDUs.

use super::ident::{fivegs_mobile_identity, ue_address};
use super::{lve, optional, skip_lv, skip_lve};
use crate::engine::{Dir, Engine};
use anyhow::Result;

const EPD_5GMM: u8 = 0x7E;
const EPD_5GSM: u8 = 0x2E;

pub fn process(eng: &mut Engine, b: &mut [u8], dir: Dir) -> Result<()> {
    nas(eng, b, dir, 0)
}

fn looks_plain(b: &[u8]) -> bool {
    if b.len() >= 3 && b[0] == EPD_5GMM && b[1] == 0x00 {
        return (0x41..=0x68).contains(&b[2]);
    }
    b.len() >= 4 && b[0] == EPD_5GSM && (0xC1..=0xD6).contains(&b[3])
}

fn nas(eng: &mut Engine, b: &mut [u8], dir: Dir, depth: u8) -> Result<()> {
    if b.len() < 3 || depth > 4 {
        return Ok(());
    }
    match b[0] {
        EPD_5GMM => match b[1] & 0x0F {
            0 => gmm(eng, b, dir, depth),
            // integrity protected: EPD(1) SHT(1) MAC(4) SQN(1) + plain message
            1 | 3 if b.len() > 7 => nas(eng, &mut b[7..], dir, depth + 1),
            // integrity protected and ciphered: readable only with NEA0
            2 | 4 if b.len() > 7 => {
                if eng.nas_readable(looks_plain(&b[7..])) {
                    eng.stats.nas_null_ciphered += 1;
                    nas(eng, &mut b[7..], dir, depth + 1)
                } else {
                    eng.stats.nas_ciphered += 1;
                    Ok(())
                }
            }
            _ => Ok(()),
        },
        EPD_5GSM => gsm(eng, b),
        _ => Ok(()),
    }
}

/// Nested plain NAS message (NAS message container / payload container).
fn nested(eng: &mut Engine, v: &mut [u8], dir: Dir, depth: u8) -> Result<()> {
    if eng.nas_readable(looks_plain(v)) {
        nas(eng, v, dir, depth + 1)
    } else {
        Ok(())
    }
}

fn gmm(eng: &mut Engine, b: &mut [u8], dir: Dir, depth: u8) -> Result<()> {
    match b[2] {
        // Registration request: [3] type+ngKSI, 5GS mobile identity (LV-E), optionals
        0x41 => {
            let o = lve(eng, b, 4, fivegs_mobile_identity)?;
            optional(eng, b, o, &[(0x52, 7)], |eng, iei, v| match iei {
                0x77 => fivegs_mobile_identity(eng, v), // additional GUTI
                0x71 => nested(eng, v, Dir::Ul, depth), // NAS message container
                _ => Ok(()),
            })
        }
        // Registration accept: 5GS registration result (LV), optionals
        0x42 => {
            let o = skip_lv(b, 3)?;
            optional(eng, b, o, &[], |eng, iei, v| match iei {
                0x77 => fivegs_mobile_identity(eng, v), // 5G-GUTI
                _ => Ok(()),
            })
        }
        // Deregistration request (UE originating)
        0x45 => lve(eng, b, 4, fivegs_mobile_identity).map(|_| ()),
        // Service request: [3] type+ngKSI, 5G-S-TMSI (LV-E), optionals
        0x4C => {
            let o = lve(eng, b, 4, fivegs_mobile_identity)?;
            optional(eng, b, o, &[], |eng, iei, v| match iei {
                0x71 => nested(eng, v, Dir::Ul, depth),
                _ => Ok(()),
            })
        }
        // Configuration update command
        0x54 => optional(eng, b, 3, &[(0x46, 2), (0x47, 8)], |eng, iei, v| match iei {
            0x77 => fivegs_mobile_identity(eng, v),
            _ => Ok(()),
        }),
        // Identity response
        0x5C => lve(eng, b, 3, fivegs_mobile_identity).map(|_| ()),
        // Security mode complete: IMEISV, NAS message container, non-IMEISV PEI
        0x5E => optional(eng, b, 3, &[], |eng, iei, v| match iei {
            0x77 | 0x78 => fivegs_mobile_identity(eng, v),
            0x71 => nested(eng, v, Dir::Ul, depth),
            _ => Ok(()),
        }),
        // UL / DL NAS transport: [3] payload container type, payload container (LV-E)
        0x67 | 0x68 => {
            if b.len() < 4 {
                return Ok(());
            }
            let pct = b[3] & 0x0F;
            lve(eng, b, 4, |eng, v| if pct == 1 { nested(eng, v, dir, depth) } else { Ok(()) })
                .map(|_| ())
        }
        _ => Ok(()),
    }
}

fn gsm(eng: &mut Engine, b: &mut [u8]) -> Result<()> {
    if b.len() < 4 {
        return Ok(());
    }
    match b[3] {
        // PDU session establishment accept: [4] type+SSC mode, QoS rules (LV-E),
        // session AMBR (LV), optionals incl. PDU address (0x29)
        0xC2 => {
            let o = skip_lve(b, 5)?;
            let o = skip_lv(b, o)?;
            optional(eng, b, o, &[(0x59, 2), (0x56, 2)], |eng, iei, v| match iei {
                0x29 => ue_address(eng, v),
                _ => Ok(()),
            })
        }
        _ => Ok(()),
    }
}
