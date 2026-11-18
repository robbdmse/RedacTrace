//! S1AP (3GPP TS 36.413) walker: S1-MME between eNB and MME.

use crate::ap::{self, int_ext};
use crate::engine::{Dir, Engine};
use crate::nas;
use crate::per::{collect_ies, parse_ap_header, single_container, Choice, Per, PduType};
use crate::pseudo::{Domain, NameKind};
use anyhow::{anyhow, Result};

type ItemFn = fn(&mut Engine, &mut Per, Dir) -> Result<()>;

pub fn process(eng: &mut Engine, buf: &mut [u8], lenient: bool) -> Result<()> {
    let (hdr, ies) = {
        let mut p = Per::new(buf).with_lenient(lenient);
        let hdr = parse_ap_header(&mut p)?;
        let mut v = p.sub(hdr.value.0, hdr.value.1);
        let ies = collect_ies(&mut v)?;
        (hdr, ies)
    };
    // initialUEMessage (12) and uplinkNASTransport (13) carry uplink NAS
    let dir = match (hdr.pdu, hdr.procedure) {
        (PduType::Initiating, 12 | 13) => Dir::Ul,
        _ => Dir::Dl,
    };
    let mut first_err = None;
    for (id, s, l) in ies {
        let mut p = Per::range(buf, s, l)?.with_lenient(lenient);
        if let Err(e) = ie(eng, &mut p, id, dir) {
            first_err.get_or_insert(anyhow!("S1AP proc {} IE {}: {}", hdr.procedure, id, e));
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn ie(eng: &mut Engine, p: &mut Per, id: u16, dir: Dir) -> Result<()> {
    match id {
        26 => {
            let (s, l) = p.octets()?;
            nas_at(eng, p, s, l, dir)
        }
        59 => global_enb_id(eng, p),
        60 => ap::name(eng, p, NameKind::Ran),
        61 => ap::name(eng, p, NameKind::Mme),
        96 => s_tmsi(eng, p),
        43 => ue_paging_id(eng, p),
        100 => eutran_cgi(eng, p),
        67 => tai(eng, p),
        189 => {
            // UserLocationInformation ::= SEQUENCE { eutran-cgi, tai, iE-Ext OPT, ... }
            p.seq(true, 1)?;
            eutran_cgi(eng, p)
        }
        4 => target_id(eng, p),
        75 | 157 => gummei(eng, p),
        154 => {
            // GUMMEIList ::= SEQUENCE (SIZE (1..maxnoofMMECs=256)) OF GUMMEI
            let n = p.cwn(256)? + 1;
            for _ in 0..n {
                gummei(eng, p)?;
            }
            Ok(())
        }
        105 => served_gummeis(eng, p),
        224 => {
            // Additional-GUTI ::= SEQUENCE { gUMMEI, m-TMSI, iE-Ext OPT, ... }
            p.seq(true, 1)?;
            gummei(eng, p)?;
            let pos = p.octets_fixed(4)?;
            ap::tmsi_bits(eng, p, pos);
            Ok(())
        }
        24 => erab_list(eng, p, 52, item_ctxt_su_req, dir),
        16 => erab_list(eng, p, 17, item_bearer_su_req, dir),
        30 => erab_list(eng, p, 36, item_bearer_mod_req, dir),
        51 => erab_list(eng, p, 50, item_tla_teid, dir),
        28 => erab_list(eng, p, 39, item_tla_teid, dir),
        22 => erab_list(eng, p, 23, item_tla_teid, dir),
        95 => erab_list(eng, p, 94, item_tla_teid, dir),
        53 => erab_list(eng, p, 27, item_tla_teid, dir),
        199 => erab_list(eng, p, 200, item_tla_teid, dir),
        201 => erab_list(eng, p, 202, item_tla_teid, dir),
        18 => erab_list(eng, p, 20, item_admitted, dir),
        25 => ap::trace_activation(eng, p),
        192 => ap::masked_imeisv(eng, p),
        155 | 184 => ap::tla(eng, p), // GW / SIPTO L-GW TransportLayerAddress
        _ => Ok(()),
    }
}

fn nas_at(eng: &mut Engine, p: &mut Per, s: usize, l: usize, dir: Dir) -> Result<()> {
    nas::eps::process(eng, &mut p.buf[s..s + l], dir)
}

/// Global-ENB-ID ::= SEQUENCE { pLMNidentity, eNB-ID, iE-Extensions OPT, ... }
fn global_enb_id(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    // ENB-ID ::= CHOICE { macro (20), home (28), ..., short-macro (18), long-macro (21) }
    match p.choice(2, true)? {
        Choice::Root(i) => {
            let n = if i == 0 { 20 } else { 28 };
            let pos = p.bits_fixed(n)?;
            ap::enb_bits(eng, p, pos, n);
        }
        Choice::Ext(i) => {
            let (s, l) = p.open_type()?;
            let n = match i {
                0 => 18,
                1 => 21,
                _ => return Ok(()),
            };
            let mut sp = p.sub(s, l);
            let pos = sp.bits_fixed(n)?;
            ap::enb_bits(eng, &mut sp, pos, n);
        }
    }
    Ok(())
}

/// EUTRAN-CGI ::= SEQUENCE { pLMNidentity, cell-ID BIT STRING (SIZE(28)), iE-Ext OPT, ... }
fn eutran_cgi(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    let pos = p.bits_fixed(28)?;
    ap::eutra_cell_bits(eng, p, pos);
    Ok(())
}

/// TAI ::= SEQUENCE { pLMNidentity, tAC, iE-Ext OPT, ... } (PLMN only observed)
fn tai(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    ap::plmn(eng, p)
}

/// S-TMSI ::= SEQUENCE { mMEC OCTET STRING(1), m-TMSI OCTET STRING(4), iE-Ext OPT, ... }
fn s_tmsi(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    let mmec = p.octets_fixed(1)?;
    let tmsi = p.octets_fixed(4)?;
    ap::cn_id_bits(eng, p, mmec, 8, Domain::MmeCode);
    ap::tmsi_bits(eng, p, tmsi);
    Ok(())
}

/// UEPagingID ::= CHOICE { s-TMSI, iMSI IMSI (OCTET STRING (SIZE(3..8))), ... }
fn ue_paging_id(eng: &mut Engine, p: &mut Per) -> Result<()> {
    match p.choice(2, true)? {
        Choice::Root(0) => s_tmsi(eng, p),
        Choice::Root(1) => {
            let (s, l) = p.octets_sized(3, 8, false)?;
            if eng.cfg.anonymize.imsi {
                nas::ident::tbcd_imsi(eng, &mut p.buf[s..s + l]);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// GUMMEI ::= SEQUENCE { pLMN-Identity, mME-Group-ID (2 octets), mME-Code (1 octet), iE-Ext OPT, ... }
fn gummei(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let s = p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    let g = p.octets_fixed(2)?;
    let c = p.octets_fixed(1)?;
    ap::cn_id_bits(eng, p, g, 16, Domain::MmeGroup);
    ap::cn_id_bits(eng, p, c, 8, Domain::MmeCode);
    p.finish_seq(&s, Some(0))
}

/// ServedGUMMEIs ::= SEQUENCE (SIZE(1..8)) OF ServedGUMMEIsItem
fn served_gummeis(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let n = p.cwn(8)? + 1;
    for _ in 0..n {
        let s = p.seq(true, 1)?;
        let np = p.cwn(32)? + 1;
        for _ in 0..np {
            ap::plmn(eng, p)?;
        }
        let ng = p.cwn(65535)? + 1;
        for _ in 0..ng {
            let pos = p.octets_fixed(2)?;
            ap::cn_id_bits(eng, p, pos, 16, Domain::MmeGroup);
        }
        let nc = p.cwn(256)? + 1;
        for _ in 0..nc {
            let pos = p.octets_fixed(1)?;
            ap::cn_id_bits(eng, p, pos, 8, Domain::MmeCode);
        }
        p.finish_seq(&s, Some(0))?;
    }
    Ok(())
}

/// TargetID ::= CHOICE { targeteNB-ID, targetRNC-ID, cGI, ..., targetgNgRanNode-ID }
fn target_id(eng: &mut Engine, p: &mut Per) -> Result<()> {
    if let Choice::Root(0) = p.choice(3, true)? {
        // TargeteNB-ID ::= SEQUENCE { global-ENB-ID, selected-TAI, iE-Ext OPT, ... }
        p.seq(true, 1)?;
        global_enb_id(eng, p)?;
    }
    Ok(())
}

/// E-RAB-IE-ContainerList: SEQUENCE (SIZE(1..256)) OF ProtocolIE-SingleContainer
fn erab_list(eng: &mut Engine, p: &mut Per, item_id: u16, f: ItemFn, dir: Dir) -> Result<()> {
    let n = p.cwn(256)? + 1;
    for _ in 0..n {
        let (id, s, l) = single_container(p)?;
        if id == item_id {
            let mut sp = p.sub(s, l);
            f(eng, &mut sp, dir)?;
        }
    }
    Ok(())
}

fn erab_id(p: &mut Per) -> Result<()> {
    int_ext(p, 16).map(|_| ())
}

fn skip_erab_qos(p: &mut Per) -> Result<()> {
    // E-RABLevelQoSParameters ::= SEQUENCE { qCI, allocationRetentionPriority,
    //     gbrQosInformation OPT, iE-Extensions OPT, ... }
    let s = p.seq(true, 2)?;
    p.cwn(256)?; // QCI
    // AllocationAndRetentionPriority ::= SEQUENCE { priorityLevel (0..15),
    //     pre-emptionCapability, pre-emptionVulnerability, iE-Ext OPT, ... }
    let a = p.seq(true, 1)?;
    p.cwn(16)?;
    p.cwn(2)?;
    p.cwn(2)?;
    p.finish_seq(&a, Some(0))?;
    if s.has(0) {
        // GBR-QosInformation ::= SEQUENCE { 4 x BitRate (0..10000000000), iE-Ext OPT, ... }
        let g = p.seq(true, 1)?;
        for _ in 0..4 {
            p.cwn(10_000_000_001)?;
        }
        p.finish_seq(&g, Some(0))?;
    }
    p.finish_seq(&s, Some(1))
}

fn teid(p: &mut Per) -> Result<()> {
    p.octets_fixed(4).map(|_| ())
}

/// E-RABToBeSetupItemCtxtSUReq ::= SEQUENCE { e-RAB-ID, e-RABlevelQoSParameters,
///     transportLayerAddress, gTP-TEID, nAS-PDU OPT, iE-Extensions OPT, ... }
fn item_ctxt_su_req(eng: &mut Engine, p: &mut Per, dir: Dir) -> Result<()> {
    let s = p.seq(true, 2)?;
    erab_id(p)?;
    skip_erab_qos(p)?;
    ap::tla(eng, p)?;
    teid(p)?;
    if s.has(0) {
        let (st, l) = p.octets()?;
        nas_at(eng, p, st, l, dir)?;
    }
    Ok(())
}

/// E-RABToBeSetupItemBearerSUReq ::= SEQUENCE { e-RAB-ID, e-RABlevelQoSParameters,
///     transportLayerAddress, gTP-TEID, nAS-PDU, iE-Extensions OPT, ... }
fn item_bearer_su_req(eng: &mut Engine, p: &mut Per, dir: Dir) -> Result<()> {
    p.seq(true, 1)?;
    erab_id(p)?;
    skip_erab_qos(p)?;
    ap::tla(eng, p)?;
    teid(p)?;
    let (st, l) = p.octets()?;
    nas_at(eng, p, st, l, dir)
}

/// E-RABToBeModifiedItemBearerModReq ::= SEQUENCE { e-RAB-ID, e-RABLevelQoSParameters,
///     nAS-PDU, iE-Extensions OPT, ... }
fn item_bearer_mod_req(eng: &mut Engine, p: &mut Per, dir: Dir) -> Result<()> {
    p.seq(true, 1)?;
    erab_id(p)?;
    skip_erab_qos(p)?;
    let (st, l) = p.octets()?;
    nas_at(eng, p, st, l, dir)
}

/// Items starting with { e-RAB-ID, transportLayerAddress, gTP-TEID, ... }
fn item_tla_teid(eng: &mut Engine, p: &mut Per, _dir: Dir) -> Result<()> {
    p.seq(true, 1)?;
    erab_id(p)?;
    ap::tla(eng, p)
}

/// E-RABAdmittedItem ::= SEQUENCE { e-RAB-ID, transportLayerAddress, gTP-TEID,
///     dL-transportLayerAddress OPT, dL-gTP-TEID OPT, uL-TransportLayerAddress OPT,
///     uL-GTP-TEID OPT, iE-Extensions OPT, ... }
fn item_admitted(eng: &mut Engine, p: &mut Per, _dir: Dir) -> Result<()> {
    let s = p.seq(true, 5)?;
    erab_id(p)?;
    ap::tla(eng, p)?;
    teid(p)?;
    if s.has(0) {
        ap::tla(eng, p)?;
    }
    if s.has(1) {
        teid(p)?;
    }
    if s.has(2) {
        ap::tla(eng, p)?;
    }
    Ok(())
}
