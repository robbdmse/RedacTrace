//! NGAP (3GPP TS 38.413) walker: N2 between gNB / ng-eNB / N3IWF and AMF.

use crate::ap;
use crate::engine::{Dir, Engine};
use crate::nas;
use crate::per::{collect_ies, parse_ap_header, Choice, Per, PduType};
use crate::pseudo::{Domain, NameKind};
use anyhow::{anyhow, Result};

pub fn process(eng: &mut Engine, buf: &mut [u8], lenient: bool) -> Result<()> {
    let (hdr, ies) = {
        let mut p = Per::new(buf).with_lenient(lenient);
        let hdr = parse_ap_header(&mut p)?;
        let mut v = p.sub(hdr.value.0, hdr.value.1);
        let ies = collect_ies(&mut v)?;
        (hdr, ies)
    };
    // InitialUEMessage (15) and UplinkNASTransport (46) carry uplink NAS
    let dir = match (hdr.pdu, hdr.procedure) {
        (PduType::Initiating, 15 | 46) => Dir::Ul,
        _ => Dir::Dl,
    };
    let mut first_err = None;
    for (id, s, l) in ies {
        let mut p = Per::range(buf, s, l)?.with_lenient(lenient);
        if let Err(e) = ie(eng, &mut p, id, dir) {
            first_err.get_or_insert(anyhow!("NGAP proc {} IE {}: {}", hdr.procedure, id, e));
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn ie(eng: &mut Engine, p: &mut Per, id: u16, dir: Dir) -> Result<()> {
    match id {
        1 | 48 => ap::name(eng, p, NameKind::Amf), // AMFName, OldAMF
        82 => ap::name(eng, p, NameKind::Ran),     // RANNodeName
        274 | 443 => ap::extended_name(eng, p, NameKind::Amf),
        273 => ap::extended_name(eng, p, NameKind::Ran),
        27 => global_ran_node_id(eng, p),
        105 => target_id(eng, p),
        26 => five_g_s_tmsi(eng, p),
        115 => {
            // UEPagingIdentity ::= CHOICE { fiveG-S-TMSI, choice-Extensions }
            if let Choice::Root(0) = p.choice(2, false)? {
                five_g_s_tmsi(eng, p)?;
            }
            Ok(())
        }
        28 => guami(eng, p),
        3 => {
            // AMFSetID ::= BIT STRING (SIZE(10))
            let pos = p.bits_fixed(10)?;
            ap::cn_id_bits(eng, p, pos, 10, Domain::AmfSet);
            Ok(())
        }
        34 => ap::masked_imeisv(eng, p),
        96 => served_guami_list(eng, p),
        120 => unavailable_guami_list(eng, p),
        38 => {
            let (s, l) = p.octets()?;
            nas_at(eng, p, s, l, dir)
        }
        121 => user_location_information(eng, p),
        45 => nr_cgi(eng, p),
        25 => eutra_cgi(eng, p),
        71 | 74 => pdu_setup_req_list(eng, p, true, dir),
        73 => pdu_setup_req_list(eng, p, false, dir),
        72 | 75 => pdu_transfer_list(eng, p, setup_response_transfer),
        53 => pdu_transfer_list(eng, p, ho_request_ack_transfer),
        76 => pdu_transfer_list(eng, p, path_switch_request_transfer),
        77 => pdu_transfer_list(eng, p, path_switch_ack_transfer),
        64 => modify_req_list(eng, p, dir),
        5..=8 => tnl_association_list(eng, p, id),
        108 => ap::trace_activation(eng, p),
        _ => Ok(()),
    }
}

fn nas_at(eng: &mut Engine, p: &mut Per, s: usize, l: usize, dir: Dir) -> Result<()> {
    nas::fivegs::process(eng, &mut p.buf[s..s + l], dir)
}

/// GlobalRANNodeID ::= CHOICE { globalGNB-ID, globalNgENB-ID, globalN3IWF-ID, choice-Extensions }
fn global_ran_node_id(eng: &mut Engine, p: &mut Per) -> Result<()> {
    match p.choice(4, false)? {
        Choice::Root(0) => global_gnb_id(eng, p),
        Choice::Root(1) => global_ngenb_id(eng, p),
        _ => Ok(()),
    }
}

/// GlobalGNB-ID ::= SEQUENCE { pLMNIdentity, gNB-ID GNB-ID, iE-Ext OPT, ... }
/// GNB-ID ::= CHOICE { gNB-ID BIT STRING (SIZE(22..32)), choice-Extensions }
fn global_gnb_id(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    if let Choice::Root(0) = p.choice(2, false)? {
        let (pos, n) = p.bits_sized(22, 32, false)?;
        ap::gnb_bits(eng, p, pos, n);
    }
    Ok(())
}

/// GlobalNgENB-ID ::= SEQUENCE { pLMNIdentity, ngENB-ID NgENB-ID, iE-Ext OPT, ... }
/// NgENB-ID ::= CHOICE { macro (20), shortMacro (18), longMacro (21), choice-Extensions }
fn global_ngenb_id(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    let n = match p.choice(4, false)? {
        Choice::Root(0) => 20,
        Choice::Root(1) => 18,
        Choice::Root(2) => 21,
        _ => return Ok(()),
    };
    let pos = p.bits_fixed(n)?;
    ap::enb_bits(eng, p, pos, n);
    Ok(())
}

/// TargetID ::= CHOICE { targetRANNodeID, targeteNB-ID, choice-Extensions }
fn target_id(eng: &mut Engine, p: &mut Per) -> Result<()> {
    match p.choice(3, false)? {
        Choice::Root(0) => {
            // TargetRANNodeID ::= SEQUENCE { globalRANNodeID, selectedTAI, iE-Ext OPT, ... }
            p.seq(true, 1)?;
            global_ran_node_id(eng, p)
        }
        Choice::Root(1) => {
            // TargeteNB-ID ::= SEQUENCE { globalENB-ID GlobalNgENB-ID, selected-EPS-TAI, ... }
            p.seq(true, 1)?;
            global_ngenb_id(eng, p)
        }
        _ => Ok(()),
    }
}

/// FiveG-S-TMSI ::= SEQUENCE { aMFSetID (10 bits), aMFPointer (6 bits), fiveG-TMSI (4 octets), iE-Ext OPT, ... }
fn five_g_s_tmsi(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    let set = p.bits_fixed(10)?;
    let ptr = p.bits_fixed(6)?;
    let tmsi = p.octets_fixed(4)?;
    ap::cn_id_bits(eng, p, set, 10, Domain::AmfSet);
    ap::cn_id_bits(eng, p, ptr, 6, Domain::AmfPointer);
    ap::tmsi_bits(eng, p, tmsi);
    Ok(())
}

/// GUAMI ::= SEQUENCE { pLMNIdentity, aMFRegionID (8), aMFSetID (10), aMFPointer (6), iE-Ext OPT, ... }
fn guami(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let s = p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    let region = p.bits_fixed(8)?;
    let set = p.bits_fixed(10)?;
    let ptr = p.bits_fixed(6)?;
    ap::cn_id_bits(eng, p, region, 8, Domain::AmfRegion);
    ap::cn_id_bits(eng, p, set, 10, Domain::AmfSet);
    ap::cn_id_bits(eng, p, ptr, 6, Domain::AmfPointer);
    p.finish_seq(&s, Some(0))
}

/// ServedGUAMIList ::= SEQUENCE (SIZE(1..256)) OF
///   ServedGUAMIItem ::= SEQUENCE { gUAMI, backupAMFName OPT, iE-Extensions OPT, ... }
fn served_guami_list(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let n = p.cwn(256)? + 1;
    for _ in 0..n {
        let s = p.seq(true, 2)?;
        guami(eng, p)?;
        if s.has(0) {
            ap::name(eng, p, NameKind::Amf)?;
        }
        p.finish_seq(&s, Some(1))?;
    }
    Ok(())
}

/// UnavailableGUAMIList ::= SEQUENCE (SIZE(1..256)) OF
///   UnavailableGUAMIItem ::= SEQUENCE { gUAMI, timerApproachForGUAMIRemoval OPT,
///                                       backupAMFName OPT, iE-Extensions OPT, ... }
fn unavailable_guami_list(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let n = p.cwn(256)? + 1;
    for _ in 0..n {
        let s = p.seq(true, 3)?;
        guami(eng, p)?;
        if s.has(0) {
            p.enumerated(1, true)?;
        }
        if s.has(1) {
            ap::name(eng, p, NameKind::Amf)?;
        }
        p.finish_seq(&s, Some(2))?;
    }
    Ok(())
}

/// UserLocationInformation ::= CHOICE { EUTRA, NR, N3IWF-with-PortNumber, choice-Extensions }
fn user_location_information(eng: &mut Engine, p: &mut Per) -> Result<()> {
    match p.choice(4, false)? {
        Choice::Root(0) => {
            p.seq(true, 2)?; // { eUTRA-CGI, tAI, timeStamp OPT, iE-Ext OPT, ... }
            eutra_cgi(eng, p)
        }
        Choice::Root(1) => {
            p.seq(true, 2)?; // { nR-CGI, tAI, timeStamp OPT, iE-Ext OPT, ... }
            nr_cgi(eng, p)
        }
        Choice::Root(2) => {
            p.seq(true, 1)?; // { iPAddress, portNumber, iE-Ext OPT, ... }
            ap::tla(eng, p)
        }
        _ => Ok(()),
    }
}

/// NR-CGI ::= SEQUENCE { pLMNIdentity, nRCellIdentity BIT STRING (SIZE(36)), iE-Ext OPT, ... }
fn nr_cgi(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    let pos = p.bits_fixed(36)?;
    ap::nr_cell_bits(eng, p, pos);
    Ok(())
}

/// EUTRA-CGI ::= SEQUENCE { pLMNIdentity, eUTRACellIdentity BIT STRING (SIZE(28)), iE-Ext OPT, ... }
fn eutra_cgi(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 1)?;
    ap::plmn(eng, p)?;
    let pos = p.bits_fixed(28)?;
    ap::eutra_cell_bits(eng, p, pos);
    Ok(())
}

/// S-NSSAI ::= SEQUENCE { sST (1 octet), sD (3 octets) OPT, iE-Ext OPT, ... }
fn skip_snssai(p: &mut Per) -> Result<()> {
    let s = p.seq(true, 2)?;
    p.octets_fixed(1)?;
    if s.has(0) {
        p.octets_fixed(3)?;
    }
    p.finish_seq(&s, Some(1))
}

/// PDUSessionResourceSetupItemSUReq / CxtReq ::= SEQUENCE { pDUSessionID, NAS-PDU OPT,
///     s-NSSAI, ...Transfer, iE-Ext OPT, ... }
/// PDUSessionResourceSetupItemHOReq ::= SEQUENCE { pDUSessionID, s-NSSAI, ...Transfer, iE-Ext OPT, ... }
fn pdu_setup_req_list(eng: &mut Engine, p: &mut Per, has_nas: bool, dir: Dir) -> Result<()> {
    let n = p.cwn(256)? + 1;
    for _ in 0..n {
        let s = p.seq(true, if has_nas { 2 } else { 1 })?;
        p.cwn(256)?; // PDUSessionID
        if has_nas && s.has(0) {
            let (st, l) = p.octets()?;
            nas_at(eng, p, st, l, dir)?;
        }
        skip_snssai(p)?;
        let (st, l) = p.octets()?;
        setup_request_transfer(eng, &mut p.sub(st, l))?;
        p.finish_seq(&s, Some(if has_nas { 1 } else { 0 }))?;
    }
    Ok(())
}

/// PDUSessionResourceSetupRequestTransfer ::= SEQUENCE { protocolIEs, ... }
fn setup_request_transfer(eng: &mut Engine, p: &mut Per) -> Result<()> {
    for (id, s, l) in collect_ies(p)? {
        match id {
            139 => up_tnl_information(eng, &mut p.sub(s, l))?, // UL-NGU-UP-TNLInformation
            126 => {
                // AdditionalUL-NGU-UP-TNLInformation: SEQUENCE (SIZE(1..3)) OF
                //   UPTransportLayerInformationItem ::= SEQUENCE { nGU-UP-TNLInformation, iE-Ext OPT, ... }
                let mut sp = p.sub(s, l);
                let n = sp.cwn(3)? + 1;
                for _ in 0..n {
                    let seq = sp.seq(true, 1)?;
                    up_tnl_information(eng, &mut sp)?;
                    sp.finish_seq(&seq, Some(0))?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// UPTransportLayerInformation ::= CHOICE { gTPTunnel, choice-Extensions }
/// GTPTunnel ::= SEQUENCE { transportLayerAddress, gTP-TEID, iE-Ext OPT, ... }
fn up_tnl_information(eng: &mut Engine, p: &mut Per) -> Result<()> {
    if let Choice::Root(0) = p.choice(2, false)? {
        let s = p.seq(true, 1)?;
        ap::tla(eng, p)?;
        p.octets_fixed(4)?;
        p.finish_seq(&s, Some(0))?;
    }
    Ok(())
}

type TransferFn = fn(&mut Engine, &mut Per) -> Result<()>;

/// Lists of SEQUENCE { pDUSessionID, OCTET STRING (CONTAINING transfer), iE-Ext OPT, ... }
fn pdu_transfer_list(eng: &mut Engine, p: &mut Per, f: TransferFn) -> Result<()> {
    let n = p.cwn(256)? + 1;
    for _ in 0..n {
        let s = p.seq(true, 1)?;
        p.cwn(256)?;
        let (st, l) = p.octets()?;
        f(eng, &mut p.sub(st, l))?;
        p.finish_seq(&s, Some(0))?;
    }
    Ok(())
}

/// PDUSessionResourceSetupResponseTransfer ::= SEQUENCE { dLQosFlowPerTNLInformation,
///     4 x OPTIONAL, ... } with QosFlowPerTNLInformation ::= SEQUENCE {
///     uPTransportLayerInformation, associatedQosFlowList, iE-Ext OPT, ... }
fn setup_response_transfer(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 4)?;
    p.seq(true, 1)?;
    up_tnl_information(eng, p)
}

/// HandoverRequestAcknowledgeTransfer ::= SEQUENCE { dL-NGU-UP-TNLInformation,
///     dLForwardingUP-TNLInformation OPT, ... (5 optional in total) }
fn ho_request_ack_transfer(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let s = p.seq(true, 5)?;
    up_tnl_information(eng, p)?;
    if s.has(0) {
        up_tnl_information(eng, p)?;
    }
    Ok(())
}

/// PathSwitchRequestTransfer ::= SEQUENCE { dL-NGU-UP-TNLInformation, (3 optional), ... }
fn path_switch_request_transfer(eng: &mut Engine, p: &mut Per) -> Result<()> {
    p.seq(true, 3)?;
    up_tnl_information(eng, p)
}

/// PathSwitchRequestAcknowledgeTransfer ::= SEQUENCE { uL-NGU-UP-TNLInformation OPT, (3 optional), ... }
fn path_switch_ack_transfer(eng: &mut Engine, p: &mut Per) -> Result<()> {
    let s = p.seq(true, 3)?;
    if s.has(0) {
        up_tnl_information(eng, p)?;
    }
    Ok(())
}

/// PDUSessionResourceModifyItemModReq ::= SEQUENCE { pDUSessionID, nAS-PDU OPT,
///     ...ModifyRequestTransfer, iE-Ext OPT, ... }
fn modify_req_list(eng: &mut Engine, p: &mut Per, dir: Dir) -> Result<()> {
    let n = p.cwn(256)? + 1;
    for _ in 0..n {
        let s = p.seq(true, 2)?;
        p.cwn(256)?;
        if s.has(0) {
            let (st, l) = p.octets()?;
            nas_at(eng, p, st, l, dir)?;
        }
        p.octets()?;
        p.finish_seq(&s, Some(1))?;
    }
    Ok(())
}

/// AMF-TNLAssociation{Setup,ToAdd,ToRemove,ToUpdate}List ::= SEQUENCE (SIZE(1..32)) OF item;
/// every item starts with aMF-TNLAssociationAddress CPTransportLayerInformation.
fn tnl_association_list(eng: &mut Engine, p: &mut Per, id: u16) -> Result<()> {
    let n = p.cwn(32)? + 1;
    for _ in 0..n {
        let n_opt = match id {
            6 => 2, // usage OPT, weight, iE-Ext OPT
            8 => 3, // usage OPT, weight OPT, iE-Ext OPT
            _ => 1, // iE-Ext OPT
        };
        let s = p.seq(true, n_opt)?;
        // CPTransportLayerInformation ::= CHOICE { endpointIPAddress, choice-Extensions }
        match p.choice(2, false)? {
            Choice::Root(0) => ap::tla(eng, p)?,
            _ => {
                p.skip_ie_field()?;
            }
        }
        match id {
            6 => {
                if s.has(0) {
                    p.enumerated(3, true)?;
                }
                p.cwn(256)?;
                p.finish_seq(&s, Some(1))?;
            }
            8 => {
                if s.has(0) {
                    p.enumerated(3, true)?;
                }
                if s.has(1) {
                    p.cwn(256)?;
                }
                p.finish_seq(&s, Some(2))?;
            }
            _ => p.finish_seq(&s, Some(0))?,
        }
    }
    Ok(())
}
