#!/usr/bin/env python3
"""Generate synthetic S1-MME (S1AP) and N2 (NGAP) test traces.

Writes <outdir>/test_s1_n2.pcap and <outdir>/test_s1_n2.pcapng. All S1AP / NGAP
messages are hand-encoded in ALIGNED PER and carry well-known test identities,
so it is easy to verify that they are gone after anonymization:

  IMSI 001010123456789 (EPS), SUCI MSIN 0000000001 (5G), IMEISV 3569380356438007,
  M-TMSI 0xc0ffee01, 5G-TMSI 0xc0ffee02 / 0xc0ffee03, AMF name "open5gs-amf0",
  gNB-ID 0x1a2b3 (22 bits) "gnb-brussels-01", eNB-ID 0x00042 "enb-gent-02",
  MME "mme-core-1", UE IPs 10.45.0.2 / 10.45.0.7, GTP endpoints 10.10.0.5 ...

Usage: python gen_test_traces.py [outdir]
"""
import os
import struct
import sys

REJECT, IGNORE = 0, 1
PLMN = bytes([0x00, 0xF1, 0x10])  # MCC 001, MNC 01

ENB_MAC, MME_MAC = bytes.fromhex("020000aa0001"), bytes.fromhex("020000bb0002")
GNB_MAC, AMF_MAC = bytes.fromhex("3c2c30c0ffee"), bytes.fromhex("0050569a1b2c")
ENB_IP, MME_IP = [192, 168, 10, 20], [192, 168, 10, 1]
GNB_IP, AMF_IP = [10, 100, 200, 11], [10, 100, 200, 1]
GNB_IP6 = bytes.fromhex("20010db8000100000000000000000011")
AMF_IP6 = bytes.fromhex("20010db8000100000000000000000001")

GNB_ID, GNB_ID_LEN = 0x1A2B3, 22
ENB_ID = 0x00042
IMSI = "001010123456789"
MSIN = "0000000001"
IMEISV = "3569380356438007"


# --------------------------------------------------------------- APER builder
class Bits:
    def __init__(self):
        self.v = []

    def u(self, val, n):
        for i in range(n - 1, -1, -1):
            self.v.append((val >> i) & 1)
        return self

    def align(self):
        while len(self.v) % 8:
            self.v.append(0)
        return self

    def raw(self, bs):
        for b in bs:
            self.u(b, 8)
        return self

    def octets(self, bs):
        return self.align().raw(bs)

    def cwn(self, val, rng):
        if rng <= 1:
            return self
        if rng <= 255:
            return self.u(val, (rng - 1).bit_length())
        if rng == 256:
            return self.align().u(val, 8)
        if rng <= 65536:
            return self.align().u(val, 16)
        n = max(1, (val.bit_length() + 7) // 8)
        maxo = ((rng - 1).bit_length() + 7) // 8
        self.cwn(n - 1, maxo)
        return self.align().u(val, n * 8)

    def len_det(self, n):
        self.align()
        if n < 128:
            return self.u(n, 8)
        assert n < 16384
        return self.u(0x8000 | n, 16)

    def open_type(self, bs):
        return self.len_det(len(bs)).raw(bs)

    def string(self, s):  # PrintableString (SIZE(1..150, ...))
        return self.u(0, 1).cwn(len(s) - 1, 150).align().raw(s.encode())

    def bytes(self):
        self.align()
        out = bytearray()
        for i in range(0, len(self.v), 8):
            b = 0
            for bit in self.v[i:i + 8]:
                b = (b << 1) | bit
            out.append(b)
        return bytes(out)


def ie(id_, crit, val):
    if isinstance(val, Bits):
        val = val.bytes()
    return Bits().cwn(id_, 65536).u(crit, 2).open_type(val).bytes()


def ap_pdu(kind, proc, crit, ies):
    body = Bits().u(0, 1).cwn(len(ies), 65536)
    for x in ies:
        body.align().raw(x)
    return Bits().u(0, 1).u(kind, 2).cwn(proc, 256).u(crit, 2).open_type(body.bytes()).bytes()


def ie_container(ies):
    b = Bits().u(0, 1).cwn(len(ies), 65536)
    for x in ies:
        b.align().raw(x)
    return b.bytes()


def octets_ie(bs):
    return Bits().open_type(bs).bytes()


# --------------------------------------------------------------- NAS helpers
def tbcd(digits):
    ds = [int(c) for c in digits]
    if len(ds) % 2:
        ds.append(0xF)
    return bytes(ds[i] | (ds[i + 1] << 4) for i in range(0, len(ds), 2))


def mi_digits(digits, typ):
    ds = [int(c) for c in digits]
    first = (ds[0] << 4) | ((len(ds) % 2) << 3) | typ
    rest = ds[1:]
    if len(rest) % 2:
        rest.append(0xF)
    return bytes([first]) + bytes(rest[i] | (rest[i + 1] << 4) for i in range(0, len(rest), 2))


def lv(b):
    return bytes([len(b)]) + b


def lve(b):
    return struct.pack(">H", len(b)) + b


def tlv(iei, b):
    return bytes([iei, len(b)]) + b


def tlve(iei, b):
    return bytes([iei]) + struct.pack(">H", len(b)) + b


def guti5g(tmsi, region=2, amf_set=1, ptr=0):
    return bytes([0xF2]) + PLMN + bytes([region]) + struct.pack(">HI", (amf_set << 6) | ptr, tmsi)


def s_tmsi5g(tmsi, amf_set=1, ptr=0):
    return bytes([0xF4]) + struct.pack(">HI", (amf_set << 6) | ptr, tmsi)


def suci_null(msin):
    return bytes([0x01]) + PLMN + bytes([0xF0, 0xFF, 0x00, 0x00]) + tbcd(msin)


def prot5g(sht, inner, sqn=1):
    return bytes([0x7E, sht]) + bytes.fromhex("11223344") + bytes([sqn]) + inner


def prot4g(sht, inner, sqn=1):
    return bytes([(sht << 4) | 7]) + bytes.fromhex("55667788") + bytes([sqn]) + inner


REG_REQ = bytes([0x7E, 0x00, 0x41, 0x79]) + lve(suci_null(MSIN)) + tlv(0x2E, bytes.fromhex("f0f0f0f0"))
REG_ACCEPT = (bytes([0x7E, 0x00, 0x42]) + lv(b"\x01") + tlve(0x77, guti5g(0xC0FFEE02))
              + tlv(0x54, b"\x00" + PLMN + b"\x00\x00\x01") + tlv(0x15, b"\x01\x01"))
SMC_5G = bytes([0x7E, 0x00, 0x5D, 0x02, 0x01]) + lv(bytes.fromhex("f0f0f0f0")) + b"\xe1"
SMC_COMPLETE_5G = bytes([0x7E, 0x00, 0x5E]) + tlve(0x77, mi_digits(IMEISV, 5)) + tlve(0x71, REG_REQ)
QOS_RULES = bytes.fromhex("0100063131010 1ff01".replace(" ", ""))
PDU_EST_ACCEPT = (bytes([0x2E, 0x01, 0x01, 0xC2, 0x11]) + lve(QOS_RULES) + lv(bytes.fromhex("060 1f4 06 01f4".replace(" ", "")))
                  + tlv(0x29, bytes([0x01, 10, 45, 0, 2])) + tlv(0x22, b"\x01") + tlv(0x25, b"\x08internet"))
DL_NAS_TRANSPORT_5G = bytes([0x7E, 0x00, 0x68, 0x01]) + lve(PDU_EST_ACCEPT) + bytes([0x12, 0x01])
SERVICE_REQ_5G = bytes([0x7E, 0x00, 0x4C, 0x01]) + lve(s_tmsi5g(0xC0FFEE03))

ESM_PDN_CONN_REQ = bytes([0x02, 0x01, 0xD0, 0x11])
ATTACH_REQ = (bytes([0x07, 0x41, 0x71]) + lv(mi_digits(IMSI, 1)) + lv(bytes.fromhex("e0e0"))
              + lve(ESM_PDN_CONN_REQ) + bytes.fromhex("5c0a00"))
ESM_ACT_DEFAULT = (bytes([0x52, 0x01, 0xC1]) + lv(b"\x09") + lv(b"\x08internet") + lv(bytes([0x01, 10, 45, 0, 7])))
GUTI4G = bytes([0xF6]) + PLMN + struct.pack(">HBI", 0x8001, 0x01, 0xC0FFEE01)
ATTACH_ACCEPT = (bytes([0x07, 0x42, 0x01, 0x21]) + lv(b"\x00" + PLMN + b"\x00\x01") + lve(ESM_ACT_DEFAULT)
                 + tlv(0x50, GUTI4G) + bytes([0x13]) + PLMN + b"\x00\x01" + tlv(0x23, bytes([0xF4]) + struct.pack(">I", 0x12345678)))
SMC_COMPLETE_4G = bytes([0x07, 0x5E]) + tlv(0x23, mi_digits(IMEISV, 3))
TAU_REQ = bytes([0x07, 0x48, 0x70]) + lv(GUTI4G) + bytes([0x52]) + PLMN + b"\x00\x01" + tlv(0x57, b"\x20\x00")
IDENTITY_RESP_4G = bytes([0x07, 0x56]) + lv(mi_digits(IMSI, 1))


# --------------------------------------------------------------- NGAP messages
def ran_ue_id(v):
    return Bits().cwn(v, 2 ** 32)


def amf_ue_id(v):
    return Bits().cwn(v, 2 ** 40)


def uli_nr(nci):
    b = Bits().cwn(1, 4).u(0, 1).u(0, 2)
    b.u(0, 1).u(0, 1).octets(PLMN).align().u(nci, 36)
    b.u(0, 1).u(0, 1).octets(PLMN).octets(b"\x00\x00\x01")
    return b


def up_tnl(ip, teid):
    b = Bits().cwn(0, 2).u(0, 1).u(0, 1).u(0, 1).cwn(31, 160).align().raw(bytes(ip))
    return b.octets(struct.pack(">I", teid))


def guami():
    return Bits().u(0, 1).u(0, 1).octets(PLMN).u(2, 8).u(1, 10).u(0, 6)


NCI = (GNB_ID << (36 - GNB_ID_LEN)) | 0x10


def ng_setup_request():
    grn = Bits().cwn(0, 4).u(0, 1).u(0, 1).octets(PLMN).cwn(0, 2).cwn(GNB_ID_LEN - 22, 11).align().u(GNB_ID, GNB_ID_LEN)
    ta = Bits().cwn(0, 256).u(0, 1).u(0, 1).octets(b"\x00\x00\x01").cwn(0, 12)
    ta.u(0, 1).u(0, 1).octets(PLMN).cwn(0, 1024).u(0, 1).u(0, 1).u(0, 1).u(0, 2).raw(b"\x01")
    return ap_pdu(0, 21, REJECT, [
        ie(27, REJECT, grn), ie(82, IGNORE, Bits().string("gnb-brussels-01")),
        ie(102, REJECT, ta), ie(21, IGNORE, Bits().u(0, 1).cwn(2, 4))])


def ng_setup_response():
    g = Bits().cwn(0, 256).u(0, 1).u(0b10, 2).u(0, 1).u(0, 1).octets(PLMN).u(2, 8).u(1, 10).u(0, 6)
    g.string("amf-backup-1")
    pl = Bits().cwn(0, 12).u(0, 1).u(0, 1).octets(PLMN).cwn(0, 1024).u(0, 1).u(0, 1).u(0, 1).u(0, 2).raw(b"\x01")
    return ap_pdu(1, 21, REJECT, [
        ie(1, REJECT, Bits().string("open5gs-amf0")), ie(96, REJECT, g),
        ie(86, IGNORE, Bits().cwn(255, 256)), ie(80, REJECT, pl)])


def ngap_initial_ue_reg():
    return ap_pdu(0, 15, IGNORE, [
        ie(85, REJECT, ran_ue_id(1)), ie(38, REJECT, octets_ie(REG_REQ)), ie(121, REJECT, uli_nr(NCI)),
        ie(90, IGNORE, Bits().u(0, 1).cwn(3, 10)), ie(112, IGNORE, Bits().u(0, 1))])


def ngap_dl_smc():
    return ap_pdu(0, 4, IGNORE, [
        ie(10, REJECT, amf_ue_id(1)), ie(85, REJECT, ran_ue_id(1)), ie(38, REJECT, octets_ie(prot5g(3, SMC_5G)))])


def ngap_ul_smc_complete():
    return ap_pdu(0, 46, IGNORE, [
        ie(10, REJECT, amf_ue_id(1)), ie(85, REJECT, ran_ue_id(1)),
        ie(38, REJECT, octets_ie(prot5g(4, SMC_COMPLETE_5G))), ie(121, IGNORE, uli_nr(NCI))])


def ngap_ics_request():
    transfer = ie_container([ie(139, REJECT, up_tnl([10, 10, 0, 5], 1)), ie(134, REJECT, Bits().u(0, 1).cwn(0, 5))])
    lst = Bits().cwn(0, 256).u(0, 1).u(0b10, 2).cwn(1, 256).open_type(prot5g(2, DL_NAS_TRANSPORT_5G, 2))
    lst.u(0, 1).u(0, 2).raw(b"\x01").open_type(transfer)
    return ap_pdu(0, 14, REJECT, [
        ie(10, REJECT, amf_ue_id(1)), ie(85, REJECT, ran_ue_id(1)), ie(28, REJECT, guami()),
        ie(71, REJECT, lst), ie(94, REJECT, Bits().octets(bytes(range(32)))),
        ie(34, IGNORE, Bits().octets(bytes.fromhex("3569380356ffff07"))),
        ie(38, IGNORE, octets_ie(prot5g(2, REG_ACCEPT, 3)))])


def ngap_ics_response():
    t = Bits().u(0, 1).u(0, 4).u(0, 1).u(0, 1)
    t.cwn(0, 2).u(0, 1).u(0, 1).u(0, 1).cwn(31, 160).align().raw(bytes([10, 20, 0, 7])).octets(struct.pack(">I", 2))
    t.cwn(0, 64).u(0, 1).u(0, 2).u(0, 1).cwn(1, 64)
    lst = Bits().cwn(0, 256).u(0, 1).u(0, 1).cwn(1, 256).open_type(t.bytes())
    return ap_pdu(1, 14, REJECT, [ie(10, IGNORE, amf_ue_id(1)), ie(85, IGNORE, ran_ue_id(1)), ie(72, IGNORE, lst)])


def ngap_paging():
    pid = Bits().cwn(0, 2).u(0, 1).u(0, 1).u(1, 10).u(0, 6).octets(struct.pack(">I", 0xC0FFEE02))
    tai = Bits().cwn(0, 16).u(0, 1).u(0, 1).u(0, 1).u(0, 1).octets(PLMN).octets(b"\x00\x00\x01")
    return ap_pdu(0, 24, IGNORE, [ie(115, IGNORE, pid), ie(103, IGNORE, tai)])


def ngap_initial_ue_service():
    st = Bits().u(0, 1).u(0, 1).u(1, 10).u(0, 6).octets(struct.pack(">I", 0xC0FFEE03))
    return ap_pdu(0, 15, IGNORE, [
        ie(85, REJECT, ran_ue_id(2)), ie(38, REJECT, octets_ie(prot5g(1, SERVICE_REQ_5G, 4))),
        ie(121, REJECT, uli_nr(NCI | 0x1)), ie(90, IGNORE, Bits().u(0, 1).cwn(4, 10)), ie(26, REJECT, st)])


def ngap_big_ics_request():
    """> MTU: carried in 3 SCTP fragments."""
    radio_cap = bytes((i * 7) & 0xFF for i in range(3000))
    return ap_pdu(0, 14, REJECT, [
        ie(10, REJECT, amf_ue_id(7)), ie(85, REJECT, ran_ue_id(7)), ie(28, REJECT, guami()),
        ie(117, IGNORE, octets_ie(radio_cap)), ie(94, REJECT, Bits().octets(bytes(32))),
        ie(38, IGNORE, octets_ie(prot5g(2, bytes([0x7E, 0x00, 0x42]) + lv(b"\x01") + tlve(0x77, guti5g(0xC0FFEE04)), 5)))])


# --------------------------------------------------------------- S1AP messages
def enb_ue_id(v):
    return Bits().cwn(v, 2 ** 24)


def mme_ue_id(v):
    return Bits().cwn(v, 2 ** 32)


def s1_tai():
    return Bits().u(0, 1).u(0, 1).octets(PLMN).raw(b"\x00\x01")


ECI = (ENB_ID << 8) | 0x01


def s1_cgi():
    return Bits().u(0, 1).u(0, 1).octets(PLMN).align().u(ECI, 28)


def s1_tla(ip):
    return Bits().u(0, 1).cwn(31, 160).align().raw(bytes(ip))


def s1_setup_request():
    gid = Bits().u(0, 1).u(0, 1).octets(PLMN).u(0, 1).cwn(0, 2).align().u(ENB_ID, 20)
    tas = Bits().cwn(0, 256).u(0, 1).u(0, 1).raw(b"\x00\x01").cwn(0, 6).octets(PLMN)
    return ap_pdu(0, 17, REJECT, [
        ie(59, REJECT, gid), ie(60, IGNORE, Bits().string("enb-gent-02")),
        ie(64, REJECT, tas), ie(137, IGNORE, Bits().u(0, 1).cwn(2, 4))])


def s1_setup_response():
    g = Bits().cwn(0, 8).u(0, 1).u(0, 1).cwn(0, 32).octets(PLMN).cwn(0, 65535).raw(b"\x80\x01").cwn(0, 256).raw(b"\x01")
    return ap_pdu(1, 17, REJECT, [
        ie(61, IGNORE, Bits().string("mme-core-1")), ie(105, REJECT, g), ie(87, IGNORE, Bits().cwn(255, 256))])


def s1_initial_ue_attach():
    return ap_pdu(0, 12, IGNORE, [
        ie(8, REJECT, enb_ue_id(1)), ie(26, REJECT, octets_ie(ATTACH_REQ)), ie(67, REJECT, s1_tai()),
        ie(100, IGNORE, s1_cgi()), ie(134, IGNORE, Bits().u(0, 1).cwn(3, 5))])


def s1_ul_identity_resp():
    return ap_pdu(0, 13, IGNORE, [
        ie(0, REJECT, mme_ue_id(1)), ie(8, REJECT, enb_ue_id(1)), ie(26, REJECT, octets_ie(IDENTITY_RESP_4G)),
        ie(100, IGNORE, s1_cgi()), ie(67, IGNORE, s1_tai())])


def s1_ul_smc_complete():
    return ap_pdu(0, 13, IGNORE, [
        ie(0, REJECT, mme_ue_id(1)), ie(8, REJECT, enb_ue_id(1)),
        ie(26, REJECT, octets_ie(prot4g(4, SMC_COMPLETE_4G))), ie(100, IGNORE, s1_cgi()), ie(67, IGNORE, s1_tai())])


def s1_ics_request():
    item = Bits().u(0, 1).u(0b10, 2).u(0, 1).u(5, 4)  # ext, opt(nas), e-RAB-ID 5
    item.u(0, 1).u(0, 2).cwn(9, 256).u(0, 1).u(0, 1).u(1, 4).u(0, 1).u(0, 1)  # QoS: QCI 9, ARP 1
    item.u(0, 1).cwn(31, 160).align().raw(bytes([10, 30, 0, 9])).octets(struct.pack(">I", 0x01020304))
    item.open_type(prot4g(2, ATTACH_ACCEPT, 2))
    lst = Bits().cwn(0, 256).raw(ie(52, REJECT, item))
    ambr = Bits().u(0, 1).u(0, 1).cwn(100000000, 10000000001).cwn(50000000, 10000000001)
    seccap = Bits().u(0, 1).u(0, 1).u(0, 1).u(0xE000, 16).u(0, 1).u(0xC000, 16)
    return ap_pdu(0, 9, REJECT, [
        ie(0, REJECT, mme_ue_id(1)), ie(8, REJECT, enb_ue_id(1)), ie(66, REJECT, ambr),
        ie(24, REJECT, lst), ie(107, REJECT, seccap), ie(73, REJECT, Bits().octets(bytes(32)))])


def s1_ics_response():
    item = Bits().u(0, 1).u(0, 1).u(0, 1).u(5, 4).u(0, 1).cwn(31, 160).align().raw(bytes([10, 40, 0, 1]))
    item.octets(struct.pack(">I", 0x0A0B0C0D))
    lst = Bits().cwn(0, 256).raw(ie(50, IGNORE, item))
    return ap_pdu(1, 9, REJECT, [ie(0, IGNORE, mme_ue_id(1)), ie(8, IGNORE, enb_ue_id(1)), ie(51, IGNORE, lst)])


def s1_paging():
    pid = Bits().u(0, 1).cwn(1, 2).cwn(len(tbcd(IMSI)) - 3, 6).align().raw(tbcd(IMSI))
    tai_item = ie(47, IGNORE, Bits().u(0, 1).u(0, 1).u(0, 1).u(0, 1).octets(PLMN).raw(b"\x00\x01"))
    return ap_pdu(0, 10, IGNORE, [
        ie(80, IGNORE, Bits().u(0x1E5, 10)), ie(43, IGNORE, pid), ie(109, IGNORE, Bits().cwn(0, 2)),
        ie(46, IGNORE, Bits().cwn(0, 256).raw(tai_item))])


def s1_initial_ue_tau():
    stmsi = Bits().u(0, 1).u(0, 1).u(0x01, 8).octets(struct.pack(">I", 0xC0FFEE01))
    return ap_pdu(0, 12, IGNORE, [
        ie(8, REJECT, enb_ue_id(2)), ie(26, REJECT, octets_ie(prot4g(1, TAU_REQ, 3))), ie(67, REJECT, s1_tai()),
        ie(100, IGNORE, s1_cgi()), ie(134, IGNORE, Bits().u(0, 1).cwn(4, 5)), ie(96, REJECT, stmsi)])


# --------------------------------------------------------------- packet builders
def inet_csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


CRC_T = _crc_table()


def crc32c(b):
    c = 0xFFFFFFFF
    for x in b:
        c = CRC_T[(c ^ x) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def eth(src, dst, et, payload):
    return dst + src + struct.pack(">H", et) + payload


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, bytes(src), bytes(dst))
    return h[:10] + struct.pack(">H", inet_csum(h)) + h[12:] + payload


def ipv6(src, dst, nh, payload):
    return struct.pack(">IHBB", 0x60000000, len(payload), nh, 64) + src + dst + payload


def pad4(b):
    return b + b"\0" * ((4 - len(b) % 4) % 4)


def data_chunk(tsn, sid, ssn, ppid, payload, flags=0x03):
    return pad4(struct.pack(">BBHIHHI", 0, flags, 16 + len(payload), tsn, sid, ssn, ppid) + payload)


def sctp(sport, dport, vtag, chunks):
    p = struct.pack(">HHII", sport, dport, vtag, 0) + b"".join(chunks)
    return p[:8] + struct.pack("<I", crc32c(p)) + p[12:]


def udp(sport, dport, payload, src, dst):
    h = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    ph = bytes(src) + bytes(dst) + struct.pack(">BBH", 0, 17, 8 + len(h + payload) - 8)
    c = inet_csum(ph + h + payload) or 0xFFFF
    return h[:6] + struct.pack(">H", c) + payload


class Flow:
    """One SCTP association with per-direction TSNs."""

    def __init__(self, a_mac, a_ip, b_mac, b_ip, port, ppid, v6=None, cport=40000):
        self.a, self.b = (a_mac, a_ip), (b_mac, b_ip)
        self.port, self.ppid, self.v6, self.cport = port, ppid, v6, cport
        self.tsn = {True: 1000 + cport, False: 5000 + cport}
        self.ssn = {True: 0, False: 0}

    def frame(self, up, chunks):
        (sm, sip), (dm, dip) = (self.a, self.b) if up else (self.b, self.a)
        sport, dport = (self.cport, self.port) if up else (self.port, self.cport)
        seg = sctp(sport, dport, (0x1234 if up else 0x5678) + self.cport, chunks)
        if self.v6:
            s6, d6 = self.v6 if up else self.v6[::-1]
            return eth(sm, dm, 0x86DD, ipv6(s6, d6, 132, seg))
        return eth(sm, dm, 0x0800, ipv4(sip, dip, 132, seg))

    def msg(self, up, payload):
        c = data_chunk(self.tsn[up], 0 if payload[1] in (21, 17) else 1, self.ssn[up], self.ppid, payload)
        self.tsn[up] += 1
        self.ssn[up] += 1
        return self.frame(up, [c])

    def fragments(self, up, payload, size=1200):
        parts = [payload[i:i + size] for i in range(0, len(payload), size)]
        out = []
        for i, part in enumerate(parts):
            flags = (0x02 if i == 0 else 0) | (0x01 if i == len(parts) - 1 else 0)
            out.append(self.frame(up, [data_chunk(self.tsn[up], 1, self.ssn[up], self.ppid, part, flags)]))
            self.tsn[up] += 1
        self.ssn[up] += 1
        return out


def init_chunk(ctype, tag, ips):
    # the last parameter's padding is chunk padding (not counted in the chunk length)
    params = b"".join(struct.pack(">HH4s", 5, 8, bytes(ip)) for ip in ips) + struct.pack(">HHH", 12, 6, 5)
    body = struct.pack(">IIHHI", tag, 65535, 10, 10, 1000) + params
    return pad4(struct.pack(">BBH", ctype, 0, 4 + len(body)) + body)


def heartbeat_chunk(ctype, dst_ip, port):
    # Linux-style heartbeat info: sockaddr_in of the destination + timestamps
    info = struct.pack("<H", 2) + struct.pack(">H", port) + bytes(dst_ip) + bytes(8) + bytes(range(16))
    param = struct.pack(">HH", 1, 4 + len(info)) + info
    return pad4(struct.pack(">BBH", ctype, 0, 4 + len(param)) + param)


def build_packets():
    pk = []
    n2 = Flow(GNB_MAC, GNB_IP, AMF_MAC, AMF_IP, 38412, 60)
    s1 = Flow(ENB_MAC, ENB_IP, MME_MAC, MME_IP, 36412, 18)
    n2v6 = Flow(GNB_MAC, None, AMF_MAC, None, 38412, 60, v6=(GNB_IP6, AMF_IP6), cport=40006)

    # ARP + SCTP association setup
    arp = struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, GNB_MAC, bytes(GNB_IP), bytes(6), bytes(AMF_IP))
    pk.append(eth(GNB_MAC, b"\xff" * 6, 0x0806, arp))
    pk.append(n2.frame(True, [init_chunk(1, 0x5678, [GNB_IP, [10, 100, 201, 11]])]))
    pk.append(n2.frame(False, [init_chunk(2, 0x1234, [AMF_IP])]))
    # N2
    pk.append(n2.msg(True, ng_setup_request()))
    pk.append(n2.msg(False, ng_setup_response()))
    pk.append(n2.msg(True, ngap_initial_ue_reg()))
    pk.append(n2.msg(False, ngap_dl_smc()))
    pk.append(n2.msg(True, ngap_ul_smc_complete()))
    pk.append(n2.msg(False, ngap_ics_request()))
    pk.append(n2.msg(True, ngap_ics_response()))
    pk.append(n2.frame(True, [heartbeat_chunk(4, AMF_IP, 38412)]))
    pk.append(n2.frame(False, [heartbeat_chunk(5, AMF_IP, 38412)]))
    pk.append(n2.msg(True, ngap_initial_ue_service()))
    pk.append(n2v6.msg(False, ngap_paging()))
    # fragmented message with an unrelated packet in between and a late retransmission
    frags = n2.fragments(False, ngap_big_ics_request())
    pk.append(frags[0])
    pk.append(n2.frame(True, [heartbeat_chunk(4, AMF_IP, 38412)]))
    pk.extend(frags[1:])
    pk.append(frags[1])
    # S1
    pk.append(s1.msg(True, s1_setup_request()))
    pk.append(s1.msg(False, s1_setup_response()))
    pk.append(s1.msg(True, s1_initial_ue_attach()))
    pk.append(s1.msg(True, s1_ul_identity_resp()))
    pk.append(s1.msg(True, s1_ul_smc_complete()))
    pk.append(s1.msg(False, s1_ics_request()))
    pk.append(s1.msg(True, s1_ics_response()))
    pk.append(s1.msg(False, s1_paging()))
    pk.append(s1.msg(True, s1_initial_ue_tau()))
    # other traffic: DNS query
    dns = bytes.fromhex("abcd01000001000000000000") + b"\x03amf\x08operator\x07example\x00\x00\x01\x00\x01"
    pk.append(eth(MME_MAC, ENB_MAC, 0x0800, ipv4(MME_IP, [8, 8, 8, 8], 17, udp(53000, 53, dns, MME_IP, [8, 8, 8, 8]))))
    return pk


# --------------------------------------------------------------- file writers
def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", 1700000000 + i, 1000 * i, len(p), len(p)))
            f.write(p)


def opt(code, val):
    return struct.pack("<HH", code, len(val)) + pad4(val)


def block(btype, body):
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def write_pcapng(path, packets):
    with open(path, "wb") as f:
        shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb += opt(1, b"Lab capture, UE IMSI 001010123456789") + opt(4, b"gen_test_traces.py") + opt(0, b"")
        f.write(block(0x0A0D0D0A, shb))
        idb = struct.pack("<HHI", 1, 0, 0)
        idb += opt(2, b"s1-n2-site-brussels") + opt(4, bytes([10, 100, 200, 1, 255, 255, 255, 0]))
        idb += opt(9, b"\x06") + opt(0, b"")
        f.write(block(1, idb))
        nrb = struct.pack("<HH", 1, 4 + 21) + pad4(bytes(AMF_IP) + b"amf.operator.example\0") + struct.pack("<HH", 0, 0)
        f.write(block(4, nrb))
        for i, p in enumerate(packets):
            ts = (1700000000 + i) * 1000000
            body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(p), len(p)) + pad4(p)
            if i == 5:
                body += opt(1, b"Registration of IMSI 001010000000001") + opt(0, b"")
            f.write(block(6, body))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    pk = build_packets()
    write_pcap(os.path.join(out, "test_s1_n2.pcap"), pk)
    write_pcapng(os.path.join(out, "test_s1_n2.pcapng"), pk)
    print("wrote %d packets to %s" % (len(pk), out))


if __name__ == "__main__":
    main()
