# RedacTrace

**RedacTrace** redacts subscriber and network identities from telecom signalling traces (`.pcap` / `.pcapng`) captured on the
**S1-MME** (eNB ↔ MME, S1AP) and **N2** (gNB / ng-eNB ↔ AMF, NGAP) interfaces,
so they can be shared with vendors, colleagues or the public.

* Every identifier is replaced by a **pseudonym of exactly the same size and format**:
  the output still decodes cleanly in Wireshark, and nothing is shifted or re-encoded.
* Pseudonyms are **consistent**. The same IMSI, TMSI, IP, gNB-ID ... gets the same
  replacement everywhere in the trace (and in every file of a run), so call flows can
  still be followed. Two different originals never share a pseudonym.
* Checksums (IPv4, TCP/UDP/ICMP, SCTP CRC32c) are recomputed.
* A settings file decides which fields are anonymized.
* Single standalone `.exe`, no installation needed. Drag and drop works.

## Quick start (Windows)

1. Build once (see [Building](#building)), or take `redactrace.exe` from `dist\`.
2. Drag one or more capture files onto `redactrace.exe`.
   You get `<name>_anon.pcap(ng)` next to each input, and a summary window.

Command line:

```bash
redactrace trace.pcapng
```
```bash
redactrace trace.pcap -o shared\trace.pcap
```
```bash
redactrace traces\ -o anonymized\
```
```bash
redactrace -c strict.toml --mapping mapping.csv trace.pcap
```
```bash
redactrace --init-config
```

| Option | Meaning |
|---|---|
| `-o, --output` | output file (one input) or folder (several inputs / a folder) |
| `-c, --config` | settings file (default: `./anonymizer.toml`, then `anonymizer.toml` next to the exe, else built-in defaults) |
| `--init-config [FILE]` | write the documented default settings file |
| `--mapping CSV` | write the `category,original,pseudonym` table (**contains the originals**, keep it private) |
| `--secret TEXT` | secret for the pseudonyms (overrides the settings file) |
| `-q, --quiet` | only print warnings |

## What is anonymized

| Setting (`[anonymize]`) | Fields |
|---|---|
| `mac_addresses` | Ethernet, Linux cooked capture (SLL/SLL2), ARP, IPv6 neighbour discovery, 5GS MAC-address identity |
| `ip_addresses` | IPv4/IPv6 headers (incl. IP-in-IP, ICMP-quoted headers), ARP, SCTP INIT/INIT-ACK/ASCONF address parameters, addresses inside SCTP HEARTBEAT info |
| `ip_in_signalling` | S1AP/NGAP TransportLayerAddress: GTP-U tunnel endpoints (E-RAB lists, PDU session resource setup/response/handover/path-switch transfers), AMF TNL association addresses, trace collection entity, N3IWF user location (UE IP) |
| `ue_ip_addresses` | UE IP in NAS: EPS *PDN address* (Activate default EPS bearer context request), 5GS *PDU address* (PDU session establishment accept) |
| `imsi` | IMSI in EPS NAS (Attach / Detach / Identity response ...), S1AP paging IMSI, MSIN of a 5G **SUCI** with the null protection scheme |
| `tmsi` | M-TMSI / 5G-TMSI / (P-)TMSI: S1AP S-TMSI, NGAP 5G-S-TMSI & paging identity, NAS GUTI / 5G-GUTI / 5G-S-TMSI / MS identity, S1AP Additional GUTI |
| `imei` | IMEI / IMEISV in NAS (Identity response, Security mode complete ...); the TAC is kept by default and the check digit recomputed; Masked-IMEISV gets its whole serial number masked |
| `amf_name` | NGAP AMF Name, backup AMF name (Served/Unavailable GUAMI list), Old AMF, extended (Visible/UTF8) AMF names |
| `mme_name` | S1AP MME name |
| `ran_node_name` | NGAP RAN Node Name (gNB/ng-eNB, incl. extended names), S1AP eNB name |
| `gnb_id` | gNB-ID in Global RAN Node ID / Target ID |
| `enb_id` | eNB-ID (macro, home, short/long macro) in S1AP Global-ENB-ID / Target ID, NGAP ng-eNB-ID |
| `cell_identity` | NR Cell Identity and E-UTRAN Cell Identity (EUTRAN-CGI, NR-CGI, User Location Information). The embedded gNB/eNB-ID part gets the same pseudonym as the node itself, and the local cell bits are kept |
| `amf_identifiers` *(off)* | AMF Region ID, AMF Set ID, AMF Pointer (GUAMI, 5G-S-TMSI, 5G-GUTI) |
| `mme_identifiers` *(off)* | MME Group ID, MME Code (GUMMEI, ServedGUMMEIs, S-TMSI, GUTI) |

Kept on purpose: MCC/MNC (PLMN), TAC (tracking area code), S1AP/NGAP UE IDs,
timestamps, APN/DNN, S-NSSAI, QoS, causes and so on. Everything needed for
troubleshooting stays, and none of it identifies a subscriber.

### How the pseudonyms are built

* Keyed HMAC-SHA256. With an empty `secret` (default) a **random secret per run**
  is used, so pseudonyms can't be reproduced or brute-forced afterwards. Set
  `secret` to get the same pseudonyms across runs (e.g. for traces anonymized in batches).
* **IMSI**: MCC+MNC are kept and the MSIN is replaced. The MNC length (2/3 digits)
  is learned from PLMN IDs in the trace (`imsi.default_mnc_length` otherwise).
  A SUCI MSIN and the IMSI of the same subscriber map consistently.
* **IP**: `prefix-preserving` (default) keeps subnet structure: two addresses that
  share an n-bit prefix share an n-bit prefix after anonymization. Use `random` for
  unrelated addresses. Loopback/multicast/broadcast are kept (`keep_special`).
* **MAC**: locally administered unicast pseudonyms (`keep_oui` keeps the vendor part).
* **Names**: same length, e.g. `open5gs-amf0` → `amf-70c24c60`, `gnb-brussels-01` → `ran-2fe00da4273`.
* **gNB-ID**: same bit length. The gNB-ID length used inside NR cell identities is
  learned from NGSetup/RANConfigurationUpdate (or `ran.gnb_id_length`).

The program reads every input twice. The first pass only learns PLMNs and
gNB/eNB-ID lengths, so pseudonyms don't depend on where in the trace a setup message appears.

### NAS ciphering

Messages with security header "integrity protected and ciphered" can only be read
when the null algorithm (EEA0/NEA0) is used, which is common in lab setups. With
`nas.detect_null_ciphering = true` (default) such messages are checked and
anonymized when they turn out to be plain text. Messages that are really encrypted
contain no readable identity and are left untouched.

### SCTP details handled

* bundled DATA chunks, any number of S1AP/NGAP messages per packet
* **SCTP-fragmented messages** (e.g. an InitialContextSetupRequest carrying a large
  UE radio capability) are reassembled, anonymized and written back into the original
  fragments. Retransmitted fragments get the same replacement.
* recognition by PPID (18 = S1AP, 60 = NGAP) or port (36412 / 38412), configurable

## Settings file

All options are documented in [anonymizer.toml](anonymizer.toml), which is also
what `--init-config` writes. Every key is optional, and unknown keys are rejected
(that catches typos). Important general options:

| Option | Default | |
|---|---|---|
| `other_traffic` | `keep` | non-S1AP/NGAP packets (GTP-U, Diameter, DNS, ...): `keep` (only MAC/IP headers anonymized) or `drop` |
| `on_error` | `keep` | packets with S1AP/NGAP content that could not be fully processed: `keep` or `drop` (strictest) |
| `fix_checksums` | `true` | recompute checksums |
| `strip_pcapng_comments` | `true` | remove free-text comments. Name-resolution blocks, decryption secrets, custom blocks and interface names/descriptions/addresses are always removed |
| `mapping_file` | empty | path for the mapping CSV (relative to the output folder) |

## After the run

A summary is printed:

```
Packets: 58 read, 58 written, 0 dropped
Signalling: 18 S1AP and 20 NGAP messages (2 reassembled from SCTP fragments)
Fields replaced: amf_name 4, cell_identity 14, enb_id 2, gnb_id 2, imei 4, imsi 10, ip 122, ...
NAS: 12 null-ciphered (EEA0/NEA0) messages anonymized, 0 really ciphered messages left untouched
```

Problems are listed as `WARNING` lines with frame numbers. Examples: a capture whose
snap length cut S1AP/NGAP messages (anonymized as far as captured), or an SCTP
fragment whose first part is missing from the capture. With `on_error = "drop"`
those packets are removed instead of kept.

To check a result in Wireshark, enable *Protocols → NAS-5GS → Try to detect and
decode 5G-EA0 ciphered messages* and the NAS-EPS equivalent, or with tshark:

```bash
tshark -r trace_anon.pcap -o nas-5gs.null_decipher:TRUE -o nas-eps.null_decipher:TRUE -V
```

## Limitations

* Only S1AP and NGAP payloads are parsed. Other protocols in the capture (GTP-U user
  data, Diameter, SBI/HTTP2, DNS, SIP ...) keep their payload: use
  `other_traffic = "drop"` when they may contain identities.
* Opaque containers inside S1AP/NGAP (RRC containers such as UE radio capability or
  handover source-to-target containers, NRPPa/LPPa) are not parsed.
* IP-fragmented SCTP packets are not reassembled (reported as a warning).
* SUCIs protected with ECIES (profile A/B) are left as they are; the MSIN in them is encrypted.
* Calling numbers in CS service notifications and SMS contents are not anonymized.

## Building

Requires Rust (https://rustup.rs). On Windows either toolchain works:

* **GNU** (`rustup default stable-x86_64-pc-windows-gnu`) needs no Visual Studio
* **MSVC** needs the Visual Studio C++ build tools; the CRT is linked statically (see `.cargo/config.toml`)

```bash
cargo build --release
```

The binary is `target/release/redactrace(.exe)` and only depends on
system libraries. `build-release.ps1` runs the tests, builds, and puts the
`.exe`, the settings file and this README into `dist\`:

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File build-release.ps1
```

The code is portable: on Linux/macOS, `cargo build --release` gives the same tool.

## Tests

```bash
cargo test
```

* unit tests for the PER cursor, checksums, pseudonym generation and NAS digit coding
* `tests/leak_check.rs`: anonymizes the synthetic traces in `tests/data/` and checks
  that none of the planted identifiers is left anywhere in the output bytes

`tools/gen_test_traces.py` (Python 3, no dependencies) regenerates those traces:
hand-encoded S1AP/NGAP messages (setup, registration/attach, security mode,
initial context setup with E-RAB/PDU session lists, paging, service request / TAU,
an SCTP-fragmented message, IPv6, HEARTBEAT, INIT, ARP, DNS) in pcap and pcapng.

## Source layout

| File | Purpose |
|---|---|
| `src/main.rs` | command line, file handling |
| `src/config.rs` | settings file |
| `src/capture.rs` | pcap / pcapng reader and writer |
| `src/engine.rs` | per-file loop, SCTP reassembly, keep/drop policies |
| `src/net.rs`, `src/sctp.rs`, `src/checksum.rs` | Ethernet/SLL/ARP/IP/ICMP, SCTP chunks, checksums |
| `src/per.rs`, `src/ap.rs` | ALIGNED PER cursor, shared S1AP/NGAP building blocks |
| `src/s1ap.rs`, `src/ngap.rs` | S1AP and NGAP information elements |
| `src/nas/` | EPS and 5GS NAS messages and mobile identities |
| `src/pseudo.rs` | pseudonym generation and mapping table |
