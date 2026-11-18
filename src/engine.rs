//! Per-file processing loop: reads packets, anonymizes them, reassembles
//! SCTP-fragmented S1AP/NGAP messages and applies the keep/drop policies.

use crate::capture::{Reader, Record, Writer};
use crate::checksum;
use crate::config::{Config, Policy};
use crate::net;
use crate::pseudo::Pseudo;
use crate::stats::Stats;
use crate::{ngap, s1ap};
use anyhow::Result;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

/// Packets are held back at most this long while waiting for the last
/// fragment of an SCTP-fragmented message.
const MAX_HOLD: usize = 50_000;
const DONE_CACHE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Ul,
    Dl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    S1ap,
    Ngap,
}

#[derive(Debug, Clone, Copy)]
pub struct SctpLoc {
    pub off: usize,
    pub len: usize,
    pub crc_ok: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Frag {
    pub key: u64,
    pub tsn: u32,
    pub first: bool,
    pub last: bool,
    pub off: usize,
    pub len: usize,
    pub proto: Sig,
}

/// What processing found out about one packet.
#[derive(Debug, Default)]
pub struct PktMeta {
    /// S1AP/NGAP payload or S1/N2 SCTP association
    pub signalling: bool,
    /// S1AP/NGAP content that could not be fully processed
    pub error: bool,
    pub unsupported: bool,
    pub ip_fragment: bool,
    pub sctp: Option<SctpLoc>,
    pub sctp_dirty: bool,
    pub frags: Vec<Frag>,
}

thread_local! {
    pub static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub struct Engine {
    pub cfg: Config,
    pub ps: Pseudo,
    pub stats: Stats,
}

struct Pending {
    rec: Record,
    meta: PktMeta,
}

#[derive(Clone, Copy)]
struct Part {
    idx: usize,
    off: usize,
    len: usize,
    tsn: u32,
}

struct Reasm {
    key: u64,
    proto: Sig,
    parts: Vec<Part>,
    next_tsn: u32,
}

#[derive(Default)]
struct FileState {
    q: VecDeque<Pending>,
    base: usize,
    open: HashMap<u64, Reasm>,
    done: HashMap<(u64, u32), (Vec<u8>, Vec<u8>)>,
    done_order: VecDeque<(u64, u32)>,
}

impl FileState {
    fn pending(&mut self, idx: usize) -> &mut Pending {
        let i = idx - self.base;
        &mut self.q[i]
    }
    fn data(&mut self, idx: usize) -> &mut Vec<u8> {
        match &mut self.pending(idx).rec {
            Record::Packet(p) => &mut p.data,
            Record::Block(b) => b,
        }
    }
}

impl Engine {
    pub fn new(cfg: Config, secret: &[u8]) -> Engine {
        let ps = Pseudo::new(&cfg, secret);
        Engine { cfg, ps, stats: Stats::default() }
    }

    pub fn proto_by_port(&self, sport: u16, dport: u16) -> Option<Sig> {
        let p = &self.cfg.protocols;
        if p.ngap_sctp_ports.contains(&sport) || p.ngap_sctp_ports.contains(&dport) {
            Some(Sig::Ngap)
        } else if p.s1ap_sctp_ports.contains(&sport) || p.s1ap_sctp_ports.contains(&dport) {
            Some(Sig::S1ap)
        } else {
            None
        }
    }

    pub fn proto_by_ppid(&self, ppid: u32) -> Option<Sig> {
        let p = &self.cfg.protocols;
        if p.ngap_ppids.contains(&ppid) {
            Some(Sig::Ngap)
        } else if p.s1ap_ppids.contains(&ppid) {
            Some(Sig::S1ap)
        } else {
            None
        }
    }

    /// Should a NAS message marked "ciphered" be parsed as plain text?
    pub fn nas_readable(&self, looks_plain: bool) -> bool {
        self.cfg.nas.assume_null_ciphering || (self.cfg.nas.detect_null_ciphering && looks_plain)
    }

    /// Anonymize one complete S1AP / NGAP message in place. Returns false on error.
    pub fn process_message(&mut self, proto: Sig, buf: &mut [u8]) -> bool {
        self.process_message_ext(proto, buf, false)
    }

    /// `truncated`: the message was cut by the capture snap length; anonymize
    /// every IE that is fully present (best effort).
    pub fn process_message_ext(&mut self, proto: Sig, buf: &mut [u8], truncated: bool) -> bool {
        match proto {
            Sig::S1ap => self.stats.s1ap_msgs += 1,
            Sig::Ngap => self.stats.ngap_msgs += 1,
        }
        let r = catch_unwind(AssertUnwindSafe(|| match proto {
            Sig::S1ap => s1ap::process(self, buf, truncated),
            Sig::Ngap => ngap::process(self, buf, truncated),
        }));
        if truncated {
            // errors are expected for the cut-off IEs; the caller reports the packet
            return matches!(r, Ok(Ok(())));
        }
        match r {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                self.stats.error(format!("{:#}", e));
                false
            }
            Err(_) => {
                let msg = LAST_PANIC.with(|p| p.borrow_mut().take()).unwrap_or_default();
                self.stats.error(format!("{:?}: internal error {}", proto, msg));
                false
            }
        }
    }

    /// Run one file. With `output == None` nothing is written (learning pass).
    pub fn run_file(&mut self, input: &Path, output: Option<&Path>) -> Result<()> {
        let mut rd = Reader::open(input, self.cfg.general.strip_pcapng_comments)?;
        let mut wr = match output {
            Some(p) => Some(Writer::create(p, &rd)?),
            None => None,
        };
        let mut st = FileState::default();
        while let Some(rec) = rd.next()? {
            match rec {
                Record::Block(b) => st.q.push_back(Pending { rec: Record::Block(b), meta: PktMeta::default() }),
                Record::Packet(mut p) => {
                    self.stats.frame += 1;
                    self.stats.packets_in += 1;
                    let mut meta = PktMeta::default();
                    let r = catch_unwind(AssertUnwindSafe(|| {
                        net::process_packet(self, p.linktype, &mut p.data, &mut meta)
                    }));
                    if r.is_err() {
                        let msg = LAST_PANIC.with(|x| x.borrow_mut().take()).unwrap_or_default();
                        self.stats.error(format!("internal error {}", msg));
                        meta.error = true;
                        meta.frags.clear();
                    }
                    if meta.unsupported {
                        self.stats.unsupported_linktype += 1;
                    }
                    if meta.ip_fragment {
                        self.stats.ip_fragments += 1;
                    }
                    let frags = std::mem::take(&mut meta.frags);
                    let idx = st.base + st.q.len();
                    st.q.push_back(Pending { rec: Record::Packet(p), meta });
                    for f in frags {
                        self.handle_frag(&mut st, idx, f);
                    }
                }
            }
            if st.open.is_empty() {
                self.flush(&mut st, &mut wr)?;
            } else if st.q.len() > MAX_HOLD {
                self.abandon_all(&mut st);
                self.flush(&mut st, &mut wr)?;
            }
        }
        self.abandon_all(&mut st);
        self.flush(&mut st, &mut wr)?;
        self.stats.dropped_blocks += rd.dropped_blocks;
        if let Some(w) = wr {
            w.finish()?;
        }
        Ok(())
    }

    fn flush(&mut self, st: &mut FileState, wr: &mut Option<Writer>) -> Result<()> {
        let g = &self.cfg.general;
        while let Some(mut pd) = st.q.pop_front() {
            st.base += 1;
            if let Record::Packet(p) = &mut pd.rec {
                let m = &pd.meta;
                let error = m.error || m.unsupported || m.ip_fragment;
                let keep = if error {
                    g.on_error == Policy::Keep
                } else if !m.signalling {
                    g.other_traffic == Policy::Keep
                } else {
                    true
                };
                if !keep {
                    if error {
                        self.stats.dropped_error += 1;
                    } else {
                        self.stats.dropped_other += 1;
                    }
                    continue;
                }
                if error {
                    self.stats.kept_with_error += 1;
                }
                if m.sctp_dirty && g.fix_checksums {
                    if let Some(s) = m.sctp {
                        if s.crc_ok && s.off + s.len <= p.data.len() {
                            checksum::sctp_fix(&mut p.data[s.off..s.off + s.len]);
                        }
                    }
                }
                self.stats.packets_out += 1;
            }
            if let Some(w) = wr.as_mut() {
                w.write(&pd.rec)?;
            }
        }
        Ok(())
    }

    fn handle_frag(&mut self, st: &mut FileState, idx: usize, f: Frag) {
        let part = Part { idx, off: f.off, len: f.len, tsn: f.tsn };
        // retransmitted fragment of a message that is still being collected
        if let Some(r) = st.open.get_mut(&f.key) {
            if r.parts.iter().any(|p| p.tsn == f.tsn) {
                r.parts.push(part);
                return;
            }
        }
        // retransmitted fragment of a message that was already reassembled
        if let Some((orig, anon)) = st.done.get(&(f.key, f.tsn)) {
            let i = idx - st.base;
            let pd = &mut st.q[i];
            if let Record::Packet(p) = &mut pd.rec {
                if p.data.get(f.off..f.off + f.len) == Some(&orig[..]) {
                    p.data[f.off..f.off + f.len].copy_from_slice(anon);
                    pd.meta.sctp_dirty = true;
                    return;
                }
            }
        }
        if f.first {
            if let Some(old) = st.open.remove(&f.key) {
                self.abandon(st, old);
            }
            st.open.insert(
                f.key,
                Reasm { key: f.key, proto: f.proto, parts: vec![part], next_tsn: f.tsn.wrapping_add(1) },
            );
            return;
        }
        let in_order = matches!(st.open.get(&f.key), Some(r) if r.next_tsn == f.tsn);
        if in_order {
            let r = st.open.get_mut(&f.key).unwrap();
            r.parts.push(part);
            r.next_tsn = f.tsn.wrapping_add(1);
            if f.last {
                let r = st.open.remove(&f.key).unwrap();
                self.complete(st, r);
            }
            return;
        }
        if let Some(old) = st.open.remove(&f.key) {
            self.abandon(st, old);
        }
        self.stats.error("SCTP fragment without its preceding fragments (not anonymized)".into());
        st.pending(idx).meta.error = true;
    }

    fn complete(&mut self, st: &mut FileState, r: Reasm) {
        let mut seen = HashSet::new();
        let mut uniq = Vec::new();
        let mut buf = Vec::new();
        for p in &r.parts {
            if seen.insert(p.tsn) {
                uniq.push(*p);
                let d = st.data(p.idx);
                buf.extend_from_slice(&d[p.off..p.off + p.len]);
            }
        }
        let orig = buf.clone();
        let ok = self.process_message(r.proto, &mut buf);
        self.stats.reassembled += 1;
        let mut offs = HashMap::new();
        let mut o = 0;
        for p in &uniq {
            offs.insert(p.tsn, (o, p.len));
            o += p.len;
        }
        for p in &r.parts {
            let (o, l) = offs[&p.tsn];
            if l != p.len {
                continue;
            }
            st.data(p.idx)[p.off..p.off + l].copy_from_slice(&buf[o..o + l]);
            let pd = st.pending(p.idx);
            pd.meta.sctp_dirty = true;
            if !ok {
                pd.meta.error = true;
            }
        }
        for p in &uniq {
            let (o, l) = offs[&p.tsn];
            let k = (r.key, p.tsn);
            if st.done.insert(k, (orig[o..o + l].to_vec(), buf[o..o + l].to_vec())).is_none() {
                st.done_order.push_back(k);
            }
        }
        while st.done_order.len() > DONE_CACHE {
            if let Some(k) = st.done_order.pop_front() {
                st.done.remove(&k);
            }
        }
    }

    fn abandon(&mut self, st: &mut FileState, r: Reasm) {
        self.stats.error(format!(
            "incomplete SCTP-fragmented {:?} message ({} fragment(s)) not anonymized",
            r.proto,
            r.parts.len()
        ));
        for p in &r.parts {
            st.pending(p.idx).meta.error = true;
        }
    }

    fn abandon_all(&mut self, st: &mut FileState) {
        let open: Vec<Reasm> = st.open.drain().map(|(_, r)| r).collect();
        for r in open {
            self.abandon(st, r);
        }
    }
}
