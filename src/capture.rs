//! Reading and writing classic pcap and pcapng files.
//!
//! Packet data is handed out as an owned `Vec<u8>`; anonymization never changes
//! its length. pcapng blocks are re-serialized in the byte order of their section:
//! name-resolution / decryption-secret / custom blocks are dropped, interface
//! descriptions lose their name/description/address/filter options and comments
//! are optionally stripped.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

const MAX_BLOCK: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    Pcapng,
}

#[derive(Debug, Clone)]
pub enum RecHdr {
    Pcap { ts_sec: u32, ts_frac: u32 },
    Epb { be: bool, iface: u32, ts_hi: u32, ts_lo: u32, options: Vec<u8> },
    Spb { be: bool },
    ObsoletePb { be: bool, iface: u16, drops: u16, ts_hi: u32, ts_lo: u32, options: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct PacketRec {
    pub linktype: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
    pub hdr: RecHdr,
}

#[derive(Debug, Clone)]
pub enum Record {
    Packet(PacketRec),
    /// A complete, already sanitized pcapng block to copy to the output.
    Block(Vec<u8>),
}

fn rd16(b: &[u8], be: bool) -> u16 {
    let a = [b[0], b[1]];
    if be { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) }
}

fn rd32(b: &[u8], be: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if be { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
}

fn w16(v: u16, be: bool) -> [u8; 2] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}

fn w32(v: u32, be: bool) -> [u8; 4] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

pub struct Reader {
    inner: BufReader<File>,
    pub format: Format,
    /// pcap: 24-byte file header (copied verbatim to the output)
    pub pcap_header: Vec<u8>,
    be: bool,
    pcap_linktype: u32,
    ifaces: Vec<u32>,
    strip_comments: bool,
    /// number of pcapng blocks removed (name resolution, secrets, custom ...)
    pub dropped_blocks: u64,
}

impl Reader {
    pub fn open(path: &Path, strip_comments: bool) -> Result<Reader> {
        let f = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let mut inner = BufReader::with_capacity(1 << 20, f);
        let mut magic = [0u8; 4];
        inner.read_exact(&mut magic).context("file too short")?;
        let mut r = Reader {
            inner,
            format: Format::Pcap,
            pcap_header: Vec::new(),
            be: false,
            pcap_linktype: 0,
            ifaces: Vec::new(),
            strip_comments,
            dropped_blocks: 0,
        };
        match u32::from_le_bytes(magic) {
            0xa1b2c3d4 | 0xa1b23c4d => r.be = false,
            0xd4c3b2a1 | 0x4d3cb2a1 => r.be = true,
            0x0a0d0d0a => {
                r.format = Format::Pcapng;
                r.pcap_header = magic.to_vec(); // first 4 bytes of the first SHB
                return Ok(r);
            }
            _ => bail!("{} is not a pcap or pcapng file", path.display()),
        }
        let mut rest = [0u8; 20];
        r.inner.read_exact(&mut rest).context("truncated pcap header")?;
        r.pcap_header = [magic.as_slice(), rest.as_slice()].concat();
        r.pcap_linktype = rd32(&rest[16..20], r.be) & 0xFFFF;
        Ok(r)
    }

    pub fn next(&mut self) -> Result<Option<Record>> {
        match self.format {
            Format::Pcap => self.next_pcap(),
            Format::Pcapng => loop {
                if let Some(r) = self.next_pcapng()? {
                    match r {
                        Some(rec) => return Ok(Some(rec)),
                        None => continue, // dropped block
                    }
                }
                return Ok(None);
            },
        }
    }

    fn read_exact_or_eof(&mut self, buf: &mut [u8]) -> Result<bool> {
        let mut got = 0;
        while got < buf.len() {
            let n = self.inner.read(&mut buf[got..])?;
            if n == 0 {
                if got == 0 {
                    return Ok(false);
                }
                bail!("truncated file (partial record at end)");
            }
            got += n;
        }
        Ok(true)
    }

    fn next_pcap(&mut self) -> Result<Option<Record>> {
        let mut h = [0u8; 16];
        if !self.read_exact_or_eof(&mut h)? {
            return Ok(None);
        }
        let be = self.be;
        let incl = rd32(&h[8..12], be) as usize;
        if incl > MAX_BLOCK {
            bail!("corrupt pcap record (length {})", incl);
        }
        let mut data = vec![0u8; incl];
        if !self.read_exact_or_eof(&mut data)? && incl > 0 {
            bail!("truncated pcap record");
        }
        Ok(Some(Record::Packet(PacketRec {
            linktype: self.pcap_linktype,
            orig_len: rd32(&h[12..16], be),
            data,
            hdr: RecHdr::Pcap { ts_sec: rd32(&h[0..4], be), ts_frac: rd32(&h[4..8], be) },
        })))
    }

    /// Ok(None) = EOF, Ok(Some(None)) = block dropped, Ok(Some(Some(rec))) = record.
    fn next_pcapng(&mut self) -> Result<Option<Option<Record>>> {
        let mut head = [0u8; 8];
        if !self.pcap_header.is_empty() {
            // first 4 bytes already consumed while sniffing the format
            head[..4].copy_from_slice(&self.pcap_header);
            self.pcap_header.clear();
            let mut rest = [0u8; 4];
            self.inner.read_exact(&mut rest)?;
            head[4..].copy_from_slice(&rest);
        } else if !self.read_exact_or_eof(&mut head)? {
            return Ok(None);
        }
        let btype_raw = [head[0], head[1], head[2], head[3]];
        if u32::from_le_bytes(btype_raw) == 0x0a0d0d0a {
            // Section Header Block: byte order comes from the magic that follows
            let mut bom = [0u8; 4];
            self.inner.read_exact(&mut bom)?;
            self.be = match u32::from_le_bytes(bom) {
                0x1a2b3c4d => false,
                0x4d3c2b1a => true,
                _ => bail!("bad pcapng byte-order magic"),
            };
            let total = rd32(&head[4..8], self.be) as usize;
            if !(28..=MAX_BLOCK).contains(&total) {
                bail!("corrupt pcapng section header");
            }
            let mut body = vec![0u8; total - 12];
            self.inner.read_exact(&mut body)?;
            self.ifaces.clear();
            let be = self.be;
            // body: bom(already read) | major(2) minor(2) section_len(8) options | total(4)
            let fixed = &body[..12];
            let opts = filter_options(&body[12..body.len() - 4], be, |code| {
                !(self.strip_comments && code == 1) && !is_custom_opt(code)
            });
            let mut out = Vec::new();
            out.extend_from_slice(&w32(0x0a0d0d0a, be));
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&w32(0x1a2b3c4d, be));
            out.extend_from_slice(&fixed[..4]); // version
            out.extend_from_slice(&[0xff; 8]); // section length unknown (blocks may be dropped)
            out.extend_from_slice(&opts);
            return Ok(Some(Some(Record::Block(finish_block(out, be)))));
        }
        let be = self.be;
        let btype = rd32(&head[0..4], be);
        let total = rd32(&head[4..8], be) as usize;
        if !(12..=MAX_BLOCK).contains(&total) || !total.is_multiple_of(4) {
            bail!("corrupt pcapng block (type {:#x}, length {})", btype, total);
        }
        let mut body = vec![0u8; total - 8];
        self.inner.read_exact(&mut body)?;
        let body = &body[..body.len() - 4]; // strip trailing length
        match btype {
            1 => {
                // Interface Description Block
                if body.len() < 8 {
                    bail!("short IDB");
                }
                let linktype = rd16(&body[0..2], be) as u32;
                self.ifaces.push(linktype);
                // keep only harmless options: if_speed(8) if_tsresol(9) if_fcslen(13) if_tsoffset(14)
                let opts = filter_options(&body[8..], be, |c| matches!(c, 8 | 9 | 13 | 14));
                let mut out = Vec::new();
                out.extend_from_slice(&w32(1, be));
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&body[..8]);
                out.extend_from_slice(&opts);
                Ok(Some(Some(Record::Block(finish_block(out, be)))))
            }
            6 => {
                // Enhanced Packet Block
                if body.len() < 20 {
                    bail!("short EPB");
                }
                let iface = rd32(&body[0..4], be);
                let caplen = rd32(&body[12..16], be) as usize;
                if 20 + caplen > body.len() {
                    bail!("corrupt EPB");
                }
                let data = body[20..20 + caplen].to_vec();
                let opt_start = 20 + caplen + pad4(caplen);
                let options = if opt_start < body.len() {
                    // drop comments, packet hash (3) and custom options
                    filter_options(&body[opt_start..], be, |c| {
                        !(self.strip_comments && c == 1) && c != 3 && !is_custom_opt(c)
                    })
                } else {
                    Vec::new()
                };
                Ok(Some(Some(Record::Packet(PacketRec {
                    linktype: self.iface_linktype(iface)?,
                    orig_len: rd32(&body[16..20], be),
                    data,
                    hdr: RecHdr::Epb {
                        be,
                        iface,
                        ts_hi: rd32(&body[4..8], be),
                        ts_lo: rd32(&body[8..12], be),
                        options,
                    },
                }))))
            }
            3 => {
                // Simple Packet Block
                if body.len() < 4 {
                    bail!("short SPB");
                }
                let orig_len = rd32(&body[0..4], be);
                let caplen = (orig_len as usize).min(body.len() - 4);
                Ok(Some(Some(Record::Packet(PacketRec {
                    linktype: self.iface_linktype(0)?,
                    orig_len,
                    data: body[4..4 + caplen].to_vec(),
                    hdr: RecHdr::Spb { be },
                }))))
            }
            2 => {
                // obsolete Packet Block
                if body.len() < 20 {
                    bail!("short packet block");
                }
                let iface = rd16(&body[0..2], be);
                let caplen = rd32(&body[12..16], be) as usize;
                if 20 + caplen > body.len() {
                    bail!("corrupt packet block");
                }
                let opt_start = 20 + caplen + pad4(caplen);
                let options = if opt_start < body.len() {
                    filter_options(&body[opt_start..], be, |c| {
                        !(self.strip_comments && c == 1) && c != 3 && !is_custom_opt(c)
                    })
                } else {
                    Vec::new()
                };
                Ok(Some(Some(Record::Packet(PacketRec {
                    linktype: self.iface_linktype(iface as u32)?,
                    orig_len: rd32(&body[16..20], be),
                    data: body[20..20 + caplen].to_vec(),
                    hdr: RecHdr::ObsoletePb {
                        be,
                        iface,
                        drops: rd16(&body[2..4], be),
                        ts_hi: rd32(&body[4..8], be),
                        ts_lo: rd32(&body[8..12], be),
                        options,
                    },
                }))))
            }
            5 => {
                // Interface Statistics Block: keep, minus comments
                if body.len() < 12 {
                    bail!("short ISB");
                }
                let opts = filter_options(&body[12..], be, |c| {
                    !(self.strip_comments && c == 1) && !is_custom_opt(c)
                });
                let mut out = Vec::new();
                out.extend_from_slice(&w32(5, be));
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&body[..12]);
                out.extend_from_slice(&opts);
                Ok(Some(Some(Record::Block(finish_block(out, be)))))
            }
            _ => {
                // Name Resolution (4), Decryption Secrets (10), custom, journal, unknown
                self.dropped_blocks += 1;
                Ok(Some(None))
            }
        }
    }

    fn iface_linktype(&self, iface: u32) -> Result<u32> {
        self.ifaces
            .get(iface as usize)
            .copied()
            .with_context(|| format!("packet references unknown interface {}", iface))
    }
}

fn is_custom_opt(code: u16) -> bool {
    matches!(code, 2988 | 2989 | 19372 | 19373)
}

/// Re-serialize an options list keeping only the options accepted by `keep`.
fn filter_options(raw: &[u8], be: bool, keep: impl Fn(u16) -> bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= raw.len() {
        let code = rd16(&raw[i..], be);
        let len = rd16(&raw[i + 2..], be) as usize;
        if code == 0 {
            break;
        }
        let end = i + 4 + len;
        if end > raw.len() {
            break;
        }
        if keep(code) {
            out.extend_from_slice(&raw[i..end]);
            out.extend(std::iter::repeat_n(0, pad4(len)));
        }
        i = end + pad4(len);
    }
    if !out.is_empty() {
        out.extend_from_slice(&[0, 0, 0, 0]); // opt_endofopt
    }
    out
}

/// `out` starts with type(4) + placeholder length(4); append trailer and fix lengths.
fn finish_block(mut out: Vec<u8>, be: bool) -> Vec<u8> {
    let total = (out.len() + 4) as u32;
    out[4..8].copy_from_slice(&w32(total, be));
    out.extend_from_slice(&w32(total, be));
    out
}

pub struct Writer {
    out: BufWriter<File>,
    format: Format,
    pcap_be: bool,
}

impl Writer {
    pub fn create(path: &Path, reader: &Reader) -> Result<Writer> {
        let f = File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
        let mut out = BufWriter::with_capacity(1 << 20, f);
        if reader.format == Format::Pcap {
            out.write_all(&reader.pcap_header)?;
        }
        Ok(Writer { out, format: reader.format, pcap_be: reader.be })
    }

    pub fn write(&mut self, rec: &Record) -> Result<()> {
        match rec {
            Record::Block(b) => self.out.write_all(b)?,
            Record::Packet(p) => self.write_packet(p)?,
        }
        Ok(())
    }

    fn write_packet(&mut self, p: &PacketRec) -> Result<()> {
        let caplen = p.data.len() as u32;
        match &p.hdr {
            RecHdr::Pcap { ts_sec, ts_frac } => {
                debug_assert_eq!(self.format, Format::Pcap);
                let be = self.pcap_be;
                self.out.write_all(&w32(*ts_sec, be))?;
                self.out.write_all(&w32(*ts_frac, be))?;
                self.out.write_all(&w32(caplen, be))?;
                self.out.write_all(&w32(p.orig_len, be))?;
                self.out.write_all(&p.data)?;
            }
            RecHdr::Epb { be, iface, ts_hi, ts_lo, options } => {
                let be = *be;
                let mut b = Vec::with_capacity(p.data.len() + 40 + options.len());
                b.extend_from_slice(&w32(6, be));
                b.extend_from_slice(&[0; 4]);
                b.extend_from_slice(&w32(*iface, be));
                b.extend_from_slice(&w32(*ts_hi, be));
                b.extend_from_slice(&w32(*ts_lo, be));
                b.extend_from_slice(&w32(caplen, be));
                b.extend_from_slice(&w32(p.orig_len, be));
                b.extend_from_slice(&p.data);
                b.extend(std::iter::repeat_n(0, pad4(p.data.len())));
                b.extend_from_slice(options);
                self.out.write_all(&finish_block(b, be))?;
            }
            RecHdr::Spb { be } => {
                let be = *be;
                let mut b = Vec::with_capacity(p.data.len() + 20);
                b.extend_from_slice(&w32(3, be));
                b.extend_from_slice(&[0; 4]);
                b.extend_from_slice(&w32(p.orig_len, be));
                b.extend_from_slice(&p.data);
                b.extend(std::iter::repeat_n(0, pad4(p.data.len())));
                self.out.write_all(&finish_block(b, be))?;
            }
            RecHdr::ObsoletePb { be, iface, drops, ts_hi, ts_lo, options } => {
                let be = *be;
                let mut b = Vec::with_capacity(p.data.len() + 40 + options.len());
                b.extend_from_slice(&w32(2, be));
                b.extend_from_slice(&[0; 4]);
                b.extend_from_slice(&w16(*iface, be));
                b.extend_from_slice(&w16(*drops, be));
                b.extend_from_slice(&w32(*ts_hi, be));
                b.extend_from_slice(&w32(*ts_lo, be));
                b.extend_from_slice(&w32(caplen, be));
                b.extend_from_slice(&w32(p.orig_len, be));
                b.extend_from_slice(&p.data);
                b.extend(std::iter::repeat_n(0, pad4(p.data.len())));
                b.extend_from_slice(options);
                self.out.write_all(&finish_block(b, be))?;
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}
