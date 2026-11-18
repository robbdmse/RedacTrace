//! Counters and the end-of-run report.

use std::collections::BTreeMap;

const MAX_SAMPLES: usize = 15;

#[derive(Debug, Default)]
pub struct Stats {
    /// frame number (1-based) of the packet being processed, for messages
    pub frame: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub dropped_other: u64,
    pub dropped_error: u64,
    pub kept_with_error: u64,
    pub dropped_blocks: u64,
    pub s1ap_msgs: u64,
    pub ngap_msgs: u64,
    pub reassembled: u64,
    pub nas_ciphered: u64,
    pub nas_null_ciphered: u64,
    pub unsupported_linktype: u64,
    pub ip_fragments: u64,
    pub fields: BTreeMap<&'static str, u64>,
    pub errors: u64,
    pub samples: Vec<String>,
    /// file currently processed (for messages)
    pub file: String,
}

impl Stats {
    pub fn field(&mut self, f: &'static str) {
        *self.fields.entry(f).or_default() += 1;
    }

    pub fn error(&mut self, msg: String) {
        self.errors += 1;
        if self.samples.len() < MAX_SAMPLES {
            self.samples.push(format!("{} frame {}: {}", self.file, self.frame, msg));
        }
    }

    pub fn report(&self) -> String {
        let mut s = String::new();
        let dropped = self.dropped_other + self.dropped_error;
        s += &format!(
            "Packets: {} read, {} written, {} dropped",
            self.packets_in, self.packets_out, dropped
        );
        if dropped > 0 {
            s += &format!(" ({} other traffic, {} with errors)", self.dropped_other, self.dropped_error);
        }
        s += "\n";
        s += &format!("Signalling: {} S1AP and {} NGAP messages", self.s1ap_msgs, self.ngap_msgs);
        if self.reassembled > 0 {
            s += &format!(" ({} reassembled from SCTP fragments)", self.reassembled);
        }
        s += "\n";
        if !self.fields.is_empty() {
            let parts: Vec<String> = self.fields.iter().map(|(k, v)| format!("{} {}", k, v)).collect();
            s += &format!("Fields replaced: {}\n", parts.join(", "));
        }
        if self.nas_null_ciphered + self.nas_ciphered > 0 {
            s += &format!(
                "NAS: {} null-ciphered (EEA0/NEA0) messages anonymized, {} really ciphered messages left untouched\n",
                self.nas_null_ciphered, self.nas_ciphered
            );
        }
        if self.dropped_blocks > 0 {
            s += &format!(
                "pcapng: {} name-resolution/secrets/custom block(s) removed\n",
                self.dropped_blocks
            );
        }
        if self.unsupported_linktype > 0 {
            s += &format!(
                "WARNING: {} packet(s) with an unsupported link type could not be anonymized\n",
                self.unsupported_linktype
            );
        }
        if self.ip_fragments > 0 {
            s += &format!(
                "WARNING: {} IP-fragmented SCTP packet(s) could not be anonymized\n",
                self.ip_fragments
            );
        }
        if self.errors > 0 || self.kept_with_error > 0 {
            if self.kept_with_error > 0 {
                s += &format!(
                    "WARNING: {} problem(s); {} affected packet(s) were kept and may contain un-anonymized fields (set general.on_error = \"drop\" to remove them)\n",
                    self.errors, self.kept_with_error
                );
            } else {
                s += &format!(
                    "NOTE: {} problem(s); the {} affected packet(s) were dropped (general.on_error = \"drop\")\n",
                    self.errors, self.dropped_error
                );
            }
            for e in &self.samples {
                s += &format!("  - {}\n", e);
            }
            if self.errors as usize > self.samples.len() {
                s += &format!("  ... and {} more\n", self.errors as usize - self.samples.len());
            }
        }
        s
    }
}
