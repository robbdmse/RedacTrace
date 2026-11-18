//! Settings file (TOML). Every field has a default, so a partial file is fine.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The documented default settings file, written by `--init-config`.
pub const TEMPLATE: &str = include_str!("../anonymizer.toml");
pub const DEFAULT_FILE_NAME: &str = "anonymizer.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub protocols: Protocols,
    pub anonymize: Fields,
    pub mac: MacCfg,
    pub ip: IpCfg,
    pub imsi: ImsiCfg,
    pub imei: ImeiCfg,
    pub ran: RanCfg,
    pub nas: NasCfg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Keep,
    Drop,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub secret: String,
    pub mapping_file: String,
    pub other_traffic: Policy,
    pub on_error: Policy,
    pub fix_checksums: bool,
    pub strip_pcapng_comments: bool,
}

impl Default for General {
    fn default() -> Self {
        General {
            secret: String::new(),
            mapping_file: String::new(),
            other_traffic: Policy::Keep,
            on_error: Policy::Keep,
            fix_checksums: true,
            strip_pcapng_comments: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Protocols {
    pub s1ap_sctp_ports: Vec<u16>,
    pub ngap_sctp_ports: Vec<u16>,
    pub s1ap_ppids: Vec<u32>,
    pub ngap_ppids: Vec<u32>,
}

impl Default for Protocols {
    fn default() -> Self {
        Protocols {
            s1ap_sctp_ports: vec![36412],
            ngap_sctp_ports: vec![38412],
            s1ap_ppids: vec![18],
            ngap_ppids: vec![60],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fields {
    pub mac_addresses: bool,
    pub ip_addresses: bool,
    pub ip_in_signalling: bool,
    pub ue_ip_addresses: bool,
    pub imsi: bool,
    pub tmsi: bool,
    pub imei: bool,
    pub amf_name: bool,
    pub mme_name: bool,
    pub ran_node_name: bool,
    pub gnb_id: bool,
    pub enb_id: bool,
    pub cell_identity: bool,
    pub amf_identifiers: bool,
    pub mme_identifiers: bool,
}

impl Default for Fields {
    fn default() -> Self {
        Fields {
            mac_addresses: true,
            ip_addresses: true,
            ip_in_signalling: true,
            ue_ip_addresses: true,
            imsi: true,
            tmsi: true,
            imei: true,
            amf_name: true,
            mme_name: true,
            ran_node_name: true,
            gnb_id: true,
            enb_id: true,
            cell_identity: true,
            amf_identifiers: false,
            mme_identifiers: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MacCfg {
    pub keep_oui: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpMode {
    PrefixPreserving,
    Random,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpCfg {
    pub mode: IpMode,
    pub keep_special: bool,
}

impl Default for IpCfg {
    fn default() -> Self {
        IpCfg { mode: IpMode::PrefixPreserving, keep_special: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImsiCfg {
    pub default_mnc_length: u8,
}

impl Default for ImsiCfg {
    fn default() -> Self {
        ImsiCfg { default_mnc_length: 2 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImeiCfg {
    pub keep_tac: bool,
}

impl Default for ImeiCfg {
    fn default() -> Self {
        ImeiCfg { keep_tac: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RanCfg {
    pub gnb_id_length: u8,
    pub enb_id_length: u8,
}

impl Default for RanCfg {
    fn default() -> Self {
        RanCfg { gnb_id_length: 0, enb_id_length: 20 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NasCfg {
    pub detect_null_ciphering: bool,
    pub assume_null_ciphering: bool,
}

impl Default for NasCfg {
    fn default() -> Self {
        NasCfg { detect_null_ciphering: true, assume_null_ciphering: false }
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read settings file {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("invalid settings file {}", path.display()))
    }

    fn validate(&self) -> Result<()> {
        if !(self.imsi.default_mnc_length == 2 || self.imsi.default_mnc_length == 3) {
            bail!("imsi.default_mnc_length must be 2 or 3");
        }
        let g = self.ran.gnb_id_length;
        if g != 0 && !(22..=32).contains(&g) {
            bail!("ran.gnb_id_length must be 0 (auto) or 22..32");
        }
        if ![18u8, 20, 21, 28].contains(&self.ran.enb_id_length) {
            bail!("ran.enb_id_length must be 18, 20, 21 or 28");
        }
        Ok(())
    }
}

/// Find the settings file: explicit path, then ./anonymizer.toml, then next to the exe.
pub fn locate(explicit: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(p) = explicit {
        if !p.is_file() {
            bail!("settings file {} does not exist", p.display());
        }
        return Ok(Some(p.to_path_buf()));
    }
    let cwd = PathBuf::from(DEFAULT_FILE_NAME);
    if cwd.is_file() {
        return Ok(Some(cwd));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(DEFAULT_FILE_NAME);
            if p.is_file() {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_matches_defaults() {
        let t = Config::parse(TEMPLATE).expect("template parses");
        let d = Config::default();
        assert_eq!(format!("{:?}", t), format!("{:?}", d));
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(Config::parse("[anonymize]\nimsii = true\n").is_err());
    }
}
