//! End-to-end test: anonymize the synthetic S1/N2 traces in tests/data (made by
//! tools/gen_test_traces.py) and make sure none of the original identifiers is
//! left anywhere in the output bytes.

use std::path::{Path, PathBuf};
use std::process::Command;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// (description, byte pattern) of every identifier planted in the test traces.
fn originals() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = [
        ("IMSI in NAS mobile identity", "0910101032547698"),
        ("IMSI in S1AP paging (TBCD)", "00010121436587f9"),
        ("SUCI null-scheme MSIN", "00f110f0ff00000000000010"),
        ("IMEISV in 5GS NAS", "3565390853468300f7"),
        ("IMEISV in EPS NAS", "3365390853468300f7"),
        ("M-TMSI", "c0ffee01"),
        ("5G-TMSI", "c0ffee02"),
        ("5G-TMSI (service request)", "c0ffee03"),
        ("5G-TMSI (fragmented message)", "c0ffee04"),
        ("TMSI (MS identity)", "12345678"),
        ("AMF IPv4", "0a64c801"),
        ("gNB IPv4", "0a64c80b"),
        ("gNB second path IPv4", "0a64c90b"),
        ("MME IPv4", "c0a80a01"),
        ("eNB IPv4", "c0a80a14"),
        ("UE IPv4 (5GS)", "0a2d0002"),
        ("UE IPv4 (EPS)", "0a2d0007"),
        ("GTP-U endpoint UPF", "0a0a0005"),
        ("GTP-U endpoint gNB", "0a140007"),
        ("GTP-U endpoint SGW", "0a1e0009"),
        ("GTP-U endpoint eNB", "0a280001"),
        ("AMF IPv6", "20010db8000100000000000000000001"),
        ("gNB IPv6", "20010db8000100000000000000000011"),
        ("gNB MAC", "3c2c30c0ffee"),
        ("AMF MAC", "0050569a1b2c"),
        ("eNB MAC", "020000aa0001"),
        ("MME MAC", "020000bb0002"),
        ("gNB-ID", "068acc"),
        ("eNB-ID", "000420"),
    ]
    .iter()
    .map(|(d, h)| (*d, hex(h)))
    .collect();
    for (d, s) in [
        ("AMF name", "open5gs-amf0"),
        ("backup AMF name", "amf-backup-1"),
        ("gNB name", "gnb-brussels-01"),
        ("eNB name", "enb-gent-02"),
        ("MME name", "mme-core-1"),
        ("pcapng interface name", "s1-n2-site-brussels"),
        ("pcapng comment", "IMSI"),
    ] {
        v.push((d, s.as_bytes().to_vec()));
    }
    v
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn out_dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_redactrace")).args(args).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "anonymizer failed:\n{}", text);
    text
}

fn check_file(input: &str) {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(input);
    let orig = std::fs::read(&data).unwrap();
    for (what, pat) in originals() {
        let pcapng_only = what.starts_with("pcapng");
        if input.ends_with(".pcapng") || !pcapng_only {
            assert!(count(&orig, &pat) > 0, "test fixture should contain {}", what);
        }
    }
    let dir = out_dir(input);
    let out = dir.join(format!("anon_{}", input));
    // an empty settings file = all defaults, independent of any anonymizer.toml around
    let cfg = dir.join("defaults.toml");
    std::fs::write(&cfg, "").unwrap();
    let log = run(&["-c", cfg.to_str().unwrap(), data.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert!(!log.contains("WARNING"), "unexpected warnings:\n{}", log);

    let anon = std::fs::read(&out).unwrap();
    let leaks: Vec<String> = originals()
        .into_iter()
        .filter(|(_, p)| count(&anon, p) > 0)
        .map(|(d, p)| format!("{} ({} times)", d, count(&anon, &p)))
        .collect();
    assert!(leaks.is_empty(), "original identifiers left in {}: {:?}", input, leaks);
    if input.ends_with(".pcap") {
        assert_eq!(anon.len(), orig.len(), "pcap size must not change");
    }
}

#[test]
fn pcap_has_no_leaks() {
    check_file("test_s1_n2.pcap");
}

#[test]
fn pcapng_has_no_leaks() {
    check_file("test_s1_n2.pcapng");
}

#[test]
fn same_secret_gives_same_output() {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/test_s1_n2.pcap");
    let dir = out_dir("determinism");
    let cfg = dir.join("defaults.toml");
    std::fs::write(&cfg, "").unwrap();
    let (a, b) = (dir.join("a.pcap"), dir.join("b.pcap"));
    for o in [&a, &b] {
        run(&["-q", "-c", cfg.to_str().unwrap(), "--secret", "s", data.to_str().unwrap(), "-o", o.to_str().unwrap()]);
    }
    assert_eq!(std::fs::read(a).unwrap(), std::fs::read(b).unwrap());
}
