//! RedacTrace: anonymize S1-MME (S1AP) and N2 (NGAP) traces.

mod ap;
mod capture;
mod checksum;
mod config;
mod engine;
mod nas;
mod net;
mod ngap;
mod per;
mod pseudo;
mod s1ap;
mod sctp;
mod stats;

use anyhow::{bail, Context, Result};
use clap::Parser;
use config::Config;
use engine::{Engine, LAST_PANIC};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "redactrace",
    version,
    about = "Anonymize S1AP (S1-MME) and NGAP (N2) telecom traces in pcap/pcapng files",
    after_help = "Examples:\n  \
        redactrace trace.pcapng                      -> trace_anon.pcapng\n  \
        redactrace trace.pcap -o shared.pcap\n  \
        redactrace traces\\ -o anonymized\\          (all captures in a folder)\n  \
        redactrace --init-config                     (write anonymizer.toml)\n  \
        redactrace -c strict.toml --mapping map.csv trace.pcap\n\n\
        On Windows you can also drag and drop capture files onto the .exe."
)]
struct Cli {
    /// Capture files (.pcap / .pcapng / .cap) or folders containing them
    inputs: Vec<PathBuf>,

    /// Output file (one input) or output folder (several inputs).
    /// Default: <name>_anon.<ext> next to each input
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Settings file (default: ./anonymizer.toml, then anonymizer.toml next to the program)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Write a documented default settings file and exit
    #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = config::DEFAULT_FILE_NAME)]
    init_config: Option<PathBuf>,

    /// Write the original -> pseudonym table to this CSV file (contains the originals!)
    #[arg(long, value_name = "CSV")]
    mapping: Option<PathBuf>,

    /// Secret for pseudonym generation (overrides the settings file)
    #[arg(long)]
    secret: Option<String>,

    /// Only print warnings and errors
    #[arg(short, long)]
    quiet: bool,
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let msg = match info.location() {
            Some(l) => format!("({}:{}: {})", l.file(), l.line(), panic_text(info)),
            None => format!("({})", panic_text(info)),
        };
        LAST_PANIC.with(|p| *p.borrow_mut() = Some(msg));
    }));
    let interactive = launched_from_explorer();
    let code = match run(interactive) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {:#}", e);
            1
        }
    };
    if interactive {
        eprintln!("\nPress Enter to close this window.");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
    std::process::exit(code);
}

fn panic_text(info: &std::panic::PanicHookInfo) -> String {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "panic".into()
    }
}

fn run(interactive: bool) -> Result<()> {
    let cli = Cli::parse();

    if let Some(path) = &cli.init_config {
        if path.exists() {
            bail!("{} already exists; remove it first or choose another name", path.display());
        }
        std::fs::write(path, config::TEMPLATE).with_context(|| format!("cannot write {}", path.display()))?;
        println!("Wrote default settings to {}", path.display());
        return Ok(());
    }

    if cli.inputs.is_empty() {
        use clap::CommandFactory;
        Cli::command().print_help()?;
        if interactive {
            println!("\n\nTip: drag and drop .pcap / .pcapng files onto this program to anonymize them.");
        }
        return Ok(());
    }

    let cfg_path = config::locate(cli.config.as_deref())?;
    let mut cfg = match &cfg_path {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    };
    if let Some(s) = &cli.secret {
        cfg.general.secret = s.clone();
    }

    let files = expand_inputs(&cli.inputs)?;
    if files.is_empty() {
        bail!("no capture files found in the given input(s)");
    }
    let jobs = plan_outputs(&files, cli.output.as_deref())?;

    let log = |s: &str| {
        if !cli.quiet {
            println!("{}", s);
        }
    };
    match &cfg_path {
        Some(p) => log(&format!("Settings: {}", p.display())),
        None => log("Settings: built-in defaults (no anonymizer.toml found)"),
    }

    let secret: Vec<u8> = if cfg.general.secret.is_empty() {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|e| anyhow::anyhow!("cannot get random bytes for the secret: {}", e))?;
        log("Secret: random for this run (pseudonyms are not reproducible)");
        k.to_vec()
    } else {
        log("Secret: from settings (pseudonyms are reproducible)");
        cfg.general.secret.as_bytes().to_vec()
    };
    let mapping = cli.mapping.clone().or_else(|| {
        let m = &cfg.general.mapping_file;
        if m.is_empty() {
            None
        } else {
            let p = PathBuf::from(m);
            Some(if p.is_relative() {
                jobs[0].1.parent().map(|d| d.join(&p)).unwrap_or(p)
            } else {
                p
            })
        }
    });

    let mut eng = Engine::new(cfg, &secret);
    let start = Instant::now();

    // Pass 1: learn facts needed for consistent pseudonyms (gNB-ID lengths, PLMNs)
    eng.ps.learning = true;
    for (inp, _) in &jobs {
        eng.stats.file = file_name(inp);
        eng.run_file(inp, None).with_context(|| format!("reading {}", inp.display()))?;
    }
    eng.ps.learning = false;
    eng.stats = Default::default();

    // Pass 2: anonymize
    for (inp, out) in &jobs {
        eng.stats.file = file_name(inp);
        let before = eng.stats.packets_out;
        eng.run_file(inp, Some(out)).with_context(|| format!("processing {}", inp.display()))?;
        log(&format!(
            "{} -> {} ({} packets)",
            inp.display(),
            out.display(),
            eng.stats.packets_out - before
        ));
    }

    log("");
    let report = eng.stats.report();
    if cli.quiet {
        for line in report.lines().filter(|l| l.starts_with("WARNING") || l.starts_with("  ")) {
            eprintln!("{}", line);
        }
    } else {
        print!("{}", report);
    }
    if let Some(m) = mapping {
        eng.ps.write_mapping(&m).with_context(|| format!("cannot write mapping file {}", m.display()))?;
        log(&format!(
            "Mapping table ({} entries, contains ORIGINAL values - keep private): {}",
            eng.ps.mapping_len(),
            m.display()
        ));
    }
    log(&format!("Done in {:.1}s", start.elapsed().as_secs_f64()));
    Ok(())
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn is_capture(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref(),
        Some("pcap" | "pcapng" | "cap" | "pcap0" | "dmp" | "ntar")
    )
}

fn expand_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for i in inputs {
        if i.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(i)
                .with_context(|| format!("cannot read folder {}", i.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file() && is_capture(p))
                .filter(|p| !p.file_stem().map(|s| s.to_string_lossy().ends_with("_anon")).unwrap_or(false))
                .collect();
            v.sort();
            files.extend(v);
        } else if i.is_file() {
            files.push(i.clone());
        } else {
            bail!("input {} does not exist", i.display());
        }
    }
    Ok(files)
}

fn default_output(input: &Path, dir: Option<&Path>) -> PathBuf {
    let stem = input.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let name = match input.extension() {
        Some(e) => format!("{}_anon.{}", stem, e.to_string_lossy()),
        None => format!("{}_anon", stem),
    };
    match dir {
        Some(d) => d.join(name),
        None => input.with_file_name(name),
    }
}

/// `-o` names a folder when it is an existing folder, ends with a path
/// separator, or has no file extension; otherwise it names the output file.
fn output_is_dir(o: &Path) -> bool {
    let s = o.to_string_lossy();
    o.is_dir() || s.ends_with('/') || s.ends_with('\\') || o.extension().is_none()
}

fn plan_outputs(files: &[PathBuf], output: Option<&Path>) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut jobs = Vec::new();
    match output {
        Some(o) if files.len() > 1 && !output_is_dir(o) => {
            bail!("{} is a file name, but several inputs were given; use a folder for -o", o.display())
        }
        Some(o) if files.len() == 1 && !output_is_dir(o) => {
            if let Some(dir) = o.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).with_context(|| format!("cannot create folder {}", dir.display()))?;
            }
            jobs.push((files[0].clone(), o.to_path_buf()))
        }
        Some(o) => {
            std::fs::create_dir_all(o).with_context(|| format!("cannot create folder {}", o.display()))?;
            for f in files {
                jobs.push((f.clone(), default_output(f, Some(o))));
            }
        }
        None => {
            for f in files {
                jobs.push((f.clone(), default_output(f, None)));
            }
        }
    }
    for (i, o) in &jobs {
        let same = match (std::fs::canonicalize(i), std::fs::canonicalize(o)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if same {
            bail!("output {} would overwrite its input", o.display());
        }
    }
    Ok(jobs)
}

/// True when the console was created just for this process (double-click or
/// drag-and-drop in Explorer), so we should keep the window open at the end.
#[cfg(windows)]
fn launched_from_explorer() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    }
    let mut buf = [0u32; 4];
    // SAFETY: the buffer is valid for 4 entries, as passed.
    let n = unsafe { GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32) };
    n == 1
}

#[cfg(not(windows))]
fn launched_from_explorer() -> bool {
    false
}
