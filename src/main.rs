//! OpenSentinel — lightweight, open-source antivirus scanner (Rust).
//!
//! Milestone 1 vertical slice:
//! - recursive directory scanning with bounded concurrency and cancellation
//! - streaming SHA-256 hashing (bounded memory)
//! - local hash-signature database with validation
//! - conservative, explainable heuristics (suspicious, never auto-delete)
//! - safe quarantine (unguessable IDs, no overwrite on restore, no auto-delete)
//!
//! Exit codes: 0 clean, 10 detected, 11 suspicious-only, 12 scanned with
//! errors, 1 user error (bad args, missing path, config error).
//!
//! All engine logic lives in the library crate (`opensentinel`); this file
//! is a thin CLI wrapper.

/// Top-level CLI entry point.
fn main() {
    let code = cli();
    std::process::exit(code);
}

fn cli() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.first().map(String::as_str) {
        Some(c @ ("scan" | "hash" | "quarantine" | "status" | "help" | "--help" | "-h")) => {
            (c, &args[1..])
        }
        _ => ("help", &args[..]),
    };
    let outcome = match cmd {
        "scan" => commands::scan(rest),
        "hash" => commands::hash(rest),
        "quarantine" => commands::quarantine(rest),
        "status" => commands::status(rest),
        _ => commands::help(),
    };
    match outcome {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            e.code()
        }
    }
}

mod commands {
    use opensentinel::{
        build_engine, hash_file, quarantine_add, quarantine_purge, quarantine_restore, scan_paths,
        summary_counts, Config, Error, ErrorKind, FileResult,
    };

    fn parse_opts(args: &[String], need_paths: bool) -> Result<Vec<String>, Error> {
        let mut paths = Vec::new();
        for a in args {
            match a.as_str() {
                "--json" | "--quiet" | "-q" => {}
                s if s.starts_with('-') => {
                    return Err(Error::new(
                        ErrorKind::InvalidArgument,
                        format!("unknown option: {s}"),
                    ));
                }
                p => paths.push(p.to_string()),
            }
        }
        if need_paths && paths.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "no path given; usage: opensentinel scan <path> [--json] [--quiet]",
            ));
        }
        Ok(paths)
    }

    pub(super) fn scan(args: &[String]) -> Result<i32, Error> {
        let paths = parse_opts(args, true)?;
        let mut cfg = Config::load_default()?;
        for a in args {
            match a.as_str() {
                "--quiet" | "-q" => cfg.quiet = true,
                "--json" => cfg.json = true,
                _ => {}
            }
        }
        let engine = build_engine(&cfg)?;
        let mut results: Vec<FileResult> = Vec::new();
        let t0 = std::time::Instant::now();
        let scan_err = scan_paths(&paths, &cfg, &engine, &mut results);
        let elapsed = t0.elapsed();
        let cancelled = matches!(scan_err, Err(ref e) if e.kind == ErrorKind::Cancelled);
        if let Err(e) = scan_err {
            if !cancelled {
                return Err(e);
            }
            eprintln!("scan cancelled by user; partial results shown below");
        }
        let counts = summary_counts(&results);
        let summary = opensentinel::Summary {
            scanned: counts.clean,
            detected: counts.detected,
            suspicious: counts.suspicious,
            errors: counts.errors,
            skipped: counts.skipped,
            elapsed,
        };
        print_results(&results, &summary, &cfg);
        let rc = if cancelled {
            130
        } else {
            match (counts.detected, counts.suspicious, counts.errors) {
                (0, 0, 0) => 0,
                (_, 0, 0) => 10,
                (_, _, 0) => 11,
                _ => 12,
            }
        };
        Ok(rc)
    }

    fn print_results(results: &[FileResult], summary: &opensentinel::Summary, cfg: &Config) {
        if cfg.json {
            let s = json_summary(results, summary);
            println!("{s}");
            return;
        }
        for r in results {
            match r {
                FileResult::Clean(p) => println!("clean      {}", p.display()),
                FileResult::Detected(d) => println!(
                    "DETECTED   {}  [{}: {}]",
                    d.path.display(),
                    d.severity_str(),
                    d.name
                ),
                FileResult::Suspicious(s) => {
                    println!(
                        "SUSPICIOUS {}  [{}]",
                        s.path.display(),
                        s.reasons.join("; ")
                    )
                }
                FileResult::Error(e) => {
                    println!("error      {}  ({})", e.path.display(), e.message)
                }
                FileResult::Skipped(s) => {
                    if !cfg.quiet {
                        println!("skipped    {s}");
                    }
                }
            }
        }
        println!(
            "Summary: {} clean, {} detected, {} suspicious, {} errors, {} skipped, in {}",
            summary.scanned,
            summary.detected,
            summary.suspicious,
            summary.errors,
            summary.skipped,
            format_duration(summary.elapsed)
        );
        if summary.detected > 0 && !cfg.quiet {
            println!(
                "\nDetections are NOT quarantined automatically.\n\
                 Quarantine manually:  opensentinel quarantine add <path>\n\
                 Inspect:             opensentinel quarantine list"
            );
        }
    }

    fn json_summary(results: &[FileResult], s: &opensentinel::Summary) -> String {
        let items: Vec<String> = results
            .iter()
            .map(|r| match r {
                FileResult::Clean(p) => format!(
                    "{{\"status\":\"clean\",\"path\":{}}}",
                    json_str(&p.to_string_lossy())
                ),
                FileResult::Detected(d) => format!(
                    "{{\"status\":\"detected\",\"path\":{},\"reason\":{},\"severity\":{},\"sha256\":{}}}",
                    json_str(&d.path.to_string_lossy()),
                    json_str(&d.name),
                    json_str(d.severity_str()),
                    json_str(&d.sha256)
                ),
                FileResult::Suspicious(x) => format!(
                    "{{\"status\":\"suspicious\",\"path\":{},\"reasons\":{},\"sha256\":{}}}",
                    json_str(&x.path.to_string_lossy()),
                    json_array(&x.reasons),
                    json_str(&x.sha256)
                ),
                FileResult::Error(e) => format!(
                    "{{\"status\":\"error\",\"path\":{},\"message\":{}}}",
                    json_str(&e.path.to_string_lossy()),
                    json_str(&e.message)
                ),
                FileResult::Skipped(s) => format!(
                    "{{\"status\":\"skipped\",\"reason\":{}}}",
                    json_str(s)
                ),
            })
            .collect();
        format!(
            "{{\"summary\":{{\"clean\":{},\"detected\":{},\"suspicious\":{},\"errors\":{},\"skipped\":{},\"elapsed_secs\":{}}},\"results\":[{}]}}",
            s.scanned,
            s.detected,
            s.suspicious,
            s.errors,
            s.skipped,
            s.elapsed.as_secs_f64(),
            items.join(",")
        )
    }

    fn json_str(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    fn json_array(items: &[String]) -> String {
        let inner: Vec<String> = items.iter().map(|i| json_str(i)).collect();
        format!("[{}]", inner.join(","))
    }

    fn format_duration(d: std::time::Duration) -> String {
        let secs = d.as_secs_f64();
        if secs >= 60.0 {
            format!("{:.1} min", secs / 60.0)
        } else {
            format!("{secs:.2} s")
        }
    }

    pub(super) fn hash(args: &[String]) -> Result<i32, Error> {
        let paths = parse_opts(args, true)?;
        let mut rc = 0;
        for p in &paths {
            match hash_file(p) {
                Ok(h) => println!("{h}  {p}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    rc = 1;
                }
            }
        }
        Ok(rc)
    }

    pub(super) fn quarantine(args: &[String]) -> Result<i32, Error> {
        let sub = args.first().map(String::as_str).unwrap_or("help");
        match sub {
            "list" => {
                let items = opensentinel::list_quarantined()?;
                if items.is_empty() {
                    println!("No quarantined items.");
                }
                for i in &items {
                    println!(
                        "{}  {}  sha256={}  {}",
                        i.id,
                        i.original_path.display(),
                        i.sha256,
                        i.quarantined_at
                    );
                }
                Ok(0)
            }
            "add" => {
                let paths = parse_opts(&args[1..], true)?;
                let mut rc = 0;
                let root = Config::load_default()?.quarantine_dir.clone();
                for p in &paths {
                    match quarantine_add(std::path::Path::new(p), &root) {
                        Ok(entry) => println!(
                            "Quarantined {} as {id} (sha256={hash})",
                            entry.original_path.display(),
                            id = entry.id,
                            hash = entry.sha256
                        ),
                        Err(e) => {
                            eprintln!("error quarantining {p}: {e}");
                            rc = 1;
                        }
                    }
                }
                Ok(rc)
            }
            "restore" => {
                let ids = parse_opts(&args[1..], true)?;
                let root = Config::load_default()?.quarantine_dir.clone();
                let mut rc = 0;
                for id in &ids {
                    match quarantine_restore(id, &root) {
                        Ok(orig) => println!("Restored {id} to {}", orig.display()),
                        Err(e) => {
                            eprintln!("error restoring {id}: {e}");
                            rc = 1;
                        }
                    }
                }
                Ok(rc)
            }
            "purge" => {
                let mut ids: Vec<String> = Vec::new();
                let mut yes = false;
                for a in &args[1..] {
                    if a == "--yes" {
                        yes = true;
                    } else if !a.starts_with('-') {
                        ids.push(a.clone());
                    } else {
                        return Err(Error::new(
                            ErrorKind::InvalidArgument,
                            format!("unknown option for purge: {a}"),
                        ));
                    }
                }
                if ids.is_empty() {
                    return Err(Error::new(
                        ErrorKind::InvalidArgument,
                        "usage: opensentinel quarantine purge <ID>... --yes",
                    ));
                }
                if !yes {
                    eprintln!(
                        "Refusing to permanently delete {} quarantined item(s) without --yes.\n\
                         This cannot be undone. Run again with --yes to confirm.",
                        ids.len()
                    );
                    return Ok(1);
                }
                let root = Config::load_default()?.quarantine_dir.clone();
                match quarantine_purge(&ids, &root) {
                    Ok(()) => println!("Purged {} item(s).", ids.len()),
                    Err(e) => {
                        eprintln!("error purging: {e}");
                        return Ok(1);
                    }
                }
                Ok(0)
            }
            _ => {
                println!(
                    "usage: opensentinel quarantine <command>\n\n\
                     commands:\n  \
                     list                 show quarantined items\n  \
                     add <path>           quarantine a file (the original is moved, not copied)\n  \
                     restore <ID>         restore a quarantined item (refuses to overwrite)\n  \
                     purge <ID>... --yes  permanently delete quarantined items (explicit confirmation)"
                );
                Ok(0)
            }
        }
    }

    pub(super) fn status(_args: &[String]) -> Result<i32, Error> {
        let cfg = Config::load_default()?;
        let sigs = opensentinel::load_signatures(&cfg.signatures_path);
        let q = opensentinel::list_quarantined().unwrap_or_default();
        println!("OpenSentinel v{}", env!("CARGO_PKG_VERSION"));
        println!(
            "signatures: {} (file: {})",
            sigs.len(),
            cfg.signatures_path.display()
        );
        println!("quarantine: {} item(s)", q.len());
        println!("concurrency: {}", cfg.concurrency);
        println!("max file size: {}", human_bytes(cfg.max_file_size));
        println!("heuristics: {}", if cfg.heuristics { "on" } else { "off" });
        Ok(0)
    }

    fn human_bytes(n: u64) -> String {
        const U: [(&str, u64); 5] = [
            ("B", 1),
            ("KiB", 1 << 10),
            ("MiB", 1 << 20),
            ("GiB", 1 << 30),
            ("TiB", 1 << 40),
        ];
        for (u, div) in U {
            if n < 10 * div || u == "TiB" {
                return format!("{n}{u}");
            }
        }
        format!("{n}B")
    }

    pub(super) fn help() -> Result<i32, Error> {
        println!(
            "OpenSentinel v{} — lightweight open-source antivirus scanner\n\
\n\
usage: opensentinel <command> [options]\n\
\n\
commands:\n\
  scan <path>...             scan files or directories recursively\n\
      --json                 machine-readable JSON output\n\
      --quiet, -q            summary only (no per-file lines)\n\
  hash <path>...             print streaming SHA-256 of each path\n\
  quarantine <command>       list | add <path> | restore <ID> | purge <ID>... --yes\n\
  status                     show signature count, quarantine size, settings\n\
  help                       this message\n\
\n\
exit codes: 0 clean · 10 detected · 11 suspicious only · 12 scanned with errors · 1 user error · 130 cancelled\n\
\n\
Note: detections are never quarantined or deleted automatically.\n\
No file is ever executed by OpenSentinel.",
            env!("CARGO_PKG_VERSION")
        );
        Ok(0)
    }
}
