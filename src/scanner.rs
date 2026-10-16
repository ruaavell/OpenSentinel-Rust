//! File scanning: recursive directory traversal, cancellation, size limits,
//! exclusion rules, symlink-loop protection.
//!
//! Concurrency is intentionally single-threaded in this slice to keep the
//! code easy to review; the queue shape already supports a worker pool when
//! one is added.

use crate::config::Config;
use crate::detection::{Classification, Detection, Engine};
use crate::error::{Error, ErrorKind};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Per-file scan outcome.
pub enum FileResult {
    /// No enabled engine fired. Not a safety guarantee — the file simply had
    /// no matching detection.
    Clean(PathBuf),
    /// A signature definitively matched.
    Detected(Detection),
    /// Heuristics raised explainable warnings needing human review.
    Suspicious(Detection),
    /// The file could not be scanned reliably.
    Error(FileError),
    /// Intentionally excluded from scanning.
    Skipped(String),
}

pub struct FileError {
    pub path: PathBuf,
    pub message: String,
}

/// Aggregate counters for the final summary line.
pub struct Summary {
    pub scanned: usize,
    pub detected: usize,
    pub suspicious: usize,
    pub errors: usize,
    pub skipped: usize,
    pub elapsed: Duration,
}

/// Streaming SHA-256 of an opened file. Bounded memory: 8 KiB buffer.
pub fn hash_stream(file: &std::fs::File) -> Result<String, Error> {
    let mut h = Sha256::new();
    let mut reader = std::io::BufReader::with_capacity(8192, file);
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let digest = h.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Hash an arbitrary path (used by the `hash` subcommand).
pub fn hash_file(path: &str) -> Result<String, Error> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| Error::new(ErrorKind::Io, format!("{path}: {e}")))?;
    let meta = f
        .metadata()
        .map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
    if !meta.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            format!("{path} is not a regular file"),
        ));
    }
    hash_stream(&f)
}

/// Cooperative cancellation flag; set by SIGINT (POSIX) or manually.
pub struct CancelToken {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self {
            flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    /// Install a best-effort SIGINT handler (POSIX) that cancels this token
    /// within ~25 ms. No-op on other platforms.
    pub fn on_sigint(&self) {
        #[cfg(unix)]
        {
            let flag = std::sync::Arc::clone(&self.flag);
            std::thread::spawn(move || {
                let _ = signal_hook::register(signal_hook::consts::signal::SIGINT, move || {
                    flag.store(true, Ordering::SeqCst);
                });
            });
            // ponytail: signal-hook only flips its own flag on the signal
            // thread; a 25 ms poller mirrors it into this token.
            let this_flag = std::sync::Arc::clone(&self.flag);
            std::thread::spawn(move || loop {
                if this_flag.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            });
        }
        #[cfg(not(unix))]
        {
            let _ = self;
        }
    }
    #[allow(dead_code)]
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan a list of paths (files or directories) recursively. Results are
/// appended to `results` in encounter order. Cancellation stops the walk and
/// returns `ErrorKind::Cancelled` with whatever was collected so far.
pub fn scan_paths(
    paths: &[String],
    cfg: &Config,
    engine: &Engine,
    results: &mut Vec<FileResult>,
) -> Result<(), Error> {
    let cancel = CancelToken::new();
    cancel.on_sigint();

    for p in paths {
        let pb = PathBuf::from(p);
        match std::fs::symlink_metadata(&pb) {
            Ok(m) => {
                let ft = m.file_type();
                if ft.is_dir() {
                    walk_dir(&pb, cfg, engine, &cancel, results);
                } else if ft.is_file() {
                    classify_file(&pb, cfg, engine, &cancel, results);
                } else {
                    results.push(FileResult::Skipped(
                        "special file (not a regular file)".into(),
                    ));
                }
            }
            Err(e) => {
                let msg = if e.kind() == std::io::ErrorKind::NotFound {
                    "path does not exist".to_string()
                } else {
                    e.to_string()
                };
                results.push(FileResult::Error(FileError {
                    path: pb,
                    message: msg,
                }));
            }
        }
        if cancel.is_cancelled() {
            return Err(Error::new(ErrorKind::Cancelled, "scan cancelled by user"));
        }
    }
    Ok(())
}

/// Best-effort SIGINT install on POSIX; no-op on Windows in this slice.
fn _unused_install_sigint(cancel: &CancelToken) {
    #[cfg(unix)]
    {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f2 = std::sync::Arc::clone(&flag);
        std::thread::spawn(move || {
            let _ = signal_hook::register(signal_hook::consts::signal::SIGINT, move || {
                f2.store(true, Ordering::SeqCst);
            });
        });
        let outer = cancel;
        std::thread::spawn(move || loop {
            if flag.load(Ordering::SeqCst) {
                outer.cancel();
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        });
        // ponytail: 25 ms polling bridge from signal-hook to CancelToken.
    }
    #[cfg(not(unix))]
    {
        let _ = cancel;
    }
}

fn walk_dir(
    dir: &Path,
    cfg: &Config,
    engine: &Engine,
    cancel: &CancelToken,
    results: &mut Vec<FileResult>,
) {
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    let mut seen: HashSet<u64> = inode_set(dir);
    while let Some(d) = stack.pop() {
        if cancel.is_cancelled() {
            return;
        }
        if is_excluded(&d, cfg) {
            results.push(FileResult::Skipped("excluded directory".into()));
            continue;
        }
        let rd = match std::fs::read_dir(&d) {
            Ok(r) => r,
            Err(e) => {
                results.push(FileResult::Error(FileError {
                    path: d.clone(),
                    message: e.to_string(),
                }));
                continue;
            }
        };
        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    results.push(FileResult::Error(FileError {
                        path: d.join("(unreadable entry)"),
                        message: e.to_string(),
                    }));
                    continue;
                }
            };
            let p = entry.path();
            let m = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    results.push(FileResult::Error(FileError {
                        path: p.clone(),
                        message: e.to_string(),
                    }));
                    continue;
                }
            };
            if m.is_dir() {
                // Symlink-loop guard (POSIX): skip inodes already on the
                // stack.
                if let Some(ino) = inode_of(&m) {
                    if !seen.insert(ino) {
                        results.push(FileResult::Skipped("symlink loop".into()));
                        continue;
                    }
                }
                stack.push(p);
            } else if m.is_file() {
                classify_file(&p, cfg, engine, cancel, results);
            } else {
                results.push(FileResult::Skipped(
                    "special file (device, pipe, etc.)".into(),
                ));
            }
        }
    }
}

fn inode_set(p: &Path) -> HashSet<u64> {
    let m = match p.symlink_metadata() {
        Ok(m) => m,
        Err(_) => return HashSet::new(),
    };
    inode_of(&m).into_iter().collect()
}

fn inode_of(m: &std::fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(m.ino())
    }
    #[cfg(not(unix))]
    {
        // No public `ino()` in the stable Windows API; revisit depth is
        // still bounded by the stack, and user-directory symlink loops are
        // uncommon. No inode guard on this platform.
        let _ = m;
        None
    }
}

fn is_excluded(p: &Path, cfg: &Config) -> bool {
    cfg.excluded.iter().any(|x| p.starts_with(x))
}

fn classify_file(
    p: &Path,
    cfg: &Config,
    engine: &Engine,
    cancel: &CancelToken,
    results: &mut Vec<FileResult>,
) {
    if cancel.is_cancelled() {
        results.push(FileResult::Skipped("cancelled".into()));
        return;
    }
    if is_excluded(p, cfg) {
        results.push(FileResult::Skipped("excluded by config".into()));
        return;
    }
    let file = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(e) => {
            results.push(FileResult::Error(FileError {
                path: p.to_path_buf(),
                message: e.to_string(),
            }));
            return;
        }
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            results.push(FileResult::Error(FileError {
                path: p.to_path_buf(),
                message: e.to_string(),
            }));
            return;
        }
    };
    let size = meta.len();
    if size > cfg.max_file_size {
        results.push(FileResult::Skipped(format!(
            "size {size} exceeds max_file_size"
        )));
        return;
    }
    match engine.classify(p, &file, &meta) {
        Ok(Some(c)) => {
            let det = c.to_detection(p);
            match c {
                Classification::Detected { .. } => results.push(FileResult::Detected(det)),
                Classification::Suspicious { .. } => results.push(FileResult::Suspicious(det)),
            }
        }
        Ok(None) => results.push(FileResult::Clean(p.to_path_buf())),
        Err(e) => results.push(FileResult::Error(FileError {
            path: p.to_path_buf(),
            message: e.to_string(),
        })),
    }
}

/// Re-read a hash to detect concurrent modification between detection and
/// quarantine. Returns None if the file vanished.
pub fn rehash(path: &Path) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    hash_stream(&f).ok()
}
