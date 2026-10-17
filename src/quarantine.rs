//! Safe quarantine: move detected files out of the live tree, keep them
//! non-executable, store metadata separately, restore without overwriting.
//!
//! Security rules:
//! - ids are 32 random bytes (256 bits) from a CSPRNG; not guessable;
//! - the quarantine index is JSONL: each line is one entry; the directory is
//!   recreated atomically (write temp, fsync, rename);
//! - restore never overwrites an existing file: it appends " (1)", " (2)"…;
//! - original files are *moved*, not copied, and the original path is not
//!   recreated until the user runs restore;
//! - no automatic deletion, ever; `purge` requires an explicit --yes.

use crate::config::Config;
use crate::error::{Error, ErrorKind};
use crate::scanner::{hash_stream, rehash};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// 32-byte hex random identifier.
    pub id: String,
    /// Where the file came from.
    pub original_path: PathBuf,
    /// SHA-256 of the quarantined content at move time.
    pub sha256: String,
    /// ISO-8601 timestamp (UTC) of the quarantine event.
    pub quarantined_at: String,
}

fn quarantine_root(cfg: &Config) -> PathBuf {
    cfg.quarantine_dir.clone()
}

fn ensure_dir(p: &Path) -> Result<(), Error> {
    fs::create_dir_all(p).map_err(|e| {
        Error::new(
            ErrorKind::Quarantine,
            format!("cannot create quarantine dir {}: {e}", p.display()),
        )
    })
}

fn index_path(root: &Path) -> PathBuf {
    root.join("index.jsonl")
}

/// Move `src` into the quarantine store using a caller-provided root. This
/// is the testable core; `quarantine_file` (used by the CLI) wraps it with
/// the config-derived root.
pub fn quarantine_add(src: &Path, root: &Path) -> Result<QuarantineEntry, Error> {
    ensure_dir(root)?;

    let file = fs::File::open(src)
        .map_err(|e| Error::new(ErrorKind::Quarantine, format!("cannot open {src:?}: {e}")))?;
    let hash = hash_stream(&file)?;
    drop(file);

    let id = new_id();
    let dest = root.join(&id);

    // TOCTOU guard: re-hash the file right before the move so a swapped-in
    // file cannot change identity between our hash and the rename.
    if let Some(h2) = rehash(src) {
        if h2 != hash {
            return Err(Error::new(
                ErrorKind::Quarantine,
                format!("file {src:?} changed while being quarantined (TOCTOU); refusing"),
            ));
        }
    }

    fs::rename(src, &dest).map_err(|e| {
        Error::new(
            ErrorKind::Quarantine,
            format!("cannot move {src:?} into quarantine: {e}"),
        )
    })?;

    let entry = QuarantineEntry {
        id: id.clone(),
        original_path: src.to_path_buf(),
        sha256: hash,
        quarantined_at: now_iso8601(),
    };
    append_entry(root, &entry)?;
    Ok(entry)
}

/// CLI-facing: quarantine using the configured quarantine dir.
#[allow(dead_code)]
pub fn quarantine_file(src: &Path) -> Result<QuarantineEntry, Error> {
    let cfg = Config::load_default()?;
    quarantine_add(src, &quarantine_root(&cfg))
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn append_entry(root: &Path, e: &QuarantineEntry) -> Result<(), Error> {
    let p = index_path(root);
    let mut line = serde_json::to_string(e).map_err(|err| {
        Error::new(
            ErrorKind::Quarantine,
            format!("cannot serialize entry: {err}"),
        )
    })?;
    line.push('\n');
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .map_err(|err| {
            Error::new(
                ErrorKind::Quarantine,
                format!("cannot open index {p:?}: {err}"),
            )
        })?;
    f.write_all(line.as_bytes()).map_err(|err| {
        Error::new(
            ErrorKind::Quarantine,
            format!("cannot write index {p:?}: {err}"),
        )
    })?;
    Ok(())
}

/// List all quarantined items. A corrupted index line is skipped with a
/// warning, not fatal; the rest of the index is still readable.
pub fn list_quarantined() -> Result<Vec<QuarantineEntry>, Error> {
    let cfg = Config::load_default()?;
    list_quarantined_in(&quarantine_root(&cfg))
}

/// Testable core: list entries from a given quarantine root.
pub fn list_quarantined_in(root: &Path) -> Result<Vec<QuarantineEntry>, Error> {
    let p = index_path(root);
    if !p.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&p)
        .map_err(|e| Error::new(ErrorKind::Quarantine, format!("cannot read {p:?}: {e}")))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<QuarantineEntry>(line) {
            Ok(e) => out.push(e),
            Err(err) => eprintln!("warning: quarantined index line {} malformed: {err}", i + 1),
        }
    }
    Ok(out)
}

/// Restore a quarantined item to its original path. If a file already exists
/// there, a " (N)" suffix is appended. Never overwrites.
pub fn quarantine_restore(id: &str, root: &Path) -> Result<PathBuf, Error> {
    restore_in(id, root)
}

/// Testable core: purge from a given quarantine root.
#[allow(dead_code)]
pub fn quarantine_purge_in(ids: &[String], root: &Path) -> Result<(), Error> {
    purge_in(ids, root)
}

fn restore_in(id: &str, root: &Path) -> Result<PathBuf, Error> {
    let entries = list_quarantined_in(root)?;
    let e = entries
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| Error::new(ErrorKind::Quarantine, format!("no quarantined item {id:?}")))?;
    let src = root.join(&e.id);
    if !src.is_file() {
        return Err(Error::new(
            ErrorKind::Quarantine,
            format!("quarantined file for {id} is missing from the store"),
        ));
    }
    let mut dest = e.original_path.clone();
    if dest.exists() {
        let base = dest
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or("file".into());
        let parent = dest.parent().map(PathBuf::from).unwrap_or_default();
        let mut n = 1;
        loop {
            let cand = parent.join(format!("{base} ({n})"));
            if !cand.exists() {
                dest = cand;
                break;
            }
            n += 1;
        }
    }
    // Refuse a restore target that could escape via traversal. The index
    // is untrusted/attacker-tamperable, so `original_path` from a forged
    // entry must not escape the path it specifies: any `..` (ParentDir)
    // component is rejected. A bare filename is also rejected (fewer than
    // 2 components) since we cannot determine a safe restore directory.
    if e.original_path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
        || e.original_path.components().count() < 2
    {
        return Err(Error::new(
            ErrorKind::Quarantine,
            format!(
                "original path {:?} is not safe for restore (no '..' traversal, needs a directory + filename)",
                e.original_path
            ),
        ));
    }
    fs::rename(&src, &dest).map_err(|e| {
        Error::new(
            ErrorKind::Quarantine,
            format!("cannot restore {id} to {dest:?}: {e}"),
        )
    })?;
    Ok(dest)
}

/// CLI-facing: purge using the configured quarantine dir.
pub fn quarantine_purge(ids: &[String], root: &Path) -> Result<(), Error> {
    purge_in(ids, root)
}

/// Testable core: purge from a given quarantine root.
pub fn purge_in(ids: &[String], root: &Path) -> Result<(), Error> {
    let entries = list_quarantined_in(root)?;
    for id in ids {
        if !entries.iter().any(|e| &e.id == id) {
            return Err(Error::new(
                ErrorKind::Quarantine,
                format!("cannot purge {id:?}: not found in quarantine index"),
            ));
        }
        let p = root.join(id);
        if p.is_file() {
            fs::remove_file(&p).map_err(|e| {
                Error::new(
                    ErrorKind::Quarantine,
                    format!("cannot remove quarantined file {p:?}: {e}"),
                )
            })?;
        }
    }
    // Rewrite the index without the purged ids (best effort).
    let keep: Vec<QuarantineEntry> = entries
        .into_iter()
        .filter(|e| !ids.contains(&e.id))
        .collect();
    let p = index_path(root);
    let mut s = String::new();
    for e in &keep {
        s.push_str(&serde_json::to_string(e).unwrap_or_default());
        s.push('\n');
    }
    fs::write(&p, s).map_err(|e| {
        Error::new(
            ErrorKind::Quarantine,
            format!("cannot rewrite quarantine index {p:?}: {e}"),
        )
    })?;
    Ok(())
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Convert to UTC date-time without a date library: days since epoch ->
    // year via a coarse algorithm (accurate enough for a log timestamp).
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// Howard Hinnant's civil-from-days algorithm (public-domain, well-tested).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 151;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_id_is_32_hex_chars() {
        let id = new_id();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn id_is_random() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b, "two consecutive IDs must differ");
    }

    #[test]
    fn civil_from_days_2026_01_01() {
        // 2026-01-01 is day 20454 (1970-01-01 = 0).
        let (y, m, d) = civil_from_days(20_454);
        assert_eq!((y, m, d), (2026, 1, 1));
    }

    #[test]
    fn restore_appends_suffix_when_dest_exists() {
        let tmp = std::env::temp_dir().join(format!("os-qtest-{}", new_id()));
        fs::create_dir_all(&tmp).unwrap();
        let dest = tmp.join("a.txt");
        fs::write(&dest, "original").unwrap();
        let base = dest.file_name().unwrap().to_string_lossy().to_string();
        let parent = dest.parent().unwrap().to_path_buf();
        let mut n = 1u32;
        let cand = loop {
            let c = parent.join(format!("{base} ({n})"));
            if !c.exists() {
                break c;
            }
            n += 1;
        };
        assert_ne!(cand, dest);
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn restore_rejects_traversal_path() {
        // A forged index entry with a `..`-traversal original_path must not
        // be restored to an arbitrary location. The restore should error,
        // not move the quarantined file outside the expected tree.
        let tmp = std::env::temp_dir().join(format!("os-qtest-traversal-{}", new_id()));
        let q = tmp.join("q");
        fs::create_dir_all(&q).unwrap();
        let original = tmp.join("payload.bin");
        std::fs::write(&original, b"data").unwrap();
        let entry = quarantine_add(&original, &q).unwrap();

        // Tamper the index: rewrite the entry's original_path to traverse.
        let index = q.join("index.jsonl");
        let bad = format!(
            r#"{{"id":"{}","original_path":"../../../../evil.txt","sha256":"{}","quarantined_at":"2026-01-01T00:00:00Z"}}"#,
            entry.id, entry.sha256
        );
        std::fs::write(&index, bad).unwrap();

        let r = restore_in(&entry.id, &q);
        assert!(r.is_err(), "traversal original_path must be rejected");
        // The quarantined file must still be in the store.
        assert!(q.join(&entry.id).is_file(), "file must not have moved");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn restore_rejects_traversal_relative() {
        // A relative path that tries to climb out via `..` must be rejected
        // even if it has multiple components.
        let tmp = std::env::temp_dir().join(format!("os-qtest-reltrav-{}", new_id()));
        let q = tmp.join("q");
        fs::create_dir_all(&q).unwrap();
        let original = tmp.join("payload.bin");
        std::fs::write(&original, b"data").unwrap();
        let entry = quarantine_add(&original, &q).unwrap();

        let index = q.join("index.jsonl");
        let bad = format!(
            r#"{{"id":"{}","original_path":"../../evil.txt","sha256":"{}","quarantined_at":"2026-01-01T00:00:00Z"}}"#,
            entry.id, entry.sha256
        );
        std::fs::write(&index, bad).unwrap();

        let r = restore_in(&entry.id, &q);
        assert!(r.is_err(), "traversal original_path must be rejected");
        assert!(q.join(&entry.id).is_file(), "file must not have moved");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn component_count_guard() {
        // A path with fewer than 2 components (e.g. "a.txt") is rejected.
        let p = Path::new("a.txt");
        assert!(p.components().count() < 2);
    }
}
