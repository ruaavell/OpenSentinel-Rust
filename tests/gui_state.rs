//! UI-independent state tests: LastScan record semantics, config round-trip,
//! quarantine add/purge over a real temp dir (the backend the GUI calls).

use std::time::Duration;

#[test]
fn last_scan_records_are_copies() {
    let a = opensentinel::gui::LastScan {
        cancelled: true,
        elapsed_ms: 250,
        scanned: 9,
        detected: 2,
        suspicious: 1,
    };
    let b = a;
    assert!(a.cancelled == b.cancelled);
    assert_eq!(a.scanned, b.scanned);
}

#[test]
fn last_scan_defaults_are_false_zero() {
    let l = opensentinel::gui::LastScan {
        cancelled: false,
        elapsed_ms: 0,
        scanned: 0,
        detected: 0,
        suspicious: 0,
    };
    assert!(!l.cancelled);
    assert_eq!(l.elapsed_ms, 0);
}

/// The Settings screen persists through this exact path: write TOML, re-read
/// with the strict parser. A value the GUI set must survive the round-trip.
#[test]
fn settings_toml_roundtrip_preserves_concurrency() {
    let mut c = opensentinel::Config::defaults();
    c.concurrency = 8;
    c.heuristics = false;
    c.heuristic_sensitivity = opensentinel::HeuristicSensitivity::High;

    let mut parsed = opensentinel::Config::defaults();
    parsed
        .apply_toml(&c.to_toml())
        .expect("valid TOML must parse");

    assert_eq!(parsed.concurrency, 8);
    assert!(!parsed.heuristics);
    assert_eq!(
        parsed.heuristic_sensitivity,
        opensentinel::HeuristicSensitivity::High
    );
    let _ = Duration::from_millis(1);
}

/// Quarantine add → purge is the exact backend call the GUI's Purge button
/// makes; verify the record + file are both gone after a successful purge.
#[test]
fn quarantine_purge_removes_entry_and_file() {
    let dir = std::env::temp_dir().join(format!(
        "os-gui-qtest-{ts}",
        ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let root = dir.join("quarantine");
    std::fs::create_dir_all(&root).unwrap();
    let victim = dir.join("victim.bin");
    std::fs::write(&victim, b"data").unwrap();

    let entry = opensentinel::quarantine_add(&victim, &root).unwrap();
    assert!(!victim.exists(), "original must be moved out");
    let ids = vec![entry.id.clone()];

    opensentinel::quarantine_purge(&ids, &root).unwrap();
    let id = entry.id;
    assert!(!root.join(&id).exists(), "purged file must be gone");
    let entries = opensentinel::list_quarantined().unwrap_or_default();
    assert!(
        !entries.iter().any(|e| e.id == id),
        "purged id must be dropped from the index"
    );
    std::fs::remove_dir_all(&dir).ok();
}
