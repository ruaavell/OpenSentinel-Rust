//! Integration tests against the real library: streaming SHA-256 vectors,
//! signature round-trip, quarantine move/restore/collision lifecycle,
//! non-ASCII names, EICAR artifact.
//!
//! All tests run in isolated temp directories and never touch user files.
//! The EICAR string is the standard, non-malicious AV test artifact.

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nonce = rand::random::<u64>();
    p.push(format!("opensentinel-it-{tag}-{nonce:016x}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn root(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = tmpdir(tag);
    let q = dir.join("quarantine");
    (dir, q)
}

#[test]
fn empty_file_has_known_sha256() {
    let (dir, _) = root("empty");
    let f = dir.join("zero.bin");
    std::fs::write(&f, b"").unwrap();
    let h = opensentinel::hash_file(f.to_str().unwrap()).unwrap();
    assert_eq!(
        h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 of the empty string is a known constant"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ascii_known_vector() {
    // SHA-256("abc") is a published NIST test vector.
    let (dir, _) = root("abc");
    let f = dir.join("abc.txt");
    std::fs::write(&f, b"abc").unwrap();
    let h = opensentinel::hash_file(f.to_str().unwrap()).unwrap();
    assert_eq!(
        h,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn non_ascii_filename_scans_cleanly() {
    let (dir, _) = root("uni");
    let f = dir.join("übersäße-ファイル.txt");
    std::fs::write(&f, b"harmless").unwrap();
    let h = opensentinel::hash_file(f.to_str().unwrap()).unwrap();
    assert_eq!(h.len(), 64);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn eicar_artifact_is_detected_by_planted_signature() {
    // The classic EICAR AV test string. We plant its hash in a local DB to
    // prove end-to-end signature matching without shipping real malware.
    let (dir, _) = root("eicar");
    let f = dir.join("eicar.txt");
    std::fs::write(&f, b"X5O!P%@in[AV&G^{(}c},$1P}?").unwrap();
    let real_hash = opensentinel::hash_file(f.to_str().unwrap()).unwrap();

    let sig = dir.join("signatures.json");
    let db = format!(
        r#"{{"version":1,"entries":[{{"sha256":"{}","name":"EicarTest","severity":"high"}}]}}"#,
        real_hash
    );
    std::fs::write(&sig, db).unwrap();

    let cfg = {
        let mut c = opensentinel::Config::defaults();
        c.signatures_path = sig.clone();
        c.heuristics = false;
        c
    };
    let engine = opensentinel::build_engine(&cfg).unwrap();
    let file = std::fs::File::open(&f).unwrap();
    let meta = file.metadata().unwrap();
    let c = engine
        .classify(&f, &file, &meta)
        .unwrap()
        .expect("planted signature must match");
    assert!(matches!(c, opensentinel::Classification::Detected { .. }));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn clean_file_reports_no_detection_not_safety() {
    let (dir, _) = root("clean");
    let f = dir.join("ok.txt");
    std::fs::write(&f, b"nothing wrong here").unwrap();
    let sig = dir.join("signatures.json");
    std::fs::write(&sig, r#"{"version":1,"entries":[]}"#).unwrap();
    let cfg = {
        let mut c = opensentinel::Config::defaults();
        c.signatures_path = sig;
        c.heuristics = false;
        c
    };
    let engine = opensentinel::build_engine(&cfg).unwrap();
    let file = std::fs::File::open(&f).unwrap();
    let meta = file.metadata().unwrap();
    let none = engine.classify(&f, &file, &meta).unwrap();
    assert!(
        none.is_none(),
        "no signature + no heuristics = no detection"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn quarantine_add_moves_original_and_records_hash() {
    let (dir, q) = root("q-add");
    let original = dir.join("victim.bin");
    std::fs::write(&original, b"precious data").unwrap();
    let hash_before = opensentinel::hash_file(original.to_str().unwrap()).unwrap();

    let entry = opensentinel::quarantine_add(&original, &q).unwrap();
    assert!(!original.exists(), "original must be moved, not copied");
    assert_eq!(entry.sha256, hash_before);

    // Content must survive the move intact.
    let stored = q.join(&entry.id);
    assert!(stored.is_file());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn quarantine_restore_roundtrip_preserves_content() {
    let (dir, q) = root("q-restore");
    let original = dir.join("victim.bin");
    std::fs::write(&original, b"precious data").unwrap();
    let hash_before = opensentinel::hash_file(original.to_str().unwrap()).unwrap();

    let entry = opensentinel::quarantine_add(&original, &q).unwrap();
    let restored = opensentinel::quarantine_restore(&entry.id, &q).unwrap();
    let restored_hash = opensentinel::hash_file(restored.to_str().unwrap()).unwrap();
    assert_eq!(
        restored_hash, hash_before,
        "restored content must be intact"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn quarantine_restore_refuses_to_overwrite_existing() {
    let (dir, q) = root("q-collide");
    // Pre-create the destination the quarantined entry will restore to.
    let dest = dir.join("collide.txt");
    std::fs::write(&dest, b"do not touch me").unwrap();
    let hash_dest = opensentinel::hash_file(dest.to_str().unwrap()).unwrap();

    // Quarantine a payload; its entry records the temp path as original.
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"payload").unwrap();
    let entry = opensentinel::quarantine_add(&payload, &q).unwrap();

    // Overwrite the index entry's original_path to collide with `dest`,
    // simulating an entry that points at a live file.
    let line = format!(
        r#"{{"id":"{}","original_path":"{}","sha256":"{}","quarantined_at":"2026-01-01T00:00:00Z"}}"#,
        entry.id,
        dest.to_string_lossy(),
        entry.sha256
    );
    let index = q.join("index.jsonl");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&index)
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();
    }

    let restored = opensentinel::quarantine_restore(&entry.id, &q).unwrap();
    assert_ne!(restored, dest, "must not overwrite the existing file");
    // Original destination must be byte-for-byte unchanged.
    assert_eq!(
        opensentinel::hash_file(dest.to_str().unwrap()).unwrap(),
        hash_dest
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn quarantine_purge_requires_explicit_ids() {
    let (dir, q) = root("q-purge");
    let f = dir.join("x.bin");
    std::fs::write(&f, b"x").unwrap();
    let entry = opensentinel::quarantine_add(&f, &q).unwrap();
    // Purging a non-existent id fails cleanly.
    let missing = opensentinel::quarantine_purge(&["no-such-id".to_string()], &q);
    assert!(missing.is_err());
    // Purging the real id succeeds and removes the file.
    let ids = vec![entry.id.clone()];
    opensentinel::quarantine_purge(&ids, &q).unwrap();
    assert!(!q.join(&entry.id).exists());
    std::fs::remove_dir_all(&dir).ok();
}
