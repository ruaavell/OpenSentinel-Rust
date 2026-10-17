//! Signed, versioned threat-intelligence feed.
//!
//! The feed document is Ed25519-signed by the publishing infrastructure.
//! The client ships only the public verification key. This module verifies
//! the signature, enforces monotonic sequence numbers (rollback/replay
//! guard), checks expiry, and applies updates atomically (write-then-rename)
//! so a crash mid-update never leaves a half-written DB.

use crate::error::{Error, ErrorKind, Result};
use ed25519_zebra::VerificationKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One vetted record inside a feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedRecord {
    /// SHA-256 the record applies to.
    pub sha256: String,
    /// `malicious` or `suspicious`. A vetted record is the only thing that
    /// can ever produce `malicious` in the signed feed.
    pub verdict: String,
    /// 0–100 confidence as the publisher rates it.
    pub confidence: u8,
    /// Attribution: which source(s) this record was vetted from.
    pub sources: Vec<String>,
    /// Stable rule identifier, e.g. `"osr-0007"`. Used by revocation.
    pub rule_id: String,
}

/// A signed, versioned feed document (format v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedVersion {
    pub version: u32,
    /// Strictly-increasing sequence number. Rollback and replay are
    /// rejected when this is not greater than the stored value.
    pub sequence: u64,
    /// ISO-8601 UTC.
    pub issued_at: String,
    /// ISO-8601 UTC. A feed past this is not applied.
    pub expires_at: String,
    pub records: Vec<FeedRecord>,
    /// Rule IDs to remove from the active DB (false-positive correction).
    pub revocations: Vec<String>,
}

/// The on-disk signed feed file: the JSON document plus its signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedFeed {
    pub feed: FeedVersion,
    /// Ed25519 signature over the canonical JSON of `feed`.
    pub signature: Vec<u8>,
}

/// The trusted public key, shipped in the binary. Signing happens on the
/// publishing infrastructure; this key only verifies.
pub const FEED_PUBLIC_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// Decode the bundled public key. The shipped key bytes must decompress to
/// a valid Curve25519 point; `try_into` surfaces that as an error.
fn public_key() -> Result<VerificationKey> {
    VerificationKey::try_from(FEED_PUBLIC_KEY).map_err(|_| {
        Error::new(
            ErrorKind::Signatures,
            "bundled feed public key is not a valid point",
        )
    })
}

/// Canonical JSON of a feed document: deterministic key order so the
/// signature is stable. `serde_json`'s map serialization is insertion-
/// ordered, so we re-serialize through `Value` to get sorted keys.
pub fn canonical_json(feed: &FeedVersion) -> Result<Vec<u8>> {
    let v = serde_json::to_value(feed)
        .map_err(|e| Error::new(ErrorKind::Signatures, format!("feed not serializable: {e}")))?;
    let mut sorted = serde_json::Map::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            sorted.insert(k.clone(), val.clone());
        }
    }
    let val = serde_json::Value::Object(sorted);
    serde_json::to_vec(&val)
        .map_err(|e| Error::new(ErrorKind::Signatures, format!("canonical json: {e}")))
}

/// Verify the signature on a signed feed. Returns the feed on success, an
/// error on a bad signature.
pub fn verify_feed(signed: &SignedFeed) -> Result<FeedVersion> {
    let vk = public_key()?;
    let sig_bytes: [u8; 64] = signed.signature.as_slice().try_into().map_err(|_| {
        Error::new(
            ErrorKind::Signatures,
            "feed signature is not 64 bytes".to_string(),
        )
    })?;
    let sig = ed25519::Signature::from_bytes(&sig_bytes);
    let msg = canonical_json(&signed.feed)?;
    vk.verify(&sig, &msg).map_err(|e| {
        Error::new(
            ErrorKind::Signatures,
            format!("feed signature verification failed: {e}"),
        )
    })?;
    Ok(signed.feed.clone())
}

/// Check that the feed is fresh: version supported, not expired, sequence
/// strictly greater than the last applied sequence. Returns `Ok(true)` when
/// the feed should be applied.
pub fn is_acceptable(feed: &FeedVersion, last_sequence: u64, now_unix: u64) -> Result<bool> {
    if feed.version != 1 {
        return Err(Error::new(
            ErrorKind::Signatures,
            format!("unsupported feed version {}", feed.version),
        ));
    }
    if feed.sequence <= last_sequence {
        // Rollback or replay: keep the last known-good DB.
        return Ok(false);
    }
    let expires = parse_iso8601_to_unix(&feed.expires_at)
        .ok_or_else(|| Error::new(ErrorKind::Signatures, "unparseable expires_at"))?;
    if now_unix >= expires {
        return Ok(false);
    }
    Ok(true)
}

/// Atomically apply a verified feed to the DB directory.
///
/// 1. Serialize to a temp file next to the DB, fsync.
/// 2. `rename` it over the DB path (atomic on POSIX and NTFS).
///
/// The last known-good DB is preserved until the rename succeeds, so a
/// crash mid-update leaves the old DB intact.
pub fn apply_feed(dir: &Path, feed: &FeedVersion, now_unix: u64) -> Result<()> {
    let Some(parent) = dir.parent() else {
        return Err(Error::new(
            ErrorKind::Signatures,
            "no quarantine/feed directory configured".to_string(),
        ));
    };
    std::fs::create_dir_all(parent).map_err(|e| {
        Error::new(
            ErrorKind::Signatures,
            format!("cannot create feed dir: {e}"),
        )
    })?;

    // Read the last-applied sequence from the DB file (if any) to enforce
    // the rollback guard at apply time, not just at verify time.
    let last_seq = read_last_sequence(dir)?;
    if !is_acceptable(feed, last_seq, now_unix)? {
        return Err(Error::new(
            ErrorKind::Signatures,
            "feed rejected: rollback, replay, or expired".to_string(),
        ));
    }

    // Write the applied-sequence marker and the records atomically.
    let body = serde_json::to_vec(&AppliedFeed {
        sequence: feed.sequence,
        records: feed.records.clone(),
        revocations: feed.revocations.clone(),
    })
    .map_err(|e| Error::new(ErrorKind::Signatures, format!("cannot serialize feed: {e}")))?;

    let db_path = dir.join("feed.db");
    let tmp_path = dir.join("feed.db.new");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
            Error::new(
                ErrorKind::Signatures,
                format!("cannot create feed tmp: {e}"),
            )
        })?;
        f.write_all(&body)
            .map_err(|e| Error::new(ErrorKind::Signatures, format!("feed write: {e}")))?;
        f.sync_all()
            .map_err(|e| Error::new(ErrorKind::Signatures, format!("feed fsync: {e}")))?;
    }
    std::fs::rename(&tmp_path, &db_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        Error::new(
            ErrorKind::Signatures,
            format!("atomic feed apply failed: {e}"),
        )
    })?;
    Ok(())
}

/// What the client actually persists after a successful apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedFeed {
    pub sequence: u64,
    pub records: Vec<FeedRecord>,
    pub revocations: Vec<String>,
}

/// Read the last-applied sequence from an existing feed DB.
fn read_last_sequence(dir: &Path) -> Result<u64> {
    let p = dir.join("feed.db");
    if !p.is_file() {
        return Ok(0);
    }
    let text = std::fs::read_to_string(&p)
        .map_err(|e| Error::new(ErrorKind::Signatures, format!("cannot read feed DB: {e}")))?;
    let af: AppliedFeed = serde_json::from_str(&text).map_err(|e| {
        Error::new(
            ErrorKind::Signatures,
            format!("corrupt feed DB (keeping last known-good): {e}"),
        )
    })?;
    Ok(af.sequence)
}

/// Parse a `YYYY-MM-DDTHH:MM:SSZ` timestamp to unix seconds without a date
/// crate. The feed spec uses a strict UTC format.
fn parse_iso8601_to_unix(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, time) = s.split_once('T')?;
    let mut d: [i64; 3] = [0; 3];
    for (i, part) in date.split('-').enumerate() {
        if i < 3 {
            d[i] = part.parse().ok()?;
        }
    }
    let mut t: [i64; 3] = [0; 3];
    for (i, part) in time.trim_end_matches('Z').split(':').enumerate() {
        if i < 3 {
            t[i] = part.parse().ok()?;
        }
    }
    let days = civil_to_unix(d[0], d[1], d[2])?;
    let secs_of_day = (t[0] * 3600 + t[1] * 60 + t[2]).max(0) as u64;
    Some(days + secs_of_day)
}

/// Civil date to unix days (Howard Hinnant's algorithm, public domain).
fn civil_to_unix(y: i64, m: i64, d: i64) -> Option<u64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(seq: u64) -> FeedVersion {
        FeedVersion {
            version: 1,
            sequence: seq,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            records: vec![FeedRecord {
                sha256: "aa".into(),
                verdict: "malicious".into(),
                confidence: 87,
                sources: vec!["mwb".into()],
                rule_id: "osr-0001".into(),
            }],
            revocations: vec![],
        }
    }

    #[test]
    fn rollback_rejected() {
        assert!(
            !is_acceptable(&feed(5), 5, 0).unwrap(),
            "equal seq rejected"
        );
        assert!(
            !is_acceptable(&feed(3), 5, 0).unwrap(),
            "lower seq rejected"
        );
    }

    #[test]
    fn higher_seq_accepted() {
        assert!(is_acceptable(&feed(6), 5, 0).unwrap());
    }

    #[test]
    fn future_expiry_rejected() {
        // expires_at 2027; a 2028 timestamp must reject.
        assert!(
            !is_acceptable(&feed(6), 0, 1_800_000_000).unwrap(),
            "past expiry must reject"
        );
    }

    #[test]
    fn corrupt_db_keeps_last_good() {
        let dir = std::env::temp_dir().join(format!("os-feed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("feed.db"), "{not json").unwrap();
        let r = read_last_sequence(&dir);
        assert!(r.is_err(), "corrupt DB must error, not silently apply");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_then_replay_rejected() {
        let dir = std::env::temp_dir().join(format!("os-feed2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        apply_feed(&dir, &feed(1), 0).unwrap();
        // Re-applying the same sequence must fail the rollback guard.
        assert!(apply_feed(&dir, &feed(1), 0).is_err());
        // A higher sequence succeeds.
        apply_feed(&dir, &feed(2), 0).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let f = feed(1);
        let a = canonical_json(&f).unwrap();
        let b = canonical_json(&f).unwrap();
        assert_eq!(a, b, "canonical form must be stable");
    }
}
