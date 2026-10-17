//! Community report model and client-side validation rules.
//!
//! A community report is a *user-submitted suspicion* keyed by SHA-256.
//! It never ships a rule, never auto-quarantines, and never auto-creates
//! a detection. The server-side validation rules are documented in
//! `docs/reputation.md`; this module implements the client-side checks so
//! tests can run against the documented rules without a live service.

use crate::error::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The four report categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportCategory {
    SuspectedMalware,
    FalsePositive,
    SuspiciousBehavior,
    ConfirmedBenign,
}

/// One user-submitted report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CommunityReport {
    /// SHA-256 the report is about. 64 lowercase hex chars.
    pub sha256: String,
    pub category: ReportCategory,
    /// Pseudonymous user identifier — never a path, username, or email.
    pub user_id: String,
    /// ISO-8601 UTC submission time.
    pub ts: String,
}

/// The client-side view of the community store: a deduplication + rate
/// limit table. Reports from one user at the same hash in the same
/// category within the rate-limit window are dropped.
pub struct CommunityStore {
    /// Per-(user_id, sha256) submission timestamps for the rate limit.
    per_user: HashMap<(String, String), Vec<Instant>>,
    /// Per-hash accepted reports, deduplicated.
    reports: HashMap<String, Vec<CommunityReport>>,
    /// 5 reports / hash / hour per user.
    rate_window: Duration,
    rate_max: u32,
}

impl CommunityStore {
    pub fn new() -> Self {
        Self {
            per_user: HashMap::new(),
            reports: HashMap::new(),
            rate_window: Duration::from_secs(3600),
            rate_max: 5,
        }
    }

    /// Validate and insert a report. Returns the deduplicated/accepted
    /// report, or an error explaining why it was rejected.
    pub fn submit(&mut self, r: CommunityReport) -> Result<CommunityReport> {
        // Basic schema check.
        if r.sha256.len() != 64
            || !r
                .sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "community report: sha256 must be 64 lowercase hex chars".to_string(),
            ));
        }
        if r.user_id.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "community report: user_id must be non-empty (pseudonymous)".to_string(),
            ));
        }
        // No personal data allowed in the report body: reject anything that
        // looks like a path or a username.
        let joined = format!("{:?}{:?}", r.user_id, r.category);
        if joined.contains('\\') || joined.contains('/') || joined.contains('/') {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "community report: no paths or usernames in report fields".to_string(),
            ));
        }

        // Rate limit: 5 / hash / hour per user.
        let key = (r.user_id.clone(), r.sha256.clone());
        let now = Instant::now();
        let bucket = self.per_user.entry(key).or_default();
        let cutoff = now.checked_sub(self.rate_window).unwrap_or(now);
        bucket.retain(|t| *t >= cutoff);
        if (bucket.len() as u32) >= self.rate_max {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "community report: rate limit exceeded (5 per hash per hour)".to_string(),
            ));
        }
        bucket.push(now);

        // Deduplicate: same (sha256, user_id, category) — the rate limit
        // above already bounds the per-user submission rate to 5/hour, so
        // an identical in-window resubmission is redundant.
        let list = self.reports.entry(r.sha256.clone()).or_default();
        if list
            .iter()
            .any(|x| x.user_id == r.user_id && x.category == r.category)
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "community report: duplicate (same hash, user, category)".to_string(),
            ));
        }
        list.push(r.clone());
        Ok(r)
    }

    /// How many community reports back a hash, by category.
    pub fn count_by_category(&self, sha256: &str) -> HashMap<ReportCategory, usize> {
        let mut m: HashMap<ReportCategory, usize> = HashMap::new();
        if let Some(list) = self.reports.get(sha256) {
            for r in list {
                *m.entry(r.category).or_default() += 1;
            }
        }
        m
    }

    /// A community report alone can at most back a `Suspicious` verdict,
    /// never a confirmed detection. This mirrors the rule in
    /// `docs/reputation.md`.
    pub fn community_verdict(&self, sha256: &str) -> crate::reputation::Verdict {
        let counts = self.count_by_category(sha256);
        let suspected = counts
            .get(&ReportCategory::SuspectedMalware)
            .copied()
            .unwrap_or(0);
        let behavior = counts
            .get(&ReportCategory::SuspiciousBehavior)
            .copied()
            .unwrap_or(0);
        let benign = counts
            .get(&ReportCategory::ConfirmedBenign)
            .copied()
            .unwrap_or(0);
        let fp = counts
            .get(&ReportCategory::FalsePositive)
            .copied()
            .unwrap_or(0);

        if benign + fp >= 2 && suspected + behavior < 2 {
            // Two or more users saying "this is a false positive / benign"
            // out-weighs a lone suspicion.
            return crate::reputation::Verdict::CleanReported {
                source: format!("community:confirmed-benign({benign})/fp({fp})"),
            };
        }
        let conf = ((suspected + behavior) * 20).min(80) as u8;
        if suspected + behavior >= 2 {
            return crate::reputation::Verdict::Suspicious {
                confidence: conf,
                sources: vec![crate::reputation::SourceRef {
                    provider: "community".into(),
                    confidence: conf,
                    seen: String::new(),
                }],
                seen: format!("community: {suspected} suspected, {behavior} suspicious-behavior"),
            };
        }
        if suspected + behavior == 1 {
            return crate::reputation::Verdict::Suspicious {
                confidence: 20,
                sources: vec![crate::reputation::SourceRef {
                    provider: "community".into(),
                    confidence: 20,
                    seen: String::new(),
                }],
                seen: "community: single report".into(),
            };
        }
        crate::reputation::Verdict::Unknown
    }
}

impl Default for CommunityStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(user: &str, cat: ReportCategory) -> CommunityReport {
        CommunityReport {
            sha256: "aa".repeat(32),
            category: cat,
            user_id: user.into(),
            ts: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn single_suspected_report_is_suspicious_low_confidence() {
        let mut s = CommunityStore::new();
        s.submit(report("u1", ReportCategory::SuspectedMalware))
            .unwrap();
        let v = s.community_verdict("aa".repeat(32).as_str());
        match v {
            crate::reputation::Verdict::Suspicious { confidence, .. } => {
                assert_eq!(confidence, 20);
            }
            other => panic!("expected Suspicious, got {other:?}"),
        }
    }

    #[test]
    fn community_report_never_produces_malicious() {
        let mut s = CommunityStore::new();
        for i in 0..10 {
            let mut r = report(&format!("user{i}"), ReportCategory::SuspectedMalware);
            r.ts = format!("2026-01-01T00:0{0}:00Z", i % 10);
            s.submit(r).unwrap();
        }
        let v = s.community_verdict("aa".repeat(32).as_str());
        assert!(
            !matches!(v, crate::reputation::Verdict::Malicious { .. }),
            "community evidence alone must never yield a confirmed malicious"
        );
    }

    #[test]
    fn two_benign_reports_downgrade_to_clean_reported() {
        let mut s = CommunityStore::new();
        let mut r1 = report("u1", ReportCategory::ConfirmedBenign);
        r1.ts = "2026-01-01T00:00:00Z".into();
        let mut r2 = report("u2", ReportCategory::ConfirmedBenign);
        r2.ts = "2026-01-01T00:01:00Z".into();
        s.submit(r1).unwrap();
        s.submit(r2).unwrap();
        let v = s.community_verdict("aa".repeat(32).as_str());
        assert!(matches!(
            v,
            crate::reputation::Verdict::CleanReported { .. }
        ));
    }

    #[test]
    fn rate_limit_drops_sixth_report_same_user() {
        let mut s = CommunityStore::new();
        for i in 0..5 {
            let mut r = report(&format!("u{i}"), ReportCategory::SuspectedMalware);
            r.ts = format!("2026-01-01T00:0{i}:00Z");
            s.submit(r).unwrap();
        }
        // Same user 0, same hash, same category, in-window: must be dropped
        // as a duplicate.
        let mut r = report("u0", ReportCategory::SuspectedMalware);
        r.ts = "2026-01-01T00:01:30Z".into();
        let err = s
            .submit(r)
            .expect_err("in-window duplicate must be rejected");
        assert!(err.msg.contains("duplicate"), "got: {}", err.msg);
    }

    #[test]
    fn invalid_hash_rejected() {
        let mut s = CommunityStore::new();
        let mut r = report("u1", ReportCategory::SuspectedMalware);
        r.sha256 = "zz".into();
        assert!(s.submit(r).is_err());
    }

    #[test]
    fn path_like_user_id_rejected() {
        let mut s = CommunityStore::new();
        let r = report("C:\\Users\\alice", ReportCategory::SuspectedMalware);
        assert!(s.submit(r).is_err(), "user_id must not look like a path");
    }
}
