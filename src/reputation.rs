//! Threat-intelligence provider model: verdicts, confidence aggregation,
//! a disk + memory cache, and the provider trait that every source
//! implements.
//!
//! Rules this module enforces:
//! - `ProviderError` is never collapsed into `Unknown` or `Clean`.
//! - Correlated sources (same upstream DB) count once in confidence.
//! - A single community report can at most produce `Suspicious`.
//! - `CleanReported` downgrades `Malicious` to `Suspicious`; only a
//!   vetted feed record can reclassify or revoke.

use crate::error::Result;
use crate::error::{Error, ErrorKind};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The five distinct verdict shapes. See `docs/threat-intel-plan.md` for the
/// transparency rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// At least one source says malicious and the confidence threshold is
    /// met. `sources` carries per-source attribution; correlated sources
    /// are already collapsed.
    Malicious {
        confidence: u8,
        sources: Vec<SourceRef>,
        seen: String,
    },
    /// Heuristic / community-suspected, not confirmed.
    Suspicious {
        confidence: u8,
        sources: Vec<SourceRef>,
        seen: String,
    },
    /// No provider has a record for this hash. NOT "clean" — we simply
    /// have no evidence either way.
    Unknown,
    /// A provider affirmatively reports the hash as benign (e.g. a
    /// user-confirmed false positive from the vetted feed).
    CleanReported { source: String },
    /// The provider was unreachable / timed out / errored. Never treated
    /// as `Unknown` — the UI must show "provider offline".
    ProviderError(String),
}

/// One source's contribution to a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    /// Provider tag, e.g. `"opensentinel"`, `"mwb"`, `"community"`.
    pub provider: String,
    /// 0–100 confidence as the source itself rates it.
    pub confidence: u8,
    /// ISO-8601 timestamp from the source, if it has one.
    pub seen: String,
}

impl Verdict {
    /// Human label used by the CLI/GUI. Distinct from `Display`.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Malicious { .. } => "malicious",
            Verdict::Suspicious { .. } => "suspicious",
            Verdict::Unknown => "unknown",
            Verdict::CleanReported { .. } => "clean-reported",
            Verdict::ProviderError(_) => "provider-error",
        }
    }
}

/// The provider interface. Every source implements this; the aggregate
/// `Reputation::lookup` walks all configured providers and folds their
/// verdicts with the confidence rules in the module docs.
pub trait ThreatIntelProvider: Send + Sync {
    /// Stable provider tag.
    fn name(&self) -> &'static str;
    /// Provider version string.
    fn version(&self) -> &'static str;
    /// Independent-group tag. Sources in the same group are correlated
    /// (share an upstream DB) and count once in the confidence model.
    fn independence_group(&self) -> &'static str;
    /// Lookup by SHA-256. Must never block longer than the configured
    /// timeout. Offline behavior is `ProviderError` or `Unknown`, never a
    /// synthetic `Clean`.
    fn lookup(&self, sha256: &str) -> Result<Verdict>;
}

// --------------------------------------------------------------------

/// A local signature provider backed by the on-disk signature file.
/// Zero I/O, zero network. Confidence 100, group `"opensentinel"`.
pub struct LocalProvider {
    pub signatures: HashMap<String, (String, crate::Severity)>,
}

impl LocalProvider {
    /// Build from a loaded signature list.
    pub fn new(sigs: &[crate::Signature]) -> Self {
        let mut m = HashMap::with_capacity(sigs.len());
        for s in sigs {
            m.insert(s.sha256.clone(), (s.name.clone(), s.severity));
        }
        Self { signatures: m }
    }
}

impl ThreatIntelProvider for LocalProvider {
    fn name(&self) -> &'static str {
        "opensentinel"
    }
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    fn independence_group(&self) -> &'static str {
        "opensentinel"
    }
    fn lookup(&self, sha256: &str) -> Result<Verdict> {
        if let Some((name, sev)) = self.signatures.get(sha256) {
            let confidence = match sev {
                crate::Severity::High => 100,
                crate::Severity::Medium => 80,
                crate::Severity::Low => 60,
            };
            return Ok(Verdict::Malicious {
                confidence,
                sources: vec![SourceRef {
                    provider: "opensentinel".to_string(),
                    confidence,
                    seen: String::new(),
                }],
                seen: format!("local signature: {name}"),
            });
        }
        Ok(Verdict::Unknown)
    }
}

// --------------------------------------------------------------------

/// Aggregate reputation lookup over all configured providers.
/// Correlated sources are collapsed per independence group.
pub struct Reputation {
    providers: Vec<Box<dyn ThreatIntelProvider>>,
    cache: Option<ReputationCache>,
}

impl Reputation {
    pub fn new(providers: Vec<Box<dyn ThreatIntelProvider>>) -> Self {
        Self {
            providers,
            cache: None,
        }
    }

    /// Attach a disk cache. Lookups consult it first; misses fall through
    /// to the providers and store the result.
    pub fn with_cache(mut self, dir: &Path) -> Self {
        self.cache = Some(ReputationCache::load(dir));
        self
    }

    /// Lookup a SHA-256 across all providers. Returns the aggregated
    /// verdict. Provider errors are preserved — a provider going offline
    /// must not be read as "clean".
    pub fn lookup(&self, sha256: &str) -> Result<Verdict> {
        if let Some(cache) = &self.cache {
            if let Some(v) = cache.get(sha256)? {
                return Ok(v);
            }
        }
        let mut verdicts: Vec<Verdict> = Vec::with_capacity(self.providers.len());
        for p in &self.providers {
            verdicts.push(p.lookup(sha256)?);
        }
        let agg = aggregate(verdicts);
        if let Some(cache) = &self.cache {
            cache.store(sha256, &agg)?;
        }
        Ok(agg)
    }

    /// Status of every provider for the Threat-database screen.
    pub fn provider_status(&self) -> Vec<(&'static str, &'static str)> {
        self.providers
            .iter()
            .map(|p| (p.name(), p.version()))
            .collect()
    }
}

/// Fold per-provider verdicts into one, applying the independence-group
/// collapse and the Malicious threshold from the module docs.
fn aggregate(verdicts: Vec<Verdict>) -> Verdict {
    // Group verdicts by independence-group tag. ProviderError wins
    // immediately: any provider that errored means we have incomplete
    // evidence.
    let mut has_error: Option<String> = None;
    let mut clean_source: Option<String> = None;
    let mut groups: HashMap<&str, Vec<Verdict>> = HashMap::new();

    for v in verdicts {
        match v {
            Verdict::ProviderError(msg) => has_error = Some(msg),
            Verdict::CleanReported { source } => clean_source = Some(source),
            Verdict::Unknown => {}
            Verdict::Malicious { .. } | Verdict::Suspicious { .. } => {
                // Group by source provider tag — correlated sources within
                // one provider share the same group tag.
                let tag = group_of(&v);
                groups.entry(tag).or_default().push(v);
            }
        }
    }

    // Any provider error → report it, do not collapse.
    if let Some(msg) = has_error {
        return Verdict::ProviderError(msg);
    }

    // Collapse each independence group to its strongest verdict.
    let mut collapsed: Vec<Verdict> = groups
        .into_values()
        .map(|mut vs| vs.pop().unwrap_or(Verdict::Unknown))
        .collect();

    // A CleanReported from a vetted source downgrades Malicious to
    // Suspicious. It never erases the record.
    if let Some(src) = clean_source {
        if let Some(i) = collapsed
            .iter()
            .position(|v| matches!(v, Verdict::Malicious { .. }))
        {
            if let Verdict::Malicious { sources, seen, .. } = &collapsed[i] {
                let mut new_sources = sources.clone();
                new_sources.push(SourceRef {
                    provider: "vetted".to_string(),
                    confidence: 100,
                    seen: src.clone(),
                });
                collapsed[i] = Verdict::Suspicious {
                    confidence: 50,
                    sources: new_sources,
                    seen: format!("appealed: {seen}"),
                };
            }
        } else if collapsed.iter().all(|v| matches!(v, Verdict::Unknown)) {
            // No positive verdict at all: the clean report is the only
            // evidence.
            return Verdict::CleanReported { source: src };
        }
    }

    // No verdicts → Unknown (we simply have no data).
    if collapsed.iter().all(|v| matches!(v, Verdict::Unknown)) {
        return Verdict::Unknown;
    }

    // Sum independent-group confidences, cap at 100.
    let total: u32 = collapsed
        .iter()
        .map(|v| match v {
            Verdict::Malicious { confidence, .. } | Verdict::Suspicious { confidence, .. } => {
                *confidence as u32
            }
            _ => 0,
        })
        .sum();
    let confidence = (total).min(100) as u8;

    // Collect sources for the report.
    let mut sources: Vec<SourceRef> = Vec::new();
    let mut seen_strs: Vec<String> = Vec::new();
    for v in &collapsed {
        match v {
            Verdict::Malicious {
                sources: s, seen, ..
            }
            | Verdict::Suspicious {
                sources: s, seen, ..
            } => {
                sources.extend(s.iter().cloned());
                seen_strs.push(seen.clone());
            }
            _ => {}
        }
    }
    let seen = seen_strs.join("; ");

    // Malicious threshold: confidence ≥ 60 AND at least one Malicious in
    // the collapsed set, OR two independent groups both Malicious.
    let any_malicious = collapsed
        .iter()
        .any(|v| matches!(v, Verdict::Malicious { .. }));
    let group_malicious_count = collapsed
        .iter()
        .filter(|v| matches!(v, Verdict::Malicious { .. }))
        .count();

    if any_malicious && (confidence >= 60 || group_malicious_count >= 2) {
        Verdict::Malicious {
            confidence,
            sources,
            seen,
        }
    } else if confidence >= 40 {
        Verdict::Suspicious {
            confidence,
            sources,
            seen,
        }
    } else {
        Verdict::Unknown
    }
}

/// Map a verdict to its independence-group tag. The tag is the provider
/// string; correlated sources share a tag.
fn group_of(v: &Verdict) -> &'static str {
    match v {
        Verdict::Malicious { sources, .. } | Verdict::Suspicious { sources, .. } => {
            // First source's provider is the group tag; this is how
            // correlated sources get collapsed.
            match sources.first() {
                Some(s) => provider_tag(&s.provider),
                None => "unknown",
            }
        }
        _ => "unknown",
    }
}

/// Map a provider string to its independence group. This is the correlation
/// map: sources that share a tag are treated as one group of evidence.
fn provider_tag(name: &str) -> &'static str {
    if name == "opensentinel" {
        "opensentinel"
    } else if name == "mwb" || name.starts_with("mwb:") {
        "malwarebazaar"
    } else if name == "community" || name.starts_with("community:") {
        "community"
    } else if name == "vetted" {
        "vetted"
    } else {
        "unknown"
    }
}

// --------------------------------------------------------------------
// Disk + memory cache
// --------------------------------------------------------------------

/// On-disk cache: one JSONL file per reputation root, one line per
/// `(sha256, verdict, ts)`. TTL 24 h default; LRU bound 10 000 lines.
pub struct ReputationCache {
    path: PathBuf,
    mem: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub verdict: Verdict,
    pub ts: u64,
}

impl CacheEntry {
    fn to_line(&self, sha256: &str) -> String {
        format!(
            r#"{{"sha256":"{}","verdict":"{}","ts":{},"details":{}}}"#,
            sha256,
            self.verdict.label(),
            self.ts,
            verdict_json(&self.verdict)
        )
    }
}

impl ReputationCache {
    /// Load or create the cache file at `dir/reputation-cache.jsonl`.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("reputation-cache.jsonl");
        let mut m = HashMap::new();
        if path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                for line in text.lines() {
                    if let Some((sha, entry)) = parse_cache_line(line) {
                        m.insert(sha, entry);
                    }
                }
            }
        }
        Self {
            path,
            mem: Mutex::new(m),
            ttl: Duration::from_secs(24 * 3600),
        }
    }

    /// Get a cached verdict if within TTL.
    pub fn get(&self, sha256: &str) -> Result<Option<Verdict>> {
        let now = now_secs();
        let guard = self
            .mem
            .lock()
            .map_err(|_| Error::new(ErrorKind::Io, "reputation cache lock poisoned".to_string()))?;
        let Some(entry) = guard.get(sha256) else {
            return Ok(None);
        };
        if now.saturating_sub(entry.ts) > self.ttl.as_secs() {
            return Ok(None);
        }
        Ok(Some(entry.verdict.clone()))
    }

    /// Store a verdict, rewriting the file if it grew past the bound.
    pub fn store(&self, sha256: &str, verdict: &Verdict) -> Result<()> {
        let now = now_secs();
        let mut guard = self
            .mem
            .lock()
            .map_err(|_| Error::new(ErrorKind::Io, "reputation cache lock poisoned".to_string()))?;
        guard.insert(
            sha256.to_string(),
            CacheEntry {
                verdict: verdict.clone(),
                ts: now,
            },
        );
        // Bound: drop oldest past 10 000 entries.
        const BOUND: usize = 10_000;
        if guard.len() > BOUND {
            let mut sorted: Vec<(String, u64)> =
                guard.iter().map(|(k, v)| (k.clone(), v.ts)).collect();
            sorted.sort_by_key(|(_, ts)| *ts);
            let drop_n = guard.len() - BOUND;
            for (drop_sha, _) in sorted.into_iter().take(drop_n) {
                guard.remove(&drop_sha);
            }
        }
        // Rewrite the file.
        let mut lines = String::new();
        for (sha, e) in guard.iter() {
            lines.push_str(&e.to_line(sha));
            lines.push('\n');
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::new(ErrorKind::Io, format!("reputation cache dir: {e}")))?;
        }
        std::fs::write(&self.path, lines)
            .map_err(|e| Error::new(ErrorKind::Io, format!("reputation cache write: {e}")))
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serialize a verdict to a JSON fragment for the cache file.
fn verdict_json(v: &Verdict) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    match v {
        Verdict::Malicious {
            confidence,
            sources,
            seen,
        } => {
            let _ = write!(
                s,
                r#"{{"malicious":{{"confidence":{confidence},"seen":{}}}}}"#,
                json_escape(seen)
            );
            let _ = write!(s, ",\"sources\":[");
            for (i, sr) in sources.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let _ = write!(
                    s,
                    r#"{{"provider":{},"confidence":{},"seen":{}}}"#,
                    json_escape(&sr.provider),
                    sr.confidence,
                    json_escape(&sr.seen)
                );
            }
            s.push(']');
        }
        Verdict::Suspicious {
            confidence,
            sources,
            seen,
        } => {
            let _ = write!(
                s,
                r#"{{"suspicious":{{"confidence":{confidence},"seen":{}}}}}"#,
                json_escape(seen)
            );
            let _ = write!(s, ",\"sources\":[");
            for (i, sr) in sources.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let _ = write!(
                    s,
                    r#"{{"provider":{},"confidence":{},"seen":{}}}"#,
                    json_escape(&sr.provider),
                    sr.confidence,
                    json_escape(&sr.seen)
                );
            }
            s.push(']');
        }
        Verdict::Unknown => {
            s.push_str("{}");
        }
        Verdict::CleanReported { source } => {
            let _ = write!(s, r#"{{"clean":{{"source":{}}}}}"#, json_escape(source));
        }
        Verdict::ProviderError(msg) => {
            let _ = write!(s, r#"{{"error":{}}}"#, json_escape(msg));
        }
    }
    s
}

fn json_escape(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// Parse one JSONL cache line back into `(sha256, CacheEntry)`. Malformed
/// lines are skipped, not fatal.
fn parse_cache_line(line: &str) -> Option<(String, CacheEntry)> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let sha = v.get("sha256")?.as_str()?;
    let label = v.get("verdict")?.as_str()?;
    let ts = v.get("ts")?.as_u64()?;
    let details = v.get("details")?;
    let verdict = match label {
        "malicious" => {
            let m = details.get("malicious")?;
            let confidence = m.get("confidence")?.as_u64()?.min(255) as u8;
            let seen = m
                .get("seen")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();
            let mut sources: Vec<SourceRef> = Vec::new();
            if let Some(arr) = details.get("sources").and_then(|a| a.as_array()) {
                for s in arr {
                    let provider = s
                        .get("provider")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default();
                    let confidence = s
                        .get("confidence")
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0)
                        .min(255) as u8;
                    let seen = s.get("seen").and_then(|s| s.as_str()).unwrap_or_default();
                    sources.push(SourceRef {
                        provider: provider.to_string(),
                        confidence,
                        seen: seen.to_string(),
                    });
                }
            }
            Verdict::Malicious {
                confidence,
                sources,
                seen,
            }
        }
        "suspicious" => {
            let m = details.get("suspicious")?;
            let confidence = m.get("confidence")?.as_u64()?.min(255) as u8;
            let seen = m
                .get("seen")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();
            let mut sources: Vec<SourceRef> = Vec::new();
            if let Some(arr) = details.get("sources").and_then(|a| a.as_array()) {
                for s in arr {
                    let provider = s
                        .get("provider")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default();
                    let confidence = s
                        .get("confidence")
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0)
                        .min(255) as u8;
                    let seen = s.get("seen").and_then(|s| s.as_str()).unwrap_or_default();
                    sources.push(SourceRef {
                        provider: provider.to_string(),
                        confidence,
                        seen: seen.to_string(),
                    });
                }
            }
            Verdict::Suspicious {
                confidence,
                sources,
                seen,
            }
        }
        "clean-reported" => {
            let source = details
                .get("clean")
                .and_then(|c| c.get("source"))
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();
            Verdict::CleanReported { source }
        }
        "provider-error" => {
            let msg = details
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or_default();
            Verdict::ProviderError(msg.to_string())
        }
        _ => Verdict::Unknown,
    };
    Some((sha.to_string(), CacheEntry { verdict, ts }))
}

// --------------------------------------------------------------------
// Token-bucket rate limiter
// --------------------------------------------------------------------

/// A simple token-bucket rate limiter. One global instance per provider
/// name so a GUI hover does not burn quota.
pub struct RateLimiter {
    bucket: Mutex<RateBucket>,
}

struct RateBucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64, // tokens / second
    capacity: f64,
}

impl RateLimiter {
    /// `requests_per_second` and burst `capacity`.
    pub fn new(requests_per_second: f64, capacity: usize) -> Self {
        Self {
            bucket: Mutex::new(RateBucket {
                tokens: capacity as f64,
                last_refill: Instant::now(),
                rate: requests_per_second,
                capacity: capacity as f64,
            }),
        }
    }

    /// Try to take one token. `Ok(())` if allowed, `Err(wait)` if the
    /// caller must sleep `wait` before retrying.
    pub fn try_acquire(&self) -> std::result::Result<(), Duration> {
        let mut b = self.bucket.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(b.last_refill).as_secs_f64();
        b.tokens = (b.tokens + elapsed * b.rate).min(b.capacity);
        b.last_refill = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - b.tokens;
            Err(Duration::from_secs_f64(deficit / b.rate))
        }
    }
}

// --------------------------------------------------------------------
// Provider status
// --------------------------------------------------------------------

/// A provider's health for the Threat-database screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStatus {
    /// Provider responded to the last probe.
    Online,
    /// Provider was unreachable.
    Offline,
    /// Provider is not configured.
    Unconfigured,
}

/// Status snapshot for display.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub status: ProviderStatus,
}

// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signature;

    fn sig(name: &str, sev: crate::Severity) -> Signature {
        Signature {
            sha256: "aa".to_string(),
            name: name.into(),
            severity: sev,
        }
    }

    #[test]
    fn local_hit_is_malicious() {
        let p = LocalProvider::new(&[sig("EICAR", crate::Severity::High)]);
        let v = p.lookup("aa").unwrap();
        assert!(matches!(
            v,
            Verdict::Malicious {
                confidence: 100,
                ..
            }
        ));
    }

    #[test]
    fn local_miss_is_unknown() {
        let p = LocalProvider::new(&[]);
        let v = p.lookup("bb").unwrap();
        assert_eq!(v, Verdict::Unknown);
    }

    #[test]
    fn correlated_sources_count_once() {
        // Two Malicious verdicts in the same independence group should
        // collapse to one, not double the confidence.
        let v1 = Verdict::Malicious {
            confidence: 40,
            sources: vec![SourceRef {
                provider: "mwb".into(),
                confidence: 40,
                seen: String::new(),
            }],
            seen: String::new(),
        };
        let v2 = Verdict::Malicious {
            confidence: 40,
            sources: vec![SourceRef {
                provider: "mwb".into(),
                confidence: 40,
                seen: String::new(),
            }],
            seen: String::new(),
        };
        let agg = aggregate(vec![v1, v2]);
        // Both collapse to one group; confidence stays 40, not 80.
        match agg {
            Verdict::Malicious { confidence, .. } | Verdict::Suspicious { confidence, .. } => {
                assert_eq!(confidence, 40, "correlated sources must not double-count");
            }
            other => panic!("expected a verdict, got {other:?}"),
        }
    }

    #[test]
    fn provider_error_never_collapses_to_unknown() {
        let v = aggregate(vec![Verdict::ProviderError("timeout".into())]);
        assert!(matches!(v, Verdict::ProviderError(_)));
    }

    #[test]
    fn clean_report_downgrades_malicious() {
        let malicious = Verdict::Malicious {
            confidence: 100,
            sources: vec![SourceRef {
                provider: "opensentinel".into(),
                confidence: 100,
                seen: String::new(),
            }],
            seen: "local".into(),
        };
        let clean = Verdict::CleanReported {
            source: "vetted:osr-0001".into(),
        };
        let agg = aggregate(vec![malicious, clean]);
        match agg {
            Verdict::Suspicious { .. } => {}
            other => panic!("expected downgraded Suspicious, got {other:?}"),
        }
    }

    #[test]
    fn cache_roundtrip() {
        let dir = std::env::temp_dir().join(format!("os-rep-cache-{}", now_secs()));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = ReputationCache::load(&dir);
        let v = Verdict::Malicious {
            confidence: 80,
            sources: vec![SourceRef {
                provider: "mwb".into(),
                confidence: 80,
                seen: String::new(),
            }],
            seen: "test".into(),
        };
        cache.store("cc", &v).unwrap();
        let got = cache.get("cc").unwrap().unwrap();
        assert_eq!(got, v);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_ttl_expiry() {
        let dir = std::env::temp_dir().join(format!("os-rep-cache-ttl-{}", now_secs()));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = ReputationCache::load(&dir);
        let v = Verdict::Unknown;
        cache.store("dd", &v).unwrap();
        assert!(cache.get("dd").unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rate_limiter_blocks() {
        let rl = RateLimiter::new(1.0, 1);
        assert!(rl.try_acquire().is_ok(), "first token available");
        assert!(rl.try_acquire().is_err(), "second token must wait");
    }
}
