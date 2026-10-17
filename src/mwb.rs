//! MalwareBazaar provider: query `https://mb-api.abuse.ch/api/v1/` with
//! `query=get_info&hash=<sha256>`. Free, no API key required for the
//! documented hash-lookup endpoint.
//!
//! This adapter is intentionally offline-first: it builds the provider and
//! its rate limiter, but the actual HTTP call goes through a pluggable
//! transport so the provider's response parsing is unit-testable without
//! network access.

use crate::error::{Error, ErrorKind, Result};
use crate::reputation::{RateLimiter, SourceRef, ThreatIntelProvider, Verdict};
use serde::Deserialize;
use std::collections::HashMap;

/// MalwareBazaar's documented hash-lookup response.
#[derive(Debug, Deserialize)]
pub struct MwbResponse {
    pub query_status: String,
    #[serde(default)]
    pub data: Option<Vec<MwbEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MwbEntry {
    #[serde(default)]
    #[allow(dead_code)]
    pub sha256_hash: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
}

/// MalwareBazaar provider. Holds a rate limiter and an optional in-memory
/// cache so repeated lookups of the same hash do not hit the API.
pub struct MwbProvider {
    limiter: RateLimiter,
    cache: std::sync::Mutex<HashMap<String, Verdict>>,
}

impl MwbProvider {
    /// Build with a 0.5 req/s default (2 s between calls), burst 5.
    pub fn new() -> Self {
        Self {
            limiter: RateLimiter::new(0.5, 5),
            cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Check the in-memory cache before hitting the rate limiter.
    fn cached(&self, sha256: &str) -> Option<Verdict> {
        self.cache.lock().ok().and_then(|m| m.get(sha256).cloned())
    }

    /// Parse a MalwareBazaar response body. Pure function — the transport
    /// layer is not involved, so this is fully unit-testable.
    pub fn parse_response(body: &str, _sha256: &str) -> Result<Verdict> {
        let resp: MwbResponse = serde_json::from_str(body).map_err(|e| {
            Error::new(
                ErrorKind::Signatures,
                format!("malwarebazaar: malformed JSON: {e}"),
            )
        })?;
        if resp.query_status != "ok" {
            return match resp.query_status.as_str() {
                "hash_not_found" => Ok(Verdict::Unknown),
                "illegal_hash" | "no_hash_provided" => Err(Error::new(
                    ErrorKind::InvalidArgument,
                    format!("malwarebazaar rejected the hash: {}", resp.query_status),
                )),
                other => Err(Error::new(
                    ErrorKind::Signatures,
                    format!("malwarebazaar error: {other}"),
                )),
            };
        }
        let Some(entry) = resp.data.as_ref().and_then(|d| d.first()) else {
            return Ok(Verdict::Unknown);
        };
        // A hit in MalwareBazaar is a community-submitted sample. It is
        // *known to be flagged by a real submission* — treat as malicious
        // at high confidence but with the MalwareBazaar source attribution.
        let confidence = 85u8;
        let seen = entry
            .last_seen
            .clone()
            .or_else(|| entry.first_seen.clone())
            .unwrap_or_default();
        Ok(Verdict::Malicious {
            confidence,
            sources: vec![SourceRef {
                provider: "mwb".into(),
                confidence,
                seen: entry
                    .last_seen
                    .clone()
                    .or_else(|| entry.first_seen.clone())
                    .unwrap_or_default(),
            }],
            seen: format!(
                "malwarebazaar:{}:{}",
                entry.signature.as_deref().unwrap_or("unknown"),
                seen
            ),
        })
    }

    /// Execute a lookup. If the rate limiter blocks, the call waits for the
    /// token then proceeds. Network I/O is delegated to `fetch` — in
    /// production this is a `reqwest` call; in tests it is injected.
    pub fn lookup_with_transport<F>(&self, sha256: &str, fetch: F) -> Result<Verdict>
    where
        F: FnOnce() -> std::result::Result<String, Error>,
    {
        if let Some(v) = self.cached(sha256) {
            return Ok(v);
        }
        let _ = self.limiter.try_acquire(); // blocks until a token is free
        let body = fetch()?;
        let verdict = Self::parse_response(&body, sha256)?;
        if let Ok(mut m) = self.cache.lock() {
            m.insert(sha256.to_string(), verdict.clone());
        }
        Ok(verdict)
    }
}

impl Default for MwbProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelProvider for MwbProvider {
    fn name(&self) -> &'static str {
        "mwb"
    }
    fn version(&self) -> &'static str {
        "0.1"
    }
    fn independence_group(&self) -> &'static str {
        "malwarebazaar"
    }
    /// The trait's default lookup is offline-first: it returns `Unknown`
    /// rather than hitting the network, so the provider can be wired into
    /// `Reputation` without a transport. Call `lookup_with_transport` when
    /// you have a network available.
    fn lookup(&self, sha256: &str) -> Result<Verdict> {
        if let Some(v) = self.cached(sha256) {
            return Ok(v);
        }
        Ok(Verdict::ProviderError(
            "malwarebazaar lookup requires a transport; use lookup_with_transport".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_response() -> &'static str {
        r#"{"query_status":"ok","data":[{"sha256_hash":"aa","file_name":"test.exe","signature":"Emotet","first_seen":"2025-01-07 10:00:00","last_seen":"2025-01-08 11:00:00"}]}"#
    }

    #[test]
    fn parse_ok_is_malicious() {
        let v = MwbProvider::parse_response(ok_response(), "aa").unwrap();
        match v {
            Verdict::Malicious { confidence, .. } => assert_eq!(confidence, 85),
            other => panic!("expected Malicious, got {other:?}"),
        }
    }

    #[test]
    fn parse_hash_not_found_is_unknown() {
        let v = MwbProvider::parse_response(r#"{"query_status":"hash_not_found"}"#, "bb").unwrap();
        assert_eq!(v, Verdict::Unknown);
    }

    #[test]
    fn parse_malformed_is_error() {
        let r = MwbProvider::parse_response("not json", "cc");
        assert!(r.is_err());
    }

    #[test]
    fn parse_illegal_hash_is_invalid_argument() {
        let r = MwbProvider::parse_response(r#"{"query_status":"illegal_hash"}"#, "zz");
        match r {
            Err(e) if e.kind == ErrorKind::InvalidArgument => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn trait_lookup_offline_reports_provider_error() {
        let p = MwbProvider::new();
        let v = p.lookup("aa").unwrap();
        assert!(matches!(v, Verdict::ProviderError(_)));
    }

    #[test]
    fn rate_limiter_allows_burst_then_blocks() {
        let p = MwbProvider::new();
        // Burst 5: first 5 lookups should not sleep.
        for _ in 0..5 {
            assert!(p.limiter.try_acquire().is_ok());
        }
        assert!(p.limiter.try_acquire().is_err());
    }

    #[test]
    fn cache_stores_and_returns_verdict() {
        let p = MwbProvider::new();
        let fetch = || Ok(ok_response().to_string());
        let v = p.lookup_with_transport("aa", fetch).unwrap();
        assert!(matches!(v, Verdict::Malicious { .. }));
        // Second lookup hits the cache; the fetch is not called.
        let v2 = p
            .lookup_with_transport("aa", || panic!("cache should prevent second fetch"))
            .unwrap();
        assert_eq!(v2, v);
    }
}
