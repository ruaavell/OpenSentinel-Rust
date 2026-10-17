# OpenSentinel — threat-intelligence architecture & audit

## 1. Current-state audit

Existing modules:

| Area | File | What's there | What's missing |
|---|---|---|---|
| Signature DB | `src/detection.rs` | 64-BiB, version-1 hash signatures; parse-time validation | No external provider; no update channel |
| Heuristics | `src/detection.rs` | MZ / `.scr` / entropy / bat-marker, sensitivity-capped at `Suspicious` | No YARA |
| Scanner | `src/scanner.rs` | Walk + streaming SHA-256 + cancel | No per-file reputation hook |
| Quarantine | `src/quarantine.rs` | Move + index + no-overwrite restore + `--yes` purge | No evidence fields in index |
| CLI / GUI | `src/main.rs`, `src/gui/` | scan / hash / quarantine / status / settings | No provider status screen |
| Config | `src/config.rs` | TOML-subset parser, safe defaults | No provider settings |

## 2. Threat-intelligence provider model

New module `src/reputation.rs`:

```rust
/// One provider's verdict about a single SHA-256.
pub enum Verdict {
    /// At least one source says malicious. `sources` carries per-source
    /// attribution; correlated sources are collapsed.
    Malicious { confidence: u8, sources: Vec<SourceRef>, seen: String },
    /// Heuristic / community-suspected, not confirmed.
    Suspicious { confidence: u8, sources: Vec<SourceRef>, seen: String },
    /// No provider has a record for this hash. NOT "clean" — we simply have
    /// no evidence either way.
    Unknown,
    /// A provider affirmatively reports the hash as benign (e.g. a
    /// user-confirmed false positive in the community feed).
    CleanReported { source: String },
    /// The provider was unreachable / timed out / errored. Must never be
    /// collapsed into `Unknown`.
    ProviderError(String),
}

pub struct SourceRef {
    pub provider: &'static str,
    pub confidence: u8,  // 0–100
    pub seen: String,    // ISO-8601 from the source, if it has one
}
```

### Confidence rules (transparent, documented in `docs/reputation.md`)

- `Malicious` starts at the provider's own confidence.
- Each *independent* corroborating source adds its confidence; correlated
  sources (same upstream database) count once. Independence is declared in
  the provider's `independence_group()` — MalwareBazaar and VirusTotal are
  in different groups; a local community record reporting the same hash
  belongs to the community group.
- `Malicious` requires confidence ≥ 60 or ≥ 2 independent groups.
- `Suspicious` = confirmed-malicious not met but at least one source at
  confidence ≥ 40, or ≥ 2 community reports in the "suspected" category.
- A single `CleanReported` from a *vetted* feed record downgrades
  `Malicious` to `Suspicious` and attaches the appeal source. It never erases
  a vetted vetted record — only the *vetted* feed can reclassify.

### Provider trait

```rust
pub trait ThreatIntelProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    /// Independent-group tag for the confidence model above.
    fn independence_group(&self) -> &'static str;
    /// Lookup by SHA-256. Must never block longer than the configured
    /// timeout; offline behavior is a `ProviderError` or `Unknown`,
    /// never a synthetic `Clean`.
    fn lookup(&self, sha256: &str) -> ReputationResult<Verdict>;
}
```

## 3. Providers shipped in this slice

1. **Local provider** (`LocalProvider`) — wraps the existing hash-signature
   DB. Zero I/O, zero network. Confidence 100, group `"opensentinel"`.
2. **MalwareBazaar provider** (`MwbProvider`) — MalwareBazaar's documented
   `?query=hash&hash=…` JSON API (https://mb.securegate.de). Rate-limited
   (default 1 lookup / 2 s), cached on disk, TLS via `reqwest` with
   `rustls-tls` (no native openssl dep on Windows). API failures →
   `ProviderError`. No file uploads, no scrape.
3. **Community report provider** (`CommunityProvider`) — local records only
   in this slice (no server yet); category and moderation rules live in
   `docs/reputation.md`. Server upload is a documented, not-implemented
   follow-up — no placeholder endpoints.
4. **VirusTotal** — *documented as an opt-in follow-up*, not implemented
   here. The plan + license note are in `docs/reputation.md`; code lands
   only when an API key and permitted-use case are both present.
5. **ClamAV / YARA** — documented only; license/compat verification is a
   prerequisite, not silently assumed.

## 4. Signed feed format

`docs/feed-format.md` (new, version 1) specifies:

```json
{
  "version": 1,
  "sequence": 4821,            // strictly increasing; rollback rejected
  "issued_at": "2026-10-17T00:00:00Z",
  "expires_at": "2027-10-17T00:00:00Z",
  "records": [ { "sha256": "…", "verdict": "malicious", "confidence": 87,
                 "sources": ["mwb:3.1", "community:2026-10-01"],
                 "rule_id": "osr-0007" } ],
  "revocations": [ "osr-0007" ],
  "signature": "base64(p134570 over the canonicalized document)"
}
```

- Signature: Ed25519, public key shipped in the binary; *the private key
  never ships*. A controlled publishing infra (not this repo) signs.
- Client verifies: signature valid, `sequence` > stored, `expires_at` > now,
  JSON well-formed, per-record schema. Failure → keep last known-good,
  record the error, do **not** apply.
- Atomic apply: write to `…new`, fsync, `rename` over the DB, so a crash
  mid-update never leaves a half-written DB.
- Rollback / replay: `sequence` monotonicity check; a feed with
  `sequence <= stored` is rejected and logged.
- `revocations` lets a false positive be corrected by pulling the record
  out of the active DB without changing `sequence` history.

## 5. Rate limit / caching / offline

- `reqwest` timeout: provider-level, default 5 s, configurable.
- On-disk cache: one JSONL file under the quarantine dir, keyed by SHA-256,
  TTL 24 h default. Bounded: drop oldest entries past 10 000 lines.
- In-memory `HashMap` + LRU bound (2 048 entries) so the GUI does not
  re-read disk every hover.
- Offline (network failure / provider down): every provider returns
  `ProviderError` and the aggregate stays `Unknown` for hashes without a
  local hit. The UI shows "provider offline" and the scan result is
  honestly labelled "no reputation data available", not "clean".

## 6. Community backend (documented, not yet built)

`docs/reputation.md` defines:

- Report schema: `{ sha256, category, source, user_id, ts }` — no file
  contents, no paths, no usernames by default.
- Server-side validation: known SHA-256 format, category whitelist, 5
  reports / hash / hour per user, deduplication by `(sha256, user_id,
  category)`.
- Moderation: community reports only feed `Suspicious`; promotion to
  `Malicious` requires a *vetted* publisher writing a signed feed record
  referencing the report. False-positive appeals are a signed-feed
  revocation + `CleanReported` downgrade.
- No server shipped here. The design is what a later `opensentinel-server`
  repo would implement; this slice ships the *client-side* record format
  and validation so tests can run against the documented rules without a
  live service.

## 7. Implementation order

1. `src/reputation.rs` — trait, `LocalProvider`, confidence model, cache,
   rate limiter.
2. `src/providers/mwb.rs` — MalwareBazaar adapter.
3. `src/feed.rs` — signed-feed format + atomic apply + rollback guard.
4. `src/community.rs` — report record types + validation (client side).
5. Tests: malformed provider JSON, rate limit, offline, invalid signature,
   rollback, false-positive correction, abusive report.
6. `docs/reputation.md` + `docs/feed-format.md` + README updates.
7. Wire provider status into the GUI Threat-database screen (local DB only
   in this slice; remote provider status shown as configured / offline).

## 8. Out of scope in this slice

- VirusTotal provider code (license + API-key gating)
- ClamAV / YARA engine integration
- Community backend service (server repo)
- Real-time protection
