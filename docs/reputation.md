# OpenSentinel — reputation & threat-intel model

This document is the **authoritative source** for the client-side confidence
rules enforced in `src/reputation.rs`. Provider adapters
(`src/mwb.rs`, `src/community.rs`, `src/feed.rs`) and tests are written against
the rules below, so keep this file in sync if the rules change.

## 1. Verdicts

`src/reputation.rs::Verdict` has five shapes, each carrying a distinct meaning
the UI must surface honestly:

| Verdict        | Meaning                                                                 |
|----------------|-------------------------------------------------------------------------|
| `Malicious`    | At least one source confirms malware; confidence threshold met.         |
| `Suspicious`   | Heuristic / community / low-threshold suspicion, not confirmed.         |
| `Unknown`      | No provider has a record. **Not** "clean" — no evidence either way.     |
| `CleanReported`| A vetted source (signed feed revocation/appeal, or ≥2 community benign) affirmatively says benign. |
| `ProviderError`| The provider was unreachable, timed out, or errored.                    |

### Non-negotiables

- **A provider timeout or unavailable service must never be interpreted as
  a clean result.** `ProviderError` is folded into the aggregate as an error,
  never collapsed into `Unknown` or `Clean`.
- **`Unknown` must never be labeled "clean"** in the UI scan output.
- A **community report alone never yields `Malicious`** — at most `Suspicious`.
  Promotion to `Malicious` requires a vetted source writing a signed feed
  record.
- `CleanReported` **downgrades** `Malicious` to `Suspicious` (attaches the
  appeal source); it does not erase a vetted record.

## 2. Confidence aggregation

`aggregate(verdicts) -> Verdict` in `src/reputation.rs`:

1. Collect every provider's verdict.
2. `ProviderError` wins immediately — any provider error means evidence is
   incomplete; return `ProviderError(msg)`.
3. Group verdicts by **independence group** (`independence_group()`). Sources
   sharing a tag are correlated (same upstream DB) and count once.
4. Collapse each group to its strongest verdict.
5. If a `CleanReported` source exists and the strongest group verdict is
   `Malicious`, downgrade that group to `Suspicious` at confidence 50 and
   attach the appeal source.
6. Sum independent-group confidences, cap at 100.
7. **Malicious** iff there is at least one `Malicious` group verdict **and**
   (confidence ≥ 60 **or** ≥ 2 independent groups both report `Malicious`).
8. Otherwise **Suspicious** iff confidence ≥ 40.
9. Otherwise **Unknown** (no positive evidence).

### Independence groups (correlation map)

| Provider tag      | Group           | Notes                                     |
|-------------------|-----------------|-------------------------------------------|
| `opensentinel`    | `opensentinel`  | Local signature DB, confidence 100.       |
| `mwb*`            | `malwarebazaar` | Community-submitted samples.              |
| `community*`      | `community`     | Client-side reports (see §4).             |
| `vetted`          | `vetted`        | Signed feed records / appeals.            |
| anything else     | `unknown`       | Treated as independent.                   |

## 3. Provider trait

```rust
pub trait ThreatIntelProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn independence_group(&self) -> &'static str;
    fn lookup(&self, sha256: &str) -> Result<Verdict>;
}
```

- `lookup` must return `Verdict::Unknown` (not `Clean`) on a cache miss with no
  network — see §5 for the local provider's behavior.
- A provider with no configured transport (e.g. `MwbProvider` offline) returns
  `ProviderError`.

## 4. Community reports (client rules)

Schema (`src/community.rs::CommunityReport`):

```jsonc
{
  "sha256": "64 lowercase hex chars",
  "category": "suspected_malware | false_positive | suspicious_behavior | confirmed_benign",
  "user_id": "pseudonymous, no paths / usernames / emails",
  "ts": "ISO-8601 UTC"
}
```

Client validation (`CommunityStore::submit`):

- `sha256` must be 64 lowercase hex chars.
- `user_id` non-empty, must not contain `\`, `/`.
- Rate limit: **5 reports / (hash, user) / hour**.
- Dedup: same `(sha256, user_id, category)` within the window is rejected.

### Community verdict (`CommunityStore::community_verdict`)

- ≥ 2 `confirmed_benign`/`false_positive` and < 2 `suspected` → `CleanReported`.
- ≥ 2 `suspected` or `suspicious_behavior` → `Suspicious`, confidence
  `min((suspected + behavior) * 20, 80)`.
- exactly 1 `suspected`/`suspicious_behavior` → `Suspicious`, confidence 20.
- otherwise `Unknown`.

**Community evidence alone never produces `Malicious`.** Promotion requires a
vetted provider writing a signed feed record referencing the report.

## 5. Local provider

`LocalProvider` (`src/reputation.rs`) wraps the on-disk signature DB
(`src/detection::load_signatures`):

- `High` → `Malicious` confidence 100, group `opensentinel`.
- `Medium` → 80; `Low` → 60.
- Cache miss → `Unknown` (honest "no local rule").

## 6. Caching, rate limiting, offline

- **Disk cache** (`ReputationCache`): JSONL at
  `<quarantine_dir>/reputation-cache.jsonl`, 24h TTL, 10 000-line LRU bound.
- **In-memory** `HashMap` + LRU bound so the GUI does not re-read disk per
  hover (see §TODO: the in-memory bound is planned per `docs/threat-intel-plan.md` §5).
- **Rate limiter** (`RateLimiter`): token bucket per provider,
  `try_acquire() -> Result<(), Duration>`; must never panic on a poisoned lock.
- **Offline**: every provider returns `ProviderError` or `Unknown`; the UI
  shows "provider offline" and scan results are labeled
  "no reputation data available", **not** "clean".

## 7. Threat-database provider status

`Reputation::provider_status()` returns `(name, version)` for every wired
provider. The GUI Threat-database screen shows:

- Local signature count + integrity bytes (always available offline).
- Each remote provider as `Online` / `Offline` / `Unconfigured`.
- A "Lookup requires community feed / signed feed not configured" message when
  a provider is not configured — never a placeholder.

## 8. Out of scope

- VirusTotal provider code (opt-in, API-key gated; documented here only).
- ClamAV / YARA engine integration (documented, not assumed).
- Community backend service — this is a *client-side* model. A future
  `opensentinel-server` repo would implement the server-side validation,
  moderation, and abuse-prevention; the client record format and rules live
  here so tests run without a live service.
- Real-time protection.

---

This file is the single source of truth for the rules in
`src/reputation.rs` tests: `correlated_sources_count_once`,
`provider_error_never_collapses_to_unknown`, `clean_report_downgrades_malicious`,
`cache_roundtrip`, `cache_ttl_expiry`, `rate_limiter_blocks`.
