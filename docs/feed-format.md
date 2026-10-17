# OpenSentinel — signed threat-intel feed format

This document specifies the on-disk feed format verified and applied by
`src/feed.rs`. The **private signing key never ships** — it lives only on the
controlled publishing infrastructure. The client ships only
`FEED_PUBLIC_KEY` and verifies every update before applying it.

## 1. File layout

A signed feed is delivered as a single JSON object:

```jsonc
{
  "feed": {
    "version": 1,
    "sequence": 4821,
    "issued_at": "2026-10-17T00:00:00Z",
    "expires_at": "2027-10-17T00:00:00Z",
    "records": [ { "sha256": "...", "verdict": "malicious", "confidence": 87,
                    "sources": ["mwb:3.1", "community:2026-10-01"],
                    "rule_id": "osr-0007" } ],
    "revocations": [ "osr-0007" ]
  },
  "signature": "<64-byte Ed25519 signature over the canonical feed JSON>"
}
```

The applied result is persisted at `<quarantine_dir>/feed.db` as an
`AppliedFeed` object (same shape minus the signature):

```jsonc
{
  "sequence": 4821,
  "records": [ "...FeedRecord..." ],
  "revocations": [ "osr-0007" ]
}
```

## 2. Field semantics

| Field          | Type     | Rules                                                                 |
|----------------|----------|-----------------------------------------------------------------------|
| `version`      | u32      | Must be `1`. Other versions are rejected.                             |
| `sequence`     | u64      | **Strictly increasing**. A feed with `sequence <= stored` is rejected (rollback / replay guard). |
| `issued_at`    | string   | ISO-8601 UTC `YYYY-MM-DDTHH:MM:SSZ`. When the feed was published.     |
| `expires_at`   | string   | ISO-8601 UTC. A feed where `now >= expires_at` is rejected.            |
| `records`      | array    | Vetted records. Only a vetted feed record can produce `Malicious`.    |
| `revocations`  | string[] | Rule IDs (`osr-...`) to remove from the active DB — false-positive correction. |
| `signature`    | bytes    | Ed25519 over the canonical JSON of `feed` (see §3).                    |

### Record fields

| Field        | Type   | Rules                                                |
|--------------|--------|------------------------------------------------------|
| `sha256`     | string | 64 lowercase hex chars.                              |
| `verdict`    | string | `"malicious"` or `"suspicious"`. Vetted record only. |
| `confidence` | u8     | 0–100 as the publisher rates it.                     |
| `sources`    | string[] | Attribution tags, e.g. `"mwb:3.1"`, `"community:2026-10-01"`. |
| `rule_id`    | string | Stable identifier, e.g. `"osr-0007"`. Used by revocation. |

## 3. Canonical JSON

The signature is computed over `canonical_json(feed)` in `src/feed.rs`:

- Serialize the `FeedVersion` to `serde_json::Value`.
- Re-insert fields into a fresh `serde_json::Map` (which sorts keys by
  insertion order). **Field order in the JSON object is normalized** so the
  signature is deterministic regardless of how the document was serialized.
- Serialize to a compact `Vec<u8>` with `serde_json::to_vec`.

Deterministic ordering and compact form are the whole point — any reordering
or extra whitespace would change the signature.

## 4. Signature

- Algorithm: **Ed25519** (`ed25519-zebra` 5.0 + `ed25519` 3.0).
- Public key: `FEED_PUBLIC_KEY` constant in `src/feed.rs` — the **only** copy
  in the client.
- Private key: **never in this repo**. Signing happens on the publishing
  infrastructure. A contributor must not add a private key here.
- Verification: `VerificationKey::try_from(FEED_PUBLIC_KEY)`, then
  `vk.verify(&sig, &canonical_msg)` where `sig` is the 64-byte signature.

### Verification steps (`verify_feed`)

1. Decode the public key — must decompress to a valid curve point.
2. Signature must be exactly 64 bytes.
3. `vk.verify(&sig, canonical_json(&feed))` — Ed25519 check.

## 5. Acceptability (`is_acceptable`)

A verified feed is only applied if:

1. `version == 1`.
2. `sequence > last_applied_sequence` (strictly greater — **rollback and replay
   are rejected, last known-good DB is kept**).
3. `now < expires_at` (not expired). A feed past its expiry is not applied even
   if signed.

`is_acceptable` returns `Ok(true)` to apply, `Ok(false)` to keep the last-good
DB (e.g. expired feed, equal/lower sequence), or `Err(...)` for an unsupported
version.

## 6. Atomic apply (`apply_feed`)

The atomic write guarantees a crash mid-update never leaves a half-written DB:

1. Read `last_seq = read_last_sequence(dir)`. This reads `feed.db`; if the
   file is **corrupt**, the call errors and the apply is refused — the
   last known-good is kept.
2. `is_acceptable(feed, last_seq, now)` — reject rollback / expiry / bad
   version.
3. Serialize `AppliedFeed { sequence, records, revocations }` to a temp file
   `<quarantine_dir>/feed.db.new`.
4. `fsync` the temp file so it is durable.
5. `rename` the temp file over `feed.db` (atomic on POSIX and NTFS).

If the rename fails, the temp file is removed and the apply errors; the old
`feed.db` is untouched.

### Rollback protection

`sequence` is strictly monotonic. Re-applying a feed at the same or lower
sequence is a replay/rollback attempt and is rejected. `read_last_sequence`
returns the last durable sequence from `feed.db`; if that file is corrupt,
the apply fails rather than silently regressing.

## 7. Revocation & false-positive correction

`revocations` is a list of `rule_id` strings. When a feed is applied, the
listed rule IDs are removed from the active records. A vetted feed record
that is the *only* source for a `Malicious` verdict can thereby be corrected
to `Unknown`/`Suspicious` without changing sequence history.

Per the reputation rules in `docs/reputation.md` §1, a `CleanReported`
from an appeal source downgrades `Malicious` to `Suspicious` and attaches the
appeal — a revoked rule never reclassifies a file as clean, it only removes
the now-withdrawn rule from evidence.

## 8. Offline behavior

- If no `feed.db` exists, `read_last_sequence` returns `0`; the first
  acceptable feed (`version == 1`, `sequence > 0`, not expired) is applied.
- A corrupt `feed.db` blocks apply and keeps nothing new; the client keeps
  the absence state (or the last good DB if present) and reports the error.
- An expired or rolled-back feed is ignored; the last known-good DB remains
  in effect.

## 9. Threats mitigated

| Threat                  | Mitigation                                           |
|-------------------------|------------------------------------------------------|
| Forged feed             | Ed25519 signature over canonical JSON.               |
| Rollback / replay       | Strict `sequence > last` monotonic check.            |
| Expiration / stale DB   | `expires_at` check; expired feeds not applied.        |
| Corruption / half-write | Temp-file + `fsync` + atomic `rename`.                |
| Corrupt stored DB       | `read_last_sequence` errors on corrupt `feed.db`; apply refused, last-good kept. |
| Rule-withdrawal (FP)    | `revocations` list removes rule IDs from active DB.   |

## 10. Out of scope

- No live feed endpoint is configured in this client. Do **not** ship a
  placeholder URL — the UI must show "signed feed not configured" until a
  real, pinned source is documented.
- The private key lives off-repo; contributors must not add one here.
- No automatic feed polling. Feeds are applied on demand or via an explicit
  update path, never silently on a timer.

---

This file is the contract verified by the tests in `src/feed.rs`:
`rollback_rejected`, `higher_seq_accepted`, `future_expiry_rejected`,
`corrupt_db_keeps_last_good`, `apply_then_replay_rejected`,
`canonical_json_is_deterministic`.
