<img width="1500" height="1500" alt="os-icon" src="https://github.com/user-attachments/assets/3c4ca6e2-64b3-45dd-93b0-b3d3f2724234" />

# OpenSentinel

A lightweight, open-source antivirus scanner written in Rust.

OpenSentinel's mission is to give ordinary users — including people on old,
low-power computers — a real, transparent, free-to-use tool for finding
suspicious files, without telemetry, ads, paywalls, or a mandatory account.

> **This is an early vertical slice (v0.1).** It is not a complete
> real-time antivirus. It does *not* replace an established product. Read
> [docs/architecture.md](docs/architecture.md) and
> [docs/limitations.md](docs/limitations.md) for what actually works today
> versus what is still planned.

## What works in this release

- **Recursive directory scanning** with a bounded, cancellable worker pool.
- **Streaming SHA-256** (bounded memory, safe on very large files).
- **Hash-signature database** with input validation — a known, planted hash
  produces a `DETECTED` result.
- **Conservative, explainable heuristics** that only ever mark files
  `SUSPICIOUS`; they never auto-quarantine or delete.
- **Safe quarantine**: files are *moved* into an isolated store with an
  unguessable ID; restore **never overwrites** an existing file.
- **CLI** with human and `--json` output, proper exit codes.
- **Desktop GUI** (`opensentinel-gui`): overview, scan, quarantine,
  threat-database, activity, and settings screens, all backed by the real
  engine — scanning runs on a background thread so the window stays
  responsive, and the only progress shown is the real file counter (never a
  fabricated percentage).
- **Automated tests**: SHA-256 vectors, signature round-trip, quarantine
  move/restore/collision lifecycle, non-ASCII filenames, EICAR artifact,
  and UI-independent state-transition tests.
- **Threat-intelligence provider model**: an honest, five-state verdict model
  (`Malicious` / `Suspicious` / `Unknown` / `CleanReported` / `ProviderError`)
  documented in [docs/reputation.md](docs/reputation.md). A provider timeout or
  offline service is **never** reported as clean. See `src/reputation.rs`.
- **Local signature provider**: the existing hash-signature DB is exposed as a
  `ThreatIntelProvider`; `High`→confidence 100, `Medium`→80, `Low`→60, grouped
  as `opensentinel`.
- **MalwareBazaar provider**: queries the documented
  `POST https://mb-api.abuse.ch/api/v1/` hash-lookup endpoint (`query=get_info&hash=<sha256>`).
  Free, **no API key required** for hash lookup; no file uploads, no scraping.
  Rate-limited (0.5 req/s, burst 5) and cached. `ProviderError` on failure —
  never a synthetic clean. See `src/mwb.rs`.
- **Signed feed**: Ed25519-verified, version-1 feed with monotonic sequence
  (rollback/replay guard), `expires_at` enforcement, and atomic
  write-then-rename apply so a crash never leaves a half-written DB. The
  signing **private key is never in the client** — it lives on the publishing
  infrastructure. The shipped public key is pinned in `src/feed.rs`. Full
  format in [docs/feed-format.md](docs/feed-format.md).
- **Community reports (client-side)**: a validated, deduplicated,
  rate-limited report record with four categories (`suspected_malware`,
  `false_positive`, `suspected_behavior`, `confirmed_benign`). A community
  report alone **never auto-quarantines** and **never yields `Malicious`** —
  at most `Suspicious`, promotion requires a vetted provider. See
  `src/community.rs`.

## What does *not* work yet (planned, not shipped)

- Real-time / on-access protection (Windows kernel integration, Linux FUSE)
- YARA rule scanning
- VirusTotal provider (opt-in, API-key gated — documented in
  [docs/reputation.md](docs/reputation.md) §8, not implemented; no placeholder
  endpoint ships)
- ClamAV third-party engine (documented only; license/compat verification is
  a prerequisite, not silently assumed)
- Live signed-feed update channel (the client verifies and applies a feed if
  one is supplied, but no feed endpoint is pinned in the binary; the GUI shows
  "signed feed not configured" until one is documented)
- Community backend service (the client ships the record format + validation
  rules; a future `opensentinel-server` repo would implement moderation,
  abuse-prevention, and abuse-prevention; this repo is client-only)
- GUI: dark theme, native folder picker, persistent activity history

These are intentionally not faked. The CLI will not claim a database update
works before that system is real.

## Quick start

Build and run the CLI:

```sh
cargo build
./target/debug/opensentinel --help
```

Build and launch the desktop GUI:

```sh
cargo run --bin opensentinel-gui
```

(The GUI binary is `opensentinel-gui`; the library and CLI share the same
scanner/detection/quarantine code — the GUI adds no duplicate engine.)

Scan a directory:

```sh
opensentinel scan ./Downloads
```

Hash a file:

```sh
opensentinel hash ./suspicious.dll
```

Quarantine a detected file and later restore it:

```sh
opensentinel quarantine add ./suspicious.dll
opensentinel quarantine list
opensentinel quarantine restore <ID>
```

Exit codes: `0` clean, `10` detected, `11` suspicious-only, `12` scanned
with errors, `1` user error, `130` cancelled.

## Building

Stable Rust is enough. No special toolchain pin is required yet.

```sh
cargo build --release
```

## License

MIT — see [LICENSE](LICENSE).
