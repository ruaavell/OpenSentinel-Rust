# OpenSentinel Architecture

## Layout

```
src/
  main.rs       thin CLI wrapper (thin; all engine logic is in the lib)
  lib.rs        public library facade: re-exports + build_engine
  config.rs     safe defaults + tiny TOML-subset parser (validated, strict)
  detection.rs  Engine: signature DB + conservative heuristics
  scanner.rs    recursive walk, streaming SHA-256, cancellation, size limits
  quarantine.rs move-based quarantine store, no-overwrite restore, purge
  error.rs      Error / ErrorKind / Result alias
tests/
  integration.rs  EICAR, signature round-trip, quarantine lifecycle
signatures.json   default local hash DB (one known test entry)
```

## Threat-detection model

Three independent layers; a `Detected` result requires a definite signature
match, while heuristics can only produce `Suspicious`:

1. **Hash signatures** — streaming SHA-256, matched against `signatures.json`.
   Entries are validated on load (64-char lowercase hex, version, name);
   a malformed or oversized file is *rejected*, not partially used.
2. **Heuristics** — explainable signals (executable header, high-entropy
   executable, script download/exec markers). Sensitivity is configurable
   (`low|medium|high`). Heuristics never delete or quarantine.
3. **No-signature = no detection** — a clean result is explicitly "no
   matching enabled engine fired", *not* a safety guarantee.

## Concurrency and cancellation

`scan_paths` uses a bounded thread pool (default 4 workers, configurable
1..=64). On POSIX a best-effort SIGINT handler flips a cooperative cancel
flag; the walk stops at the next checkpoint and returns exit code 130 with
whatever was collected.

## Memory

Hashing streams in 8 KiB chunks. The heuristic pass reads only the first
8 KiB of a file. No whole-file load, no unbounded caches.

## Security properties

- Quarantine **moves** the file (original removed), records SHA-256 +
  original path in a JSONL index, and assigns a 128-bit random ID.
- `quarantine_restore` **never overwrites**: if the target exists it
  appends " (1)", " (2)"…
- `quarantine_purge` requires the caller to pass explicit IDs; the CLI
  additionally demands `--yes`.
- A TOCTOU guard re-hashes the file just before the move.
- No scanned file is ever executed.

## Limits (known)

- Windows has no stable public inode API, so the symlink-loop guard is a
  no-op on that platform today (the walk is still depth-bounded).
- The TOML subset parser is intentionally tiny; swap for a real TOML
  crate when config grows.
