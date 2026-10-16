# Known Limitations & Security Notes

OpenSentinel v0.1 is a **scanner**, not a real-time protector. Be precise
about what it does and does not do.

## Detection coverage

- Only files whose SHA-256 is in `signatures.json` produce a `DETECTED`
  result. The default database ships with a single well-known EICAR test
  entry so the engine is verifiably live — **that is not a general malware
  signature set**. Add your own validated entries or an upstream feed.
- Heuristics only emit `SUSPICIOUS` with human-readable reasons. They are
  tuned low-precision to avoid false positives; many real threats will not
  trip them.
- No YARA, no ClamAV, no behavioral analysis, no cloud lookups. Absence of
  a detection is **not** an assertion that a file is safe.

## Platform

- POSIX: full symlink-loop guard via inodes, best-effort SIGINT cancel.
- Windows: the walk still depth-bounds the traversal, but there is no public
  stable inode API, so a deliberately crafted symlink cycle in a user
  directory is not deduplicated. Cancellation is manual (no Ctrl-C hook).

## Quarantine safety

- The store lives at `.opensentinel-quarantine/` by default (configurable).
  Contents are inert files; nothing here is executed.
- Restore never overwrites. Purge is explicit-ID + `--yes`.
- The JSONL index is human-inspectable; a tampered index line is skipped
  with a warning, not fatal.

## What is *not* protected against

- Kernel/rootkit-level threats, in-memory malware, and anything that needs
  on-access blocking. Those require OS integration that does not exist yet.
- Network delivery (dropper that downloads a payload after execution).

## Data & privacy

The binary performs no network I/O in this release. It does not phone home,
collect telemetry, or require an account. The only files it reads are the
paths you tell it to scan plus `signatures.json` and any `opensentinel.toml`.
