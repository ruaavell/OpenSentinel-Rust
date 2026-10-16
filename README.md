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
- **Automated tests**: SHA-256 vectors, signature round-trip, quarantine
  move/restore/collision lifecycle, non-ASCII filenames, EICAR artifact.

## What does *not* work yet (planned, not shipped)

- Real-time / on-access protection (Windows kernel integration, Linux FUSE)
- YARA rule scanning
- Community threat-intelligence update with signed manifests
- GUI
- ClamAV third-party engine

These are intentionally not faked. The CLI will not claim a database update
works before that system is real.

## Quick start

Build and run the CLI:

```sh
cargo build
./target/debug/opensentinel --help
```

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
