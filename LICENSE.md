# OpenSentinel — License

This project is licensed under the MIT License. A copy of the license
text lives in [`LICENSE`](LICENSE) at the repository root.

## Why MIT

OpenSentinel is a security tool that people will fork, audit, and build
upon. MIT is simple, permissive, and patent-friendly, which fits a
community-driven project that wants to:

- let anyone use and modify the scanner without restriction,
- stay compatible with the MIT-licensed dependencies it uses
  (`serde`, `sha2`, `rand`, `signal-hook`, `serde_json`),
- keep corporate adoption easy (no copyleft obligations).

The choice is revisited in `CONTRIBUTING.md` when a new dependency with a
different license is ever added; if that happens, compatibility must be
re-checked before the dependency lands.

## Third-party

Standard crates are used under their own permissive licenses. No code is
taken under an incompatible license.
