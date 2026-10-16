# Contributing

Thanks for helping OpenSentinel. Keep changes small and reviewable.

## Ground rules

- **No real malware** in the repo. Use the EICAR test string and synthetic
  files only.
- **Never** add telemetry, ads, auto-deletion, or a required account.
- Detection claims must match implemented behavior. If a feature is
  unimplemented, say so in the README — don't dress it up.
- Prefer `std` over new dependencies. Justify any new crate in the PR.
- Run the full gate locally before pushing:

  ```sh
  cargo fmt --all
  cargo clippy --all-targets -- -D warnings
  cargo test --all
  ```

## Layout expectations

- Engine logic belongs in `src/*.rs` (library); the CLI stays a thin
  wrapper in `main.rs`.
- Quarantine operations must stay move-based, no-overwrite on restore,
  explicit purge.
- Detection output: `Detected` only for definite signature matches;
  heuristics cap out at `Suspicious` with a human-readable reason.

## Pull request checklist

- [ ] `cargo fmt` and `clippy` clean
- [ ] New behavior has a test in `tests/` or the module's `#[cfg(test)]`
- [ ] No new secret, key, or telemetry
- [ ] README "What works" list still accurate
