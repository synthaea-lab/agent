# Synthaea — project conventions

Multi-platform EDR/XDR (Windows/Linux/macOS) with on-device ML. Rust agent workspace +
Python training pipeline (`ml/`) + control plane (`server/`, tech not locked yet).
Everything — code, comments, docs, commits — is in **English**.

The previous iteration lives untracked in `old/`. Code is migrated from it crate by crate,
**with its tests**, after review — never copied wholesale. Docs are written fresh, not
copied (`docs/README.md` has the index).

## Dependency direction (enforced by `tools/check-deps.py`, run in CI)

- `schema` is the platform boundary: event types + `Sensor`/`EventSink` contract.
  It depends on no workspace crate and stays dependency-light. Treat its public API as
  semi-frozen — changes there ripple everywhere and need explicit justification.
- `policy` sits next to `schema` as the base tier (shared agent/server types); it
  depends only on `schema`, everything else may depend on both.
- Sensor crates (`crates/sensors/*`) depend **only** on `schema`.
- Detection crates (`rules`, `sigma`, `correlator`, `ml`, `yara`, `enrich`) depend on
  the base tier, each other, and `store` — **never on a sensor**.
- Leaf crates (`response`, `transport`, `ipc`, `sinks`, `updater`, `config`, `store`,
  `conformance`) depend only on the base tier.
- Only the binaries (`agent/`, `watchdog/`, `cli/`) may depend on everything.

New crate? Add it to the rules in `tools/check-deps.py` in the same change.

## Platform code

- Core crates compile on all three OSes; CI tests ubuntu/windows/macos and clippy runs
  with `-D warnings`.
- Platform-specific code (`#[cfg(target_os = ...)]`, platform-only deps) is allowed
  **only inside `crates/sensors/*`** — sensor crates compile to empty stubs elsewhere.
  Platform deps must be target-gated: `[target.'cfg(windows)'.dependencies]`, never
  unconditional.
- `crates/sensors/linux-ebpf` is excluded from the workspace (special toolchain, GPLv2);
  build it explicitly on Linux.

## Conventions

- Errors: `thiserror` in library crates, `anyhow` only in binaries. No `unwrap`/`expect`
  outside tests and provably-infallible cases.
- Logging: `tracing`, structured fields; never log event payload contents at info level.
- Visibility: `pub(crate)` by default; a crate's `pub` surface is its contract — keep it
  minimal and deliberate.
- Config: format decided once via ADR before the first config file lands.
- Cross-cutting decisions get an ADR (`docs/adr/template.md`) at the time they're made.

## Parity seams (golden fixtures required)

- Event schema: versioned JSON fixtures; a serialization change that breaks a fixture is
  a schema version bump, not a silent edit.
- ML features: `crates/ml` (Rust) and `ml/` (Python) share feature definitions;
  both sides test against the same fixture vectors so they cannot drift.

## Commands

- `cargo check --workspace` / `cargo test --workspace` — works on any OS.
- `cargo clippy --workspace --all-targets -- -D warnings` — must stay clean.
- `python3 tools/check-deps.py` — dependency direction check.

## Migration order (from `old/`)

`schema` → `sensors/linux` + `rules` (walking skeleton: one synthetic
event end to end) → `correlator` + `ml` → `sensors/windows` → the rest.
