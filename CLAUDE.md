# Synthaea — project conventions

Multi-platform EDR/XDR (Windows/Linux/macOS) with on-device ML. Rust agent workspace +
Python training pipeline (`ml/`) + control plane (`server/`: Next.js + PostgreSQL, ADR-0001).
Everything — code, comments, docs, commits — is in **English**.

The previous iteration lived in a local `old/` clone during migration (now deleted; its
history and final working-tree translations are on github.com/synthaea-lab/edr, branch
`pre-migration-translations` — the source for the remaining #20/#67 migrations).
`old/...` paths in code comments are historical provenance. Docs are written fresh,
never copied (`docs/README.md` has the index).

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
- Config: TOML `agent.toml` per ADR-0013 — the agent **fails fast** on a missing or
  invalid file (`config::load`, discovery order in `crates/config`); `RUST_LOG` still
  overrides the configured log level for ad-hoc debugging.
- Cross-cutting decisions get an ADR (`docs/adr/template.md`) at the time they're made.

## Code quality (full reference: `docs/development/code-style.md`)

- Curated lint bar in root `[workspace.lints]`; clippy runs `-D warnings`, so every
  listed lint is enforced: `dbg_macro`/`todo`/`unimplemented` and
  `undocumented_unsafe_blocks` (write `// SAFETY:` on every unsafe block) are deny;
  `doc_markdown`, `must_use_candidate`, `missing_errors_doc`, `missing_panics_doc`,
  `semicolon_if_nothing_returned` are enforced warns. `similar_names` is deliberately
  off (pid/ppid is kernel nomenclature).
- Every `pub` item documented; `Result` fns get `# Errors`, panicking fns `# Panics`.
- Functions stay at one level of abstraction — dispatchers dispatch, workers work.
- Comments state what code can't (invariants, calibration dates, incident lessons),
  never what the next line does.
- Detection state is bounded + observable (`store::BoundedMap`, counted shedding);
  time windows are sliding (timestamp deques), never reset buckets; name-keyed
  exclusions must be gated on evidence (`policy::name_exclusion_applies`).
- Bug fixes land with the regression test that would have caught them, named after
  the behavior.
- Test event literals come from `schema::fixtures` (feature `test-fixtures`,
  dev-dependencies only) via struct-update syntax — never hand-write a full
  `EventMeta`/event literal in a test; the golden suite (`schema/tests/golden.rs`)
  is the one deliberate exception.
- Byte parsers (anything consuming kernel-socket or attacker-influenced bytes) get
  a never-panic robustness suite in their crate's `tests/` and, where high-value, a
  fuzz target in `fuzz/`.
- Platform-gated code must be linted for its platform before pushing:
  `cargo clippy -p sensor-windows --target x86_64-pc-windows-msvc` (and the Linux
  equivalent) — host-only clippy misses it entirely.

## Parity seams (golden fixtures required)

- Event schema: versioned JSON fixtures; a serialization change that breaks a fixture is
  a schema version bump, not a silent edit.
- ML features: `crates/ml` (Rust) and `ml/` (Python) share feature definitions;
  both sides test against the same fixture vectors so they cannot drift.

## Commands

- `tools/gauntlet.sh` — the full local check matrix (fmt, deps, clippy on host +
  linux target + the Windows sensor crates, tests, cargo-deny, docs). `--fast`
  skips the cross-target/docs passes; opt-in pre-push gate:
  `git config core.hooksPath tools/hooks`. **While CI is billing-blocked
  (workflow_dispatch only, issue #318), this is the enforcement — run it before
  every push.**
- `cargo check` / `cargo test` (default members) — works on any OS; with `--workspace`, add `--exclude sensor-linux-ebpf` (bpfel target).
- `cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets -- -D warnings` — must stay clean.
- `python3 tools/check-deps.py` — dependency direction check.
- `cargo +nightly fuzz run audit_parse` / `netlink_parse` — coverage-guided parser
  fuzzing (`fuzz/README.md`; workspace-excluded, needs `cargo-fuzz`).

## Migration order (from `old/`)

`schema` → `sensors/linux` + `rules` (walking skeleton: one synthetic
event end to end) → `correlator` + `ml` → `sensors/windows` → the rest.
