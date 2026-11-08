# Synthaea — project conventions

Multi-platform EDR/XDR (Windows/Linux/macOS) with on-device ML. Rust agent workspace +
Python training pipeline (`ml/`) + control plane (`server/`: Next.js + PostgreSQL, ADR-0001).
Everything — code, comments, docs, commits — is in **English**.

The previous iteration lived in a local `old/` clone during migration (now deleted).
`old/...` paths in code comments are historical provenance. Docs are written fresh,
never copied.

## Repository layout / siblings

This repo is the agent workspace. The public repos that test against each other are
cloned side by side in one directory as sibling checkouts: `agent/` (this repo,
synthaea-lab/edr-agent), `server/` (edr-server), `ml/` (edr-ml), `rules/` (edr-rules).
This repo must never depend on anything outside those public repos. The ONNX Runtime
and build-machine toolchain scripts live here under `toolchain/`.

- Cross-repo contract tests (golden fixtures in `server/tests/fixtures` and
  `ml/tests/fixtures`, the shipped content in `rules/`, the server's routes) read the
  sibling through the dev-only `crates/siblings` crate: `siblings::require!(repo, rel)`
  (file text) / `siblings::require_path!(repo, rel)` return the value or print one
  `skipped: needs sibling repo ...` line and return from the test. Never reach into a
  sibling by relative path or `include_str!` — the agent must build and test alone.
- `SYNTHAEA_ROOT` points at the directory holding the siblings (default: this repo's
  parent directory).
- `SYNTHAEA_REQUIRE_SIBLINGS=1` turns every such skip into a panic; CI's `test` and
  `content` jobs check the siblings out and set it, so a contract test cannot pass by
  not running.
- `tools/attack-coverage.py` scans this repo plus the `rules/` sibling (resolved the
  same way) and writes `docs/attack-coverage.md` in this repo; its `--check` runs in
  CI's `content` job. Regenerate it when a rule's ATT&CK technique changes.

## Dependency direction (enforced by `tools/check-deps.py`, run in CI)

- `schema` is the platform boundary: event types + `Sensor`/`EventSink` contract.
  It depends on no workspace crate and stays dependency-light. Treat its public API as
  semi-frozen — changes there ripple everywhere and need explicit justification.
- `policy` sits next to `schema` as the base tier (shared agent/server types); it
  depends only on `schema`, everything else may depend on both.
- Sensor crates (`crates/sensors/*`) depend **only** on `schema`.
- Detection crates (`rules`, `sigma`, `correlator`, `verdict`, `ml`, `yara`, `enrich`)
  depend on the base tier, each other, and `store` — **never on a sensor**.
- Leaf crates (`response`, `transport`, `ipc`, `sinks`, `updater`, `config`, `store`,
  `conformance`) depend only on the base tier.
- Only the binaries (`agent/`, `watchdog/`, `cli/`, and the offline `release-tool/`) may depend on everything.

New crate? Add it to the rules in `tools/check-deps.py` in the same change.

## Platform code

- Core crates compile on all three OSes; CI tests ubuntu/windows/macos and clippy runs
  with `-D warnings`.
- Platform-specific code (`#[cfg(target_os = ...)]`, platform-only deps) is allowed
  **only inside `crates/sensors/*`, `crates/updater`, and the narrow filesystem
  permission and descriptor helpers in `crates/response/src/quarantine.rs`**. Sensors and updater compile to empty
  stubs elsewhere. `updater`'s exception is scoped narrowly: ADR-0015 is a
  Linux-first slice (the `bootstrap`/`current`/`versions` layout and its atomic
  symlink swap are POSIX-shaped by nature); ADR-0039 (proposed) is the
  Windows slice this led to (its own layout, marker swap and DACL — not shared
  with Linux's trait or module; the SCM orchestration stays in the `watchdog`
  binary); its code lands once the ADR is
  accepted, not before. macOS self-update still needs its own design
  before it gets a stub worth writing (ADR-0015 Deferred) — this
  is not a general invitation for leaf crates to grow platform branches. The
  quarantine exception is limited to mode/ACL enforcement and to opening and moving the
  source by descriptor at the privileged response boundary; see ADR-0021.
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
- Cross-cutting decisions get an ADR at the time they're made. ADRs are not in this
  repo: a code comment may cite `ADR-00xx`, but must state the reason itself — never
  "see ADR-00xx for why", never a path or link to one.

## Code quality

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
  `git config core.hooksPath tools/hooks`. CI (`ci.yml`) is the enforcement
  again on every push and PR; the gauntlet is the pre-push convenience
  that catches the same failures on one machine before CI does.
- `cargo check` / `cargo test` (default members) — works on any OS; with `--workspace`, add `--exclude sensor-linux-ebpf` (bpfel target).
- `cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets -- -D warnings` — must stay clean.
- `python3 tools/check-deps.py` — dependency direction check.
- `python3 tools/attack-coverage.py [--check]` — regenerate / verify `docs/attack-coverage.md` (needs the `rules/` sibling).
- `cargo +nightly fuzz run audit_parse` / `netlink_parse` — coverage-guided parser
  fuzzing (`fuzz/README.md`; workspace-excluded, needs `cargo-fuzz`).

## Migration order (from `old/`)

`schema` → `sensors/linux` + `rules` (walking skeleton: one synthetic
event end to end) → `correlator` + `ml` → `sensors/windows` → the rest.
