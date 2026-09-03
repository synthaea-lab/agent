# crates — Agent Modules

The Rust modules that make up the agent, each an independent workspace crate. All are
currently skeletons (doc comments only); the table tracks what each one is for and where
its code comes from. Dependency direction between them is enforced by
`tools/check-deps.py` — see `CLAUDE.md`.

| Crate | Purpose | Status | Source |
| --- | --- | --- | --- |
| `schema` | Event types + `Sensor`/`EventSink` contract — the platform boundary everything depends on | skeleton | migrate from `old/` |
| `sensors/linux/userspace` | Linux sensor, userspace side (loads/drains eBPF probes) | skeleton | migrate from `old/` |
| `sensors/linux/ebpf` | Linux kernel probes (eBPF, GPLv2, excluded from workspace) | skeleton | migrate from `old/` |
| `sensors/windows/etw` | Windows sensor (ETW) | skeleton | migrate from `old/` |
| `sensors/macos/endpoint-security` | macOS sensor (EndpointSecurity) | skeleton | new development |
| `rules` | Rule engine — stateless + stateful detections | skeleton | migrate from `old/` |
| `sigma` | Sigma rule parsing and compilation | skeleton | migrate from `old/` |
| `correlator` | Correlation + scoring — builds cases from detections | skeleton | migrate from `old/` |
| `ml` | On-device ONNX inference + feature extraction | skeleton | migrate from `old/` |
| `response` | Response actions — kill, quarantine, isolate | skeleton | new development |
| `transport` | Agent ↔ control-plane comms — mTLS, store-and-forward | skeleton | new development |

Planned, not yet created (add here first, create the crate when work starts, and extend
`tools/check-deps.py` in the same change):

| Crate | Purpose |
| --- | --- |
| `yara` | YARA-X file/memory scanning, feeding detections to the correlator |
| `config` | Agent configuration loading and validation, shared by binaries |
| `store` | Bounded local state — entity store (process graph), event spool |

The binaries live outside this folder: `agent/` (the pipeline host) and `watchdog/`.

## Adding a crate

1. Add a row to the table above.
2. `cargo new --lib crates/<name>` (or `crates/sensors/<platform>/<mechanism>` for a
   sensor), add it to the workspace `members` in the root `Cargo.toml`.
3. Add it to the dependency rules in `tools/check-deps.py`.
4. Start the crate with a `//!` doc comment stating its purpose and boundaries.
