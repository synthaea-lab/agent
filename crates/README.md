# crates — Agent Modules

The Rust modules that make up the agent, each an independent workspace crate. All are
currently skeletons (doc comments only); the table tracks what each one is for and where
its code comes from. Dependency direction between them is enforced by
`tools/check-deps.py` — see `CLAUDE.md`.

| Crate | Purpose | Status | Source |
| --- | --- | --- | --- |
| `schema` | Event types + `Sensor`/`EventSink` contract — the platform boundary everything depends on | **migrated** | `old/` (PR #40) |
| `sensors/linux/wire` | Ring-buffer ABI shared by the Linux probes and loader | **migrated** | `old/` schema wire structs (issue #4) |
| `sensors/linux/userspace` | Linux sensor, userspace side (loads/drains eBPF probes, normalizes) | **migrated** | `old/` (issue #5) |
| `sensors/linux/ebpf` | Linux kernel probes (eBPF, excluded from workspace) | **migrated** | `old/` (issue #4) |
| `sensors/linux/audit` | Linux fallback sensor (auditd + fanotify) | skeleton | new development |
| `sensors/windows/etw` | Windows sensor (ETW; cmdline, registry, DNS, AMSI, ... per audit) | skeleton | migrate from `old/` |
| `sensors/windows/driver` | Windows kernel driver (minifilter, ELAM/PPL) — not a member | planned | new development |
| `sensors/macos/endpoint-security` | macOS sensor (EndpointSecurity) | skeleton | new development |
| `sensors/macos/network-extension` | macOS network/DNS sensor (NetworkExtension) | skeleton | new development |
| `rules` | Rule engine — stateless + stateful detections | **migrated** | `old/` (issue #6) |
| `sigma` | Sigma rule parsing and compilation | **migrated** | `old/` (issue #11) |
| `correlator` | Correlation + scoring — builds cases from detections | skeleton | migrate from `old/` |
| `ml` | On-device ONNX inference + feature extraction | skeleton | migrate from `old/` |
| `yara` | YARA-X file and memory scanning, feeding detections to the correlator | skeleton | new development |
| `enrich` | Cross-platform enrichment: hashing, code signing, file metadata | skeleton | new development |
| `policy` | Policy model shared by agent and control plane (versioned, signed) | skeleton | new development |
| `config` | Local agent configuration loading and validation | skeleton | new development |
| `store` | Bounded local state: entity store (process graph) + event spool | skeleton | new development |
| `response` | Response actions — kill, quarantine, isolate | skeleton | new development |
| `transport` | Agent ↔ control-plane comms — mTLS, store-and-forward | skeleton | new development |
| `ipc` | Local IPC: agent ↔ endpoint UI/CLI (named pipe / Unix socket) | skeleton | new development |
| `sinks` | Local outputs: JSONL, syslog/CEF export | **migrated** | `old/agent` (issue #7) |
| `updater` | Agent self-update + content/model distribution client (canary rings) | skeleton | new development |
| `conformance` | Sensor conformance suite — generates the capability matrix | skeleton | new development |

The binaries live outside this folder: `agent/` (the pipeline host), `watchdog/`, and
`cli/` (admin tool, an `ipc` client).

## Adding a crate

1. Add a row to the table above.
2. `cargo new --lib crates/<name>` (or `crates/sensors/<platform>/<mechanism>` for a
   sensor), add it to the workspace `members` in the root `Cargo.toml`.
3. Add it to the dependency rules in `tools/check-deps.py`.
4. Start the crate with a `//!` doc comment stating its purpose and boundaries.
