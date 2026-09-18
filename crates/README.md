# crates — Agent Modules

The Rust modules that make up the agent, each an independent workspace crate. The table
tracks what each one is for, its current implementation state, and where its code
comes from. Dependency direction between them is enforced by `tools/check-deps.py` —
see `CLAUDE.md`.

**Status legend** (last refreshed 2026-09-17):

- **built** — implementation live, code exercised by other crates or by the agent.
- **partial** — non-trivial implementation but declared scope is not yet met (open
  issues track what remains).
- **skeleton** — `//!` doc comment only, no code yet.

| Crate | Purpose | Status | Source |
| --- | --- | --- | --- |
| `schema` | Event types + `Sensor`/`EventSink` contract — the platform boundary everything depends on | **built** | migrated from `old/` (PR #40) |
| `sensors/linux/wire` | Ring-buffer ABI shared by the Linux probes and loader | **built** | migrated from `old/` schema wire structs (issue #4) |
| `sensors/linux/userspace` | Linux sensor, userspace side (loads/drains eBPF probes, normalizes) | **built** | migrated from `old/` (issue #5) |
| `sensors/linux/ebpf` | Linux kernel probes (eBPF, excluded from workspace) | **built** | migrated from `old/` (issue #4) |
| `sensors/linux/netlink` | Linux netlink sensor (conntrack, listener drift — #92) | **built** | new development (issue #92) |
| `sensors/linux/audit` | Linux fallback sensor (auditd + fanotify) | skeleton | new development |
| `sensors/linux/uprobes` | Linux uprobes sensor (TLS + shell readline — #90) | partial | new development, in-flight PR #178 |
| `sensors/windows/etw` | Windows sensor (ETW: process/network/file, F-1..F-7 fixed; expansion #21) | **built** | migrated from `old/` via edr@pre-migration-translations (issue #20) |
| `sensors/windows/eventlog` | Windows sensor (eventlog polling: 7045/4698/4720 persistence + logon events — #94) | **built** | new development (issue #94), see ADR-0004 |
| `sensors/windows/driver` | Windows kernel driver (minifilter, ELAM/PPL) — not a member | planned | new development |
| `sensors/macos/endpoint-security` | macOS sensor (EndpointSecurity) | skeleton | new development |
| `sensors/macos/network-extension` | macOS network/DNS sensor (NetworkExtension) | skeleton | new development |
| `sensors/macos/unifiedlog` | macOS system-log sensor (unified log) | skeleton | new development |
| `rules` | Rule engine — stateless + stateful detections | **built** | migrated from `old/` (issue #6) |
| `sigma` | Sigma rule parsing and compilation | **built** | migrated from `old/` (issue #11) |
| `correlator` | Correlation + scoring — builds cases from detections | **built** | migrated from `old/` (issue #12) |
| `ml` | On-device ONNX inference + feature extraction (behaviour vector + correlation vector + scorer) | **built** | migrated from `old/`, extended per ADR-0002/0008 |
| `yara` | YARA-X file scanning: budgeted queue, content suite in CI | **built** | issue #17 |
| `intel` | IOC matching: hash/IP/domain indicator sets, canary-ring distributed | skeleton | new development |
| `enrich` | Cross-platform enrichment: cached SHA-256 + code-signature verdicts | **built** | issue #16 |
| `policy` | Policy model shared by agent and control plane (versioned, signed) | partial | new development — helpers + `EventLogPolicy`, extension in-flight per ADR-0010 (issue #23) |
| `config` | Local agent configuration loading and validation | skeleton | new development (issue #19) |
| `store` | Bounded local state: LRU-bounded maps (BoundedMap) + durable event spool | **built** | issue #15, two-phase drain/ack per #108 |
| `response` | Endpoint actions: automated (kill/quarantine/isolate) + live-response sessions (`response::live`) | skeleton | new development (M6) |
| `transport` | Agent ↔ control-plane comms — mTLS, store-and-forward | **built** | new development, mTLS + event upload landed (commit `29ab5d5`) |
| `ipc` | Local IPC: agent ↔ endpoint UI/CLI (named pipe / Unix socket) | skeleton | new development (issue #26) |
| `sinks` | Local outputs: JSONL, syslog/CEF export | **built** | migrated from `old/agent` (issue #7) |
| `updater` | Agent self-update + content/model distribution client (canary rings) | skeleton | new development |
| `conformance` | Sensor conformance suite — generates the capability matrix | skeleton | new development |
| `tamper` | Runtime tamper protection: self-integrity, sensor-silence, protected resources | partial | new development, primitives shipped; wiring open |
| `mesh` | Agent peer mesh: signed attestation heartbeats + heighten-only posture gossip | skeleton | new development (issue #79) |
| `deception` | Per-host canaries and decoy credentials — near-zero-FP tripwires | skeleton | new development |
| `device-control` | Removable-media telemetry + policy-gated control (USB first) | skeleton | new development (issue #84) |
| `inventory` | Diffed asset inventory: packages, services, autoruns, ports | skeleton | new development (issue #87) |

The binaries live outside this folder: `agent/` (the pipeline host), `watchdog/`, and
`cli/` (admin tool, an `ipc` client).

## Adding a crate

1. Add a row to the table above.
2. `cargo new --lib crates/<name>` (or `crates/sensors/<platform>/<mechanism>` for a
   sensor), add it to the workspace `members` in the root `Cargo.toml`.
3. Add it to the dependency rules in `tools/check-deps.py`.
4. Start the crate with a `//!` doc comment stating its purpose and boundaries.

## Keeping this table fresh

The `Status` column drifts as PRs land — an audit at each milestone bump (`git log
--diff-filter=A --name-only --since=<last audit> crates/*/src/*.rs`) is the cheap
way to catch new implementation without waiting for a full crate to become
"built". A crate should not stay "skeleton" if any of its `.rs` files exceed the
docstring; it should move to "partial" as soon as executable code lands.
