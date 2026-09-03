# Synthaea

**An open-source, truly multi-platform EDR/XDR with on-device ML detection.**

> **Status: clean-slate restructure.** This repository is the fresh start of the project.
> Every file currently contains only a description of its intended purpose. Working code is
> migrated piece by piece from the previous iteration (kept locally in `old/`, not tracked here)
> after review against the new structure.

## Goals

- **True multi-platform agent** — Windows (ETW / driver), Linux (eBPF), macOS
  (EndpointSecurity), behind one formal sensor contract. No reference platform.
- **On-device ML detection** — models trained offline (Python), exported to ONNX, scored on the
  endpoint alongside a Sigma-compatible rule engine.
- **Correlation, not alert spam** — detections are evidence, correlated into cases.
- **A control plane** — enrollment, policy, ingest, triage — designed in from day one instead of
  bolted on.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/schema` | Shared event types + the `Sensor`/`EventSink` contract (the platform boundary) |
| `crates/sensors/linux/userspace` | Linux sensor — userspace side (loads and drains eBPF probes) |
| `crates/sensors/linux/ebpf` | Linux kernel probes (eBPF, built separately, GPLv2) |
| `crates/sensors/windows/etw` | Windows sensor (ETW) |
| `crates/sensors/macos/endpoint-security` | macOS sensor (EndpointSecurity framework) |
| `crates/sensors/macos/network-extension` | macOS network/DNS sensor (NetworkExtension) |
| `crates/sensors/linux/audit` | Linux fallback sensor (auditd + fanotify) |
| `crates/sensors/windows/driver` | Windows kernel driver (long-term, not a workspace member) |
| `crates/rules` | Rule engine (stateless + stateful detections) |
| `crates/sigma` | Sigma rule parsing and compilation |
| `crates/correlator` | Temporal correlation + scoring (case building) |
| `crates/ml` | On-device ML inference (ONNX) and feature extraction |
| `crates/response` | Response actions — kill, quarantine, isolate |
| `crates/transport` | Agent ↔ control-plane communication (mTLS, store-and-forward) |
| `crates/ipc` | Local IPC between agent and on-host clients (UI, CLI) |
| `crates/policy` | Policy model shared by agent and control plane |
| `crates/store` | Bounded local state: entity store + event spool |
| `crates/enrich` | Enrichment: hashing, code signing, file metadata |
| `crates/yara` | YARA-X file and memory scanning |
| `crates/sinks` | Local outputs: JSONL, syslog/CEF |
| `crates/config` | Local agent configuration |
| `crates/updater` | Self-update + content/model distribution client |
| `crates/conformance` | Sensor conformance suite |
| `agent/` | The agent binary — wires sensors, detection, response together |
| `watchdog/` | Watchdog binary — keeps the agent alive, detects tampering |
| `cli/` | Admin command-line tool — local IPC client of the agent |
| `server/` | Control plane — ingest, API, web console |
| `ui/` | Endpoint interface — tray/menu-bar app, notifications, local status |
| `ml/` | Python training pipeline — features, training, ONNX export |
| `rules/` | Detection content (Sigma and YARA rules) |
| `docs/` | Specification, architecture, ADRs |
| `lab/` | Test lab — VM setup, attack scenarios |
| `tools/` | Developer tooling and scripts |

## Building

`cargo check` on the workspace builds the stub crates on any platform. Platform sensors and the
eBPF probes are built explicitly on their target platform once implemented.

## License

Apache-2.0, except Linux eBPF probes (GPLv2, a kernel constraint).
