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

## Architecture

The system has two halves: an **agent** on every endpoint that observes, detects, and
responds locally, and a **control plane** that manages the fleet and turns detections
into cases.

```
┌───────────────────────────── ENDPOINT ──────────────────────────────┐
│                                                                     │
│   kernel/OS: ETW (Windows) · eBPF (Linux) · EndpointSecurity (macOS)│
│        │                                                            │
│  ┌─────▼───────────────────────────────────────────────────┐        │
│  │ sensors  — platform-specific, one shared contract        │        │
│  │     │  normalized events (schema)                        │        │
│  │  enrich — hashes, code signing, file metadata            │        │
│  │     │                                                    │        │
│  │  store — entity store (process graph) + event spool      │        │
│  │     │                                                    │        │
│  │  ┌──┴────────┬─────────┬────────┐                        │        │
│  │  rules     sigma      yara     ml (ONNX)   ← detection   │        │
│  │  └──┬────────┴─────────┴────────┘                        │        │
│  │  correlator — detections → scored cases (Bayesian LLR)   │        │
│  │     │                                                    │        │
│  │  verdict ──► response — kill · quarantine · isolate      │        │
│  │     │              (gated by policy)                     │        │
│  │  sinks (JSONL, syslog/CEF)   transport (mTLS, spooled)   │        │
│  └─────┬──────────────────────────────┬─────────────────────┘        │
│        │ ipc                          │                              │
│   ui (tray) · cli          watchdog · updater                        │
└───────────────────────────────────────┼──────────────────────────────┘
                                        ▼
┌────────────────────────── CONTROL PLANE ────────────────────────────┐
│  Next.js + PostgreSQL (ADR-0001)                                    │
│  ingest — events, detections, heartbeats (silence is a detection)   │
│  api    — enrollment/PKI · policy · fleet inventory · audit log     │
│  console— case-centric triage · fleet health · content/model rings  │
└─────────────────────────────────────────────────────────────────────┘
```

How to read it:

1. **Sensors** capture kernel-level telemetry with whatever mechanism each OS offers
   (ETW, eBPF, EndpointSecurity), and normalize it into one shared event schema — the
   `schema` crate is the platform boundary, and the only thing sensors and detection
   share. A conformance suite generates the honest per-platform capability matrix.
2. **Detection** runs on-device, on four engines fed by the same events: the stateful
   rule engine, compiled Sigma content, YARA-X content scanning, and ONNX models
   trained offline by the Python pipeline (`ml/`). Events are enriched (hashes, code
   signatures) and contextualized against the entity store before evaluation.
3. **Correlation** turns individual detections into scored cases per entity — the
   agent escalates campaigns, not single events, and the console triages cases.
4. **Response** executes verdicts inline (kill, quarantine, isolate), gated by the
   signed `policy` distributed from the control plane, and audited.
5. **Self-defense and operations**: a separate `watchdog` process restarts and
   attests the agent; `updater` handles self-update and content/model canary rings;
   `transport` spools events through outages — and agent silence is itself a
   server-side detection. On-host visibility comes from the `ui` tray app and `cli`,
   both unprivileged clients of the agent over local `ipc`.
6. **The control plane** is one Next.js + PostgreSQL app: agent-facing ingest,
   management API (enrollment, policy, audit), and the analyst console.

Dependency direction between the agent's crates is mechanically enforced
(`tools/check-deps.py`, in CI): sensors know only the schema; detection never touches
sensors; only the binaries see everything.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/` | The agent's Rust modules — see [crates/README.md](crates/README.md) for the full table |
| `crates/schema` | Shared event types + the `Sensor`/`EventSink` contract (the platform boundary) |
| `crates/sensors/` | Platform sensors, grouped by platform — [coverage matrices per platform](crates/sensors/README.md) |
| `agent/` | The agent binary — wires sensors, detection, response together |
| `watchdog/` | Watchdog binary — keeps the agent alive, detects tampering |
| `cli/` | Admin command-line tool — local IPC client of the agent |
| `server/` | Control plane — Next.js + PostgreSQL: ingest, API, console |
| `ui/` | Endpoint interface — tray/menu-bar app, notifications, local status |
| `packaging/` | Installers and service integration per platform (MSI, pkg, deb/rpm) |
| `ml/` | Python training pipeline — features, training, ONNX export |
| `rules/` | Detection content (Sigma and YARA rules) |
| `docs/` | Specification, architecture, ADRs |
| `lab/` | Test lab — machine matrix, provisioning, attack scenarios |
| `tools/` | Developer tooling and scripts |

## Building

`cargo check` on the workspace builds the stub crates on any platform (toolchain pinned
in `rust-toolchain.toml`). Platform sensors and the eBPF probes are built explicitly on
their target platform once implemented. CI runs fmt, dependency-direction and
cargo-deny checks, plus clippy and tests on Linux, Windows, and macOS.

## License

Apache-2.0, except Linux eBPF probes (GPLv2, a kernel constraint).
