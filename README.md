# Synthaea

**An open-source, truly multi-platform EDR/XDR with on-device ML detection.**

> **Status: Linux walking skeleton proven, detection depth landing.** The Linux
> pipeline runs end to end on real kernel telemetry — eBPF probes accepted by the
> verifier, events normalized, four detection engines evaluating, alerts firing on
> live attack scenarios in the lab, watchdog surviving SIGKILL. The remaining
> platforms, the control plane, and the fleet features are structured, issue-tracked,
> and dependency-ordered in **[docs/roadmap.md](docs/roadmap.md)**.

## Goals

- **True multi-platform agent** — Windows (ETW / driver), Linux (eBPF), macOS
  (EndpointSecurity), behind one formal sensor contract. No reference platform.
- **On-device ML detection** — models trained offline (Python), exported to ONNX,
  scored on the endpoint alongside the deterministic engines; every score carries
  per-feature attributions and traces to a registry model card.
- **Correlation, not alert spam** — detections are evidence, correlated into cases,
  on the host and across the fleet.
- **A control plane designed in from day one** — enrollment, policy, ingest, triage,
  and the fleet-derived signals (prevalence, cross-endpoint correlation) an attacker
  cannot reproduce by reading our code.

## The detection stack

Ten layers of defense in depth, mapped one-to-one to components in
**[docs/detection/layers.md](docs/detection/layers.md)**: signatures/hashes → static
ML → behavioral rules → behavioral ML → prevalence → attack-chain correlation →
cross-endpoint correlation → identity/network/cloud → threat intel → human/MDR.
Layers 1–4 and 6 run on-device (milliseconds, works offline); the rest is where the
control plane earns its keep — including **retrospective detection**: new intel
replayed over the telemetry lake, turning yesterday's unknown into today's case.

## Architecture

```
┌───────────────────────────── ENDPOINT ──────────────────────────────┐
│  kernel/OS: ETW+EventLog (Win) · eBPF/LSM/uprobes/netlink/journald  │
│             (Linux) · EndpointSecurity+NE+UnifiedLog (macOS)        │
│        │  one sensor contract; sources inventoried, never assumed   │
│  ┌─────▼───────────────────────────────────────────────────┐        │
│  │ sensors → schema events → enrich (hash · signature)      │        │
│  │     │                                                    │        │
│  │  store — bounded state · durable spool                   │        │
│  │  ┌──┴──────┬───────┬───────┬────────┬──────────┐         │        │
│  │  rules   sigma   yara    ml(ONNX)  intel   deception     │        │
│  │  └──┬──────┴───────┴───────┴────────┴──────────┘         │        │
│  │  correlator — detections → scored cases (Bayesian LLR)   │        │
│  │     │                                                    │        │
│  │  verdict ─► response — kill·quarantine·isolate + live    │        │
│  │     │        sessions (policy-gated, audited)            │        │
│  │  sinks · transport (mTLS, spooled) · tamper · mesh (P2P  │        │
│  │  peer attestation + posture gossip)                      │        │
│  └─────┬──────────────────────────────┬─────────────────────┘        │
│   ipc: ui (tray) · cli      watchdog · updater (canary rings)        │
└───────────────────────────────────────┼──────────────────────────────┘
                                        ▼
┌────────────────────────── CONTROL PLANE ────────────────────────────┐
│  Next.js + PostgreSQL (ADR-0001) · better-auth tenancy (ADR-0003)   │
│  ingest → datalake (full-fidelity telemetry)                        │
│  cloud-detection — streaming · scheduled · RETROSPECTIVE            │
│  fleet — cross-machine cases + adaptive posture   graph — entities  │
│  prevalence — first-seen/rarity     hunt — saved hunts → content    │
│  forensics — DFIR workbench    disruption — isolate·suspend·block   │
│  assistant — grounded LLM (narrates, never scores)                  │
│  ops — fleet health   integrations — SOAR/ticketing   export — SIEM │
│  api/console — enrollment·PKI · policy · triage · audit             │
└─────────────────────────────────────────────────────────────────────┘
```

What's real today: the full left column on Linux (sensors → enrich → store → four
engines → correlator → alerts, plus watchdog), validated live in the lab. The rest
is skeletoned with its design recorded in place and an issue per component.

## What makes it different

- **The fleet-derived half** — prevalence, cross-endpoint correlation, adaptive
  posture (a detection on one machine raises the alertness of its neighbors, over
  the server and over the P2P mesh), per-site model adaptation: signals an attacker
  cannot derive from our public code and content.
- **Deception** — per-host-unique canaries and decoy credentials: a near-zero-FP
  tripwire layer, seed-derived so decoys never transfer between hosts.
- **Detection as code** — all content versioned, PR-reviewed, and CI-enforced:
  every shipped rule must compile *and* fire on a crafted sample (this pipeline has
  already caught a rule that was silently dead in the previous iteration).
- **Honest engineering as a feature** — capability matrices generated from
  conformance runs, telemetry-source inventory with *rejected-with-reason* entries
  (`docs/sensors/sources.md`), observable loss counters on every bounded buffer,
  model cards required before any model ships, and ADRs for every locked decision.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/` | The agent's Rust modules — full table in [crates/README.md](crates/README.md) |
| `crates/sensors/` | Platform sensors by mechanism — [coverage matrices](crates/sensors/README.md), [source inventory](docs/sensors/sources.md) |
| `agent/` · `watchdog/` · `cli/` | The agent binaries |
| `server/` | Control plane — [module table](server/README.md) |
| `ui/` | Endpoint tray/notifications (unprivileged ipc client) |
| `packaging/` | MSI · notarized pkg · deb/rpm + service integration |
| `ml/` | The ML space — datasets, training, calibration, evaluation, registry |
| `rules/` | Detection content (Sigma, YARA) — CI-enforced |
| `docs/` | Specification, [detection stack](docs/detection/layers.md), [roadmap](docs/roadmap.md), ADRs |
| `lab/` | Machine matrix, provisioning, attack scenarios |
| `tools/` | check-deps and developer tooling |

## Building

`cargo check` / `cargo test` build the default members on any OS (toolchain pinned).
CI enforces fmt, dependency direction, cargo-deny, clippy `-D warnings`, and tests on
Linux/Windows/macOS, plus content and ML pipelines. The eBPF probes build on a lab
machine via `lab/provisioning/`; `lab/vagrant/` boots the validation matrix.

## License

Apache-2.0, except Linux eBPF probes (GPLv2, a kernel constraint).
