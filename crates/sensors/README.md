# crates/sensors — Platform Sensors

One folder per platform, one crate per collection mechanism inside it. Every sensor
implements the same `Sensor`/`EventSink` contract from `schema`. This folder is the
**only** place in the workspace where platform-specific code and target-gated
dependencies are allowed; each sensor compiles to an empty stub on foreign targets so
`cargo check --workspace` works everywhere.

| Path | Package | Mechanism | Notes |
| --- | --- | --- | --- |
| `linux/userspace` | `sensor-linux` | eBPF userspace loader | pairs with `linux/ebpf` |
| `linux/ebpf` | `sensor-linux-ebpf` | eBPF kernel probes | GPLv2, excluded from workspace, eBPF toolchain |
| `linux/audit` | `sensor-linux-audit` | auditd + fanotify | fallback where eBPF is unavailable |
| `linux/uprobes` | `sensor-linux-uprobes` | eBPF uprobes | TLS plaintext taps, shell readline |
| `linux/lsm` | `sensor-linux-lsm` | BPF-LSM hooks | io_uring-proof observation + inline blocking |
| `linux/netlink` | `sensor-linux-netlink` | sock_diag/conntrack/proc-connector | zero-probe supplementary source |
| `linux/journal` | `sensor-linux-journal` | journald | logins, service lifecycle |
| `windows/eventlog` | `sensor-windows-eventlog` | EvtSubscribe channels | driverless logons/service-install telemetry |
| `macos/unifiedlog` | `sensor-macos-unifiedlog` | OSLog predicates | auth/TCC/Gatekeeper context |
| `windows/etw` | `sensor-windows` | ETW subscriptions | the user-mode base (audit P1–P8 scope) |
| `windows/driver` | — | kernel driver (minifilter, ELAM/PPL) | long-term, own build/signing pipeline, not a member |
| `macos/endpoint-security` | `sensor-macos` | EndpointSecurity client | needs the ES entitlement |
| `macos/network-extension` | `sensor-macos-network-extension` | NetworkExtension | DNS + flow telemetry ES lacks |

The full mechanism inventory (used / planned / rejected-with-reason) lives in
`docs/sensors/sources.md`. Each platform folder has a README with its
telemetry-source coverage matrix — which
sources exist, which mechanism carries them, and what lands where.

Sensors depend only on `schema` — never on detection crates or each other.
Per-platform capability differences are measured by the conformance suite
(`docs/sensors/contract.md`), not papered over.
