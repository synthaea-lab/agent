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
| `windows/etw` | `sensor-windows` | ETW subscriptions | `windows/driver` is a later milestone |
| `macos/endpoint-security` | `sensor-macos` | EndpointSecurity client | needs the ES entitlement |

Future crates land in their platform folder (e.g. `windows/driver`, a macOS network
extension) — no restructuring needed.

Sensors depend only on `schema` — never on detection crates or each other.
Per-platform capability differences are measured by the conformance suite
(`docs/sensors/contract.md`), not papered over.
