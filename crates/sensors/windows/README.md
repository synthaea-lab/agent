# crates/sensors/windows

Windows telemetry from user mode, plus the kernel driver that adds file-system visibility.

| Crate | Package | Mechanism |
| --- | --- | --- |
| `etw/` | `sensor-windows` | ETW session: process, file, network, registry, DNS, PowerShell, AMSI, WMI and authentication providers |
| `eventlog/` | `sensor-windows-eventlog` | Event Log channels: logons, service installs, scheduled tasks, account creation, Defender, AppLocker, WDAC and RDP |
| `sockets/` | `sensor-windows-sockets` | TCP and UDP socket-table snapshots for listener-drift detection |
| `minifilter/` | `sensor-windows-minifilter` | User-mode client of the minifilter's communication port |
| [`driver/`](driver/README.md) | none | The `SynthaeaFilter` file-system minifilter, in C, built with the WDK |

The Rust crates build with Cargo on any host and compile to stubs off Windows. The driver is
not a Cargo member; it has its own build. The
[Windows sensor guide](../../../docs/sensors/windows/README.md) covers each source and its
liveness checks.
