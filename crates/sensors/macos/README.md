# crates/sensors/macos

macOS telemetry, one crate per system facility. The EndpointSecurity and libproc calls go
through small C shims compiled on macOS only.

| Crate | Package | Mechanism |
| --- | --- | --- |
| `endpoint-security/` | `sensor-macos` | EndpointSecurity client: exec, file, persistence, session and XPC events |
| `unifiedlog/` | `sensor-macos-unifiedlog` | sudo, TCC and Gatekeeper events from `log stream` |
| `sockets/` | `sensor-macos-sockets` | libproc socket-table snapshots for listener-drift detection, no entitlement needed |
| `network-extension/` | `sensor-macos-network-extension` | Flows and DNS from a Network Extension; the Swift providers are in [`extension/`](network-extension/extension/README.md) |

EndpointSecurity and the Network Extension need restricted entitlements granted by Apple, and
the extension must be hosted by a signed app bundle; [packaging/macos](../../../packaging/macos/README.md)
describes the bundle and the approval flow. The [macOS sensor guide](../../../docs/sensors/macos/README.md)
covers each source.
