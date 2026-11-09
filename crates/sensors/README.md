# crates/sensors

Platform sensors, one folder per operating system and one crate per collection mechanism.
Each crate turns one OS facility into `schema::Event` values through the `Sensor`/`EventSink`
contract defined in [`schema`](../schema/src/sensor.rs).

This folder is the only place in the workspace where platform-specific code and
target-gated dependencies are allowed. Every sensor compiles to an empty stub on other
targets, so `cargo check` and `cargo test` work on any host, and the pure parsing and
normalization code is tested on all three operating systems.

| Folder | Mechanisms | Guide |
| --- | --- | --- |
| [`linux/`](linux/README.md) | eBPF probes and loader, BPF-LSM, uprobes, netlink, journald, service logs, process memory, audit fallback | [docs/sensors/linux](../../docs/sensors/linux/README.md) |
| [`windows/`](windows/README.md) | ETW, Event Log, socket-table snapshots, minifilter client and kernel driver | [docs/sensors/windows](../../docs/sensors/windows/README.md) |
| [`macos/`](macos/README.md) | EndpointSecurity, unified log, socket-table snapshots, Network Extension | [docs/sensors/macos](../../docs/sensors/macos/README.md) |

Sensors depend only on `schema`, never on a detection crate or on each other;
[`tools/check-deps.py`](../../tools/check-deps.py) enforces it.
