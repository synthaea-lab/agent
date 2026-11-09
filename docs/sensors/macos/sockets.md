# Socket-table snapshots (macOS)

`sensor-macos-sockets` ([`crates/sensors/macos/sockets`](../../../crates/sensors/macos/sockets/src/lib.rs)) snapshots listening TCP sockets for the LISTENER-DRIFT rule. It is the one macOS source that needs **no entitlement**, so it delivers listening-port telemetry even on hosts where the EndpointSecurity grant is missing. It is the macOS sibling of the [Windows IP Helper snapshots](../windows/sockets.md) and the Linux `sock_diag` path.

## Mechanism

A libproc walk done in a C shim ([`shim/sockets_shim.c`](../../../crates/sensors/macos/sockets/shim/sockets_shim.c), built by [`build.rs`](../../../crates/sensors/macos/sockets/build.rs)): `proc_listpids`, then each process's fd table, then `PROC_PIDFDSOCKETINFO` per socket fd. `socket_fdinfo` is a large union-heavy struct, so as with the ES shim the layout stays in C and Rust receives one flat [`syn_sock_record`](../../../crates/sensors/macos/sockets/shim/sockets_shim.h) per TCP socket. TCP states are mapped to shim-owned values (`LISTEN`, `ESTABLISHED`, other), never transcribed from `TCPS_*`.

Because the walk is per process, attribution is direct: every entry carries pid, the **real** ppid, effective uid/gid and the executable path ([`SocketSnapshotEntry`](../../../crates/sensors/macos/sockets/src/raw.rs)).

Visibility follows libproc's rules. Unprivileged, only the caller's own processes resolve; as root the walk sees the whole table. Processes that exit mid-walk or are unreadable are skipped silently, and partial visibility is returned as is. Only a failure of the initial pid enumeration is an error ([`SocketsError::Snapshot`](../../../crates/sensors/macos/sockets/src/lib.rs)).

The callback into Rust only collects records, so no user code runs inside the C walk and nothing can unwind across the FFI boundary ([`snapshot.rs`](../../../crates/sensors/macos/sockets/src/snapshot.rs)).

## Events

[`snapshot`](../../../crates/sensors/macos/sockets/src/snapshot.rs) returns every TCP socket, listening and established. [`listen_port_events`](../../../crates/sensors/macos/sockets/src/snapshot.rs) maps only listeners to `Event::ListenPort` through [`listen_port_event`](../../../crates/sensors/macos/sockets/src/normalize.rs). Established sockets produce no event: connections come from the [Network Extension](network-extension.md) flow stream, and a poll echo would double-count. Snapshot semantics are those of `schema::ListenPortEvent` (poll-time timestamp, short-lived listeners invisible, value in the drift).

## How the agent uses it

[`seeded_rule_state`](../../../apps/agent/src/commands/macos.rs) seeds the LISTENER-DRIFT baseline from one snapshot at startup (listeners only, protocol TCP). [`spawn_socket_poller`](../../../apps/agent/src/commands/macos.rs) snapshots every 10 s and forwards the listener events. There is no heartbeat for this poller ([#34](https://github.com/synthaea-lab/agent/issues/34)).

## Gaps

- TCP only. UDP bound-socket snapshots are tracked in [#40](https://github.com/synthaea-lab/agent/issues/40).
- No container attribution or incarnation stamp.

## Testing

Unit tests for the raw and normalize halves run on every OS. [`tests/live_snapshot.rs`](../../../crates/sensors/macos/sockets/tests/live_snapshot.rs) (macOS only, unprivileged, in the default suite) binds a listener in the test process and checks the walk finds it with full self-attribution.
