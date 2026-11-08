# Socket-table snapshots (Windows)

`sensor-windows-sockets` ([`crates/sensors/windows/sockets`](../../../crates/sensors/windows/sockets/src/lib.rs)) takes periodic snapshots of the TCP listener table and the UDP endpoint table. It feeds the LISTENER-DRIFT rule: ETW's Kernel-Network provider reports connects and sends, but nothing in ETW says "this process is now accepting connections on port N". It is the Windows sibling of the Linux netlink and [macOS libproc](../macos/sockets.md) snapshots.

## Mechanism

[`snapshot`](../../../crates/sensors/windows/sockets/src/snapshot.rs) reads four tables and joins them with one Toolhelp process snapshot:

| Table | Call | Contents |
| --- | --- | --- |
| TCP IPv4, IPv6 | `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)` | listening sockets only |
| UDP IPv4, IPv6 | `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` | every bound UDP endpoint, clients included |

Each row gives the owning pid. The process snapshot adds `ppid` and the executable name; both are `None` when the owner exited mid-poll or the snapshot failed ([`ListenerEntry`](../../../crates/sensors/windows/sockets/src/raw.rs)). No privilege is needed: the tables are readable by everyone, and only the owner attribution of protected processes can come back empty, in which case it is reported empty.

Implementation details:

- The table is fetched with a sizing call then a fill call. It can grow in between (a service binding mid-poll), so the fetch retries up to 4 times ([`TABLE_FETCH_ATTEMPTS`](../../../crates/sensors/windows/sockets/src/snapshot.rs)).
- Rows are read from an owned byte buffer with the row count clamped to what the buffer holds ([`rows`](../../../crates/sensors/windows/sockets/src/snapshot.rs)), not trusted.
- Addresses and ports are stored in network byte order in the rows ([`ipv4_from_row`, `port_from_row`](../../../crates/sensors/windows/sockets/src/raw.rs)); the upper two bytes of the port field are undefined and ignored.

## UDP filter

The UDP table has no listener view. On a measured Windows 11 desktop most UDP entries were client sockets on ephemeral ports (browsers, media and chat apps), and they stayed bound for many polls, so "still bound next poll" does not separate them from services. A service that clients must find uses a fixed port, and fixed ports sit below the dynamic range.

[`is_drift_relevant`](../../../crates/sensors/windows/sockets/src/raw.rs) keeps every TCP listener and a UDP socket only when its port is outside [`EPHEMERAL_UDP_PORTS`](../../../crates/sensors/windows/sockets/src/raw.rs) (49152-65535, the default dynamic range since Vista). The range is fixed because no documented API returns the host's setting. Getting it wrong only moves noise: a range moved lower makes some client sockets look like services.

Consequence: a UDP listener that binds an ephemeral-range port on purpose is invisible to LISTENER-DRIFT. Its traffic still reaches the ETW network stream.

[`snapshot_for_drift`](../../../crates/sensors/windows/sockets/src/snapshot.rs) and [`listen_port_events_for_drift`](../../../crates/sensors/windows/sockets/src/snapshot.rs) apply the filter; [`snapshot`](../../../crates/sensors/windows/sockets/src/snapshot.rs) returns the unfiltered table.

## Events

[`listen_port_event`](../../../crates/sensors/windows/sockets/src/normalize.rs) maps one entry to `Event::ListenPort` with the protocol (6 or 17). Snapshot semantics follow `schema::ListenPortEvent`: the timestamp is the poll time, a listener that opens and closes between polls is never seen, and the value is in the drift between snapshots. `user` is `Unknown` (the table carries no token, and opening each owner's token per poll would cost a handle per listener for a field the rule does not read). Container and incarnation stamp are not filled.

Only listeners are reported. Connections are the ETW stream's job, and a poll echo would double-count them.

## How the agent uses it

There is no `Sensor` implementation. In [`agent/src/commands/windows.rs`](../../../agent/src/commands/windows.rs):

1. [`seeded_rule_state`](../../../agent/src/commands/windows.rs) takes one `snapshot_for_drift` at startup and seeds the LISTENER-DRIFT baseline with `(address, port, protocol)`. A snapshot failure leaves the baseline empty and is logged.
2. [`spawn_socket_poller`](../../../agent/src/commands/windows.rs) runs `listen_port_events_for_drift` every 10 s and forwards each entry. A successful snapshot pulses the `windows-sockets` heartbeat (30 s deadline), even when it holds no listeners. A failed one is logged and does not pulse.

## Errors

[`SocketsError::Table`](../../../crates/sensors/windows/sockets/src/lib.rs) names the table (TCP or UDP), the address family and the Win32 code. A failed process snapshot is not an error: entries then carry only the pid.

## Testing

- Unit tests for row decoding, the drift filter and event mapping (`raw.rs`, `normalize.rs`), on every OS.
- [`tests/live_snapshot.rs`](../../../crates/sensors/windows/sockets/tests/live_snapshot.rs) (Windows, unprivileged, in the default suite) binds a TCP listener and a UDP socket on the same loopback port, snapshots, and checks that both are found and attributed to the test process with the right protocol.

Linux and macOS still report TCP listeners only; the cross-platform UDP work is tracked in [#40](https://github.com/synthaea-lab/agent/issues/40).
