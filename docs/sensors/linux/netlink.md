# Netlink sources

[`sensor-linux-netlink`](../../../crates/sensors/linux/netlink/src/lib.rs) talks to three kernel
netlink families with hand-written clients: no probe, no special kernel configuration. It runs
where eBPF cannot and, next to eBPF, gives state the event stream does not: what is listening right
now, and how many bytes each TCP flow carried.

The crate exposes one-shot queries that return `schema` events, and
[`NetlinkPollSensor`](../../../crates/sensors/linux/netlink/src/poll.rs), the `Sensor` that polls
them. The agent only runs that sensor on its own thread
([`spawn_netlink_poller`](../../../apps/agent/src/commands/linux.rs)).

| Family | Client | Output | Privilege (observed) |
| --- | --- | --- | --- |
| `NETLINK_SOCK_DIAG` | [`socket.rs`](../../../crates/sensors/linux/netlink/src/socket.rs), [`wire.rs`](../../../crates/sensors/linux/netlink/src/wire.rs) | `ListenPort` via [`listen_port_events`](../../../crates/sensors/linux/netlink/src/lib.rs) | unprivileged works; full PID join needs root |
| `NETLINK_NETFILTER` (ctnetlink) | [`conntrack_socket.rs`](../../../crates/sensors/linux/netlink/src/conntrack_socket.rs), [`conntrack_attrs.rs`](../../../crates/sensors/linux/netlink/src/conntrack_attrs.rs) | `NetworkFlow` via [`conntrack_flow_events`](../../../crates/sensors/linux/netlink/src/lib.rs) | not characterized unprivileged |
| `NETLINK_CONNECTOR` (`CN_IDX_PROC`) | [`proc_socket.rs`](../../../crates/sensors/linux/netlink/src/proc_socket.rs), [`proc_events.rs`](../../../crates/sensors/linux/netlink/src/proc_events.rs) | `ProcEvent` (fork/exec/exit), not mapped to schema | root or `CAP_NET_ADMIN`; `EPERM` otherwise |

## The poller

Every 10 s ([`POLL_INTERVAL`](../../../crates/sensors/linux/netlink/src/poll.rs)) `NetlinkPollSensor`
calls `listen_port_events` and `conntrack_flow_events` and forwards the events to its sink. The
interval leaves room for the beacon rule, which needs three distinct flows inside a 60 s window. A
successful query calls the sensor's `on_poll_ok` callback whatever its event count, and the agent
pulses the `linux-netlink` heartbeat from it; a failure is logged once per failure streak,
so an unprivileged agent does not log the same `EPERM` every 10 s.

## Listening sockets

[`snapshot`](../../../crates/sensors/linux/netlink/src/lib.rs) sends one `SOCK_DIAG_BY_FAMILY` dump
per family (IPv4, IPv6) for TCP sockets in `LISTEN` or `ESTABLISHED`, and decodes each
`inet_diag_msg` ([`DiagMsg::parse`](../../../crates/sensors/linux/netlink/src/wire.rs)).
`sock_diag` reports a socket's inode and uid but no pid, so
[`inode_to_pids`](../../../crates/sensors/linux/netlink/src/proc_join.rs) scans every
`/proc/<pid>/fd/*` for `socket:[<inode>]`, the technique `ss` and `lsof` use. A socket can have
several pids (a listener shared by forked workers).

`listen_port_events` emits one `ListenPort` per (listening socket, pid). The pid's `comm`, `ppid`
and `gid` come from `/proc/<pid>/status` ([`proc_meta`](../../../crates/sensors/linux/netlink/src/proc_meta.rs));
`uid` comes from the kernel. A pid that cannot be resolved (exited between the reads, or another
user's process without root) is skipped, never emitted with made-up metadata. Established sockets
produce no event. The timestamp is the poll time.

Drift detection (a new listener compared with a baseline) is done by the rules, not here.

UDP: [`snapshot_udp`](../../../crates/sensors/linux/netlink/src/lib.rs) and
`listen_port_events_udp` exist (a bound UDP socket is `TCP_CLOSE` in `sock_diag`, mapped to
`SocketState::Unconnected`), but they report every bound socket including ephemeral client ports,
and `ListenPortEvent` has no protocol field to keep `udp/53` and `tcp/53` apart. The agent does not
call them ([#40](https://github.com/synthaea-lab/agent/issues/40)).

## Conntrack flows

[`dump_conntrack`](../../../crates/sensors/linux/netlink/src/lib.rs) sends an
`IPCTNL_MSG_CT_GET` dump and decodes each entry's nested attribute tree
([`ConntrackFlow::parse`](../../../crates/sensors/linux/netlink/src/conntrack_attrs.rs)):
`CTA_TUPLE_ORIG` and `CTA_TUPLE_REPLY` (each `CTA_TUPLE_IP` + `CTA_TUPLE_PROTO`), status, timeout,
`CTA_COUNTERS_ORIG/REPLY` (packets and bytes), and for TCP `CTA_PROTOINFO` → `CTA_PROTOINFO_TCP` →
`CTA_PROTOINFO_TCP_STATE`. UDP entries carry no protoinfo.

Byte counters appear only when `net.netfilter.nf_conntrack_acct=1`; it is off by default and the
crate does not change it. Without it, flows have no counters.

A conntrack entry has no pid. [`conntrack_flow_events`](../../../crates/sensors/linux/netlink/src/lib.rs)
takes a `sock_diag` snapshot right after the dump and joins each flow's tuple to an established
local socket ([`conntrack_flow_events_for`](../../../crates/sensors/linux/netlink/src/normalize.rs)).
ctnetlink does not say which end started the flow, so two orientations are tried:

- outbound: socket local = `orig.src`, socket remote = `orig.dst`;
- inbound: socket local = `orig.dst`, socket remote = `orig.src`.

For an inbound match the `orig`/`reply` counters are swapped before becoming `bytes_sent` /
`bytes_received`. `local_port` is the stable per-flow identity the beacon rule deduplicates on, so a
long-lived flow polled many times is not counted as many connections.

The two queries are back to back, not atomic: a flow or socket that changed in between is
unattributed for that poll. TCP only, because the snapshot never includes UDP sockets. A flow
nothing can attribute produces no event.

## Proc connector

[`ProcEventSubscription`](../../../crates/sensors/linux/netlink/src/proc_socket.rs) joins the
`CN_IDX_PROC` group and sends `PROC_CN_MCAST_LISTEN`; [`ProcEvent::parse`](../../../crates/sensors/linux/netlink/src/proc_events.rs)
decodes fork, exec and exit. UID/GID/SID/ptrace/comm/coredump notifications decode as
`ProcEvent::Other`. Receives time out after 2 s so a quiet system cannot hang a caller.

Its intended use is a cross-check against the eBPF stream (a gap between the two would be a tamper
signal). Nothing in the agent consumes it yet, and it has no schema mapping.

## Parser safety

Every decoder reads bytes off a socket, so it must never panic. They use checked slicing only and
return `None`/`Err` on malformed input. [`tests/robustness.rs`](../../../crates/sensors/linux/netlink/tests/robustness.rs)
feeds deterministic pseudo-random corpora to `DiagMsg::parse`, `ProcEvent::parse` and
`ConntrackFlow::parse`; [`netlink_parse`](../../../tests/fuzz/fuzz_targets/netlink_parse.rs) fuzzes all
three. Several unit tests decode real captures byte for byte (for example `REAL_LISTEN_SOCKET_HEX`
in `wire.rs`).
