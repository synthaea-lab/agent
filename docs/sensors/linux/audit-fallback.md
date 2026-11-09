# Audit fallback

[`sensor-linux-audit`](../../../crates/sensors/linux/audit/src/lib.rs) reads the kernel audit stream
over `NETLINK_AUDIT`. It has two uses:

- [`AuditSensor`](../../../crates/sensors/linux/audit/src/sensor.rs): the primary sensor when eBPF
  cannot run (no BTF, no privilege for BPF, lockdown, verifier refusal). Exec and connect only.
- [`AvcReader`](../../../crates/sensors/linux/audit/src/avc.rs): SELinux AVC denials next to the eBPF
  sensor, because nothing else produces them.

fanotify was considered as the file-event source of this fallback and not built; the fallback has
no file events.

## The socket

[`AuditSocket::open`](../../../crates/sensors/linux/audit/src/socket.rs) opens a raw
`NETLINK_AUDIT` socket and joins the `AUDIT_NLGRP_READLOG` multicast group. It needs
`CAP_AUDIT_READ` (or root). It never sends `AUDIT_SET` or rule commands, so it coexists with a
running `auditd` instead of displacing it, and it receives only what the host's audit configuration
emits: exec and connect records appear only if audit rules generate them.

Netlink multicast delivers one copy of each record to every subscribed socket, so `AvcReader` and
`AuditSensor` do not steal records from each other or from `auditd`.

## Parsing

[`parse_audit_message`](../../../crates/sensors/linux/audit/src/parse.rs) reads the 16-byte
`nlmsghdr`, takes the record type from `nlmsg_type`, and parses the text payload
`audit(<sec>.<ms>:<serial>): key=value ...`. The kernel's netlink form has no `type=... msg=`
prefix; only auditd's log lines do. Values the kernel hex-encoded arrive unquoted; the parser
records which keys were unquoted (`unquoted_fields`) so only those are hex-decoded, and a quoted
value that merely looks like hex (a file named `6162`) passes unchanged.

## Classification

[`classify`](../../../crates/sensors/linux/audit/src/classify.rs) maps one record at a time:

| Record type | Event | Read from the record |
| --- | --- | --- |
| `EXECVE` (1309) | `Exec` | `argc`, `a0..aN` (hex-decoded), `pid`/`uid`/`gid` if present |
| `SOCKADDR` (1306) | `Connect` | `saddr` parsed as `sockaddr_in`/`in6`, `pid`/`uid`/`gid` if present |
| `AVC` (1400) | `PolicyDenial` | `scontext`, `tcontext`, `tclass`, `permissive`, `comm`, requested permissions, `path`/`name` |

The AVC body starts with free text (`avc:  denied  { read } for  pid=1234 ...`), which the
`key=value` scan folds into the first key. The requested permission set is recovered from that key
([`avc_action`](../../../crates/sensors/linux/audit/src/classify.rs)); `pid` is not. `path=`/`name=`
are hex-decoded when unquoted, otherwise a file name with a space would arrive encoded. A record
without `scontext` and `tclass` is skipped.

## The drain

`AuditSensor` runs a current-thread tokio runtime with the socket in an `AsyncFd`. Readiness is
edge-triggered, so each wake-up drains up to `DRAIN_BUDGET` (256) records, about 36 execs at seven
records each, and leaves readiness set if the budget ran out. Errors are handled per kind:

| Condition | Behaviour |
| --- | --- |
| Unparseable record | skipped, counted, logged at powers of two |
| `ENOBUFS` | the kernel dropped records (socket buffer overrun); counted, logged at powers of two, the socket keeps working |
| `EAGAIN` | readiness cleared |
| other recv error | the sensor returns an error |

Timestamps come from the record header (seconds and milliseconds), not from the receive time.

## The AVC reader

The agent opens `AvcReader` only when eBPF is primary
([`starts_avc_reader`](../../../apps/agent/src/commands/linux.rs)); when `AuditSensor` is primary it
already classifies AVC records, and a second reader would duplicate them. On a host with SELinux
active, a failed open is reported as a degraded `linux-avc` source and retried; without SELinux it
is skipped quietly. `AvcReader::drain` uses the same 256-record budget and the same unparsed
counter, and keeps only `PolicyDenial`.

## Limits

- **One record at a time.** An audit event is several records sharing a serial (`SYSCALL`,
  `EXECVE`, `CWD`, `PATH`, `PROCTITLE`, `EOE`). The classifier does not join them, so fields that
  live on the `SYSCALL` record (`pid`, `uid`, `exe`) are 0 or absent unless the classified record
  itself carries them, and `image_path` is `argv[0]`, not the executed file.
- **No lineage**: `ppid` is always 0 and `Capabilities::parent_lineage` is `false`.
- **Connect protocol** is assumed TCP.
- **Long arguments** are logged by the kernel as `aN_len` plus `aN[i]` pieces, possibly across
  several `EXECVE` records; such an exec produces no event
  ([#51](https://github.com/synthaea-lab/agent/issues/51)).
- **AVC**: no pid; a rare `auditallow` grant would be classified as a denial; the object path is
  from the AVC line alone (often a bare file name).
- No file events.

## Testing

Unit tests for parse, classify and normalize; a deterministic never-panic suite
([`tests/robustness.rs`](../../../crates/sensors/linux/audit/tests/robustness.rs)) and a fuzz target
([`audit_parse`](../../../tests/fuzz/fuzz_targets/audit_parse.rs)) on the parser; `AvcReader` is tested
over a `socketpair`.
