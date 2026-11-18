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

## `SIGKILL` of the agent

A `SIGKILL` aimed at the agent cannot be read live: the agent dies before it drains the record. The
eBPF sensor keeps the event in a pinned map for the restarted agent; the fallback keeps it in
auditd's log (#275):

1. The operator loads [`synthaea-kill.rules`](../../../packaging/linux/audit/synthaea-kill.rules):
   `-S kill -F a1=9`, `-S tkill -F a1=9` and `-S tgkill -F a2=9`, key `synthaea-kill`, for `arch=b64` and for
   `arch=b32` (the 32-bit entry of a 64-bit kernel, `int 0x80`; `ia32_emulation=0` closes that entry). The
   packages neither install nor load it (it changes the host's audit configuration, and an immutable
   configuration refuses it). `SIGKILL` is process-wide, so a `kill`, `tkill` or `tgkill` naming the agent's pid
   or the id of any of its threads kills the agent. The marker lists the thread ids, and the agent compares them
   with `/proc/self/task` every 5 s and rewrites the marker when they change. The kernel reads the pid and the
   signal as `int`, so the parser keeps the low 32 bits of `a0`, `a1` and `a2` (`a1=100000009` is a SIGKILL).
   Only `kill` takes a negative pid: `tkill` and `tgkill` refuse an id that is not positive. For `tgkill` the
   process is `a0`, the tgid.
2. At start, `AuditSensor` (given the state directory) reads the marker `audit-agent.pid` (pid, process group,
   start time, boot id, thread ids, uid and the newest audit serial of the previous instance) and writes its
   own, mode 0600. A clean stop removes the marker, so only a kill leaves one behind.
3. It reads the tail of `/var/log/audit/audit.log`, then `audit.log.1`, `.2` and so on up to `.9`
   ([`killrec`](../../../crates/sensors/linux/audit/src/killrec.rs), at most 16 MiB each), for the latest
   `SYSCALL` record with that key, `success=yes` and signal 9 that hit the old instance: its pid or one of its
   thread ids, its process group (`kill -9 -<pgid>` is recorded with `a0` as the 32-bit negative number, read as
   a group) or every process (`kill(-1, 9)`), written after that instance started. A group or `-1` kill counts
   only when the sender's `euid` is 0 or the agent's uid: an unprivileged `kill -9 -1` succeeds on that user's
   own processes and must not be blamed for a later crash of the agent. Within the same boot, "after that
   instance started" is the audit serial of `msg=audit(<time>:<serial>)`: the marker stores the newest serial in
   the log at start and the replay takes records with a larger one, so setting the clock back before the kill
   does not hide it. Without a serial or a boot id, it falls back to the record's timestamp. The walk stops at
   the first file whose newest record is not newer than the marker's start, so a record rotated out twice
   (`auditctl --signal rotate`) is still found. A marker with this instance's own pid (a recycled pid) or from
   another boot attributes nothing. There is no upper bound on the record's time and no wall-clock window.
4. It emits an `Event::Signal` (signal 9, sender in `meta`, target the old pid): the same event the eBPF
   replay emits, so the T1562.001 rule attributes it, High unless the sender is pid 1.

Captured on Rocky 9.8 (kernel 5.14, auditd 3.1.5, systemd 252, 2026-11-16): `kill -KILL` from a shell and
`/usr/bin/kill` leave one record each with the sender's `pid`, `ppid`, `auid`, `comm` and `exe` and the target
in `a0` (hex); a single record is in `audit.log` at once, without the 50-record flush the config suggests
(`flush = INCREMENTAL_ASYNC`, `freq = 50`); `kill -0` and SIGTERM are not recorded by these rules; `systemctl kill`
leaves no record with `kill`, `tkill`, `tgkill` or `pidfd_send_signal`, and its sender would be pid 1.

When the marker survived and no record accounts for the previous instance, the restarted agent logs a warning
(`the previous agent instance did not stop cleanly and auditd's log holds no SIGKILL record for it`) with the
old pid, the log files it read, the ones it could not read and the ones longer than the 16 MiB tail it reads
(a record in the head of such a file, possible with `max_log_file` above 16 MiB, is not looked at), instead of
staying silent.

**Limits.** No rule, no attribution. Ways to SIGKILL the agent that these rules do not record, so are not
attributed: `systemctl kill` (no record, as captured), `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and
`pidfd_send_signal`. A kill of a thread started less than 5 s earlier, not yet in the marker, is not
attributed. A default Fedora ships `-a never,task`, which removes syscall auditing from every task:
with `synthaea-kill.rules` loaded next to it nothing is recorded, not even a plain `kill -9`; the rule needs no
`never,task` ahead of it (reproduced on Fedora 43, kernel 7.2, by the reviewer of #287; Rocky 9.8 has none). Needs `/var/log/audit/audit.log` readable by the agent (root) and auditd writing
to it (`write_logs = yes`, `log_format = ENRICHED` or `RAW`; the key is read from the kernel part of the line). Residual
gaps of the marker: a pid reused within the same boot by a process that is then killed can be taken for the
agent (the boot id bounds it to one boot); with no readable log at start or a wrapped serial the replay falls
back to timestamps, and a clock set back before the kill then costs the attribution (the warning above covers
it). The `arch=b32` rules, the thread-id refresh and the serial anchor are tested on lines and files, and were
not run on a lab host after the review of #287 at `7ce68b3a`. The volume of SIGKILL records on a real
host is not measured. Tested on the captured line and on files, and run end to end on Rocky 9.8 (2026-11-16, agent built without
eBPF probes, rule loaded, agent started as a systemd unit, killed, restarted on the same state directory): the restarted agent
logged `the previous agent instance was sent SIGKILL, reporting it` and raised T1562.001 with the sender's pid and `comm`
for `kill -KILL` from bash (`comm=bash`) and for `/usr/bin/kill` (`comm=kill`); after `systemctl kill -s KILL` it reported
nothing (no record, as captured); after a clean stop and restart it reported nothing. Not run: other kernels, aarch64,
an agent that is not root, the volume of SIGKILL records.

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

[`classify`](../../../crates/sensors/linux/audit/src/classify.rs) maps one record at a time; the sensor
joins an exec's `EXECVE` records first ([Split argv](#split-argv)):

| Record type | Event | Read from the record |
| --- | --- | --- |
| `EXECVE` (1309) | `Exec` | `argc`, `a0..aN` or `aN[i]` pieces (hex-decoded), `pid`/`uid`/`gid` if present |
| `SOCKADDR` (1306) | `Connect` | `saddr` parsed as `sockaddr_in`/`in6`, `pid`/`uid`/`gid` if present |
| `AVC` (1400) | `PolicyDenial` | `scontext`, `tcontext`, `tclass`, `permissive`, `comm`, requested permissions, `path`/`name` |

The AVC body starts with free text (`avc:  denied  { read } for  pid=1234 ...`), which the
`key=value` scan folds into the first key. The requested permission set is recovered from that key
([`avc_action`](../../../crates/sensors/linux/audit/src/classify.rs)); `pid` is not. `path=`/`name=`
are hex-decoded when unquoted, otherwise a file name with a space would arrive encoded. A record
without `scontext` and `tclass` is skipped.

### Split argv

The kernel writes an argument that does not fit in the record as `aN_len=` plus pieces `aN[0]=`,
`aN[1]=`, ..., and continues a long argv in further `EXECVE` records with the same serial; only the
first carries `argc`. The sensor does not classify `EXECVE` records one at a time:
[`ExecveAssembler`](../../../crates/sensors/linux/audit/src/execve.rs) holds each exec's `EXECVE`
records, keyed by serial, and rebuilds the argv when a record of another type with that serial
(`CWD`) arrives. Records of execs on other CPUs can be queued in between, so several execs can be
in progress at once. The hold is bounded:

- 128 KiB of field values per exec, then further records are dropped;
- 16 execs, then the oldest is closed;
- 2 s of audit time, then an exec whose closing record never came is closed when the next record
  arrives.

An argv that cannot be rebuilt whole (a lost record, a short piece against `aN_len`, a bound hit)
is still emitted with the head that arrived and `cmdline_truncated` set. `classify` on a lone
`EXECVE` record flags a split exec the same way.

## The drain

`AuditSensor` runs a current-thread tokio runtime with the socket in an `AsyncFd`. Readiness is
edge-triggered, so each wake-up drains up to `DRAIN_BUDGET` (256) records, about 36 execs at seven
records each, and leaves readiness set if the budget ran out. The socket asks for an 8 MiB receive
buffer and logs what the kernel granted. `SO_RCVBUFFORCE` needs `CAP_NET_ADMIN`, which the packaged
unit grants as an ambient capability; without it, `SO_RCVBUF` is capped at `net.core.rmem_max` and the
agent warns. The default held fewer
than ten execs with a long argument, so a burst of them was mostly dropped
([#237](https://github.com/synthaea-lab/agent/issues/237)). Records are read into a 64 KiB buffer; a
longer one is parsed cut and counted. Errors are handled per kind:

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
  `EXECVE`, `CWD`, `PATH`, `PROCTITLE`, `EOE`). Apart from an exec's `EXECVE` records (see
  [Split argv](#split-argv)), the classifier does not join them, so fields that
  live on the `SYSCALL` record (`pid`, `uid`, `exe`) are 0 or absent unless the classified record
  itself carries them, and `image_path` is `argv[0]`, not the executed file.
- **No lineage**: `ppid` is always 0 and `Capabilities::parent_lineage` is `false`.
- **Connect protocol** is assumed TCP.
- **Split argv**: an exec is emitted once its `CWD` record (or a later one, see
  [Split argv](#split-argv)) arrives. An exec whose `CWD` was lost stays held until the next record
  or the sensor's exit.
- **AVC**: no pid; a rare `auditallow` grant would be classified as a denial; the object path is
  from the AVC line alone (often a bare file name).
- No file events.

## Testing

Unit tests for parse, classify, the argv assembler and normalize, and a sensor-level test of
interleaved split execs through `forward`; a deterministic never-panic suite
([`tests/robustness.rs`](../../../crates/sensors/linux/audit/tests/robustness.rs)) and a fuzz target
([`audit_parse`](../../../tests/fuzz/fuzz_targets/audit_parse.rs)) on the parser; `AvcReader` is tested
over a `socketpair`.
