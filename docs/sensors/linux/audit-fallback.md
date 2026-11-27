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
   with `/proc/self/task` every 5 s and rewrites the marker when they change (it also moves the anchor to the newest kernel record then). The kernel reads the pid and the
   signal as `int`, so the parser keeps the low 32 bits of `a0`, `a1` and `a2` (`a1=100000009` is a SIGKILL).
   Only `kill` takes a negative pid: `tkill` and `tgkill` refuse an id that is not positive. For `tgkill` the
   process is `a0`, the tgid.
2. At start, `AuditSensor` (given the state directory) reads the marker `audit-agent.pid` (pid, process group,
   start time, boot id, thread ids, uid, the newest kernel record of the log, its time and serial, as the
   anchor, and the pid of its watchdog) and writes its own, mode 0600. A clean stop removes the marker, and so does a stop by SIGTERM, SIGHUP
   or SIGQUIT: the kill-loudness watcher ends the process with `exit` and removes it first, so a routine
   `systemctl restart` leaves none and only a kill or a crash does.
3. It reads the tail of `/var/log/audit/audit.log`, then `audit.log.1`, `.2` and so on up to `.9`
   ([`killrec`](../../../crates/sensors/linux/audit/src/killrec.rs), at most 16 MiB each), for the latest
   `SYSCALL` record with that key, `success=yes` and signal 9 that hit the old instance: its pid or one of its
   thread ids, its process group (`kill -9 -<pgid>` is recorded with `a0` as the 32-bit negative number, read as
   a group) or every process (`kill(-1, 9)`), written after that instance started. A group or `-1` kill counts
   only when the sender's `euid` is 0 or the agent's uid: an unprivileged `kill -9 -1` succeeds on that user's
   own processes and must not be blamed for a later crash of the agent. Within the same boot, "after that
   instance started" is a position in the log, not a serial: the marker stores the header of the newest kernel
   record of the log at start (`msg=audit(<time>:<serial>)`, auditd's own `type=DAEMON_*` records skipped, their
   serial comes from another counter), the replay looks for the last line with that header from the newest file
   back, and only what follows it in log order counts, whole newer files included; the latest such record wins.
   The serial is not compared by value: the kernel restarts it at every boot and auditd appends to the same log
   across boots, so an earlier boot's record would otherwise pass with a larger serial (found by SoFrexs and
   reproduced on Fedora 43 by Jihair54). Setting the clock back before the kill does not hide it. Without an
   anchor, with no boot id, or when no file holds the anchor any more (rotated out of reach), it falls back to the
   record's timestamp, and then the walk stops at the first file whose newest record is older than the marker's
   start, so a record rotated out twice (`auditctl --signal rotate`) is still found. A marker with this instance's own pid (a recycled pid) or from
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

**The watchdog (#342).** The watchdog starts the agent with `PR_SET_PDEATHSIG` = `SIGKILL`, so a `SIGKILL` of the
watchdog ends the agent with no record naming the agent: the record names the watchdog's pid. The marker keeps that
pid (the ninth field, `-` when there is none), and a record aimed at it counts like one aimed at the agent. The agent
takes its parent for the watchdog only when its own death signal is `SIGKILL` (`prctl(PR_GET_PDEATHSIG)`, read on the
main thread, where the kernel keeps it across `execve`) and the parent is not init: a shell or a service manager that
started it is not recorded, so a kill of it is not blamed on the agent. The event's `target_pid` is the pid the signal
went to, the watchdog's, with no `target_image_path` (the rule prints `?`); the warning says that the agent died with
it. A `tkill` or `tgkill` of a thread of the watchdog (not its pid) is not attributed, as the watchdog's thread ids are
not in the marker. Unit-tested on the marker, the replay, the real `prctl` read and the line captured below. Run under the packaged unit on Debian 13.7 (kernel 6.12.107, systemd 257, auditd 4.0.2, 2026-11-24): the marker's ninth field was the watchdog's pid, and `/usr/bin/kill -KILL <watchdog>` was reported by the restarted agent (`the previous agent instance's watchdog was sent SIGKILL, which ended the agent too`, T1562.001 `pid=<sender> comm=kill … security process pid=<watchdog> (?)`), with no "did not stop cleanly" warning; a `kill -KILL` of the agent was still reported as before. The agent was built from the head of the change; the watchdog and `cli` are those of `e1567838`, unchanged in `apps/watchdog`, `apps/cli` and `packaging/` up to it. Not run: another distribution or kernel, an agent with eBPF probes under the watchdog.

**Limits.** No rule, no attribution. The agent's own watchdog also sends SIGKILL (a heartbeat stall, a probation rollback): the restarted agent reports it like any other kill (High, T1562.001, `exe=…/watchdog`), so read the `exe` before taking a watchdog restart for tampering. The eBPF path reads the heartbeat kill as Low, but this replay does not identify the watchdog ([signals.md](signals.md#a-signal-from-the-agents-watchdog), #322). Ways to SIGKILL the agent that these rules do not record, so are not
attributed: `systemctl kill` (no record, as captured), `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and
`pidfd_send_signal`. A kill of a thread started less than 5 s earlier, not yet in the marker, is not
attributed. A default Fedora ships `-a never,task`, which removes syscall auditing from every task:
with `synthaea-kill.rules` loaded next to it nothing is recorded, not even a plain `kill -9`; the rule needs no
`never,task` ahead of it (reproduced on Fedora 43, kernel 7.2, by the reviewer of #287; Rocky 9.8 has none). Needs `/var/log/audit/audit.log` readable by the agent (root, or the packaged `synthaea` user through `CAP_DAC_READ_SEARCH`) and auditd writing
to it (`write_logs = yes`, `log_format = ENRICHED` or `RAW`, any `name_format`: a `node=<name> ` prefix, which STIG-hardened RHEL sets with `name_format = hostname`, is stripped before the line is read; the key is read from the kernel part of the line). Residual
gaps of the marker: a pid or thread id reused within the same boot by a process that is then killed can be
taken for the agent (the boot id bounds it to one boot; a record aimed at an unrelated process whose pid later
becomes one of the agent's thread ids, a blocking-pool thread say, is read as a kill of the agent if the agent
then dies without a clean stop); the anchor is refreshed every 5 s with the thread list, so it stays near the end of `audit.log` and the replay
reads one or two files; with no readable log at start, or an anchor that left the log between two refreshes (more than
`num_logs` rotations in 5 s), the replay falls back to timestamps, and a clock set back before the kill then costs the attribution (the warning above covers
it). The `arch=b32` rules and the thread-id refresh were run on Fedora 43 at `74048cde` (Jihair54). The position anchor, its refresh and the marker removal on a SIGTERM stop (only the instance's own marker: a stop before the sensor replayed the predecessor's
marker leaves it for the next start, and no write follows the removal) were run on Fedora 43 (Jihair54, kernel 7.2.10, agent binary with the runtime fix) and on Rocky 9.8
(agent built from `fa18b064`, audit fallback, rule loaded, 2026-11-19): `kill -KILL` from bash, `/usr/bin/kill`, `tgkill` of a worker thread, and `kill -KILL`
followed by `service auditd rotate` (the record read from `audit.log.1`) were each reported by the restarted agent as `the previous agent instance was sent SIGKILL`
with T1562.001 and the sender's `comm`; `systemctl kill -s KILL` was not attributed (the log says no SIGKILL record); a clean stop and a `SIGTERM` stop reported nothing and removed
the marker. An agent that is not root and has no capability cannot start in the audit fallback (`audit socket open: netlink socket error: 1`, EPERM, exit 1). Volume, one lab host:
3000 `kill -KILL` in one second added 3000 `synthaea-kill` records (about 780 bytes each, `audit.log` +2.35 MB), cost the agent 0.11 s of CPU and lost none. On Rocky 9.8 at `e1567838` (2026-11-20, agent forced onto the fallback with `SystemCallFilter=~bpf`), `tkill` of a worker thread (tid different from the pid) was reported by the restarted agent (T1562.001, `comm=python3`); a kill in boot 1 followed by a reboot and a restart attributed nothing (a marker from another boot attributes nothing, by design); and a kill in boot 2, with `audit.log` still holding boot 1 serials above boot 2's first ones (986 against 177), was attributed (T1562.001, `comm=kill`). On Debian 13.7 (kernel 6.12.107, auditd 4.0.2, AppArmor, agent built from `a24313ab` without eBPF probes, 2026-11-24, issue #275) the same cases gave the same results: `kill -KILL` from bash, `/usr/bin/kill`, `tgkill` of a worker thread and a kill followed by `auditctl --signal rotate` (the record read from `audit.log.1`) were attributed (T1562.001, sender `comm`); `systemctl kill -s KILL` was not; a clean stop and a `SIGTERM` stop reported nothing and removed the marker; 3000 kills in 1 s added 3000 records and lost none. A non-root agent (`User=edr-lab`, ambient capabilities, restarted after a `kill -KILL` from root) behaved in three ways. With no capability it does not start (EPERM). With `CAP_AUDIT_READ` alone it starts and subscribes to the socket, but `audit.log` is `root:adm 0640` and it cannot read it, so the restarted agent attributes nothing: it logs `did not stop cleanly and auditd's log holds no SIGKILL record` with `read=[]` and every log file under `unreadable=`. With `CAP_AUDIT_READ` plus `CAP_DAC_READ_SEARCH` (the capabilities of the packaged unit), or with `CAP_AUDIT_READ` plus the group `adm`, it attributed the kill (T1562.001, `comm=kill`). So the fallback's attribution needs read access to `audit.log` as well as the capability. The packaged unit itself (`synthaea-agent.service` from the `.deb`, `User=synthaea`, its seven ambient capabilities, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=read-only`, run under the watchdog; the package was assembled by hand from the `e1567838` `.deb` with the `a24313ab` agent built without eBPF) was run on the same Debian 13.7 host (2026-11-24, issue #275): the agent starts on the audit fallback, opens the `NETLINK_AUDIT` socket (receive buffer 16 MiB granted, so `CAP_NET_ADMIN` works), reads `audit.log` (`read=["/var/log/audit/audit.log"] unreadable=[]`) and `audit.log.1`, and writes `audit-agent.pid` (0600, `synthaea`) in `/var/lib/synthaea`, with no sandbox denial. A `kill -KILL` of the agent process (bash, `/usr/bin/kill`) is attributed after the watchdog restarts the agent, also when `auditctl --signal rotate` runs between the kill and the restart; `systemctl kill -s KILL` (watchdog and agent) is not; a stop, a restart and a `SIGTERM` of the agent report nothing. Not run on a lab host:
commit `609fc24a` (a stop signal that beats the marker write no longer leaves the predecessor's kill to be reported twice: unit tests only),
other kernels and distributions than Fedora 43, Rocky 9.8 and Debian 13.7, aarch64, the packaged unit with a watchdog and agent built from the same commit and with the eBPF probes (the lab package mixed the `e1567838` watchdog, whose source is unchanged since, with a no-eBPF `a24313ab` agent), and the volume on a loaded real host (one host, 3000 kills of `sleep`).

**Decision on the remaining gaps (2026-11-24, taken under the owner's delegation).** The two ways to SIGKILL the agent that were unattributed were treated differently:

- `systemctl kill` is a **permanent limit**. No `kill`, `tkill`, `tgkill` or `pidfd_send_signal` record exists for the target (captured on Rocky 9.8 and Debian 13.7), and the sender would be pid 1 anyway, so there is no sender to name. Any other route would be a different mechanism (the write to `cgroup.kill`, a journal match on the unit) with its own false-positive cost, and nobody has asked for it. It is documented here and in the capabilities row instead of being chased.
- A `SIGKILL` of the **watchdog** was a **fixable gap** when this was decided (the record names the watchdog's pid and the marker lacked it). It is fixed: the marker now holds the watchdog's pid ([#342](https://github.com/synthaea-lab/agent/issues/342), see [The watchdog](#sigkill-of-the-agent)), run under the packaged unit on Debian 13.7.

The other open points of the lab matrix (aarch64, other kernels and distributions, a loaded real host, `tkill` and the previous boot under the packaged unit) were judged not worth a run: the mechanism is the same on the three kernels tried (Fedora 43 on 7.2, Rocky 9.8 on 5.14, Debian 13.7 on 6.12) and gave the same results. They stay listed above as not verified. #275, which asked whether the flow works and whether the audit fallback can attribute a SIGKILL at all, is closed: the answers are yes for a signal sent by a process, no for `systemctl kill`.

Earlier, tested on the captured line and on files and run end to end on Rocky 9.8 (2026-11-16, agent built without eBPF probes, rule loaded, agent started as a systemd unit, killed,
restarted on the same state directory): same result for `kill -KILL` from bash (`comm=bash`) and `/usr/bin/kill` (`comm=kill`), nothing for `systemctl kill -s KILL` and after a clean stop.

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
records each, and leaves readiness set if the budget ran out. The pass is `SocketDrain::drain` in
`sensor.rs`, which takes the `recv` as a closure so tests script the socket; its three loss counts
(cut records, unparseable records, `ENOBUFS` overruns) are `ThrottledCount`s, which hand back the total
only on powers of two, the moments the sensor warns. The socket asks for an 8 MiB receive
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
