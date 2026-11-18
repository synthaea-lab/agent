# Process context

Every Linux event names a process: pid, parent, user, comm, container, and, for execs, the image,
argv, the parent's image and a few environment variables. This page explains where each comes
from, what can make it unknown, and how the sensor avoids reporting a wrong value instead of an
unknown one. That rule (unknown, never guessed) runs through all of it.

## Lineage

`ppid` cannot be read from `task_struct.real_parent` without a frozen structure layout, so the
sensor tracks forks itself in the `PROC_LINEAGE` map
([`PROC_LINEAGE`](../../../crates/sensors/linux/ebpf/src/main.rs), value
[`LineageEntry`](../../../crates/sensors/linux/wire/src/lib.rs)):

- [`raw_sched_process_fork`](../../../crates/sensors/linux/ebpf/src/raw.rs) inserts the child with
  the parent's tgid and comm, a fresh `generation`, the parent's generation, and `execd = 0`.
- [`raw_sched_process_exit`](../../../crates/sensors/linux/ebpf/src/raw.rs) removes it.
- [`record_sched_process_exec`](../../../crates/sensors/linux/ebpf/src/exec.rs) sets `execd = 1` on
  the process's own entry, after reading the entries it reports.
- At start, [`prime_proc_lineage`](../../../crates/sensors/linux/userspace/src/ebpf.rs) inserts
  every process already running, from `/proc/<pid>/stat`, in two passes so each entry can name
  its parent's generation whatever order `/proc` lists them in.

Every probe copies `ppid` and the generations into `EventMeta`
([`fill_lineage`](../../../crates/sensors/linux/ebpf/src/main.rs)). A miss leaves them 0, which
the schema carries as unknown. The map holds 65 536 entries; under a fork bomb new entries fail and
those processes report `ppid = 0`.

## Process generations

A pid is reused; a `(pid, generation)` pair is not. `generation` is `bpf_ktime_get_ns()` taken at
the fork, which every incarnation of a pid goes through, so two events with the same pid and
generation are the same process. A process primed from `/proc` never went through the sensor's fork
probe; its generation is its `starttime` with bit 63 set
([`PRIMED_GENERATION_BIT`](../../../crates/sensors/linux/wire/src/lib.rs),
[`primed_generation`](../../../crates/sensors/linux/userspace/src/proc.rs)), which a live stamp never
reaches. An unreadable `starttime` gives 0 ("no stamp").

`parent_generation` is the parent's stamp as the fork recorded it, so a lookup keyed on `ppid` can
tell whether the parent pid has since been reused. Equality is the only meaning a generation has;
it is not a start time for display.

## Exec events

The exec probe fires at `sched_process_exec`, after the new image is installed. It reports:

- **Image**: `linux_binprm.filename`, read in the probe. This is the path the kernel loaded, not
  `argv[0]`, which the caller sets freely (`execve("/tmp/x", {"/usr/bin/sshd"}, ...)`).
- **Parent comm**: from the process's lineage entry.
- **Grandparent**: from the parent's lineage entry, only when that entry's `generation` equals the
  child's `parent_generation`. If the parent exited and its pid was reused, the entry describes
  another process and is not used. `parent_execd` says whether the parent has exec'd since its own
  fork.
- **argv**: two windows of the argument block, see below.

### argv

Reading `/proc/<pid>/cmdline` when the record is drained misses short-lived processes: a lab
measurement found `systemctl` and `sudo` empty 86-99 % of the time on an idle host, and most short
commands empty under CPU load, because they exit before the drain. Those are exactly the
administrative commands rules care about. A `/proc` read is also not exec-time: a process can
rewrite its argument region before it.

So the probe reads the argument block itself, using `task->mm->arg_start..arg_end` at BTF-derived
offsets ([`read_exec_argv`](../../../crates/sensors/linux/ebpf/src/exec.rs)):

- the whole block when it is at most 1024 bytes;
- otherwise the first 768 bytes and the last 256. The tail exists so padding placed in front of a
  payload at the end of the command line does not hide it. A payload in the middle of a padded
  block is still omitted; the omitted count is the signal for that case.

Each window is one clamped `bpf_probe_read_user_buf`. The pages were just written by `execve`, so
they are expected to be resident; a failed head read reports nothing (fallback to `/proc`), a
failed tail read keeps the head.

Userspace ([`exec_argv`](../../../crates/sensors/linux/userspace/src/proc.rs)) builds tokens by
splitting the windows on NUL:

- A token cut by a window edge is kept with the bytes that were read (the last token of the head
  and the first token of the tail). Dropping it would turn `bash -c "<long script>"` into
  `bash -c`.
- The head and the tail stay separate tokens, never fused.
- No marker such as `[... N bytes omitted ...]` is written into `cmdline`: a process could write the
  same text into its own arguments. The loss is carried by two fields instead.

| Situation | `argv` | `cmdline_truncated` | `argv_omitted_bytes` |
| --- | --- | --- | --- |
| Probe read, block ≤ 1024 B | whole block | false | `Some(0)` |
| Probe read, block > 1024 B | head + tail | true | `Some(total - 1024)` |
| Head read, tail read failed | head | true | `Some(total - head)` |
| No probe read, process alive | from `/proc` | true only if the 32 KiB budget cut it | `Some(0)`, or `None` if cut |
| No probe read, process gone | empty | false | `None` |

`None` means the sensor saw nothing to measure against; a consumer must not read it as complete.
A block over the window is never completed from `/proc`, for the exec-time reason above.
`normalize::exec` applies the 32 KiB `schema::ARGV_CAPTURE_BUDGET` to every exec; the `/proc` read
stops one byte past it so the cut is detectable without copying a 2 MiB padded argv.

### Environment

[`read_proc_environ_security`](../../../crates/sensors/linux/userspace/src/proc.rs) reads
`/proc/<pid>/environ` at drain time and keeps only `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
`LD_DEBUG_OUTPUT` and `GLIBC_TUNABLES` when present. The whole environment is never captured: it
carries secrets. This read has the drain-time race the argv read used to have; a process that is
gone yields nothing.

### Parent image

The probe knows the parent's comm but not its path, and comm is whatever the process named itself.
[`ParentImages`](../../../crates/sensors/linux/userspace/src/parent_image.rs) remembers
`(pid, generation) → image` from every exec event and fills `parent_image_path` on a child's exec
with what its parent was running.

- A parent whose generation is unknown on either side, or differs from the recorded one, resolves
  to `None`.
- A parent that forked and never exec'd (a subshell, a pipeline stage) runs its forker's image.
  For it, the probe's grandparent fields are used: the forker's recorded image answers only if the
  parent never exec'd (`parent_execd == 0`) and the forker's image was already in place when the
  parent forked (the image's exec time is stored and compared with the parent's fork time). One
  case it cannot see: a subshell that did exec, if that exec event was lost.
- Processes running at start are primed from `/proc/<pid>/exe`
  ([`read_proc_images`](../../../crates/sensors/linux/userspace/src/proc.rs)).
- There is no exit event on this path, so entries are replaced or evicted. At the cap
  ([`IMAGE_CACHE_CAP`](../../../crates/sensors/linux/userspace/src/parent_image.rs), 32 768) a batch
  is evicted, preferring processes that no longer exist (asked of `/proc`) over the least recently
  used live ones. Live evictions are the real loss: they are warned about at most once a minute and
  published as [`ParentImageEvictions`](../../../crates/sensors/linux/userspace/src/parent_image.rs)
  for the agent's health beacon.

## Containers

The probe captures `bpf_get_current_cgroup_id()` while the process is still in the syscall.
Userspace maps that id to a container id by finding the cgroupfs directory with the same inode
under `/sys/fs/cgroup` ([`container_id_from_cgroupfs`](../../../crates/sensors/linux/container/src/lib.rs))
and matching a container id in its path ([`extract_container_id`](../../../crates/sensors/linux/container/src/lib.rs)):

- a 64-hex-character segment (`/docker/<id>`, cgroup v1 naming);
- `docker-<id>.scope`, `cri-containerd-<id>.scope`, or podman's `libpod-<id>.scope` (podman puts
  processes in a `container` child cgroup of the scope; the match looks at every segment).

A container's cgroup directory lives as long as the container, so this does not race a
short-lived process the way a `/proc/<pid>/cgroup` read did. Results are cached per cgroup id
([`CgroupIdCache`](../../../crates/sensors/linux/container/src/lib.rs), 4096 entries, FIFO).
The walk is bounded to depth 12.

Image and name come from Docker: on the first sighting of a container id, a background task asks
`/var/run/docker.sock` for `GET /containers/<id>/json` with a 500 ms timeout
([`lookup`](../../../crates/sensors/linux/container/src/docker.rs)). The event that triggered it goes
out with the id only; later events carry the image and name. Any failure (no Docker, containerd
only, permission, timeout) leaves them `None`. That cache is not bounded; the number of containers
over a host's uptime is expected to stay small.

Limits: cgroup v2 only (`bpf_get_current_cgroup_id` reads the v2 hierarchy); Kubernetes pod and
namespace context is not extracted; rootless podman and the podman socket are not covered; uprobe
events carry no cgroup id at all ([uprobes](uprobes.md#limits)).

## Other per-event context

- **Rename** events carry `executable_path` from `/proc/<pid>/exe` at drain time, so a rule can
  check the binary behind a name-based exclusion (`sed -i`, `perl -i`). `None` if the process is gone.
- **`finit_module`** events carry the module file path from `/proc/<pid>/fd/<fd>`; `None` if the fd
  was closed.
- **Signal** events name the target's image and unit when the target is a listed tool, captured at
  scan time because a killed target is gone by drain time ([signals](signals.md)).
