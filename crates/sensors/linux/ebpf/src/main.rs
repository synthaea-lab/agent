// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![no_std]
#![no_main]

mod cred;
mod file;
mod kernel;
mod lsm;
mod net;
mod procmem;
mod raw;
mod uprobe;

use aya_ebpf::{
    Global,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{
    ARGV_HEAD_BYTES, ARGV_TAIL_BYTES, ARGV_WINDOW_BYTES, ExecEvent, ExecRecord, LineageEntry,
    MountEvent, SignalEvent, TASK_COMM_LEN,
};

// Raw scheduler tracepoints expose task pointers instead of formatted event records.
// Their field offsets come from the running kernel's BTF in `userspace/src/btf.rs`;
// syscall arguments are decoded from `pt_regs` and passed to the existing handlers.

/// Ring buffer shared with userspace for `exec` events. `ExecEvent` is assembled in
/// the per-CPU `EXEC_SCRATCH` entry (not on the stack — `image` is `MAX_PATH_LEN`
/// bytes) and emitted with a single `output` copy — the standard libbpf/Tetragon
/// "heap map" pattern. Filling a reserved ring-buffer slot field by field instead
/// needs per-byte loops over MAX_PATH_LEN, which blow the verifier's 1M-instruction
/// budget on pre-6.6 kernels (5.15, 6.1).
///
/// 512 KiB since a record carries the argv bytes it read (<https://github.com/synthaea-lab/agent/issues/48>, ADR-0045): a record is the
/// fixed `ExecEvent` plus its command line, so this holds about as many as 256 KiB of fixed
/// records did.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Per-CPU scratch for building one `ExecRecord` off the stack (see `EXEC_EVENTS`).
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecRecord> = PerCpuArray::with_max_entries(1, 0);

// argv at exec (https://github.com/synthaea-lab/agent/issues/48). Userspace sets these from the kernel's BTF (`btf.rs`,
// `ExecArgvOffsets`) and `EXEC_ARGV_ENABLED` only when all three were found; left at zero
// the probe reads no argv and userspace falls back to `/proc/<pid>/cmdline`.
#[unsafe(no_mangle)]
static EXEC_ARGV_ENABLED: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static TASK_MM_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static MM_ARG_START_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
static MM_ARG_END_OFFSET: Global<u32> = Global::new(0);

/// Reads the current task's argument block into `rec.argv` (<https://github.com/synthaea-lab/agent/issues/48>, ADR-0045): all of it when it
/// fits in `ARGV_WINDOW_BYTES`, else the first `ARGV_HEAD_BYTES` and the last `ARGV_TAIL_BYTES`.
/// At `sched_process_exec` the new `mm` is installed and `execve` has just copied the strings
/// onto the new stack, so `arg_start..arg_end` is this exec's argv. A failed head read leaves
/// both lengths at zero (userspace falls back to `/proc`); a failed tail read keeps the head.
/// Returns the number of argv bytes written after the fixed event, at most `ARGV_WINDOW_BYTES`.
///
/// # Safety
/// `rec` points at the per-CPU scratch entry, whose `event` the caller zeroed.
unsafe fn read_exec_argv(rec: *mut ExecRecord) -> usize {
    if EXEC_ARGV_ENABLED.load() == 0 {
        return 0;
    }
    // SAFETY: helper calls on the current task; every kernel pointer read goes through
    // `bpf_probe_read_kernel` and every user read through `bpf_probe_read_user_buf`, both of
    // which fail instead of faulting. `rec` is the caller's valid scratch entry.
    unsafe {
        let task = aya_ebpf::helpers::bpf_get_current_task() as *const u8;
        let Ok(mm) =
            bpf_probe_read_kernel(task.add(TASK_MM_OFFSET.load() as usize).cast::<*const u8>())
        else {
            return 0;
        };
        if mm.is_null() {
            return 0;
        }
        let (Ok(start), Ok(end)) = (
            bpf_probe_read_kernel(mm.add(MM_ARG_START_OFFSET.load() as usize).cast::<u64>()),
            bpf_probe_read_kernel(mm.add(MM_ARG_END_OFFSET.load() as usize).cast::<u64>()),
        ) else {
            return 0;
        };
        if end <= start {
            return 0;
        }
        let total = end - start;
        let argv = &mut (*rec).argv;
        // Lengths are clamped before each helper call so the verifier sees an upper bound,
        // and each window is one helper call, not a byte loop (same as the DNS/TLS payloads).
        let head = if total > ARGV_WINDOW_BYTES as u64 {
            ARGV_HEAD_BYTES
        } else {
            total as usize
        };
        if head == 0
            || head > ARGV_WINDOW_BYTES
            || bpf_probe_read_user_buf(start as *const u8, &mut argv[..head]).is_err()
        {
            return 0;
        }
        (*rec).event.argv_total = if total > u64::from(u32::MAX) {
            u32::MAX
        } else {
            total as u32
        };
        (*rec).event.argv_head_len = head as u16;
        if total <= ARGV_WINDOW_BYTES as u64 {
            return head;
        }
        let tail_src = (end - ARGV_TAIL_BYTES as u64) as *const u8;
        if bpf_probe_read_user_buf(tail_src, &mut argv[ARGV_HEAD_BYTES..ARGV_WINDOW_BYTES]).is_err()
        {
            return head;
        }
        (*rec).event.argv_tail_len = ARGV_TAIL_BYTES as u16;
        ARGV_WINDOW_BYTES
    }
}

/// pid → parent identity (`real_parent->tgid` + its `comm`). Filled by
/// `sched_process_fork` and by userspace `/proc` priming at startup; entries removed
/// by `sched_process_exit`. Sized to the realistic live-pid space — a full map (fork
/// bomb) simply yields `ppid = 0`, which the correlation rules tolerate.
#[map]
pub(crate) static PROC_LINEAGE: HashMap<u32, LineageEntry> = HashMap::with_max_entries(65_536, 0);

/// Fills `meta.ppid` and `meta.process_generation` for the current thread group from
/// `PROC_LINEAGE`. Both stay `0` when the process forked before the probe attached
/// and `/proc` priming missed it — callers treat `ppid == 0` as "unknown", never as
/// pid 0, and `process_generation == 0` as "no stamp", never as a real generation
/// (issue #519). One lookup for both, since every probe wants both.
fn fill_lineage(meta: &mut sensor_linux_wire::EventMeta) {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(entry) = unsafe { PROC_LINEAGE.get(&tgid) } {
        meta.ppid = entry.ppid;
        meta.process_generation = entry.generation;
        meta.parent_generation = entry.parent_generation;
    }
}

/// Offset of `ret` in every `sys_exit_*` tracepoint (x86_64/aarch64): 8-byte common
/// header + `__syscall_nr`(4, +4 padding) + `ret`(8, signed). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_exit_accept{,4}/format` — identical for
/// both.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SYS_EXIT_RET_OFFSET: usize = 16;
/// i686: `ret` is a packed 4-byte `long`, not independently verified (see
/// `sys_enter_open`'s i686 note for the same packed-layout reasoning).
#[cfg(bpf_target_arch = "x86")]
const SYS_EXIT_RET_OFFSET: usize = 12;

/// `sa_family_t` values (linux/socket.h) for the two tracked families. Any other family
/// (notably `AF_UNIX` = 1, very frequent — D-Bus, local sockets) is ignored: out of scope of
/// the threat model (outbound network connections only).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// --- sched_process_exec -------------------------------------------------------------
//
// The raw tracepoint supplies `task_struct *` and `linux_binprm *`; userspace
// provides their BTF-derived member offsets, and this helper keeps event creation
// shared with the old formatted tracepoint implementation.
pub(crate) fn record_sched_process_exec(pid: u32, filename_ptr: *const u8) -> u32 {
    let tgid = pid;

    let Ok(comm) = bpf_get_current_comm() else {
        return 1;
    };
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Assemble the event in per-CPU scratch, not on the stack and not field by
    // field in a reserved ring-buffer slot (that needs per-byte loops over
    // MAX_PATH_LEN, which blow the verifier's 1M-instruction budget on pre-6.6
    // kernels). One `output` copy emits it. argv is read here at exec time through
    // BTF-derived offsets (https://github.com/synthaea-lab/agent/issues/48); without them userspace reads `/proc/<pid>/cmdline`.
    let Some(rec) = EXEC_SCRATCH.get_ptr_mut(0) else {
        return 1;
    };
    unsafe {
        // Only the fixed part is zeroed: argv bytes past the lengths read below are never
        // emitted, so stale scratch bytes cannot reach userspace.
        let e: *mut ExecEvent = &raw mut (*rec).event;
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = tgid;
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = timestamp_ns;
        (*e).meta.ppid = 0;
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        // Parent identity from the fork-lineage map.
        if let Some(l) = PROC_LINEAGE.get(&tgid) {
            (*e).meta.ppid = l.ppid;
            (*e).meta.process_generation = l.generation;
            (*e).meta.parent_generation = l.parent_generation;
            let mut i = 0usize;
            while i < TASK_COMM_LEN {
                (*e).pcomm[i] = l.comm[i];
                i += 1;
            }
            // The parent's own parent and its stamp, and whether the parent has exec'd, for
            // a parent that forked and never exec'd (#784): one more lookup, the parent's
            // entry. Only when that entry is the incarnation this child was forked from: if
            // the parent exited and its pid was reused, the entry describes someone else
            // and its forker would be lent to the child. Left zero otherwise.
            if let Some(parent) = PROC_LINEAGE.get(&l.ppid) {
                if parent.generation == l.parent_generation {
                    (*e).grandparent_pid = parent.ppid;
                    (*e).grandparent_generation = parent.parent_generation;
                    (*e).parent_execd = parent.execd;
                }
            }
        }
        // This process has exec'd: its children can no longer be told it runs its forker's
        // image. After the reads above, so the event describes the state before this exec.
        if let Some(own) = PROC_LINEAGE.get_ptr_mut(&tgid) {
            (*own).execd = 1;
        }

        // Authoritative image path: the tracepoint's own `filename` field (the
        // kernel's resolved `bprm->filename`), never argv[0]. One bounded
        // `…_str_bytes` copy into the scratch entry.
        if let Ok(s) = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut (*e).image) {
            (*e).image_len = s.len() as u16;
        }

        let argv_len = read_exec_argv(rec);
        // A variable-length record (ADR-0045): the fixed event and the argv bytes read, no
        // more. The bound is re-checked here so the verifier sees the emitted size is at most
        // the scratch entry.
        if argv_len > ARGV_WINDOW_BYTES {
            return 1;
        }
        // SAFETY: `ExecRecord` is `repr(C)` with `event` first and `argv` right after it, so
        // the first `size_of::<ExecEvent>() + argv_len` bytes (argv_len <= ARGV_WINDOW_BYTES,
        // checked above) lie inside the scratch entry, and every one of them was written.
        let bytes = core::slice::from_raw_parts(
            rec.cast::<u8>(),
            core::mem::size_of::<ExecEvent>() + argv_len,
        );
        if EXEC_EVENTS.output::<[u8]>(bytes, 0).is_err() {
            return 1;
        }
    }

    0
}

// --- Mount/unmount and signal telemetry (issue #362) --------------------------------
//
// Feeds the two platform-neutral `schema` variants #96 introduced for macOS
// (`Event::Mount`, `Event::Signal`) from Linux. See this crate's `WIRE_VERSION` v12
// changelog (`sensor-linux-wire`) for the full rationale.

/// Ring buffer shared with userspace for `mount`/`umount2` events.
#[map]
static MOUNT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `MountEvent` (see `EXEC_SCRATCH`).
#[map]
static MOUNT_SCRATCH: PerCpuArray<MountEvent> = PerCpuArray::with_max_entries(1, 0);

/// `MS_RDONLY` (`linux/mount.h`) — stable UAPI constant, not a kernel-version-
/// dependent offset.
const MS_RDONLY: u64 = 1;

/// Offsets of the `syscalls:sys_enter_mount` tracepoint: `dev_name`(16, the
/// `source` arg), `dir_name`(24, `target`), `type`(32, `filesystemtype`),
/// `flags`(40, `mountflags`), `data`(48, unread). Verified on 2026-09-23 on Ubuntu
/// 22.04 (kernel 5.15.0-91-generic, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_mount/format` — matched the
/// standard `syscalls:*` layout inferred here on first write, no offset changes
/// needed.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_SOURCE_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_TARGET_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_FSTYPE_PTR_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MOUNT_FLAGS_OFFSET: usize = 40;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_SOURCE_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_TARGET_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_FSTYPE_PTR_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const MOUNT_FLAGS_OFFSET: usize = 24;

/// glibc's `umount2(2)` libc wrapper maps to a kernel syscall the kernel itself
/// (`fs/namespace.c`) names plain `umount` — `SYSCALL_DEFINE2(umount, ...)`, not
/// `umount2` — so the tracepoint is `syscalls:sys_enter_umount`, confirmed live
/// (the assumed `sys_enter_umount2` name does not exist; this file's doc comments
/// below keep saying "`umount2(2)`" for the libc call itself, which IS
/// `umount2()`, while the identifiers here match the kernel's own name).
/// Offsets: `name`(16, the target path), `flags`(24). Verified on 2026-09-23 on
/// Ubuntu 22.04 (kernel 5.15.0-91-generic, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_umount/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const UMOUNT_TARGET_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const UMOUNT_TARGET_PTR_OFFSET: usize = 12;

pub fn sys_enter_mount(ctx: TracePointContext) -> u32 {
    match try_sys_enter_mount(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_mount(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let source_ptr: u64 = unsafe { ctx.read_at(MOUNT_SOURCE_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let source_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MOUNT_SOURCE_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_ptr: u64 = unsafe { ctx.read_at(MOUNT_TARGET_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MOUNT_TARGET_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fstype_ptr: u64 = unsafe { ctx.read_at(MOUNT_FSTYPE_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fstype_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MOUNT_FSTYPE_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = unsafe { ctx.read_at(MOUNT_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = unsafe { ctx.read_at::<u32>(MOUNT_FLAGS_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_mount_event(&ctx, target_ptr, source_ptr, fstype_ptr, flags, true)
}

pub fn sys_enter_umount(ctx: TracePointContext) -> u32 {
    match try_sys_enter_umount(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_umount(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_ptr: u64 = unsafe { ctx.read_at(UMOUNT_TARGET_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_ptr: u64 = unsafe {
        ctx.read_at::<u32>(UMOUNT_TARGET_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_mount_event(&ctx, target_ptr, 0, 0, 0, false)
}

/// Shared by `sys_enter_mount` and `sys_enter_umount` above. `source_ptr`/
/// `fstype_ptr` are `0` on an unmount (`umount2(2)` has neither argument) — left
/// zero-length on the wire event, which `normalize::mount` maps to `None`.
///
/// Always inlined, on purpose: with six parameters LLVM 23 can emit this as a real
/// BPF-to-BPF call that passes the sixth on the stack, and the 7.2 kernel's verifier
/// rejects that ("callee expects 6 args, stack arg1 is not initialized"), so
/// `raw_sys_enter` fails to load and the agent exits seconds after it starts.
#[inline(always)]
fn emit_mount_event(
    ctx: &TracePointContext,
    mount_point_ptr: u64,
    source_ptr: u64,
    fstype_ptr: u64,
    flags: u64,
    mounted: bool,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = MOUNT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        if mount_point_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(mount_point_ptr as *const u8, &mut (*e).mount_point)
            {
                (*e).mount_point_len = path.len() as u16;
            }
        }
        if source_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(source_ptr as *const u8, &mut (*e).source)
            {
                (*e).source_len = path.len() as u16;
            }
        }
        if fstype_ptr != 0 {
            if let Ok(s) = bpf_probe_read_user_str_bytes(fstype_ptr as *const u8, &mut (*e).fs_type)
            {
                (*e).fs_type_len = s.len() as u8;
            }
        }
        (*e).readonly = mounted && (flags & MS_RDONLY) != 0;
        (*e).mounted = mounted;

        if MOUNT_EVENTS.output::<MountEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping mount event"
            );
        }
    }

    Ok(0)
}

/// Single-slot map holding the agent's own pid, written by userspace before any
/// signal probe below is attached (issue #362). Filters `kill`/`tgkill` at the
/// probe to the "tamper subset, never the firehose" this ring buffer can afford —
/// system-wide signal traffic (job control, `SIGCHLD` reaping, ordinary process
/// supervision) is far too high-volume to forward unfiltered. v1 scope: only the
/// agent's own pid is watched; the watchdog process and other registered security
/// processes are a documented future extension (see `sensor-linux-wire`'s
/// `WIRE_VERSION` v12 changelog), not implemented here.
///
/// Also reused by [`is_agent_own_pid`] (#514) to drop the agent's own file
/// activity at its source — same value, different consumer.
#[map]
static SIGNAL_WATCH_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Whether `target_pid` is a signal target this sensor cares about — see
/// `SIGNAL_WATCH_PID` above. `0` (unset) never matches: userspace hasn't written
/// its pid yet, or wrote it as an explicit "watch nothing".
fn is_watched_signal_target(target_pid: u32) -> bool {
    matches!(SIGNAL_WATCH_PID.get(0), Some(&watched) if watched != 0 && watched == target_pid)
}

/// True when `pid` is the agent's own process — the same identity
/// `SIGNAL_WATCH_PID` already carries for the signal-tamper probes above,
/// reused here for a different purpose (#514): userspace's `EventSpool::push`
/// does an `open`+2×`write`+`sync_data` on the local spool file for every
/// single event it enriches (`crates/store/src/spool.rs`), all attributed to
/// the agent's own pid. Under a burst that already floods `FILE_WRITE_EVENTS`
/// (a `docker run`'s containerd/runc/dockerd writes), that self-traffic
/// roughly doubles the pressure on the same 256 KiB ring buffer, and every
/// drop's `warn!` was on top of that. It was already filtered — but only
/// *after* userspace paid for the ring-buffer slot, the decode, and the
/// allocation (`drain!`'s `schema_event.meta().pid != own_pid`,
/// `crates/sensors/linux/userspace/src/sensor.rs`). Dropping it here instead
/// gives that ring-buffer capacity back to real telemetry. The userspace
/// filter is left in place as a defense-in-depth for the narrow startup
/// window before `write_signal_watch_pid` runs (see its own doc comment).
fn is_agent_own_pid(pid: u32) -> bool {
    is_watched_signal_target(pid)
}

/// Ring buffer shared with userspace for `kill`/`tgkill` events that pass the
/// `SIGNAL_WATCH_PID` filter.
#[map]
static SIGNAL_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Last `SIGKILL` sent to a watched target (issue #362). The ring-buffer event
/// above cannot attribute a `SIGKILL`: the victim is the agent itself, which dies
/// before it drains the buffer. This single slot is written synchronously at
/// `sys_enter_kill`/`sys_enter_tgkill`, before the kernel even delivers the signal.
/// Userspace pins it to bpffs, so the restarted agent can read who killed its
/// predecessor. Unpinned (no bpffs), it still loads, but the record dies with the
/// agent. Only `SIGKILL` lands here, because every catchable signal is already
/// attributed by `agent::kill_loudness`, and a `SIGSTOP` does not end the process.
#[map]
static SIGNAL_TAMPER_LAST: Array<SignalEvent> = Array::with_max_entries(1, 0);

/// `SIGKILL`'s number, the same on every Linux architecture.
const SIGKILL: u32 = 9;

/// Per-CPU scratch for building one `SignalEvent` (see `EXEC_SCRATCH`).
#[map]
static SIGNAL_SCRATCH: PerCpuArray<SignalEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_kill` tracepoint: `pid`(16), `sig`(24) on
/// x86_64/aarch64 — same inferred-not-verified status as the mount offsets above.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const KILL_PID_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const KILL_SIG_OFFSET: usize = 24;
#[cfg(bpf_target_arch = "x86")]
const KILL_PID_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const KILL_SIG_OFFSET: usize = 16;

/// Offsets of the `syscalls:sys_enter_tgkill` tracepoint: `tgid`(16), `tid`(24),
/// `sig`(32) on x86_64/aarch64 — same inferred-not-verified status as the mount
/// offsets above. `tgid` is the field compared against `SIGNAL_WATCH_PID`, the
/// same whole-process identity `kill(2)`'s `pid` argument carries — `tid` (the
/// specific thread within that group) is read but not otherwise used.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const TGKILL_TGID_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const TGKILL_SIG_OFFSET: usize = 32;
#[cfg(bpf_target_arch = "x86")]
const TGKILL_TGID_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const TGKILL_SIG_OFFSET: usize = 20;

// `tkill(2)` is deliberately NOT attached: it takes a thread id, not a
// thread-group id, and this filter watches a whole-process pid
// (`SIGNAL_WATCH_PID`) — there is no field in `tkill(2)`'s argument list
// comparable to that identity. Superseded by `tgkill(2)` in practice (glibc's
// `pthread_kill` uses `tgkill`, and a plain `kill(1)` uses `kill(2)`), so this
// is a narrow, accepted gap rather than a missing common path **for the agent's own pid**.
// The other security tools do not have it: `raw_signal_generate` (#1103) sees `tkill`,
// `pidfd_send_signal` and `rt_sigqueueinfo` too, and compares the target's `tgid`.

pub fn sys_enter_kill(ctx: TracePointContext) -> u32 {
    match try_sys_enter_kill(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_kill(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let pid: u64 = unsafe { ctx.read_at(KILL_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let pid: u64 = unsafe { ctx.read_at::<u32>(KILL_PID_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let sig: u64 = unsafe { ctx.read_at(KILL_SIG_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let sig: u64 = unsafe { ctx.read_at::<u32>(KILL_SIG_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_signal_event(&ctx, pid as u32, sig as u32)
}

pub fn sys_enter_tgkill(ctx: TracePointContext) -> u32 {
    match try_sys_enter_tgkill(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_tgkill(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let tgid: u64 = unsafe { ctx.read_at(TGKILL_TGID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let tgid: u64 = unsafe { ctx.read_at::<u32>(TGKILL_TGID_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let sig: u64 = unsafe { ctx.read_at(TGKILL_SIG_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let sig: u64 = unsafe { ctx.read_at::<u32>(TGKILL_SIG_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_signal_event(&ctx, tgid as u32, sig as u32)
}

/// Shared by `sys_enter_kill` and `sys_enter_tgkill` above. Drops silently
/// (`Ok(0)`, no scratch touch) when `target_pid` fails the `SIGNAL_WATCH_PID`
/// filter — this is the "regression-tested: ordinary signal traffic between
/// unrelated processes produces zero events" boundary issue #362 requires.
fn emit_signal_event(ctx: &TracePointContext, target_pid: u32, sig: u32) -> Result<u32, u32> {
    if !is_watched_signal_target(target_pid) {
        return Ok(0);
    }

    let e = SIGNAL_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        fill_signal_event(e, target_pid, sig)?;

        // Written before the ring-buffer output, so the slot is recorded even
        // when the ring is full.
        if sig == SIGKILL && SIGNAL_TAMPER_LAST.set(0, &*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: failed to record SIGKILL in SIGNAL_TAMPER_LAST"
            );
        }

        if SIGNAL_EVENTS.output::<SignalEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping signal event"
            );
        }
    }

    Ok(0)
}

/// Fills `e` with a signal event: `meta` is the SENDER (the current task), the target is
/// `target_pid` — same convention as macOS's `SignalToEsClient` (see `SignalEvent`'s doc comment
/// in `sensor-linux-wire`). Shared by the syscall probes above and [`emit_tool_signal_event`].
///
/// # Safety
///
/// `e` must point at a valid, writable `SignalEvent` (the per-CPU scratch slot).
#[inline(always)]
unsafe fn fill_signal_event(e: *mut SignalEvent, target_pid: u32, sig: u32) -> Result<(), u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        fill_lineage(&mut (*e).meta);
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        (*e).signal = sig;
        (*e).target_pid = target_pid;
    }
    Ok(())
}

/// Thread-group ids of the processes of the listed security units (`SECURITY_SERVICES`), filled
/// and refreshed by userspace from each unit's cgroup (#1103). The value is the process's
/// `SigCgt` (the signals it catches, bit `sig - 1`) at scan time: a caught reload signal is
/// dropped in the probe. The size is `SIGNAL_WATCH_TOOLS_ENTRIES`, checked by the userspace
/// loader against `SECURITY_SERVICES.len()` times the per-unit process cap, with headroom.
#[map]
static SIGNAL_WATCH_TOOLS: HashMap<u32, u64> =
    HashMap::with_max_entries(sensor_linux_wire::SIGNAL_WATCH_TOOLS_ENTRIES, 0);

/// Tool signals lost because `SIGNAL_EVENTS` was full, per CPU: userspace sums and reports it.
#[map]
static SIGNAL_TOOL_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The `SigCgt` of `tgid` when it is a process of a listed security unit, `None` otherwise.
#[inline(always)]
pub(crate) fn watched_tool_sigcgt(tgid: u32) -> Option<u64> {
    // SAFETY: the map is only read here; the value is copied out before the reference ends.
    unsafe { SIGNAL_WATCH_TOOLS.get(&tgid) }.copied()
}

/// Emits a signal sent to a process of a listed security unit, from the `signal_generate`
/// raw tracepoint (#1103). The target is already known to be watched and the signal to come from
/// a process (not the kernel): `raw_signal_generate` checked both. A kill of a tool does not take
/// the agent down, so the ring buffer is enough: nothing goes to `SIGNAL_TAMPER_LAST`.
#[inline(always)]
pub(crate) fn emit_tool_signal_event(
    ctx: &RawTracePointContext,
    target_tgid: u32,
    sig: u32,
) -> Result<u32, u32> {
    let e = SIGNAL_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    // SAFETY: `e` is this CPU's scratch slot (one per CPU, and a probe does not nest on its
    // own CPU), valid for a `SignalEvent`; `fill_signal_event` initialises it before `output`
    // copies it, and the drop counter is this CPU's own slot.
    unsafe {
        fill_signal_event(e, target_tgid, sig)?;
        if SIGNAL_EVENTS.output::<SignalEvent>(&*e, 0).is_err() {
            if let Some(drops) = SIGNAL_TOOL_DROPS.get_ptr_mut(0) {
                *drops += 1;
            }
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping signal event"
            );
        }
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
