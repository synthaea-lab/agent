#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, RetProbeContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
use sensor_linux_wire::{
    ConnectEvent, ExecEvent, FileDeleteEvent, FileOpenEvent, FileRenameEvent, FileWriteEvent,
    LineageEntry, MAX_TLS_CAPTURE, ReadlineInputEvent, SocketBindEvent, TASK_COMM_LEN,
    TlsCaptureEvent,
};

// This probe reads NO `task_struct`/`mm_struct` frozen offset: parent lineage (ppid +
// parent comm) comes from `sched_process_fork` tracepoint fields via `PROC_LINEAGE`
// (issue #53), the executed image from the `sched_process_exec` tracepoint's
// `__data_loc filename` (issue #111), and argv from `/proc/<pid>/cmdline` read by the
// userspace loader (issue #152). No `vmlinux` BTF bindings, no per-kernel offset
// table — every remaining read is a stable tracepoint field or a syscall argument.

/// Ring buffer shared with userspace for `exec` events. `ExecEvent` is assembled in
/// the per-CPU `EXEC_SCRATCH` entry (not on the stack — `image` is `MAX_PATH_LEN`
/// bytes) and emitted with a single `output` copy — the standard libbpf/Tetragon
/// "heap map" pattern. Filling a reserved ring-buffer slot field by field instead
/// needs per-byte loops over MAX_PATH_LEN, which blow the verifier's 1M-instruction
/// budget on pre-6.6 kernels (5.15, 6.1).
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ExecEvent` off the stack (see `EXEC_EVENTS`).
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

/// pid → parent identity (`real_parent->tgid` + its `comm`). Filled by
/// `sched_process_fork` and by userspace `/proc` priming at startup; entries removed
/// by `sched_process_exit`. Sized to the realistic live-pid space — a full map (fork
/// bomb) simply yields `ppid = 0`, which the correlation rules tolerate.
#[map]
static PROC_LINEAGE: HashMap<u32, LineageEntry> = HashMap::with_max_entries(65_536, 0);

/// `real_parent` of the current thread group, from `PROC_LINEAGE`. `0` when the
/// parent forked before the probe attached and `/proc` priming missed it — callers
/// treat `0` as "unknown", never as pid 0.
fn lineage_ppid() -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    match unsafe { PROC_LINEAGE.get(&tgid) } {
        Some(entry) => entry.ppid,
        None => 0,
    }
}

// --- sched:sched_process_fork -------------------------------------------------------
//
// Records `child_pid -> {parent_pid, parent_comm}`. Verified on 2026-09-15 on Alpine
// (kernel 6.18.50-0-virt, x86_64) via
// `/sys/kernel/tracing/events/sched/sched_process_fork/format` — and found NOT to
// match the layout previously assumed here. This kernel emits `parent_comm`/
// `child_comm` as `__data_loc` (dynamic-offset) fields, not inline `char[16]`s, which
// also shifts every field after them:
//
//   field:__data_loc char[] parent_comm;  offset:8;  size:4;
//   field:pid_t parent_pid;               offset:12; size:4;
//   field:__data_loc char[] child_comm;   offset:16; size:4;
//   field:pid_t child_pid;                offset:20; size:4;
//
// `parent_comm` is read the same way `sched_process_exec` already reads `filename`
// (issue #111): a `u32` data-locator (low 16 bits = byte offset from the record
// start, high 16 bits = length), then a bounded string copy from that offset. All
// fields are ints/u32s, no pointers — arch-independent, unlike `sys_enter_openat`
// below. Re-verify against `/format` on any kernel row added to `lab/MATRIX.md`;
// this layout has apparently changed across kernel versions before and can again.
const FORK_PARENT_COMM_DATA_LOC_OFFSET: usize = 8;
const FORK_PARENT_PID_OFFSET: usize = 12;
const FORK_CHILD_PID_OFFSET: usize = 20;

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_sched_process_fork(&ctx);
    0
}

fn try_sched_process_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let parent_pid: i32 = unsafe {
        ctx.read_at(FORK_PARENT_PID_OFFSET).map_err(|_| {
            warn!(ctx, "sensor-linux-ebpf: fork read parent_pid failed");
            1i64
        })?
    };
    let child_pid: i32 = unsafe {
        ctx.read_at(FORK_CHILD_PID_OFFSET).map_err(|_| {
            warn!(ctx, "sensor-linux-ebpf: fork read child_pid failed");
            1i64
        })?
    };
    let data_loc: u32 = unsafe {
        ctx.read_at(FORK_PARENT_COMM_DATA_LOC_OFFSET).map_err(|_| {
            warn!(
                ctx,
                "sensor-linux-ebpf: fork read parent_comm data_loc failed"
            );
            1i64
        })?
    };

    let mut comm = [0u8; TASK_COMM_LEN];
    let comm_offset = (data_loc & 0xffff) as usize;
    let comm_src = unsafe { (ctx.as_ptr() as *const u8).add(comm_offset) };
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(comm_src, &mut comm) };

    let entry = LineageEntry {
        ppid: parent_pid as u32,
        comm,
    };
    // BPF_ANY: overwrite a stale entry left by pid reuse.
    let inserted = PROC_LINEAGE.insert(&(child_pid as u32), &entry, 0);
    match inserted {
        Ok(_) => info!(
            ctx,
            "sensor-linux-ebpf: fork child={} parent={} inserted=1", child_pid, parent_pid
        ),
        Err(_) => info!(
            ctx,
            "sensor-linux-ebpf: fork child={} parent={} inserted=0", child_pid, parent_pid
        ),
    }
    Ok(())
}

// --- sched:sched_process_exit -----------------------------------------------------
//
// `sched_process_*` share the `sched_process_template` record: `comm[16]` at 8,
// `pid_t pid` at 24. Arch-independent.
const EXIT_PID_OFFSET: usize = 24;

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    if let Ok(pid) = unsafe { ctx.read_at::<i32>(EXIT_PID_OFFSET) } {
        let _ = PROC_LINEAGE.remove(&(pid as u32));
    }
    0
}

// --- sched:sched_process_exec --------------------------------------------------------
//
// Standard tracepoint layout, validated on 2026-08-12 on WSL2 6.6.114:
// `__data_loc char[] filename` at 8 (u32: low 16 bits offset, high 16 bits length),
// `pid_t pid` at 12. Arch-independent (no pointers in the record).
const FILENAME_DATA_LOC_OFFSET: usize = 8;
const PID_OFFSET: usize = 12;

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exec(ctx: TracePointContext) -> Result<u32, u32> {
    let pid: i32 = unsafe { ctx.read_at(PID_OFFSET).map_err(|_| 1u32)? };
    let tgid = pid as u32;

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let data_loc: u32 = unsafe { ctx.read_at(FILENAME_DATA_LOC_OFFSET).map_err(|_| 1u32)? };
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Assemble the event in per-CPU scratch, not on the stack and not field by
    // field in a reserved ring-buffer slot (that needs per-byte loops over
    // MAX_PATH_LEN, which blow the verifier's 1M-instruction budget on pre-6.6
    // kernels). One `output` copy emits it. argv is not read here — the userspace
    // loader reads `/proc/<pid>/cmdline` on receipt (issue #152).
    let e = EXEC_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
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
            let mut i = 0usize;
            while i < TASK_COMM_LEN {
                (*e).pcomm[i] = l.comm[i];
                i += 1;
            }
        }

        // Authoritative image path: the tracepoint's own `filename` field (the
        // kernel's resolved `bprm->filename`), never argv[0]. One bounded
        // `…_str_bytes` copy into the scratch entry.
        let filename_offset = (data_loc & 0xffff) as usize;
        let filename_src = (ctx.as_ptr() as *const u8).add(filename_offset);
        if let Ok(s) = bpf_probe_read_kernel_str_bytes(filename_src, &mut (*e).image) {
            (*e).image_len = s.len() as u16;
        }

        if EXEC_EVENTS.output::<ExecEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping exec event"
            );
        }
    }

    info!(&ctx, "sensor-linux-ebpf: exec pid={}", pid);
    Ok(0)
}

/// Ring buffer shared with userspace for `open` events.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileOpenEvent` (see `EXEC_SCRATCH`).
#[map]
static OPEN_SCRATCH: PerCpuArray<FileOpenEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_openat` tracepoint (x86_64). Standard, stable format of
/// the `syscalls:*` subsystem (documented, unlike `sched:*` tracepoints whose layout can vary
/// more): an 8-byte common header, `__syscall_nr` (4 bytes + padding), then the syscall
/// arguments aligned on 8 bytes each — `dfd`(16), `filename`(24), `flags`(32), `mode`(40).
/// Verified on 2026-09-16 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format`.
///
/// Known limit: `filename` is the raw path passed by the caller, not resolved against `dfd` —
/// a path relative to a non-standard directory descriptor will appear as-is, without the
/// absolute prefix. Known accepted limitation; conformance reports it.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const OPENAT_FILENAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const OPENAT_FLAGS_OFFSET: usize = 32;

/// On i686, no padding between arguments (all 4-byte `int`s/pointers, packed
/// consecutively): `dfd`(12), `filename`(16), `flags`(20), `mode`(24) — verified on
/// 2026-08-19 via `/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format` on the
/// target i686 kernel (Debian 12 Bookworm, `6.1.0-52-686-pae`). Unlike x86_64 above, the raw
/// value at this offset occupies 4 bytes, not 8 — see the `u32` read below.
#[cfg(bpf_target_arch = "x86")]
const OPENAT_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const OPENAT_FLAGS_OFFSET: usize = 20;

/// Offsets of the `syscalls:sys_enter_open` tracepoint — the plain `open(2)` syscall, one
/// argument short of `openat` above (no leading `dfd`), so `filename`/`flags` land 8 bytes
/// (x86_64/aarch64) / 4 bytes (i686) earlier. Needed because musl — and every busybox applet
/// linked against it, `cat` included — still issues `open(2)` directly; glibc has rewritten
/// `open()` to call `openat(AT_FDCWD, ...)` internally since 2.26, which is why this gap did
/// not show up on the glibc labs in `lab/MATRIX.md`. Attaching only `sys_enter_openat`
/// therefore captured zero file-open events on Alpine — confirmed via
/// `strace -e trace=open,openat cat /etc/hostname` showing a bare `open()`, then via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_open/format` on 2026-09-16 (same kernel as
/// above): `filename`(16), `flags`(24), `mode`(32). i686 offsets are inferred by the same
/// 4-byte shift from the verified `sys_enter_openat` i686 layout, not independently confirmed
/// on hardware.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const OPEN_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const OPEN_FLAGS_OFFSET: usize = 24;
#[cfg(bpf_target_arch = "x86")]
const OPEN_FILENAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const OPEN_FLAGS_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(OPENAT_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(OPENAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: i64 = unsafe { ctx.read_at(OPENAT_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: i64 = unsafe { ctx.read_at::<i32>(OPENAT_FLAGS_OFFSET).map_err(|_| 1u32)? as i64 };

    emit_file_open_event(&ctx, filename_ptr, flags)
}

#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_open(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(OPEN_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(OPEN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: i64 = unsafe { ctx.read_at(OPEN_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: i64 = unsafe { ctx.read_at::<i32>(OPEN_FLAGS_OFFSET).map_err(|_| 1u32)? as i64 };

    emit_file_open_event(&ctx, filename_ptr, flags)
}

/// Shared by `sys_enter_openat` and `sys_enter_open` above: both land on the same
/// `FileOpenEvent` shape/`FILE_OPEN_EVENTS` ring buffer, and differ only in where
/// `filename`/`flags` sit in the tracepoint record.
fn emit_file_open_event(
    ctx: &TracePointContext,
    filename_ptr: u64,
    flags: i64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    // Assemble in per-CPU scratch, then one `output` copy — a struct literal on
    // the stack leaves interior padding uninitialised, and `entry.write` copying
    // that into the ring buffer is rejected by the verifier on pre-6.6 kernels.
    let e = OPEN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        (*e).flags = flags as u32;

        if filename_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
            {
                (*e).path_len = path.len() as u16;
            }
        }

        if FILE_OPEN_EVENTS.output::<FileOpenEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping open event"
            );
        }
    }

    Ok(0)
}

// --- File write/delete/rename (issue #262) ------------------------------------------

/// Ring buffer shared with userspace for `write` events.
#[map]
static FILE_WRITE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileWriteEvent` (see `EXEC_SCRATCH`).
#[map]
static WRITE_SCRATCH: PerCpuArray<FileWriteEvent> = PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `unlink`/`unlinkat` events.
#[map]
static FILE_DELETE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileDeleteEvent` (see `EXEC_SCRATCH`).
#[map]
static DELETE_SCRATCH: PerCpuArray<FileDeleteEvent> = PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `rename`/`renameat`/`renameat2` events.
#[map]
static FILE_RENAME_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileRenameEvent` (see `EXEC_SCRATCH`).
#[map]
static RENAME_SCRATCH: PerCpuArray<FileRenameEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_write` tracepoint (x86_64/aarch64). Standard
/// `syscalls:*` layout (see `sys_enter_openat` above): `fd`(16), `buf`(24),
/// `count`(32). Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_write/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const WRITE_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const WRITE_COUNT_OFFSET: usize = 32;
/// i686: packed 4-byte args, no independent kernel verification — inferred by the
/// same 4-byte-shift rule already used (and flagged the same way) for `sys_enter_open`
/// above: `fd`(12), `buf`(16), `count`(20).
#[cfg(bpf_target_arch = "x86")]
const WRITE_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const WRITE_COUNT_OFFSET: usize = 20;

#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match try_sys_enter_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_write(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(WRITE_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(WRITE_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let count: u64 = unsafe { ctx.read_at(WRITE_COUNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let count: u64 = unsafe { ctx.read_at::<u32>(WRITE_COUNT_OFFSET).map_err(|_| 1u32)? as u64 };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = WRITE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        (*e).fd = fd as u32;
        (*e).bytes_requested = count;

        if FILE_WRITE_EVENTS.output::<FileWriteEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping write event"
            );
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_unlink` tracepoint (x86_64/aarch64):
/// `pathname`(16). Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, x86_64)
/// via `/sys/kernel/tracing/events/syscalls/sys_enter_unlink/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const UNLINK_PATHNAME_PTR_OFFSET: usize = 16;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const UNLINK_PATHNAME_PTR_OFFSET: usize = 12;

/// Offsets of the `syscalls:sys_enter_unlinkat` tracepoint (x86_64/aarch64):
/// `dfd`(16), `pathname`(24), `flag`(32). Verified on 2026-09-21 on Alpine
/// (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_unlinkat/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const UNLINKAT_PATHNAME_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const UNLINKAT_PATHNAME_PTR_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_unlink(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at(UNLINK_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(UNLINK_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_file_delete_event(&ctx, pathname_ptr)
}

#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_unlinkat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at(UNLINKAT_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(UNLINKAT_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_file_delete_event(&ctx, pathname_ptr)
}

/// Shared by `sys_enter_unlink` and `sys_enter_unlinkat` above.
fn emit_file_delete_event(ctx: &TracePointContext, pathname_ptr: u64) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = DELETE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        if pathname_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut (*e).path)
            {
                (*e).path_len = path.len() as u16;
            }
        }

        if FILE_DELETE_EVENTS.output::<FileDeleteEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping delete event"
            );
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_rename` tracepoint (x86_64/aarch64):
/// `oldname`(16), `newname`(24). Verified on 2026-09-21 on Alpine
/// (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_rename/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAME_OLDNAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAME_NEWNAME_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const RENAME_OLDNAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const RENAME_NEWNAME_PTR_OFFSET: usize = 16;

/// Offsets of the `syscalls:sys_enter_renameat` tracepoint (x86_64/aarch64):
/// `olddfd`(16), `oldname`(24), `newdfd`(32), `newname`(40). Verified on 2026-09-21
/// on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_renameat/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT_OLDNAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT_NEWNAME_PTR_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT_OLDNAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT_NEWNAME_PTR_OFFSET: usize = 24;

/// Offsets of the `syscalls:sys_enter_renameat2` tracepoint (x86_64/aarch64):
/// `olddfd`(16), `oldname`(24), `newdfd`(32), `newname`(40), `flags`(48). Verified on
/// 2026-09-21 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_renameat2/format`. Same
/// oldname/newname offsets as `renameat` above (the trailing `flags` field doesn't
/// shift them).
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT2_OLDNAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT2_NEWNAME_PTR_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT2_OLDNAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT2_NEWNAME_PTR_OFFSET: usize = 24;

#[tracepoint]
pub fn sys_enter_rename(ctx: TracePointContext) -> u32 {
    match try_sys_enter_rename(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_rename(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let oldname_ptr: u64 = unsafe { ctx.read_at(RENAME_OLDNAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let oldname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RENAME_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let newname_ptr: u64 = unsafe { ctx.read_at(RENAME_NEWNAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let newname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RENAME_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_file_rename_event(&ctx, oldname_ptr, newname_ptr)
}

#[tracepoint]
pub fn sys_enter_renameat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_renameat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_renameat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let oldname_ptr: u64 = unsafe {
        ctx.read_at(RENAMEAT_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let oldname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RENAMEAT_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let newname_ptr: u64 = unsafe {
        ctx.read_at(RENAMEAT_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let newname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RENAMEAT_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_file_rename_event(&ctx, oldname_ptr, newname_ptr)
}

#[tracepoint]
pub fn sys_enter_renameat2(ctx: TracePointContext) -> u32 {
    match try_sys_enter_renameat2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_renameat2(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let oldname_ptr: u64 = unsafe {
        ctx.read_at(RENAMEAT2_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let oldname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RENAMEAT2_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let newname_ptr: u64 = unsafe {
        ctx.read_at(RENAMEAT2_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let newname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RENAMEAT2_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_file_rename_event(&ctx, oldname_ptr, newname_ptr)
}

/// Shared by `sys_enter_rename`/`sys_enter_renameat`/`sys_enter_renameat2` above.
fn emit_file_rename_event(
    ctx: &TracePointContext,
    oldname_ptr: u64,
    newname_ptr: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = RENAME_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        if oldname_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut (*e).old_path)
            {
                (*e).old_path_len = path.len() as u16;
            }
        }
        if newname_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut (*e).new_path)
            {
                (*e).new_path_len = path.len() as u16;
            }
        }

        if FILE_RENAME_EVENTS.output::<FileRenameEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping rename event"
            );
        }
    }

    Ok(0)
}

/// Ring buffer shared with userspace for `connect` events.
#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ConnectEvent` (see `EXEC_SCRATCH`).
#[map]
static CONNECT_SCRATCH: PerCpuArray<ConnectEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_connect` tracepoint (x86_64). Same stable layout as
/// `sys_enter_openat` (see above): 8-byte common header, `__syscall_nr`, then the arguments
/// aligned on 8 bytes each — `fd`(16), `uservaddr`(24), `addrlen`(32). Not verified against
/// `/sys/kernel/tracing/events/syscalls/sys_enter_connect/format` on this machine (reading
/// requires root) — to be confirmed before trusting the data outside the lab.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CONNECT_USERVADDR_PTR_OFFSET: usize = 24;

/// On i686, `fd`(12), `uservaddr`(16), `addrlen`(20) are packed without padding (the
/// `uservaddr` pointer is 4 bytes, not 8) — verified on 2026-08-19 via
/// `/sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format` on the target i686
/// kernel (Debian 12 Bookworm, `6.1.0-52-686-pae`).
#[cfg(bpf_target_arch = "x86")]
const CONNECT_USERVADDR_PTR_OFFSET: usize = 16;

/// `sa_family_t` values (linux/socket.h) for the two tracked families. Any other family
/// (notably `AF_UNIX` = 1, very frequent — D-Bus, local sockets) is ignored: out of scope of
/// the threat model (outbound network connections only).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let uservaddr_ptr: u64 = unsafe {
        ctx.read_at(CONNECT_USERVADDR_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let uservaddr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CONNECT_USERVADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    if uservaddr_ptr == 0 {
        return Ok(0);
    }

    // `sockaddr.sa_family` is the first field (u16), common to all the variants
    // (sockaddr_in, sockaddr_in6, sockaddr_un...).
    let family: u16 = match unsafe { bpf_probe_read_user(uservaddr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    // `sin_port`/`sin6_port`: same offset (2) in both structs, network byte order.
    let port_be: u16 =
        unsafe { bpf_probe_read_user((uservaddr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    // Address bytes read raw ([u8; N]), not as an integer: `bpf_probe_read_user::<u32>`
    // would apply native (LE) endianness and reverse the displayed address (observed
    // 2026-08-13: 127.0.0.11 shown as "11.0.0.127"). sockaddr_in::sin_addr at +4,
    // sockaddr_in6::sin6_addr at +8.
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe {
                bpf_probe_read_user((uservaddr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)?
            },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((uservaddr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    // Assemble in per-CPU scratch, then one `output` copy (see `try_sys_enter_openat`).
    let e = CONNECT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    let pid = unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        (*e).is_ipv6 = family == AF_INET6;
        (*e).dport = u16::from_be(port_be);
        (*e).daddr_v4 = v4;
        (*e).daddr_v6 = v6;

        if CONNECT_EVENTS.output::<ConnectEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping connect event"
            );
        }
        (*e).meta.pid
    };

    info!(&ctx, "sensor-linux-ebpf: connect pid={}", pid);
    Ok(0)
}

/// Ring buffer shared with userspace for `bind` events.
#[map]
static SOCKET_BIND_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketBindEvent` (see `EXEC_SCRATCH`).
#[map]
static BIND_SCRATCH: PerCpuArray<SocketBindEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_bind` tracepoint (x86_64/aarch64): `fd`(16),
/// `umyaddr`(24), `addrlen`(32) — identical shape to `sys_enter_connect` above.
/// Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_bind/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BIND_UMYADDR_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const BIND_UMYADDR_PTR_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    match try_sys_enter_bind(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Mirrors `try_sys_enter_connect` above field for field — same family filter, same
/// raw-byte address read (avoids the endianness bug documented on `ConnectEvent`),
/// same per-CPU-scratch assembly. Only the wire type, ring buffer, and field names
/// (`laddr`/`lport` vs `daddr`/`dport`) differ.
fn try_sys_enter_bind(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let umyaddr_ptr: u64 = unsafe { ctx.read_at(BIND_UMYADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let umyaddr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(BIND_UMYADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    if umyaddr_ptr == 0 {
        return Ok(0);
    }

    let family: u16 = match unsafe { bpf_probe_read_user(umyaddr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((umyaddr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe {
                bpf_probe_read_user((umyaddr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)?
            },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((umyaddr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = BIND_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*e).meta.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }
        (*e).is_ipv6 = family == AF_INET6;
        (*e).lport = u16::from_be(port_be);
        (*e).laddr_v4 = v4;
        (*e).laddr_v6 = v6;

        if SOCKET_BIND_EVENTS.output::<SocketBindEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping bind event"
            );
        }
    }

    Ok(0)
}

/// Per-CPU hit counter for the `file_open` LSM hook below — issue #91's foundation
/// slice, observation only. Exists so userspace (`sensor-linux-lsm`) has something
/// concrete to point at proving the hook actually fires, without yet deciding how an
/// LSM-sourced open relates to the tracepoint-sourced `FileOpenEvent` above (double-
/// counting the same open two ways needs a real answer, left to the follow-up that
/// also wires `-EPERM` to a `response` verdict — that plumbing does not exist yet).
#[map]
static LSM_FILE_OPEN_HITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Observation-only LSM hook (issue #91 foundation). Fires at the security layer
/// regardless of entry path — including `io_uring`-submitted opens, which never reach
/// `syscalls:sys_enter_openat` above (the blinding technique against tracepoint-only
/// EDRs this hook exists to close). Reads no `struct file` field: this slice proves
/// the hook attaches and fires, nothing more, so it needs no `vmlinux` BTF bindings
/// and no per-kernel offset table — same discipline as the rest of this probe.
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // `file_open`'s LSM_HOOK signature is `(struct file *file, int retval)` — `arg(1)`
    // is the verdict of whatever LSM program ran before us in the chain. Defer to an
    // earlier `-EPERM` rather than silently overriding it with our own `0`; this hook
    // never denies on its own (no verdict source to enforce yet).
    let retval: i32 = ctx.arg(1);
    if retval != 0 {
        // Forward the veto, not the exact code. `retval` reaches the verifier as an
        // unconstrained scalar (aya's `arg()` extraction loses the sign tracking a
        // raw i32 read would have), so returning it — or any value arithmetically
        // derived from it (`i32::clamp`, an if/else chain assigning to a binding —
        // both tried, both compile to a branchless sign-extend-and-mask select the
        // verifier's range tracking cannot see through) — fails the verifier's LSM
        // exit-state check, which requires every path provably within [-4095, 0]
        // (confirmed on real hardware, kernel 7.2.4: "R0 has smin=1 smax=4294967295
        // should have been in [-4095, 0]", still unconstrained even after an
        // explicit bounds comparison). The actual requirement here is only "never
        // override an earlier LSM's deny with our own allow" — the exact errno
        // doesn't matter to us, so return a fixed, compile-time-constant deny
        // instead of the arbitrary value.
        //
        // Review note (Nikolas, PR #239): this is a lossy, generic deny signal,
        // not a transparent forward — an operator debugging "why was this denied"
        // sees `EPERM` here regardless of whether the earlier LSM actually
        // returned `EACCES`, `EPIPE`, or anything else. Acceptable for this
        // observation-only hook (no policy enforcement reads this value today),
        // but anyone wiring real inline blocking on top of this hook later
        // (#131/#133) should not assume `attach_file_open`'s return value is the
        // original LSM's own errno.
        return Ok(-1);
    }

    if let Some(count) = LSM_FILE_OPEN_HITS.get_ptr_mut(0) {
        // SAFETY: `count` is a valid per-CPU slot pointer from `get_ptr_mut`; no
        // concurrent access from another CPU (each CPU owns its own slot).
        unsafe {
            *count = (*count).wrapping_add(1);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(&ctx, "sensor-linux-ebpf: lsm file_open pid={}", pid);
    Ok(0)
}

// --- Uprobes: TLS plaintext capture (issue #90) ------------------------------------
//
// These uprobes attach to SSL_read/SSL_write in OpenSSL/BoringSSL/GnuTLS libraries.
// Attachment is done from userspace (sensor-linux-uprobes) after resolving symbols
// with goblin — the eBPF programs below are just the handlers.

/// Ring buffer for TLS capture events.
#[map]
static TLS_CAPTURE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `TlsCaptureEvent` (256 bytes data budget).
#[map]
static TLS_SCRATCH: PerCpuArray<TlsCaptureEvent> = PerCpuArray::with_max_entries(1, 0);

/// Tracks SSL_read buffer pointers between entry and return: pid → (buf_ptr, num, lib_type).
/// SSL_read(SSL *ssl, void *buf, int num) fills `buf` on success, so we need to
/// stash the arguments at entry and read the buffer at return (uretprobe).
/// The lib_type (0=OpenSSL, 1=BoringSSL, 2=GnuTLS) is passed from entry to exit.
#[map]
static SSL_READ_ARGS: HashMap<u64, (u64, u32, u8)> = HashMap::with_max_entries(1024, 0);

/// Uprobe on SSL_write entry for OpenSSL (pre-encryption plaintext capture).
/// Signature: `int SSL_write(SSL *ssl, const void *buf, int num)`
/// Captures the first MAX_TLS_CAPTURE bytes of `buf` before encryption.
#[uprobe]
pub fn ssl_write_openssl(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx, 0) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uprobe on SSL_write entry for BoringSSL (pre-encryption plaintext capture).
#[uprobe]
pub fn ssl_write_boringssl(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx, 1) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uprobe on gnutls_record_send entry for GnuTLS (pre-encryption plaintext capture).
/// Signature: `ssize_t gnutls_record_send(gnutls_session_t session, const void *data, size_t data_size)`
#[uprobe]
pub fn ssl_write_gnutls(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx, 2) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_write(ctx: ProbeContext, lib_type: u8) -> Result<u32, u32> {
    // SSL_write(SSL *ssl, const void *buf, int num)
    // arg(0) = ssl, arg(1) = buf, arg(2) = num
    let buf_ptr: u64 = ctx.arg(1).ok_or(1u32)?;
    let num: i32 = ctx.arg(2).ok_or(1u32)?;

    if buf_ptr == 0 || num <= 0 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = TLS_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        (*e).direction = 1; // write (pre-encryption)
        (*e).lib_type = lib_type; // Set by probe function (OpenSSL=0, BoringSSL=1, GnuTLS=2)

        // Capture first N bytes of plaintext (budget: MAX_TLS_CAPTURE).
        // TLS data is binary, not null-terminated, so we use bulk read helper.
        let to_read = if num as usize > MAX_TLS_CAPTURE {
            MAX_TLS_CAPTURE
        } else {
            num as usize
        };

        // Batch read: single bpf_probe_read_user_buf() call instead of 256
        // individual bpf_probe_read_user() calls (verifier-friendly).
        let data_slice = &mut (*e).data;
        (*e).bytes_len = if let Ok(()) =
            bpf_probe_read_user_buf(buf_ptr as *const u8, &mut data_slice[..to_read])
        {
            to_read as u32
        } else {
            0
        };

        if TLS_CAPTURE_EVENTS
            .output::<TlsCaptureEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping TLS write event"
            );
        }
    }

    Ok(0)
}

/// Uprobe on SSL_read entry for OpenSSL: stash arguments for the uretprobe.
/// Signature: `int SSL_read(SSL *ssl, void *buf, int num)`
#[uprobe]
pub fn ssl_read_entry_openssl(ctx: ProbeContext) -> u32 {
    try_ssl_read_entry(ctx, 0)
}

/// Uprobe on SSL_read entry for BoringSSL: stash arguments for the uretprobe.
#[uprobe]
pub fn ssl_read_entry_boringssl(ctx: ProbeContext) -> u32 {
    try_ssl_read_entry(ctx, 1)
}

/// Uprobe on gnutls_record_recv entry for GnuTLS: stash arguments for the uretprobe.
/// Signature: `ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size)`
#[uprobe]
pub fn ssl_read_entry_gnutls(ctx: ProbeContext) -> u32 {
    try_ssl_read_entry(ctx, 2)
}

fn try_ssl_read_entry(ctx: ProbeContext, lib_type: u8) -> u32 {
    // SSL_read(SSL *ssl, void *buf, int num) / gnutls_record_recv(session, data, size)
    // arg(0) = ssl/session, arg(1) = buf/data, arg(2) = num/size
    if let (Some(buf_ptr), Some(num)) = (ctx.arg::<u64>(1), ctx.arg::<i32>(2)) {
        if buf_ptr != 0 && num > 0 {
            let pid_tgid = bpf_get_current_pid_tgid();
            let _ = SSL_READ_ARGS.insert(&pid_tgid, &(buf_ptr, num as u32, lib_type), 0);
        }
    }
    0
}

/// Uretprobe on SSL_read return for OpenSSL: capture decrypted plaintext.
/// The return value is the number of bytes read, or <= 0 on error.
#[uretprobe]
pub fn ssl_read_exit_openssl(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uretprobe on SSL_read return for BoringSSL: capture decrypted plaintext.
#[uretprobe]
pub fn ssl_read_exit_boringssl(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Uretprobe on gnutls_record_recv return for GnuTLS: capture decrypted plaintext.
#[uretprobe]
pub fn ssl_read_exit_gnutls(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_read_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let retval: i32 = ctx.ret::<i32>(); // SSL_read's return value
    if retval <= 0 {
        return Ok(0); // Read failed or no data
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let (buf_ptr, _num, lib_type) = match unsafe { SSL_READ_ARGS.get(&pid_tgid) } {
        Some(args) => *args,
        None => return Ok(0), // Entry wasn't tracked
    };

    let _ = SSL_READ_ARGS.remove(&pid_tgid);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = TLS_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (pid_tgid >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        (*e).direction = 0; // read (post-decryption)
        (*e).lib_type = lib_type; // Retrieved from entry probe (OpenSSL=0, BoringSSL=1, GnuTLS=2)

        // Capture first N bytes of plaintext (budget: MAX_TLS_CAPTURE).
        let to_read = if retval as usize > MAX_TLS_CAPTURE {
            MAX_TLS_CAPTURE
        } else {
            retval as usize
        };

        // Batch read: single bpf_probe_read_user_buf() call instead of 256
        // individual bpf_probe_read_user() calls (verifier-friendly).
        let data_slice = &mut (*e).data;
        (*e).bytes_len = if let Ok(()) =
            bpf_probe_read_user_buf(buf_ptr as *const u8, &mut data_slice[..to_read])
        {
            to_read as u32
        } else {
            0
        };

        if TLS_CAPTURE_EVENTS
            .output::<TlsCaptureEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping TLS read event"
            );
        }
    }

    Ok(0)
}

// --- Uprobes: Shell readline capture (issue #90) ------------------------------------

/// Ring buffer for readline input events.
#[map]
static READLINE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ReadlineInputEvent` (512 bytes input budget).
#[map]
static READLINE_SCRATCH: PerCpuArray<ReadlineInputEvent> = PerCpuArray::with_max_entries(1, 0);

/// Uretprobe on readline return: capture interactive shell command.
/// Signature: `char *readline(const char *prompt)`
/// The return value is a malloc'd string (freed by caller), or NULL on EOF/error.
#[uretprobe]
pub fn readline_exit(ctx: RetProbeContext) -> u32 {
    match try_readline_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_readline_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let line_ptr: u64 = ctx.ret::<u64>(); // readline's return value
    if line_ptr == 0 {
        return Ok(0); // EOF or error
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = READLINE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).meta.ppid = lineage_ppid();
        (*e).meta.uid = uid_gid as u32;
        (*e).meta.gid = (uid_gid >> 32) as u32;
        (*e).meta.timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            (*e).meta.comm[i] = comm[i];
            i += 1;
        }

        // Detect shell type from comm (userspace will override if needed).
        (*e).shell_type = if comm.starts_with(b"bash") {
            0 // bash
        } else if comm.starts_with(b"zsh") {
            1 // zsh
        } else {
            0 // default to bash
        };

        // Capture the full command line (budget: MAX_READLINE_INPUT).
        if let Ok(input) = bpf_probe_read_user_str_bytes(line_ptr as *const u8, &mut (*e).input) {
            (*e).input_len = input.len() as u32;
        }

        if READLINE_EVENTS
            .output::<ReadlineInputEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping readline event"
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
