#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, Global,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, RetProbeContext, TracePointContext},
};
use aya_log_ebpf::{info, warn};
use sensor_linux_wire::{
    BpfEvent, CapSetEvent, ConnectEvent, ExecEvent, FileChmodEvent, FileChownEvent,
    FileDeleteEvent, FileOpenEvent, FileRemovexattrEvent, FileRenameEvent, FileSetxattrEvent,
    FileWriteEvent, GetAddrInfoEvent, IdentityChangeEvent, KernelModuleEvent, LineageEntry,
    MAX_TLS_CAPTURE, MemfdCreateEvent, MountEvent, NamespaceEvent, ProcessVmReadEvent,
    ProcessVmWriteEvent, PtraceEvent, ReadlineInputEvent, SignalEvent, SocketAcceptEvent,
    SocketBindEvent, SocketListenEvent, TASK_COMM_LEN, TlsCaptureEvent, UdpSendEvent,
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

/// Path prefixes this sensor never emits path-bearing file events for (issue #262's
/// "Performance Considerations": named as the mitigation for the volume these
/// syscalls generate). `/dev`, `/proc`, and `/sys` are virtual filesystems that
/// legitimate processes touch continuously as a side effect of just running — not
/// because a ransomware/tamper/exfil scenario would ever target real data there —
/// and `/tmp` is high-churn scratch space (package manager staging, compiler temp
/// files, systemd's `PrivateTmp`) with the same property. Checked against every
/// event that carries a real filesystem path (open/delete/rename/chmod/chown);
/// `write(2)` has no path argument at all (it operates on an already-open `fd`) and
/// so cannot be filtered this way — a known, accepted gap, not solved here.
const FILTERED_PATH_PREFIXES: [&[u8]; 4] = [b"/dev/", b"/proc/", b"/sys/", b"/tmp/"];

/// Whether `path` falls under one of `FILTERED_PATH_PREFIXES` and the file event
/// it belongs to should be dropped before it ever reaches the ring buffer.
fn is_filtered_path(path: &[u8]) -> bool {
    let mut i = 0usize;
    while i < FILTERED_PATH_PREFIXES.len() {
        if path.starts_with(FILTERED_PATH_PREFIXES[i]) {
            return true;
        }
        i += 1;
    }
    false
}

// --- sched:sched_process_fork -------------------------------------------------------
//
// Records `child_pid -> {parent_pid, parent_comm}`. The record layout is NOT stable
// across kernels (issue #415). Two families exist in the wild:
//
//   inline (5.15, 6.1, 6.8 — verified on the Hyper-V lab):
//     field:char parent_comm[16];            offset:8;  size:16;
//     field:pid_t parent_pid;                offset:24; size:4;
//     field:pid_t child_pid;                 offset:44; size:4;
//
//   __data_loc (Alpine 6.18.50-0-virt — verified by #205):
//     field:__data_loc char[] parent_comm;   offset:8;  size:4;
//     field:pid_t parent_pid;                offset:12; size:4;
//     field:pid_t child_pid;                 offset:20; size:4;
//
// Hard-coding either one silently zeroes lineage on the other (#205 fixed 6.18 and
// broke every inline-comm kernel). So the offsets are read-only globals that
// userspace overrides at load time from the running kernel's
// `/sys/kernel/tracing/events/sched/sched_process_fork/format`
// (`sensor-linux::tracefs`). The compiled-in defaults describe the inline layout,
// but `FORK_LAYOUT_KNOWN` stays 0 unless userspace actually parsed the format: an
// unrecognised kernel makes this probe a no-op (lineage then degrades to the
// `/proc` priming snapshot) instead of inserting garbage pids. All fields are
// ints/u32s read through `bpf_probe_read`, so the variable offsets are
// verifier-safe and arch-independent.

/// 1 once userspace has parsed the running kernel's fork format; 0 = do nothing.
#[unsafe(no_mangle)]
static FORK_LAYOUT_KNOWN: Global<u32> = Global::new(0);
/// Offset of `parent_comm`: the `char[16]` itself (inline) or its data-locator.
#[unsafe(no_mangle)]
static FORK_PARENT_COMM_OFFSET: Global<u32> = Global::new(8);
/// 1 when `parent_comm` is a `__data_loc` field, 0 when it is an inline `char[16]`.
#[unsafe(no_mangle)]
static FORK_PARENT_COMM_DATA_LOC: Global<u32> = Global::new(0);
/// Offset of `pid_t parent_pid`.
#[unsafe(no_mangle)]
static FORK_PARENT_PID_OFFSET: Global<u32> = Global::new(24);
/// Offset of `pid_t child_pid`.
#[unsafe(no_mangle)]
static FORK_CHILD_PID_OFFSET: Global<u32> = Global::new(44);

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_sched_process_fork(&ctx);
    0
}

fn try_sched_process_fork(ctx: &TracePointContext) -> Result<(), i64> {
    if FORK_LAYOUT_KNOWN.load() == 0 {
        return Ok(());
    }
    let parent_pid: i32 = unsafe {
        ctx.read_at(FORK_PARENT_PID_OFFSET.load() as usize)
            .map_err(|_| {
                warn!(ctx, "sensor-linux-ebpf: fork read parent_pid failed");
                1i64
            })?
    };
    let child_pid: i32 = unsafe {
        ctx.read_at(FORK_CHILD_PID_OFFSET.load() as usize)
            .map_err(|_| {
                warn!(ctx, "sensor-linux-ebpf: fork read child_pid failed");
                1i64
            })?
    };

    let comm_field = FORK_PARENT_COMM_OFFSET.load() as usize;
    let comm_offset = if FORK_PARENT_COMM_DATA_LOC.load() != 0 {
        // u32 data-locator: low 16 bits = byte offset from the record start, high 16
        // bits = length — same decoding as `sched_process_exec`'s `filename` (#111).
        let data_loc: u32 = unsafe {
            ctx.read_at(comm_field).map_err(|_| {
                warn!(
                    ctx,
                    "sensor-linux-ebpf: fork read parent_comm data_loc failed"
                );
                1i64
            })?
        };
        (data_loc & 0xffff) as usize
    } else {
        comm_field
    };

    let mut comm = [0u8; TASK_COMM_LEN];
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
                if is_filtered_path(path) {
                    return Ok(0);
                }
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
    let pathname_ptr: u64 = unsafe { ctx.read_at(UNLINK_PATHNAME_PTR_OFFSET).map_err(|_| 1u32)? };
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
                if is_filtered_path(path) {
                    return Ok(0);
                }
                (*e).path_len = path.len() as u16;
            }
        }

        if FILE_DELETE_EVENTS
            .output::<FileDeleteEvent>(&*e, 0)
            .is_err()
        {
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
    let oldname_ptr: u64 = unsafe { ctx.read_at(RENAMEAT_OLDNAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let oldname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RENAMEAT_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let newname_ptr: u64 = unsafe { ctx.read_at(RENAMEAT_NEWNAME_PTR_OFFSET).map_err(|_| 1u32)? };
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
                if is_filtered_path(path) {
                    return Ok(0);
                }
                (*e).old_path_len = path.len() as u16;
            }
        }
        if newname_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut (*e).new_path)
            {
                if is_filtered_path(path) {
                    return Ok(0);
                }
                (*e).new_path_len = path.len() as u16;
            }
        }

        if FILE_RENAME_EVENTS
            .output::<FileRenameEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping rename event"
            );
        }
    }

    Ok(0)
}

// --- File chmod/chown (issue #262 Phase 2) -------------------------------------

/// Ring buffer shared with userspace for `chmod`/`fchmodat` events.
#[map]
static FILE_CHMOD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileChmodEvent` (see `EXEC_SCRATCH`).
#[map]
static CHMOD_SCRATCH: PerCpuArray<FileChmodEvent> = PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `chown`/`lchown`/`fchownat` events.
#[map]
static FILE_CHOWN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileChownEvent` (see `EXEC_SCRATCH`).
#[map]
static CHOWN_SCRATCH: PerCpuArray<FileChownEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_chmod` tracepoint (x86_64/aarch64): `filename`(16),
/// `mode`(24). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_chmod/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHMOD_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHMOD_MODE_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const CHMOD_FILENAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const CHMOD_MODE_OFFSET: usize = 16;

/// Offsets of the `syscalls:sys_enter_fchmodat` tracepoint (x86_64/aarch64): `dfd`(16),
/// `filename`(24), `mode`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// x86_64) via `/sys/kernel/tracing/events/syscalls/sys_enter_fchmodat/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHMODAT_FILENAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHMODAT_MODE_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const FCHMODAT_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const FCHMODAT_MODE_OFFSET: usize = 20;

#[tracepoint]
pub fn sys_enter_chmod(ctx: TracePointContext) -> u32 {
    match try_sys_enter_chmod(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_chmod(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(CHMOD_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CHMOD_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let mode: u64 = unsafe { ctx.read_at(CHMOD_MODE_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let mode: u64 = unsafe { ctx.read_at::<u32>(CHMOD_MODE_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chmod_event(&ctx, filename_ptr, mode)
}

#[tracepoint]
pub fn sys_enter_fchmodat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_fchmodat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_fchmodat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe {
        ctx.read_at(FCHMODAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(FCHMODAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let mode: u64 = unsafe { ctx.read_at(FCHMODAT_MODE_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let mode: u64 = unsafe { ctx.read_at::<u32>(FCHMODAT_MODE_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chmod_event(&ctx, filename_ptr, mode)
}

/// Shared by `sys_enter_chmod` and `sys_enter_fchmodat` above.
fn emit_file_chmod_event(
    ctx: &TracePointContext,
    filename_ptr: u64,
    mode: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CHMOD_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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

        if filename_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
            {
                if is_filtered_path(path) {
                    return Ok(0);
                }
                (*e).path_len = path.len() as u16;
            }
        }
        (*e).mode = mode as u32;

        if FILE_CHMOD_EVENTS.output::<FileChmodEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping chmod event"
            );
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_chown` tracepoint (x86_64/aarch64): `filename`(16),
/// `user`(24), `group`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// x86_64) via `/sys/kernel/tracing/events/syscalls/sys_enter_chown/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHOWN_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHOWN_USER_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CHOWN_GROUP_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const CHOWN_FILENAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const CHOWN_USER_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const CHOWN_GROUP_OFFSET: usize = 20;

/// Offsets of the `syscalls:sys_enter_lchown` tracepoint (x86_64/aarch64): identical
/// shape to `sys_enter_chown` above — `filename`(16), `user`(24), `group`(32). Verified
/// on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_lchown/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LCHOWN_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LCHOWN_USER_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LCHOWN_GROUP_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const LCHOWN_FILENAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const LCHOWN_USER_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const LCHOWN_GROUP_OFFSET: usize = 20;

/// Offsets of the `syscalls:sys_enter_fchownat` tracepoint (x86_64/aarch64): `dfd`(16),
/// `filename`(24), `user`(32), `group`(40), `flag`(48). Verified on 2026-09-22 on Alpine
/// (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_fchownat/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHOWNAT_FILENAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHOWNAT_USER_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FCHOWNAT_GROUP_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const FCHOWNAT_FILENAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const FCHOWNAT_USER_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const FCHOWNAT_GROUP_OFFSET: usize = 24;

#[tracepoint]
pub fn sys_enter_chown(ctx: TracePointContext) -> u32 {
    match try_sys_enter_chown(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_chown(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(CHOWN_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let user: u64 = unsafe { ctx.read_at(CHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let user: u64 = unsafe { ctx.read_at::<u32>(CHOWN_USER_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let group: u64 = unsafe { ctx.read_at(CHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let group: u64 = unsafe { ctx.read_at::<u32>(CHOWN_GROUP_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

#[tracepoint]
pub fn sys_enter_lchown(ctx: TracePointContext) -> u32 {
    match try_sys_enter_lchown(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_lchown(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe { ctx.read_at(LCHOWN_FILENAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(LCHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let user: u64 = unsafe { ctx.read_at(LCHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let user: u64 = unsafe { ctx.read_at::<u32>(LCHOWN_USER_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let group: u64 = unsafe { ctx.read_at(LCHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let group: u64 = unsafe { ctx.read_at::<u32>(LCHOWN_GROUP_OFFSET).map_err(|_| 1u32)? as u64 };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

#[tracepoint]
pub fn sys_enter_fchownat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_fchownat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_fchownat(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let filename_ptr: u64 = unsafe {
        ctx.read_at(FCHOWNAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let filename_ptr: u64 = unsafe {
        ctx.read_at::<u32>(FCHOWNAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let user: u64 = unsafe { ctx.read_at(FCHOWNAT_USER_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let user: u64 = unsafe { ctx.read_at::<u32>(FCHOWNAT_USER_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let group: u64 = unsafe { ctx.read_at(FCHOWNAT_GROUP_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let group: u64 = unsafe {
        ctx.read_at::<u32>(FCHOWNAT_GROUP_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

/// Shared by `sys_enter_chown`, `sys_enter_lchown`, and `sys_enter_fchownat` above.
fn emit_file_chown_event(
    ctx: &TracePointContext,
    filename_ptr: u64,
    user: u64,
    group: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CHOWN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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

        if filename_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
            {
                if is_filtered_path(path) {
                    return Ok(0);
                }
                (*e).path_len = path.len() as u16;
            }
        }
        (*e).uid = user as u32;
        (*e).gid = group as u32;

        if FILE_CHOWN_EVENTS.output::<FileChownEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping chown event"
            );
        }
    }

    Ok(0)
}

// --- Extended attributes (issue #262 Phase 3) ----------------------------------

/// Ring buffer shared with userspace for `setxattr` events.
#[map]
static FILE_SETXATTR_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileSetxattrEvent` (see `EXEC_SCRATCH`).
#[map]
static SETXATTR_SCRATCH: PerCpuArray<FileSetxattrEvent> = PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `removexattr` events.
#[map]
static FILE_REMOVEXATTR_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `FileRemovexattrEvent` (see `EXEC_SCRATCH`).
#[map]
static REMOVEXATTR_SCRATCH: PerCpuArray<FileRemovexattrEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_setxattr` tracepoint (x86_64/aarch64):
/// `pathname`(16), `name`(24), `value`(32, unused), `size`(40, unused), `flags`(48,
/// unused). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_setxattr/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETXATTR_PATHNAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETXATTR_NAME_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const SETXATTR_PATHNAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const SETXATTR_NAME_PTR_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_setxattr(ctx: TracePointContext) -> u32 {
    match try_sys_enter_setxattr(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_setxattr(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at(SETXATTR_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(SETXATTR_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let name_ptr: u64 = unsafe { ctx.read_at(SETXATTR_NAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let name_ptr: u64 = unsafe {
        ctx.read_at::<u32>(SETXATTR_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = SETXATTR_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
                if is_filtered_path(path) {
                    return Ok(0);
                }
                (*e).path_len = path.len() as u16;
            }
        }
        if name_ptr != 0 {
            if let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name) {
                (*e).name_len = name.len() as u16;
            }
        }

        if FILE_SETXATTR_EVENTS
            .output::<FileSetxattrEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping setxattr event"
            );
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_removexattr` tracepoint (x86_64/aarch64):
/// `pathname`(16), `name`(24). Verified on 2026-09-22 on Alpine (kernel
/// 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_removexattr/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const REMOVEXATTR_PATHNAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const REMOVEXATTR_NAME_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const REMOVEXATTR_PATHNAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const REMOVEXATTR_NAME_PTR_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_removexattr(ctx: TracePointContext) -> u32 {
    match try_sys_enter_removexattr(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_removexattr(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at(REMOVEXATTR_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let pathname_ptr: u64 = unsafe {
        ctx.read_at::<u32>(REMOVEXATTR_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let name_ptr: u64 = unsafe { ctx.read_at(REMOVEXATTR_NAME_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let name_ptr: u64 = unsafe {
        ctx.read_at::<u32>(REMOVEXATTR_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = REMOVEXATTR_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
                if is_filtered_path(path) {
                    return Ok(0);
                }
                (*e).path_len = path.len() as u16;
            }
        }
        if name_ptr != 0 {
            if let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name) {
                (*e).name_len = name.len() as u16;
            }
        }

        if FILE_REMOVEXATTR_EVENTS
            .output::<FileRemovexattrEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping removexattr event"
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
const BIND_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BIND_UMYADDR_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const BIND_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const BIND_UMYADDR_PTR_OFFSET: usize = 16;

/// Key into [`BIND_ADDR_MAP`]: a process's fd table entry is per-process, so the
/// same fd number on two different pids is a different socket.
#[repr(C)]
#[derive(Clone, Copy)]
struct BindAddrKey {
    pid: u32,
    fd: u32,
}

/// Value in [`BIND_ADDR_MAP`]: the address a prior `bind(2)` on this `(pid, fd)`
/// claimed, same shape as `SocketBindEvent`'s address fields.
#[repr(C)]
#[derive(Clone, Copy)]
struct BindAddrValue {
    addr_v4: [u8; 4],
    addr_v6: [u8; 16],
    port: u16,
    is_ipv6: bool,
}

/// Correlates a later `listen(2)` back to the address an earlier `bind(2)` on the
/// same `(pid, fd)` claimed — `listen(2)`'s own arguments are just `fd`+`backlog`,
/// no address. Internal to this crate: never read by userspace, so it is not part
/// of `sensor-linux-wire`'s ABI and does not bump `WIRE_VERSION` on its own.
///
/// Entries are never explicitly removed (no `close(2)` probe tracks fd lifetime
/// yet): a `bind()` on a reused fd simply overwrites the old entry, and the
/// map is bounded (`insert` fails silently once full, same graceful-degradation
/// posture as every other best-effort correlation in this file) rather than
/// growing without limit.
#[map]
static BIND_ADDR_MAP: HashMap<BindAddrKey, BindAddrValue> = HashMap::with_max_entries(4096, 0);

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
/// (`laddr`/`lport` vs `daddr`/`dport`) differ. Also records the address into
/// [`BIND_ADDR_MAP`] for `sys_enter_listen` to correlate against later.
fn try_sys_enter_bind(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(BIND_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(BIND_FD_OFFSET).map_err(|_| 1u32)? as u64 };

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
            unsafe { bpf_probe_read_user((umyaddr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)? },
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

        if SOCKET_BIND_EVENTS
            .output::<SocketBindEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping bind event"
            );
        }
    }

    let key = BindAddrKey {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        fd: fd as u32,
    };
    // `BindAddrValue`'s field order (4 + 16 + 2 + bool = 23 bytes of data, but a
    // `u16` field forces the struct's alignment to 2, so its declared size is 24)
    // leaves a 1-byte tail pad that a plain struct literal never writes. That's
    // fine for a value that's only ever read back through this same typed struct
    // — but `bpf_map_update_elem` below copies the map's full declared value_size
    // (24) off the stack, and the verifier tracks stack initialization per byte:
    // on kernel 5.15 it rejects the load with "invalid indirect read from stack
    // ... size 24" because that pad byte was never provably written (issue #390 —
    // reproduced on Ubuntu 22.04/5.15, not on the Alpine 6.18/Arch 6.6 kernels
    // this sensor had been validated against before, so the stricter check isn't
    // universal). Zeroing the whole struct first covers the pad the same way
    // `core::ptr::write_bytes` already does for every ring-buffer scratch struct
    // in this file, just without a `PerCpuArray` backing it.
    let mut value: BindAddrValue = unsafe { core::mem::zeroed() };
    value.addr_v4 = v4;
    value.addr_v6 = v6;
    value.port = u16::from_be(port_be);
    value.is_ipv6 = family == AF_INET6;
    let _ = BIND_ADDR_MAP.insert(&key, &value, 0);

    Ok(0)
}

// --- Socket listen (issue #263 Phase 2) -----------------------------------------

/// Ring buffer shared with userspace for `listen` events.
#[map]
static SOCKET_LISTEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketListenEvent` (see `EXEC_SCRATCH`).
#[map]
static LISTEN_SCRATCH: PerCpuArray<SocketListenEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_listen` tracepoint (x86_64/aarch64): `fd`(16),
/// `backlog`(24). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64)
/// via `/sys/kernel/tracing/events/syscalls/sys_enter_listen/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LISTEN_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LISTEN_BACKLOG_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const LISTEN_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const LISTEN_BACKLOG_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_listen(ctx: TracePointContext) -> u32 {
    match try_sys_enter_listen(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// `listen(2)` carries no address of its own — correlates against [`BIND_ADDR_MAP`]
/// on `(pid, fd)` to recover the address a prior `bind(2)` claimed. No match still
/// emits the event (a process just started listening is worth reporting on its
/// own), with `addr_resolved: false` and the address fields left zeroed.
fn try_sys_enter_listen(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(LISTEN_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(LISTEN_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let backlog: u64 = unsafe { ctx.read_at(LISTEN_BACKLOG_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let backlog: u64 = unsafe {
        ctx.read_at::<u32>(LISTEN_BACKLOG_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let key = BindAddrKey { pid, fd: fd as u32 };
    let bound = unsafe { BIND_ADDR_MAP.get(&key) }.copied();

    let e = LISTEN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = pid;
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
        (*e).backlog = backlog as u32;

        if let Some(addr) = bound {
            (*e).laddr_v4 = addr.addr_v4;
            (*e).laddr_v6 = addr.addr_v6;
            (*e).lport = addr.port;
            (*e).is_ipv6 = addr.is_ipv6;
            (*e).addr_resolved = true;
        }

        if SOCKET_LISTEN_EVENTS
            .output::<SocketListenEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping listen event"
            );
        }
    }

    Ok(0)
}

// --- UDP send (issue #263 Phase 2) ----------------------------------------------

/// Ring buffer shared with userspace for `sendto` events.
#[map]
static UDP_SEND_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `UdpSendEvent` (see `EXEC_SCRATCH`).
#[map]
static UDP_SEND_SCRATCH: PerCpuArray<UdpSendEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_sendto` tracepoint (x86_64/aarch64): `fd`(16),
/// `buff`(24), `len`(32), `flags`(40), `addr`(48), `addr_len`(56). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_sendto/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SENDTO_LEN_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SENDTO_ADDR_PTR_OFFSET: usize = 48;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const SENDTO_LEN_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const SENDTO_ADDR_PTR_OFFSET: usize = 28;

#[tracepoint]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    match try_sys_enter_sendto(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Mirrors `try_sys_enter_connect`/`try_sys_enter_bind` above for the address read —
/// same family filter, same raw-byte address read (avoids the endianness bug
/// documented on `ConnectEvent`) — plus the requested payload size from `len`.
fn try_sys_enter_sendto(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let len: u64 = unsafe { ctx.read_at(SENDTO_LEN_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let len: u64 = unsafe { ctx.read_at::<u32>(SENDTO_LEN_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_ptr: u64 = unsafe { ctx.read_at(SENDTO_ADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let addr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(SENDTO_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    // NULL addr: a connected-socket send (or plain `send(2)`, which glibc issues as
    // `sendto(fd, buf, len, flags, NULL, 0)`) — no destination to report, same
    // treatment as `connect`/`bind`'s own null-address check.
    if addr_ptr == 0 {
        return Ok(0);
    }

    let family: u16 = match unsafe { bpf_probe_read_user(addr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)? },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = UDP_SEND_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).dport = u16::from_be(port_be);
        (*e).daddr_v4 = v4;
        (*e).daddr_v6 = v6;
        (*e).size = len as u32;

        if UDP_SEND_EVENTS.output::<UdpSendEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping udp send event"
            );
        }
    }

    Ok(0)
}

// --- Socket accept (issue #263 Phase 2) -----------------------------------------
//
// First paired sys_enter/sys_exit probe in this crate. Every other probe here is
// sys_enter_*: it reads syscall arguments before the call runs, which is enough
// because the kernel hasn't touched anything yet. accept(2)/accept4(2) are
// different — the caller passes a sockaddr buffer that the kernel fills in DURING
// the call, so the peer address does not exist yet at sys_enter time. The standard
// sys_exit_* tracepoint format carries only __syscall_nr and the return value, not
// the original arguments, so sys_enter_accept{,4} stashes the caller's
// (fd, addr_ptr) in ACCEPT_ARGS (keyed by pid_tgid, the same entry/exit
// correlation pattern already used by the uprobes crate's SSL_READ_ARGS for
// SSL_read's output buffer), and sys_exit_accept{,4} reads it back once the kernel
// has actually written the peer address.

/// Ring buffer shared with userspace for `accept`/`accept4` events.
#[map]
static SOCKET_ACCEPT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketAcceptEvent` (see `EXEC_SCRATCH`).
#[map]
static ACCEPT_SCRATCH: PerCpuArray<SocketAcceptEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed at `sys_enter_accept{,4}`, consumed at `sys_exit_accept{,4}`.
#[repr(C)]
#[derive(Clone, Copy)]
struct AcceptArgs {
    fd: u32,
    addr_ptr: u64,
}

/// Correlates `sys_enter_accept{,4}` with its matching `sys_exit_accept{,4}` on the
/// same thread. Not part of `sensor-linux-wire`'s ABI (never read by userspace).
/// A thread that enters `accept()` and never returns (blocked forever, or the
/// process is killed mid-call) leaks its entry — same accepted risk as
/// `SSL_READ_ARGS`, bounded by `max_entries`, not explicitly swept.
#[map]
static ACCEPT_ARGS: HashMap<u64, AcceptArgs> = HashMap::with_max_entries(1024, 0);

/// Offsets of the `syscalls:sys_enter_accept`/`sys_enter_accept4` tracepoints
/// (x86_64/aarch64): `fd`(16), `upeer_sockaddr`(24) — identical shape for both
/// (accept4's extra `flags` argument trails at 40, not needed here). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_accept{,4}/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const ACCEPT_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const ACCEPT_ADDR_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const ACCEPT_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const ACCEPT_ADDR_PTR_OFFSET: usize = 16;

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

#[tracepoint]
pub fn sys_enter_accept(ctx: TracePointContext) -> u32 {
    match stash_accept_args(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_enter_accept4(ctx: TracePointContext) -> u32 {
    match stash_accept_args(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Shared by `sys_enter_accept` and `sys_enter_accept4` — both have the same
/// `fd`/`upeer_sockaddr` layout.
fn stash_accept_args(ctx: &TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(ACCEPT_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(ACCEPT_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_ptr: u64 = unsafe { ctx.read_at(ACCEPT_ADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let addr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(ACCEPT_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    if addr_ptr != 0 {
        let pid_tgid = bpf_get_current_pid_tgid();
        let args = AcceptArgs {
            fd: fd as u32,
            addr_ptr,
        };
        let _ = ACCEPT_ARGS.insert(&pid_tgid, &args, 0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_exit_accept(ctx: TracePointContext) -> u32 {
    match try_sys_exit_accept(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_exit_accept4(ctx: TracePointContext) -> u32 {
    match try_sys_exit_accept(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Shared by `sys_exit_accept` and `sys_exit_accept4`. No-ops (returns `Ok(0)`
/// without emitting) when: the matching `sys_enter` wasn't tracked (NULL addr, or
/// `ACCEPT_ARGS` was full), the call failed (`ret < 0`), or the peer's address
/// family isn't one this sensor tracks.
fn try_sys_exit_accept(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let ret: i64 = unsafe { ctx.read_at::<i32>(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? as i64 };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { ACCEPT_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = ACCEPT_ARGS.remove(&pid_tgid);

    if ret < 0 {
        return Ok(0);
    }
    let accepted_fd = ret as u32;

    let family: u16 = match unsafe { bpf_probe_read_user(args.addr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((args.addr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe {
                bpf_probe_read_user((args.addr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)?
            },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((args.addr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = ACCEPT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = (pid_tgid >> 32) as u32;
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
        (*e).listen_fd = args.fd;
        (*e).accepted_fd = accepted_fd;
        (*e).peer_addr_v4 = v4;
        (*e).peer_addr_v6 = v6;
        (*e).peer_port = u16::from_be(port_be);
        (*e).is_ipv6 = family == AF_INET6;

        if SOCKET_ACCEPT_EVENTS
            .output::<SocketAcceptEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping accept event"
            );
        }
    }

    Ok(0)
}

/// Ring buffer shared with userspace for `ptrace` events (issue #265).
#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `PtraceEvent` (see `EXEC_SCRATCH`).
#[map]
static PTRACE_SCRATCH: PerCpuArray<PtraceEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_ptrace` tracepoint (x86_64/aarch64):
/// `request`(16), `pid`(24), `addr`(32), `data`(40). Verified on 2026-09-22 on
/// Arch (kernel 6.6.9-arch1-1, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_ptrace/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_REQUEST_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_PID_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_ADDR_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PTRACE_DATA_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const PTRACE_REQUEST_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const PTRACE_PID_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const PTRACE_ADDR_OFFSET: usize = 24;
#[cfg(bpf_target_arch = "x86")]
const PTRACE_DATA_OFFSET: usize = 28;

#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    match try_sys_enter_ptrace(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_ptrace(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let request: u64 = unsafe { ctx.read_at(PTRACE_REQUEST_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let request: u64 = unsafe {
        ctx.read_at::<u32>(PTRACE_REQUEST_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_pid: u64 = unsafe { ctx.read_at(PTRACE_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_pid: u64 =
        unsafe { ctx.read_at::<u32>(PTRACE_PID_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr: u64 = unsafe { ctx.read_at(PTRACE_ADDR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let addr: u64 = unsafe { ctx.read_at::<u32>(PTRACE_ADDR_OFFSET).map_err(|_| 1u32)? as u64 };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let data: u64 = unsafe { ctx.read_at(PTRACE_DATA_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let data: u64 = unsafe { ctx.read_at::<u32>(PTRACE_DATA_OFFSET).map_err(|_| 1u32)? as u64 };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PTRACE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).request = request;
        (*e).target_pid = target_pid as u32;
        (*e).addr = addr;
        (*e).data = data;

        if PTRACE_EVENTS.output::<PtraceEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping ptrace event"
            );
        }
    }

    Ok(0)
}

/// Ring buffer shared with userspace for `process_vm_readv` events (issue #265).
#[map]
static PROCESS_VM_READ_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `ProcessVmReadEvent` (see `EXEC_SCRATCH`).
#[map]
static PROCESS_VM_READ_SCRATCH: PerCpuArray<ProcessVmReadEvent> =
    PerCpuArray::with_max_entries(1, 0);

/// Ring buffer shared with userspace for `process_vm_writev` events (issue #265).
#[map]
static PROCESS_VM_WRITE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `ProcessVmWriteEvent` (see `EXEC_SCRATCH`).
#[map]
static PROCESS_VM_WRITE_SCRATCH: PerCpuArray<ProcessVmWriteEvent> =
    PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_process_vm_readv`/`sys_enter_process_vm_writev`
/// tracepoints (x86_64/aarch64, identical shape on both): `pid`(16), `lvec`(24),
/// `liovcnt`(32), `rvec`(40), `riovcnt`(48). Verified on 2026-09-22 on Arch
/// (kernel 6.6.9-arch1-1, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_process_vm_readv/format` (and
/// `..._writev/format`, identical layout).
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_PID_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_LIOVCNT_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_REMOTE_IOV_OFFSET: usize = 40;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const PROCESS_VM_RIOVCNT_OFFSET: usize = 48;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_PID_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_LIOVCNT_OFFSET: usize = 24;
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_REMOTE_IOV_OFFSET: usize = 28;
#[cfg(bpf_target_arch = "x86")]
const PROCESS_VM_RIOVCNT_OFFSET: usize = 32;

/// Reads `iovec[0].iov_len` from a user-space `struct iovec *`. On x86_64/aarch64
/// `iov_base` (a pointer, unread here) occupies the first 8 bytes and `iov_len`
/// (`size_t`) the next 8. On i686 the whole struct is 4+4 — a 32-bit userspace
/// process's `struct iovec` has no 8-byte fields — so `iov_len` sits at offset 4,
/// not 8, and is itself 4 bytes wide; reading it the 64-bit way would pull half of
/// the next struct into the value. `0` if `iov_ptr` is null, `count` is `0`
/// (nothing to read), or the read fails — best-effort, matching every other
/// user-memory read in this file.
fn read_first_iovec_len(iov_ptr: u64, count: u64) -> u64 {
    if iov_ptr == 0 || count == 0 {
        return 0;
    }
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    {
        unsafe { bpf_probe_read_user((iov_ptr + 8) as *const u64) }.unwrap_or(0)
    }
    #[cfg(bpf_target_arch = "x86")]
    {
        unsafe { bpf_probe_read_user((iov_ptr + 4) as *const u32) }.unwrap_or(0) as u64
    }
}

#[tracepoint]
pub fn sys_enter_process_vm_readv(ctx: TracePointContext) -> u32 {
    match try_sys_enter_process_vm_readv(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_process_vm_readv(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_pid: u64 = unsafe { ctx.read_at(PROCESS_VM_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_pid: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_PID_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let local_iov_count: u64 = unsafe { ctx.read_at(PROCESS_VM_LIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let local_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_LIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_count: u64 =
        unsafe { ctx.read_at(PROCESS_VM_RIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_RIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    let remote_iov_len = read_first_iovec_len(remote_iov_ptr, remote_iov_count);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PROCESS_VM_READ_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).target_pid = target_pid as u32;
        (*e).local_iov_count = local_iov_count;
        (*e).remote_iov_count = remote_iov_count;
        (*e).remote_iov_len = remote_iov_len;

        if PROCESS_VM_READ_EVENTS
            .output::<ProcessVmReadEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping process_vm_readv event"
            );
        }
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_process_vm_writev(ctx: TracePointContext) -> u32 {
    match try_sys_enter_process_vm_writev(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_process_vm_writev(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let target_pid: u64 = unsafe { ctx.read_at(PROCESS_VM_PID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let target_pid: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_PID_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let local_iov_count: u64 = unsafe { ctx.read_at(PROCESS_VM_LIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let local_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_LIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_ptr: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_REMOTE_IOV_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let remote_iov_count: u64 =
        unsafe { ctx.read_at(PROCESS_VM_RIOVCNT_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let remote_iov_count: u64 = unsafe {
        ctx.read_at::<u32>(PROCESS_VM_RIOVCNT_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    let remote_iov_len = read_first_iovec_len(remote_iov_ptr, remote_iov_count);

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PROCESS_VM_WRITE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).target_pid = target_pid as u32;
        (*e).local_iov_count = local_iov_count;
        (*e).remote_iov_count = remote_iov_count;
        (*e).remote_iov_len = remote_iov_len;

        if PROCESS_VM_WRITE_EVENTS
            .output::<ProcessVmWriteEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping process_vm_writev event"
            );
        }
    }

    Ok(0)
}

/// Ring buffer shared with userspace for `memfd_create` events (issue #265).
#[map]
static MEMFD_CREATE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU scratch for building one `MemfdCreateEvent` (see `EXEC_SCRATCH`).
#[map]
static MEMFD_CREATE_SCRATCH: PerCpuArray<MemfdCreateEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_memfd_create` tracepoint (x86_64/aarch64):
/// `uname`(16), `flags`(24). Verified on 2026-09-22 on Arch (kernel
/// 6.6.9-arch1-1, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_memfd_create/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MEMFD_CREATE_NAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const MEMFD_CREATE_FLAGS_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const MEMFD_CREATE_NAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const MEMFD_CREATE_FLAGS_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    match try_sys_enter_memfd_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_memfd_create(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let name_ptr: u64 = unsafe {
        ctx.read_at(MEMFD_CREATE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let name_ptr: u64 = unsafe {
        ctx.read_at::<u32>(MEMFD_CREATE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = unsafe { ctx.read_at(MEMFD_CREATE_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = unsafe {
        ctx.read_at::<u32>(MEMFD_CREATE_FLAGS_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = MEMFD_CREATE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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

        if name_ptr != 0 {
            if let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name) {
                (*e).name_len = name.len() as u16;
            }
        }
        (*e).flags = flags as u32;

        if MEMFD_CREATE_EVENTS
            .output::<MemfdCreateEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping memfd_create event"
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

#[tracepoint]
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

#[tracepoint]
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
#[map]
static SIGNAL_WATCH_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Whether `target_pid` is a signal target this sensor cares about — see
/// `SIGNAL_WATCH_PID` above. `0` (unset) never matches: userspace hasn't written
/// its pid yet, or wrote it as an explicit "watch nothing".
fn is_watched_signal_target(target_pid: u32) -> bool {
    matches!(SIGNAL_WATCH_PID.get(0), Some(&watched) if watched != 0 && watched == target_pid)
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
// is a narrow, accepted gap rather than a missing common path.

#[tracepoint]
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

#[tracepoint]
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

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = SIGNAL_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        // meta is the SENDER, not the target — same convention as macOS's
        // `SignalToEsClient` (see `SignalEvent`'s doc comment in `sensor-linux-wire`).
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
        (*e).signal = sig;
        (*e).target_pid = target_pid;

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

// --- Kernel module load/unload (issue #264) -------------------------------------

/// Ring buffer shared with userspace for `init_module`/`finit_module`/
/// `delete_module` events.
#[map]
static KERNEL_MODULE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `KernelModuleEvent` (see `EXEC_SCRATCH`).
#[map]
static KERNEL_MODULE_SCRATCH: PerCpuArray<KernelModuleEvent> = PerCpuArray::with_max_entries(1, 0);

const KERNEL_MODULE_ACTION_LOAD: u8 = 0;
const KERNEL_MODULE_ACTION_LOAD_FD: u8 = 1;
const KERNEL_MODULE_ACTION_UNLOAD: u8 = 2;

/// Offsets of the `syscalls:sys_enter_init_module` tracepoint (`umod`, `len`,
/// `uargs`), assumed standard layout (16-byte header + 8 bytes/arg on
/// x86_64/aarch64) — re-verify against `/format` on any kernel row added to
/// `lab/MATRIX.md`, same posture as every other offset const in this file.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const INIT_MODULE_LEN_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const INIT_MODULE_LEN_OFFSET: usize = 16;

/// Offsets of the `syscalls:sys_enter_finit_module` tracepoint (`fd`, `uargs`,
/// `flags`), assumed standard layout — see `INIT_MODULE_LEN_OFFSET`'s note.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FINIT_MODULE_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const FINIT_MODULE_FLAGS_OFFSET: usize = 32;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const FINIT_MODULE_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const FINIT_MODULE_FLAGS_OFFSET: usize = 20;

/// Offsets of the `syscalls:sys_enter_delete_module` tracepoint (`name`,
/// `flags`), assumed standard layout — see `INIT_MODULE_LEN_OFFSET`'s note.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const DELETE_MODULE_NAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const DELETE_MODULE_FLAGS_OFFSET: usize = 24;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const DELETE_MODULE_NAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const DELETE_MODULE_FLAGS_OFFSET: usize = 16;

/// Shared by the three probes below: fills `EventMeta` and the action-specific
/// fields into `KERNEL_MODULE_SCRATCH`, then emits. Mirrors `emit_mount_event`'s
/// shape (#362) — one assembly helper for a small family of closely related
/// syscalls that share almost all of their event fields.
fn emit_kernel_module_event(
    ctx: &TracePointContext,
    action: u8,
    name_ptr: u64,
    fd: i32,
    image_len: u64,
    flags: u32,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = KERNEL_MODULE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).action = action;
        (*e).fd = fd;
        (*e).image_len = image_len;
        (*e).flags = flags;

        if name_ptr != 0 {
            if let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name) {
                (*e).name_len = name.len() as u16;
            }
        }

        if KERNEL_MODULE_EVENTS
            .output::<KernelModuleEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping kernel module event"
            );
        }
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_init_module(ctx: TracePointContext) -> u32 {
    match try_sys_enter_init_module(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_init_module(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let len: u64 = unsafe { ctx.read_at(INIT_MODULE_LEN_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let len: u64 = unsafe {
        ctx.read_at::<u32>(INIT_MODULE_LEN_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    // `init_module(2)`'s module image lives inside `umod` — the raw memory blob
    // this probe deliberately does not read (see this crate's WIRE_VERSION v12
    // changelog). Only `len` is captured.
    emit_kernel_module_event(&ctx, KERNEL_MODULE_ACTION_LOAD, 0, -1, len, 0)
}

#[tracepoint]
pub fn sys_enter_finit_module(ctx: TracePointContext) -> u32 {
    match try_sys_enter_finit_module(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_finit_module(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(FINIT_MODULE_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe {
        ctx.read_at::<u32>(FINIT_MODULE_FD_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = unsafe { ctx.read_at(FINIT_MODULE_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = unsafe {
        ctx.read_at::<u32>(FINIT_MODULE_FLAGS_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_kernel_module_event(
        &ctx,
        KERNEL_MODULE_ACTION_LOAD_FD,
        0,
        fd as i32,
        0,
        flags as u32,
    )
}

#[tracepoint]
pub fn sys_enter_delete_module(ctx: TracePointContext) -> u32 {
    match try_sys_enter_delete_module(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_delete_module(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let name_ptr: u64 = unsafe {
        ctx.read_at(DELETE_MODULE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let name_ptr: u64 = unsafe {
        ctx.read_at::<u32>(DELETE_MODULE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = unsafe { ctx.read_at(DELETE_MODULE_FLAGS_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = unsafe {
        ctx.read_at::<u32>(DELETE_MODULE_FLAGS_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    emit_kernel_module_event(
        &ctx,
        KERNEL_MODULE_ACTION_UNLOAD,
        name_ptr,
        -1,
        0,
        flags as u32,
    )
}

// --- eBPF program/map lifecycle (issue #264) --------------------------------------

/// Ring buffer shared with userspace for filtered `bpf(2)` events.
#[map]
static BPF_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `BpfEvent` (see `EXEC_SCRATCH`).
#[map]
static BPF_SCRATCH: PerCpuArray<BpfEvent> = PerCpuArray::with_max_entries(1, 0);

/// `enum bpf_cmd` values (`<linux/bpf.h>`) this probe cares about. Every other
/// command — `BPF_MAP_LOOKUP_ELEM`/`BPF_MAP_UPDATE_ELEM`/etc., the overwhelming
/// majority of real `bpf(2)` traffic, including this agent's own sensor's
/// map reads/writes at runtime — is filtered in-kernel before touching the ring
/// buffer (see this crate's WIRE_VERSION v12 changelog).
const BPF_CMD_MAP_CREATE: u32 = 0;
const BPF_CMD_PROG_LOAD: u32 = 5;
const BPF_CMD_PROG_ATTACH: u32 = 8;

/// Offsets of the `syscalls:sys_enter_bpf` tracepoint (`cmd`, `uattr`, `size`),
/// assumed standard layout — see `INIT_MODULE_LEN_OFFSET`'s note above.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BPF_CMD_OFFSET: usize = 16;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const BPF_CMD_OFFSET: usize = 12;

#[tracepoint]
pub fn sys_enter_bpf(ctx: TracePointContext) -> u32 {
    match try_sys_enter_bpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_bpf(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let cmd: u64 = unsafe { ctx.read_at(BPF_CMD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let cmd: u64 = unsafe { ctx.read_at::<u32>(BPF_CMD_OFFSET).map_err(|_| 1u32)? as u64 };
    let cmd = cmd as u32;

    if cmd != BPF_CMD_MAP_CREATE && cmd != BPF_CMD_PROG_LOAD && cmd != BPF_CMD_PROG_ATTACH {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = BPF_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).cmd = cmd;

        if BPF_EVENTS.output::<BpfEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping bpf event"
            );
        }
    }

    Ok(0)
}

// --- Identity change (issue #266) -------------------------------------------------

/// Ring buffer shared with userspace for `setuid`/`setgid`/`setresuid`/
/// `setresgid`/`setfsuid`/`setfsgid` events.
#[map]
static IDENTITY_CHANGE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `IdentityChangeEvent` (see `EXEC_SCRATCH`).
#[map]
static IDENTITY_CHANGE_SCRATCH: PerCpuArray<IdentityChangeEvent> =
    PerCpuArray::with_max_entries(1, 0);

const IDENTITY_KIND_SETUID: u8 = 0;
const IDENTITY_KIND_SETGID: u8 = 1;
const IDENTITY_KIND_SETRESUID: u8 = 2;
const IDENTITY_KIND_SETRESGID: u8 = 3;
const IDENTITY_KIND_SETFSUID: u8 = 4;
const IDENTITY_KIND_SETFSGID: u8 = 5;

/// Offset of `setuid(2)`/`setgid(2)`/`setfsuid(2)`/`setfsgid(2)`'s single
/// `uid_t`/`gid_t` argument — identical shape across all four, assumed
/// standard layout (16-byte header + 8 bytes/arg on x86_64/aarch64);
/// re-verify against `/format` on any kernel row added to `lab/MATRIX.md`,
/// same posture as every other offset const in this file.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SINGLE_ID_OFFSET: usize = 16;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const SINGLE_ID_OFFSET: usize = 12;

/// Offsets of `setresuid(2)`/`setresgid(2)`'s three `uid_t`/`gid_t`
/// arguments (real, effective, saved) — identical shape for both, assumed
/// standard layout, same posture as `SINGLE_ID_OFFSET`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RES_ID_REAL_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RES_ID_EFFECTIVE_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RES_ID_SAVED_OFFSET: usize = 32;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const RES_ID_REAL_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const RES_ID_EFFECTIVE_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const RES_ID_SAVED_OFFSET: usize = 20;

/// Shared by all six probes below: fills `EventMeta` and the kind-specific id
/// fields into `IDENTITY_CHANGE_SCRATCH`, then emits. Mirrors
/// `emit_kernel_module_event`'s shape (#264) — one assembly helper for a
/// family of syscalls that share almost all of their event fields.
fn emit_identity_change_event(
    ctx: &TracePointContext,
    kind: u8,
    real: u32,
    effective: u32,
    saved: u32,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = IDENTITY_CHANGE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).kind = kind;
        (*e).real = real;
        (*e).effective = effective;
        (*e).saved = saved;

        if IDENTITY_CHANGE_EVENTS
            .output::<IdentityChangeEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping identity change event"
            );
        }
    }

    Ok(0)
}

/// Reads a single 32-bit `uid_t`/`gid_t` syscall argument at `SINGLE_ID_OFFSET`,
/// shared by `setuid`/`setgid`/`setfsuid`/`setfsgid` — the four probes below
/// differ only in which `IDENTITY_KIND_*` they pass through.
fn read_single_id(ctx: &TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let id: u64 = unsafe { ctx.read_at(SINGLE_ID_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let id: u64 = unsafe { ctx.read_at::<u32>(SINGLE_ID_OFFSET).map_err(|_| 1u32)? as u64 };
    Ok(id as u32)
}

#[tracepoint]
pub fn sys_enter_setuid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(uid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETUID, uid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_enter_setgid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(gid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETGID, gid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_enter_setfsuid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(fsuid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETFSUID, fsuid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_enter_setfsgid(ctx: TracePointContext) -> u32 {
    match read_single_id(&ctx) {
        Ok(fsgid) => match emit_identity_change_event(&ctx, IDENTITY_KIND_SETFSGID, fsgid, 0, 0) {
            Ok(ret) | Err(ret) => ret,
        },
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_enter_setresuid(ctx: TracePointContext) -> u32 {
    match try_sys_enter_setres(&ctx) {
        Ok((real, effective, saved)) => {
            match emit_identity_change_event(&ctx, IDENTITY_KIND_SETRESUID, real, effective, saved)
            {
                Ok(ret) | Err(ret) => ret,
            }
        }
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_enter_setresgid(ctx: TracePointContext) -> u32 {
    match try_sys_enter_setres(&ctx) {
        Ok((real, effective, saved)) => {
            match emit_identity_change_event(&ctx, IDENTITY_KIND_SETRESGID, real, effective, saved)
            {
                Ok(ret) | Err(ret) => ret,
            }
        }
        Err(ret) => ret,
    }
}

fn try_sys_enter_setres(ctx: &TracePointContext) -> Result<(u32, u32, u32), u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let real: u64 = unsafe { ctx.read_at(RES_ID_REAL_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let real: u64 = unsafe { ctx.read_at::<u32>(RES_ID_REAL_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let effective: u64 = unsafe { ctx.read_at(RES_ID_EFFECTIVE_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let effective: u64 = unsafe {
        ctx.read_at::<u32>(RES_ID_EFFECTIVE_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let saved: u64 = unsafe { ctx.read_at(RES_ID_SAVED_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let saved: u64 = unsafe { ctx.read_at::<u32>(RES_ID_SAVED_OFFSET).map_err(|_| 1u32)? as u64 };

    Ok((real as u32, effective as u32, saved as u32))
}

// --- Capability set change (issue #266) ---------------------------------------

/// Ring buffer shared with userspace for `capset` events.
#[map]
static CAPSET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `CapSetEvent` (see `EXEC_SCRATCH`).
#[map]
static CAPSET_SCRATCH: PerCpuArray<CapSetEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_capset` tracepoint (`hdrp`, `data`),
/// assumed standard layout — see `SINGLE_ID_OFFSET`'s note above.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CAPSET_HDRP_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const CAPSET_DATA_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const CAPSET_HDRP_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const CAPSET_DATA_PTR_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_capset(ctx: TracePointContext) -> u32 {
    match try_sys_enter_capset(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// `struct __user_cap_header_struct { __u32 version; int pid; }` — `pid` is
/// the second field, 4 bytes in.
const CAP_HEADER_PID_OFFSET: u64 = 4;
/// `struct __user_cap_data_struct { __u32 effective; __u32 permitted;
/// __u32 inheritable; }` — this probe reads only element `[0]` of `datap`'s
/// array (the low 32 capability bits; see this crate's WIRE_VERSION v12
/// changelog for why that's deliberately sufficient), so no stride constant
/// for element `[1]` is needed.
const CAP_DATA_PERMITTED_OFFSET: u64 = 4;
const CAP_DATA_INHERITABLE_OFFSET: u64 = 8;

fn try_sys_enter_capset(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let hdrp_ptr: u64 = unsafe { ctx.read_at(CAPSET_HDRP_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let hdrp_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CAPSET_HDRP_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let data_ptr: u64 = unsafe { ctx.read_at(CAPSET_DATA_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let data_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CAPSET_DATA_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let target_pid: u32 = if hdrp_ptr != 0 {
        unsafe { bpf_probe_read_user((hdrp_ptr + CAP_HEADER_PID_OFFSET) as *const i32) }
            .map(|p: i32| p as u32)
            .unwrap_or(0)
    } else {
        0
    };

    let (effective, permitted, inheritable) = if data_ptr != 0 {
        let effective = unsafe { bpf_probe_read_user(data_ptr as *const u32) }.unwrap_or(0);
        let permitted =
            unsafe { bpf_probe_read_user((data_ptr + CAP_DATA_PERMITTED_OFFSET) as *const u32) }
                .unwrap_or(0);
        let inheritable =
            unsafe { bpf_probe_read_user((data_ptr + CAP_DATA_INHERITABLE_OFFSET) as *const u32) }
                .unwrap_or(0);
        (effective, permitted, inheritable)
    } else {
        (0, 0, 0)
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CAPSET_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).target_pid = target_pid;
        (*e).effective = effective;
        (*e).permitted = permitted;
        (*e).inheritable = inheritable;

        if CAPSET_EVENTS.output::<CapSetEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping capset event"
            );
        }
    }

    Ok(0)
}

// --- Namespace manipulation (issue #266) ----------------------------------------

/// Ring buffer shared with userspace for `setns`/`unshare` events.
#[map]
static NAMESPACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `NamespaceEvent` (see `EXEC_SCRATCH`).
#[map]
static NAMESPACE_SCRATCH: PerCpuArray<NamespaceEvent> = PerCpuArray::with_max_entries(1, 0);

const NAMESPACE_SYSCALL_SETNS: u8 = 0;
const NAMESPACE_SYSCALL_UNSHARE: u8 = 1;

/// Offsets of the `syscalls:sys_enter_setns` tracepoint (`fd`, `nstype`),
/// assumed standard layout — see `SINGLE_ID_OFFSET`'s note above.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETNS_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETNS_NSTYPE_OFFSET: usize = 24;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const SETNS_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const SETNS_NSTYPE_OFFSET: usize = 16;

/// Offset of the `syscalls:sys_enter_unshare` tracepoint's single `flags`
/// argument — assumed standard layout, see `SINGLE_ID_OFFSET`'s note above.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const UNSHARE_FLAGS_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const UNSHARE_FLAGS_OFFSET: usize = 12;

fn emit_namespace_event(ctx: &TracePointContext, syscall: u8, fd: i32, flags: u32) -> u32 {
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 1,
    };
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let Some(e) = NAMESPACE_SCRATCH.get_ptr_mut(0) else {
        return 1;
    };
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
        (*e).syscall = syscall;
        (*e).fd = fd;
        (*e).flags = flags;

        if NAMESPACE_EVENTS.output::<NamespaceEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping namespace event"
            );
        }
    }

    0
}

#[tracepoint]
pub fn sys_enter_setns(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = match unsafe { ctx.read_at(SETNS_FD_OFFSET) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = match unsafe { ctx.read_at::<u32>(SETNS_FD_OFFSET) } {
        Ok(v) => v as u64,
        Err(_) => return 1,
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let nstype: u64 = match unsafe { ctx.read_at(SETNS_NSTYPE_OFFSET) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    #[cfg(bpf_target_arch = "x86")]
    let nstype: u64 = match unsafe { ctx.read_at::<u32>(SETNS_NSTYPE_OFFSET) } {
        Ok(v) => v as u64,
        Err(_) => return 1,
    };

    emit_namespace_event(&ctx, NAMESPACE_SYSCALL_SETNS, fd as i32, nstype as u32)
}

#[tracepoint]
pub fn sys_enter_unshare(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = match unsafe { ctx.read_at(UNSHARE_FLAGS_OFFSET) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = match unsafe { ctx.read_at::<u32>(UNSHARE_FLAGS_OFFSET) } {
        Ok(v) => v as u64,
        Err(_) => return 1,
    };

    emit_namespace_event(&ctx, NAMESPACE_SYSCALL_UNSHARE, -1, flags as u32)
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

// --- Uprobes: DNS resolution capture (issue #267 Phase 1) -------------------------
//
// getaddrinfo(3) uprobe/uretprobe pair, attached from userspace (sensor-linux-uprobes)
// after resolving the symbol in libc with goblin — same shape as the SSL_read
// entry/exit pair above: the resolved address is only in `*res` once the call
// returns, so entry stashes what's needed to read it back at exit.

/// Ring buffer for DNS query events.
#[map]
static DNS_QUERY_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `GetAddrInfoEvent` (see `EXEC_SCRATCH`).
#[map]
static DNS_SCRATCH: PerCpuArray<GetAddrInfoEvent> = PerCpuArray::with_max_entries(1, 0);

/// Tracks `getaddrinfo(3)` arguments between entry and return:
/// pid_tgid → (node_ptr, res_ptr_ptr). `getaddrinfo(const char *node, const char
/// *service, const struct addrinfo *hints, struct addrinfo **res)` only populates
/// `*res` on success, so the entry probe stashes the query-name pointer and the
/// address OF the caller's `res` output variable (not what it points to yet) — the
/// uretprobe dereferences it once glibc has filled it in. Same pid_tgid-keyed
/// correlation-map shape as `SSL_READ_ARGS` above.
#[map]
static GETADDRINFO_ARGS: HashMap<u64, (u64, u64)> = HashMap::with_max_entries(1024, 0);

/// `struct addrinfo` field offsets (glibc, LP64 — `ai_flags`/`ai_family`/
/// `ai_socktype`/`ai_protocol` are each 4-byte `int`s, then `ai_addrlen`
/// (`socklen_t`, 4 bytes) plus 4 bytes of padding to align the pointer fields
/// that follow): `ai_family` at +4, the `struct sockaddr *ai_addr` pointer at
/// +24. This is a userspace ABI (glibc's `<netdb.h>`), not a kernel
/// tracepoint, so there is no i686-vs-x86_64 arg-slot-width concern here —
/// only genuine 32-bit-userspace `struct addrinfo` layout would differ, and
/// this sensor doesn't target 32-bit userspace processes.
const ADDRINFO_FAMILY_OFFSET: u64 = 4;
const ADDRINFO_ADDR_PTR_OFFSET: u64 = 24;

/// `sockaddr_in`/`sockaddr_in6` field offsets: the address bytes start right
/// after `sin_family`+`sin_port` (4 bytes) for IPv4, and after
/// `sin6_family`+`sin6_port`+`sin6_flowinfo` (8 bytes) for IPv6 — same
/// layout `sys_enter_connect`/`sys_enter_bind` above already rely on.
const SOCKADDR_IN_ADDR_OFFSET: u64 = 4;
const SOCKADDR_IN6_ADDR_OFFSET: u64 = 8;

/// Uprobe on `getaddrinfo(3)` entry: stash the query name and the `res`
/// output-parameter address for the uretprobe.
#[uprobe]
pub fn getaddrinfo_entry(ctx: ProbeContext) -> u32 {
    // int getaddrinfo(const char *node, const char *service,
    //                  const struct addrinfo *hints, struct addrinfo **res)
    if let (Some(node_ptr), Some(res_ptr_ptr)) = (ctx.arg::<u64>(0), ctx.arg::<u64>(3))
        && node_ptr != 0
    {
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = GETADDRINFO_ARGS.insert(&pid_tgid, &(node_ptr, res_ptr_ptr), 0);
    }
    0
}

/// Uretprobe on `getaddrinfo(3)` return: emits the query, the status, and —
/// on success — the first resolved address.
#[uretprobe]
pub fn getaddrinfo_exit(ctx: RetProbeContext) -> u32 {
    match try_getaddrinfo_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_getaddrinfo_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let status: i32 = ctx.ret::<i32>();

    let pid_tgid = bpf_get_current_pid_tgid();
    let (node_ptr, res_ptr_ptr) = match unsafe { GETADDRINFO_ARGS.get(&pid_tgid) } {
        Some(args) => *args,
        None => return Ok(0), // entry wasn't tracked (probe attached mid-call)
    };
    let _ = GETADDRINFO_ARGS.remove(&pid_tgid);

    // Only the FIRST addrinfo entry is decoded — see this crate's
    // WIRE_VERSION v12 changelog for why walking `ai_next` is deferred.
    let mut addr_resolved = false;
    let mut is_ipv6 = false;
    let mut addr_v4 = [0u8; 4];
    let mut addr_v6 = [0u8; 16];
    if status == 0 && res_ptr_ptr != 0 {
        let addrinfo_ptr = unsafe { bpf_probe_read_user(res_ptr_ptr as *const u64) }.unwrap_or(0);
        if addrinfo_ptr != 0 {
            let family = unsafe {
                bpf_probe_read_user((addrinfo_ptr + ADDRINFO_FAMILY_OFFSET) as *const i32)
            }
            .unwrap_or(0);
            let sockaddr_ptr = unsafe {
                bpf_probe_read_user((addrinfo_ptr + ADDRINFO_ADDR_PTR_OFFSET) as *const u64)
            }
            .unwrap_or(0);
            if sockaddr_ptr != 0 {
                if family == i32::from(AF_INET) {
                    if let Ok(addr) = unsafe {
                        bpf_probe_read_user(
                            (sockaddr_ptr + SOCKADDR_IN_ADDR_OFFSET) as *const [u8; 4],
                        )
                    } {
                        addr_v4 = addr;
                        addr_resolved = true;
                    }
                } else if family == i32::from(AF_INET6)
                    && let Ok(addr) = unsafe {
                        bpf_probe_read_user(
                            (sockaddr_ptr + SOCKADDR_IN6_ADDR_OFFSET) as *const [u8; 16],
                        )
                    }
                {
                    addr_v6 = addr;
                    is_ipv6 = true;
                    addr_resolved = true;
                }
            }
        }
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = DNS_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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

        if let Ok(query) = bpf_probe_read_user_str_bytes(node_ptr as *const u8, &mut (*e).query) {
            (*e).query_len = query.len() as u16;
        }
        (*e).status = status;
        (*e).addr_resolved = addr_resolved;
        (*e).is_ipv6 = is_ipv6;
        (*e).addr_v4 = addr_v4;
        (*e).addr_v6 = addr_v6;

        if DNS_QUERY_EVENTS.output::<GetAddrInfoEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping DNS query event"
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
