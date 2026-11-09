//! File opens: the `openat`/`open` syscall handlers.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{FileOpenEvent, TASK_COMM_LEN, is_filtered_path};

use crate::{fill_lineage, is_agent_own_pid};

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
/// not show up on the glibc lab machines. Attaching only `sys_enter_openat`
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
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if is_agent_own_pid(pid) {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    // Assemble in per-CPU scratch, then one `output` copy — a struct literal on
    // the stack leaves interior padding uninitialised, and `entry.write` copying
    // that into the ring buffer is rejected by the verifier on pre-6.6 kernels.
    let e = OPEN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        (*e).meta.pid = pid;
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
        (*e).flags = flags as u32;

        if filename_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
            {
                if is_filtered_path(path, flags, false) {
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
