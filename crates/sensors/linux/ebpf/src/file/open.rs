//! File opens: the `openat`/`openat2`/`open` syscall handlers.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use sensor_linux_wire::{DISPATCH_OPENAT2, FileOpenEvent, is_filtered_path};

use crate::{
    arch::{SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
    mount_signal::signal::is_agent_own_pid,
};

/// Ring buffer shared with userspace for `open` events. One record is 336 bytes (a 328-byte
/// `FileOpenEvent` plus the ring's 8-byte header), so 256 KiB held about 780. systemd's device
/// enumeration reads `uevent` and friends under `/sys` with relative `openat`, which the read
/// filter cannot see (#334), in bursts of a few thousand opens. In the lab (2 vCPU, release
/// agent, 2026-11-24) 256 KiB lost 6,355 of 10,000 opens sent in bursts of 2,000 and 3,000;
/// 1 MiB lost none.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Per-CPU scratch for building one `FileOpenEvent` (see `EXEC_SCRATCH`).
#[map]
static OPEN_SCRATCH: PerCpuArray<FileOpenEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_openat` tracepoint (`x86_64`). Standard, stable format of
/// the `syscalls:*` subsystem (documented, unlike `sched:*` tracepoints whose layout can vary
/// more): an 8-byte common header, `__syscall_nr` (4 bytes + padding), then the syscall
/// arguments aligned on 8 bytes each — `dfd`(16), `filename`(24), `flags`(32), `mode`(40).
/// Verified on 2026-09-16 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format`.
///
/// Known limit: `filename` is the raw path passed by the caller, not resolved against `dfd` —
/// a path relative to a non-standard directory descriptor will appear as-is, without the
/// absolute prefix. Known accepted limitation; conformance reports it.
///
/// On i686, no padding between arguments (all 4-byte `int`s/pointers, packed
/// consecutively): `dfd`(12), `filename`(16), `flags`(20), `mode`(24) — verified on
/// 2026-08-19 via `/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format` on the
/// target i686 kernel (Debian 12 Bookworm, `6.1.0-52-686-pae`). Unlike `x86_64` above, the raw
/// value at this offset occupies 4 bytes, not 8: `arch::CULong` is `u32` there, and
/// `read_ulong_arg` widens it.
const OPENAT_FILENAME_PTR_OFFSET: usize = arg_offset(1);
const OPENAT_FLAGS_OFFSET: usize = arg_offset(2);

/// Offsets of the `syscalls:sys_enter_open` tracepoint — the plain `open(2)` syscall, one
/// argument short of `openat` above (no leading `dfd`), so `filename`/`flags` land 8 bytes
/// (`x86_64/aarch64`) / 4 bytes (i686) earlier. Needed because musl — and every busybox applet
/// linked against it, `cat` included — still issues `open(2)` directly; glibc has rewritten
/// `open()` to call `openat(AT_FDCWD, ...)` internally since 2.26, which is why this gap did
/// not show up on the glibc lab machines. Attaching only `sys_enter_openat`
/// therefore captured zero file-open events on Alpine — confirmed via
/// `strace -e trace=open,openat cat /etc/hostname` showing a bare `open()`, then via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_open/format` on 2026-09-16 (same kernel as
/// above): `filename`(16), `flags`(24), `mode`(32). i686 offsets are inferred by the same
/// 4-byte shift from the verified `sys_enter_openat` i686 layout, not independently confirmed
/// on hardware.
const OPEN_FILENAME_PTR_OFFSET: usize = arg_offset(0);
const OPEN_FLAGS_OFFSET: usize = arg_offset(1);

/// Where an `openat`-shaped call keeps its flags (#349). `openat2(2)` (5.6+) takes the same
/// `dfd` and `filename`, but its third argument is a `struct open_how *`, whose first field is
/// the `u64` flags; `resolve` restricts how the path is walked, not what is opened, so it is not
/// read. Fieldless on purpose: an enum with a payload crossing a call boundary once failed the
/// verifier's uninitialised-stack check (`path_filter.rs`).
#[derive(Clone, Copy)]
pub enum OpenFlags {
    /// `openat(2)`: the flags are the third argument.
    InArgument,
    /// `openat2(2)`: the third argument points to a `struct open_how`.
    InOpenHow,
}

impl OpenFlags {
    /// The flag source of a `raw_sys_enter` action routed to [`sys_enter_openat`].
    #[must_use]
    pub fn from_action(action: u32) -> Self {
        if action == DISPATCH_OPENAT2 {
            Self::InOpenHow
        } else {
            Self::InArgument
        }
    }
}

pub fn sys_enter_openat(ctx: TracePointContext, flags_source: OpenFlags) -> u32 {
    into_ret(try_sys_enter_openat(ctx, flags_source))
}

fn try_sys_enter_openat(ctx: TracePointContext, flags_source: OpenFlags) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(OPENAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let flags = read_open_flags(&ctx, flags_source)?;

    emit_file_open_event(filename_ptr, flags)
}

/// The open flags, read from the argument or from the caller's `struct open_how`.
fn read_open_flags(ctx: &TracePointContext, flags_source: OpenFlags) -> Result<i64, u32> {
    match flags_source {
        OpenFlags::InArgument => unsafe {
            ctx.read_long_arg(OPENAT_FLAGS_OFFSET).map_err(|_| 1u32)
        },
        OpenFlags::InOpenHow => {
            let how_ptr: u64 =
                unsafe { ctx.read_ulong_arg(OPENAT_FLAGS_OFFSET).map_err(|_| 1u32)? };
            let flags = unsafe { bpf_probe_read_user(how_ptr as *const u64).map_err(|_| 1u32)? };
            Ok(flags as i64)
        }
    }
}

pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_open(ctx))
}

fn try_sys_enter_open(ctx: TracePointContext) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(OPEN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    let flags: i64 = unsafe { ctx.read_long_arg(OPEN_FLAGS_OFFSET).map_err(|_| 1u32)? };

    emit_file_open_event(filename_ptr, flags)
}

/// Shared by `sys_enter_openat` (and `openat2`) and `sys_enter_open` above: all land on the same
/// `FileOpenEvent` shape/`FILE_OPEN_EVENTS` ring buffer, and differ only in where
/// `filename`/`flags` sit in the tracepoint record.
fn emit_file_open_event(filename_ptr: u64, flags: i64) -> Result<u32, u32> {
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

        fill_event_meta(&mut (*e).meta, pid, uid_gid, &comm);
        (*e).flags = flags as u32;

        if filename_ptr != 0
            && let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
        {
            if is_filtered_path(path, flags, false) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
        }

        if FILE_OPEN_EVENTS.output::<FileOpenEvent>(&*e, 0).is_err() {
            crate::count_ring_drop(sensor_linux_wire::ring::FILE_OPEN);
        }
    }

    Ok(0)
}
