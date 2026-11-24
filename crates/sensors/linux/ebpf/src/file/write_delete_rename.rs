//! File write/delete/rename (issue #262)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{FileDeleteEvent, FileRenameEvent, FileWriteEvent, is_filtered_path};

use crate::{fill_event_meta, into_ret, mount_signal::signal::is_agent_own_pid};

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
/// `syscalls:*` layout (see `sys_enter_openat` in `open.rs`): `fd`(16), `buf`(24),
/// `count`(32). Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_write/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const WRITE_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const WRITE_BUF_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const WRITE_COUNT_OFFSET: usize = 32;
/// i686: packed 4-byte args, no independent kernel verification — inferred by the
/// same 4-byte-shift rule already used (and flagged the same way) for `sys_enter_open`
/// in `open.rs`: `fd`(12), `buf`(16), `count`(20).
#[cfg(bpf_target_arch = "x86")]
pub(crate) const WRITE_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
pub(crate) const WRITE_BUF_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
pub(crate) const WRITE_COUNT_OFFSET: usize = 20;

pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_write(ctx))
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

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if is_agent_own_pid(pid) {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = WRITE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(&mut (*e).meta, pid, uid_gid, &comm);
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

pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_unlink(ctx))
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

pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_unlinkat(ctx))
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
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );

        if pathname_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut (*e).path)
            {
                if is_filtered_path(path, 0, true) {
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

/// `AT_FDCWD`: the "directory fd" `rename(2)` implicitly has, and what a `renameat`
/// caller passes to mean the current directory (#515). Userspace resolves a relative
/// path against the renaming process's cwd when it sees it.
const AT_FDCWD: i32 = -100;

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
const RENAMEAT_OLDDFD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT_NEWDFD_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT_OLDNAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT_NEWNAME_PTR_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT_OLDDFD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT_NEWDFD_OFFSET: usize = 20;
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
const RENAMEAT2_OLDDFD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT2_NEWDFD_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT2_OLDNAME_PTR_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RENAMEAT2_NEWNAME_PTR_OFFSET: usize = 40;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT2_OLDDFD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT2_NEWDFD_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT2_OLDNAME_PTR_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const RENAMEAT2_NEWNAME_PTR_OFFSET: usize = 24;

pub fn sys_enter_rename(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_rename(ctx))
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

    emit_file_rename_event(&ctx, AT_FDCWD, oldname_ptr, AT_FDCWD, newname_ptr)
}

pub fn sys_enter_renameat(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_renameat(ctx))
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

    // The tracepoint field is a `long` holding an `int`: the low 32 bits are the fd,
    // little-endian on every supported target (#515).
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let olddfd: i32 = unsafe {
        ctx.read_at::<u64>(RENAMEAT_OLDDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    #[cfg(bpf_target_arch = "x86")]
    let olddfd: i32 = unsafe {
        ctx.read_at::<u32>(RENAMEAT_OLDDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let newdfd: i32 = unsafe {
        ctx.read_at::<u64>(RENAMEAT_NEWDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    #[cfg(bpf_target_arch = "x86")]
    let newdfd: i32 = unsafe {
        ctx.read_at::<u32>(RENAMEAT_NEWDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;

    emit_file_rename_event(&ctx, olddfd, oldname_ptr, newdfd, newname_ptr)
}

pub fn sys_enter_renameat2(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_renameat2(ctx))
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

    // The tracepoint field is a `long` holding an `int`: the low 32 bits are the fd,
    // little-endian on every supported target (#515).
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let olddfd: i32 = unsafe {
        ctx.read_at::<u64>(RENAMEAT2_OLDDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    #[cfg(bpf_target_arch = "x86")]
    let olddfd: i32 = unsafe {
        ctx.read_at::<u32>(RENAMEAT2_OLDDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let newdfd: i32 = unsafe {
        ctx.read_at::<u64>(RENAMEAT2_NEWDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    #[cfg(bpf_target_arch = "x86")]
    let newdfd: i32 = unsafe {
        ctx.read_at::<u32>(RENAMEAT2_NEWDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;

    emit_file_rename_event(&ctx, olddfd, oldname_ptr, newdfd, newname_ptr)
}

/// Shared by `sys_enter_rename`/`sys_enter_renameat`/`sys_enter_renameat2` above.
fn emit_file_rename_event(
    ctx: &TracePointContext,
    olddfd: i32,
    oldname_ptr: u64,
    newdfd: i32,
    newname_ptr: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = RENAME_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).old_dfd = olddfd;
        (*e).new_dfd = newdfd;

        if oldname_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut (*e).old_path)
            {
                if is_filtered_path(path, 0, true) {
                    return Ok(0);
                }
                (*e).old_path_len = path.len() as u16;
            }
        }
        if newname_ptr != 0 {
            if let Ok(path) =
                bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut (*e).new_path)
            {
                if is_filtered_path(path, 0, true) {
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
