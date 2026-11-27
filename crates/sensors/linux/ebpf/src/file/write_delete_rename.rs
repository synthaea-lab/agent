//! File write/delete/rename (issue #262)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, raw_tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
};
use sensor_linux_wire::{
    FileDeleteEvent, FileRenameEvent, FileWriteEvent, file_filter, is_filtered_path,
};

use super::{FILE_FILTER_PROGS, stored_path_filtered};
use crate::{
    arch::{SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
    mount_signal::signal::is_agent_own_pid,
};

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

/// Offsets of the `syscalls:sys_enter_write` tracepoint (`x86_64/aarch64`). Standard
/// `syscalls:*` layout (see `sys_enter_openat` in `open.rs`): `fd`(16), `buf`(24),
/// `count`(32). Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_write/format`.
///
/// i686: packed 4-byte args, no independent kernel verification — inferred by the
/// same 4-byte-shift rule already used (and flagged the same way) for `sys_enter_open`
/// in `open.rs`: `fd`(12), `buf`(16), `count`(20).
pub(crate) const WRITE_FD_OFFSET: usize = arg_offset(0);
pub(crate) const WRITE_BUF_OFFSET: usize = arg_offset(1);
pub(crate) const WRITE_COUNT_OFFSET: usize = arg_offset(2);

pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_write(ctx))
}

fn try_sys_enter_write(ctx: TracePointContext) -> Result<u32, u32> {
    let fd: u64 = unsafe { ctx.read_ulong_arg(WRITE_FD_OFFSET).map_err(|_| 1u32)? };

    let count: u64 = unsafe { ctx.read_ulong_arg(WRITE_COUNT_OFFSET).map_err(|_| 1u32)? };

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
            crate::count_ring_drop(sensor_linux_wire::ring::FILE_WRITE);
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_unlink` tracepoint (`x86_64`/`aarch64`):
/// `pathname`(16). Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, `x86_64`)
/// via `/sys/kernel/tracing/events/syscalls/sys_enter_unlink/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const UNLINK_PATHNAME_PTR_OFFSET: usize = arg_offset(0);

/// Offsets of the `syscalls:sys_enter_unlinkat` tracepoint (`x86_64`/`aarch64`):
/// `dfd`(16), `pathname`(24), `flag`(32). Verified on 2026-09-21 on Alpine
/// (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_unlinkat/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const UNLINKAT_PATHNAME_PTR_OFFSET: usize = arg_offset(1);

#[inline(always)]
pub fn sys_enter_unlink<const TC: bool>(raw: &RawTracePointContext, ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_unlink::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_unlink<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let pathname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(UNLINK_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    emit_file_delete_event::<TC>(raw, pathname_ptr)
}

#[inline(always)]
pub fn sys_enter_unlinkat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> u32 {
    into_ret(try_sys_enter_unlinkat::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_unlinkat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let pathname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(UNLINKAT_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    emit_file_delete_event::<TC>(raw, pathname_ptr)
}

/// Shared by `sys_enter_unlink` and `sys_enter_unlinkat` above.
#[inline(always)]
fn emit_file_delete_event<const TC: bool>(
    raw: &RawTracePointContext,
    pathname_ptr: u64,
) -> Result<u32, u32> {
    if TC {
        build_file_delete_event::<true>(raw, pathname_ptr)
    } else {
        emit_file_delete_event_inline(raw, pathname_ptr)
    }
}

/// `emit_file_delete_event` for the inline router, out of line as LLVM leaves it on `main`: inlined
/// into `raw_sys_enter` with the other file handlers, it took the router past 700k verified
/// instructions on 7.2 (#351).
#[inline(never)]
fn emit_file_delete_event_inline(
    raw: &RawTracePointContext,
    pathname_ptr: u64,
) -> Result<u32, u32> {
    build_file_delete_event::<false>(raw, pathname_ptr)
}

/// The body of `emit_file_delete_event`, for both routers.
#[inline(always)]
fn build_file_delete_event<const TC: bool>(
    raw: &RawTracePointContext,
    pathname_ptr: u64,
) -> Result<u32, u32> {
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

        if pathname_ptr != 0
            && let Ok(path) =
                bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut (*e).path)
        {
            // The inline router filters here, on the slice the helper returned, as before #351.
            if !TC && is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
        }

        // Does not return when the slot holds `raw_file_delete_filter`; an empty slot falls
        // through and the event goes out unfiltered (#351).
        if TC {
            FILE_FILTER_PROGS.tail_call(raw, file_filter::DELETE);
            output_file_delete_event(&*e);
        } else {
            output_file_delete_event(&*e);
        }
    }

    Ok(0)
}

/// `AT_FDCWD`: the "directory fd" `rename(2)` implicitly has, and what a `renameat`
/// caller passes to mean the current directory (#515). Userspace resolves a relative
/// path against the renaming process's cwd when it sees it.
const AT_FDCWD: i32 = -100;

/// Offsets of the `syscalls:sys_enter_rename` tracepoint (`x86_64`/`aarch64`):
/// `oldname`(16), `newname`(24). Verified on 2026-09-21 on Alpine
/// (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_rename/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const RENAME_OLDNAME_PTR_OFFSET: usize = arg_offset(0);
const RENAME_NEWNAME_PTR_OFFSET: usize = arg_offset(1);

/// Offsets of the `syscalls:sys_enter_renameat` tracepoint (`x86_64`/`aarch64`):
/// `olddfd`(16), `oldname`(24), `newdfd`(32), `newname`(40). Verified on 2026-09-21
/// on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_renameat/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const RENAMEAT_OLDDFD_OFFSET: usize = arg_offset(0);
const RENAMEAT_NEWDFD_OFFSET: usize = arg_offset(2);
const RENAMEAT_OLDNAME_PTR_OFFSET: usize = arg_offset(1);
const RENAMEAT_NEWNAME_PTR_OFFSET: usize = arg_offset(3);

/// Offsets of the `syscalls:sys_enter_renameat2` tracepoint (`x86_64`/`aarch64`):
/// `olddfd`(16), `oldname`(24), `newdfd`(32), `newname`(40), `flags`(48). Verified on
/// 2026-09-21 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_renameat2/format`. Same
/// oldname/newname offsets as `renameat` above (the trailing `flags` field doesn't
/// shift them).
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const RENAMEAT2_OLDDFD_OFFSET: usize = arg_offset(0);
const RENAMEAT2_NEWDFD_OFFSET: usize = arg_offset(2);
const RENAMEAT2_OLDNAME_PTR_OFFSET: usize = arg_offset(1);
const RENAMEAT2_NEWNAME_PTR_OFFSET: usize = arg_offset(3);

#[inline(always)]
pub fn sys_enter_rename<const TC: bool>(raw: &RawTracePointContext, ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_rename::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_rename<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let oldname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(RENAME_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let newname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(RENAME_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    emit_file_rename_event::<TC>(raw, AT_FDCWD, oldname_ptr, AT_FDCWD, newname_ptr)
}

#[inline(always)]
pub fn sys_enter_renameat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> u32 {
    into_ret(try_sys_enter_renameat::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_renameat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let oldname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(RENAMEAT_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let newname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(RENAMEAT_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    // The tracepoint field is a `long` holding an `int`: the low 32 bits are the fd,
    // little-endian on every supported target (#515).
    let olddfd: i32 = unsafe {
        ctx.read_ulong_arg(RENAMEAT_OLDDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    let newdfd: i32 = unsafe {
        ctx.read_ulong_arg(RENAMEAT_NEWDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;

    emit_file_rename_event::<TC>(raw, olddfd, oldname_ptr, newdfd, newname_ptr)
}

#[inline(always)]
pub fn sys_enter_renameat2<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> u32 {
    into_ret(try_sys_enter_renameat2::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_renameat2<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let oldname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(RENAMEAT2_OLDNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let newname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(RENAMEAT2_NEWNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    // The tracepoint field is a `long` holding an `int`: the low 32 bits are the fd,
    // little-endian on every supported target (#515).
    let olddfd: i32 = unsafe {
        ctx.read_ulong_arg(RENAMEAT2_OLDDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;
    let newdfd: i32 = unsafe {
        ctx.read_ulong_arg(RENAMEAT2_NEWDFD_OFFSET)
            .map_err(|_| 1u32)?
    } as i32;

    emit_file_rename_event::<TC>(raw, olddfd, oldname_ptr, newdfd, newname_ptr)
}

/// Shared by `sys_enter_rename`/`sys_enter_renameat`/`sys_enter_renameat2` above.
#[inline(always)]
fn emit_file_rename_event<const TC: bool>(
    raw: &RawTracePointContext,

    olddfd: i32,
    oldname_ptr: u64,
    newdfd: i32,
    newname_ptr: u64,
) -> Result<u32, u32> {
    if TC {
        build_file_rename_event::<true>(raw, olddfd, oldname_ptr, newdfd, newname_ptr)
    } else {
        emit_file_rename_event_inline(raw, olddfd, oldname_ptr, newdfd, newname_ptr)
    }
}

/// `emit_file_rename_event` for the inline router, out of line as LLVM leaves it on `main`: inlined
/// into `raw_sys_enter` with the other file handlers, it took the router past 700k verified
/// instructions on 7.2 (#351).
#[inline(never)]
fn emit_file_rename_event_inline(
    raw: &RawTracePointContext,

    olddfd: i32,
    oldname_ptr: u64,
    newdfd: i32,
    newname_ptr: u64,
) -> Result<u32, u32> {
    build_file_rename_event::<false>(raw, olddfd, oldname_ptr, newdfd, newname_ptr)
}

/// The body of `emit_file_rename_event`, for both routers.
#[inline(always)]
fn build_file_rename_event<const TC: bool>(
    raw: &RawTracePointContext,

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

        if oldname_ptr != 0
            && let Ok(path) =
                bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut (*e).old_path)
        {
            // The inline router filters here, on the slice the helper returned, as before #351.
            if !TC && is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).old_path_len = path.len() as u16;
        }
        if newname_ptr != 0
            && let Ok(path) =
                bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut (*e).new_path)
        {
            // The inline router filters here, on the slice the helper returned, as before #351.
            if !TC && is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).new_path_len = path.len() as u16;
        }

        // Does not return when the slot holds `raw_file_rename_filter`; an empty slot falls
        // through and the event goes out unfiltered (#351).
        if TC {
            FILE_FILTER_PROGS.tail_call(raw, file_filter::RENAME);
            output_file_rename_event(&*e);
        } else {
            output_file_rename_event(&*e);
        }
    }

    Ok(0)
}

/// The tail of every `delete` event (#351), reached from `raw_sys_enter` through
/// `FILE_FILTER_PROGS`: the path filter on the event left in `DELETE_SCRATCH`, then the output. See
/// `raw_file_open_filter`.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_file_delete_filter(_ctx: RawTracePointContext) -> u32 {
    let Some(e) = DELETE_SCRATCH.get_ptr(0) else {
        return 0;
    };
    // SAFETY: the per-CPU scratch the tail-calling handler just filled, on the same CPU.
    unsafe {
        finish_file_delete_event(&*e);
    }
    0
}

/// One `output` copy of a finished event into `FILE_DELETE_EVENTS`, counting a full ring.
#[inline(always)]
fn output_file_delete_event(e: &FileDeleteEvent) {
    if FILE_DELETE_EVENTS.output::<FileDeleteEvent>(e, 0).is_err() {
        crate::count_ring_drop(sensor_linux_wire::ring::FILE_DELETE);
    }
}

/// The tail of every `rename` event (#351), reached from `raw_sys_enter` through
/// `FILE_FILTER_PROGS`: the path filter on the event left in `RENAME_SCRATCH`, then the output. See
/// `raw_file_open_filter`.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_file_rename_filter(_ctx: RawTracePointContext) -> u32 {
    let Some(e) = RENAME_SCRATCH.get_ptr(0) else {
        return 0;
    };
    // SAFETY: the per-CPU scratch the tail-calling handler just filled, on the same CPU.
    unsafe {
        finish_file_rename_event(&*e);
    }
    0
}

/// One `output` copy of a finished event into `FILE_RENAME_EVENTS`, counting a full ring.
#[inline(always)]
fn output_file_rename_event(e: &FileRenameEvent) {
    if FILE_RENAME_EVENTS.output::<FileRenameEvent>(e, 0).is_err() {
        crate::count_ring_drop(sensor_linux_wire::ring::FILE_RENAME);
    }
}

/// The filter and the output of a finished `delete` event: what `raw_file_delete_filter` does after
/// the tail call, and what the handler does itself in `raw_sys_enter`, the inline variant (#351).
#[inline(always)]
fn finish_file_delete_event(e: &FileDeleteEvent) {
    if stored_path_filtered(&e.path, e.path_len, 0, true) {
        return;
    }
    output_file_delete_event(e);
}

/// The filter and the output of a finished `rename` event: what `raw_file_rename_filter` does after
/// the tail call, and what the handler does itself in `raw_sys_enter`, the inline variant (#351).
#[inline(always)]
fn finish_file_rename_event(e: &FileRenameEvent) {
    if stored_path_filtered(&e.old_path, e.old_path_len, 0, true)
        || stored_path_filtered(&e.new_path, e.new_path_len, 0, true)
    {
        return;
    }
    output_file_rename_event(e);
}
