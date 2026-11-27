//! Extended attributes (issue #262 Phase 3)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, raw_tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
};
use sensor_linux_wire::{FileRemovexattrEvent, FileSetxattrEvent, file_filter, is_filtered_path};

use super::{FILE_FILTER_PROGS, stored_path_filtered};
use crate::{
    arch::{SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
};

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

/// Offsets of the `syscalls:sys_enter_setxattr` tracepoint (`x86_64`/`aarch64`):
/// `pathname`(16), `name`(24), `value`(32, unused), `size`(40, unused), `flags`(48,
/// unused). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_setxattr/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const SETXATTR_PATHNAME_PTR_OFFSET: usize = arg_offset(0);
const SETXATTR_NAME_PTR_OFFSET: usize = arg_offset(1);

#[inline(always)]
pub fn sys_enter_setxattr<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> u32 {
    into_ret(try_sys_enter_setxattr::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_setxattr<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let pathname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(SETXATTR_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    let name_ptr: u64 = unsafe {
        ctx.read_ulong_arg(SETXATTR_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = SETXATTR_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        if name_ptr != 0
            && let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name)
        {
            (*e).name_len = name.len() as u16;
        }

        // Does not return when the slot holds `raw_file_setxattr_filter`; an empty slot falls
        // through and the event goes out unfiltered (#351).
        if TC {
            FILE_FILTER_PROGS.tail_call(raw, file_filter::SETXATTR);
            output_file_setxattr_event(&*e);
        } else {
            output_file_setxattr_event(&*e);
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_removexattr` tracepoint (`x86_64`/`aarch64`):
/// `pathname`(16), `name`(24). Verified on 2026-09-22 on Alpine (kernel
/// 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_removexattr/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const REMOVEXATTR_PATHNAME_PTR_OFFSET: usize = arg_offset(0);
const REMOVEXATTR_NAME_PTR_OFFSET: usize = arg_offset(1);

#[inline(always)]
pub fn sys_enter_removexattr<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> u32 {
    into_ret(try_sys_enter_removexattr::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_removexattr<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let pathname_ptr: u64 = unsafe {
        ctx.read_ulong_arg(REMOVEXATTR_PATHNAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    let name_ptr: u64 = unsafe {
        ctx.read_ulong_arg(REMOVEXATTR_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = REMOVEXATTR_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        if name_ptr != 0
            && let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name)
        {
            (*e).name_len = name.len() as u16;
        }

        // Does not return when the slot holds `raw_file_removexattr_filter`; an empty slot falls
        // through and the event goes out unfiltered (#351).
        if TC {
            FILE_FILTER_PROGS.tail_call(raw, file_filter::REMOVEXATTR);
            output_file_removexattr_event(&*e);
        } else {
            output_file_removexattr_event(&*e);
        }
    }

    Ok(0)
}

/// The tail of every `setxattr` event (#351), reached from `raw_sys_enter` through
/// `FILE_FILTER_PROGS`: the path filter on the event left in `SETXATTR_SCRATCH`, then the output. See
/// `raw_file_open_filter`.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_file_setxattr_filter(_ctx: RawTracePointContext) -> u32 {
    let Some(e) = SETXATTR_SCRATCH.get_ptr(0) else {
        return 0;
    };
    // SAFETY: the per-CPU scratch the tail-calling handler just filled, on the same CPU.
    unsafe {
        finish_file_setxattr_event(&*e);
    }
    0
}

/// One `output` copy of a finished event into `FILE_SETXATTR_EVENTS`, counting a full ring.
#[inline(always)]
fn output_file_setxattr_event(e: &FileSetxattrEvent) {
    if FILE_SETXATTR_EVENTS
        .output::<FileSetxattrEvent>(e, 0)
        .is_err()
    {
        crate::count_ring_drop(sensor_linux_wire::ring::FILE_SETXATTR);
    }
}

/// The tail of every `removexattr` event (#351), reached from `raw_sys_enter` through
/// `FILE_FILTER_PROGS`: the path filter on the event left in `REMOVEXATTR_SCRATCH`, then the output. See
/// `raw_file_open_filter`.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_file_removexattr_filter(_ctx: RawTracePointContext) -> u32 {
    let Some(e) = REMOVEXATTR_SCRATCH.get_ptr(0) else {
        return 0;
    };
    // SAFETY: the per-CPU scratch the tail-calling handler just filled, on the same CPU.
    unsafe {
        finish_file_removexattr_event(&*e);
    }
    0
}

/// One `output` copy of a finished event into `FILE_REMOVEXATTR_EVENTS`, counting a full ring.
#[inline(always)]
fn output_file_removexattr_event(e: &FileRemovexattrEvent) {
    if FILE_REMOVEXATTR_EVENTS
        .output::<FileRemovexattrEvent>(e, 0)
        .is_err()
    {
        crate::count_ring_drop(sensor_linux_wire::ring::FILE_REMOVEXATTR);
    }
}

/// The filter and the output of a finished `setxattr` event: what `raw_file_setxattr_filter` does after
/// the tail call, and what the handler does itself in `raw_sys_enter`, the inline variant (#351).
#[inline(always)]
fn finish_file_setxattr_event(e: &FileSetxattrEvent) {
    if stored_path_filtered(&e.path, e.path_len, 0, true) {
        return;
    }
    output_file_setxattr_event(e);
}

/// The filter and the output of a finished `removexattr` event: what `raw_file_removexattr_filter` does after
/// the tail call, and what the handler does itself in `raw_sys_enter`, the inline variant (#351).
#[inline(always)]
fn finish_file_removexattr_event(e: &FileRemovexattrEvent) {
    if stored_path_filtered(&e.path, e.path_len, 0, true) {
        return;
    }
    output_file_removexattr_event(e);
}
