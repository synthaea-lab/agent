//! File chmod/chown (issue #262 Phase 2)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, raw_tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
};
use sensor_linux_wire::{FileChmodEvent, FileChownEvent, file_filter, is_filtered_path};

use super::{FILE_FILTER_PROGS, stored_path_filtered};
use crate::{
    arch::{SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
};

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

/// Offsets of the `syscalls:sys_enter_chmod` tracepoint (`x86_64`/`aarch64`): `filename`(16),
/// `mode`(24). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_chmod/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const CHMOD_FILENAME_PTR_OFFSET: usize = arg_offset(0);
const CHMOD_MODE_OFFSET: usize = arg_offset(1);

/// Offsets of the `syscalls:sys_enter_fchmodat` tracepoint (`x86_64`/`aarch64`): `dfd`(16),
/// `filename`(24), `mode`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// `x86_64`) via `/sys/kernel/tracing/events/syscalls/sys_enter_fchmodat/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const FCHMODAT_FILENAME_PTR_OFFSET: usize = arg_offset(1);
const FCHMODAT_MODE_OFFSET: usize = arg_offset(2);

#[inline(always)]
pub fn sys_enter_chmod<const TC: bool>(raw: &RawTracePointContext, ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_chmod::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_chmod<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(CHMOD_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let mode: u64 = unsafe { ctx.read_ulong_arg(CHMOD_MODE_OFFSET).map_err(|_| 1u32)? };

    emit_file_chmod_event::<TC>(raw, filename_ptr, mode)
}

#[inline(always)]
pub fn sys_enter_fchmodat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> u32 {
    into_ret(try_sys_enter_fchmodat::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_fchmodat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(FCHMODAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let mode: u64 = unsafe { ctx.read_ulong_arg(FCHMODAT_MODE_OFFSET).map_err(|_| 1u32)? };

    emit_file_chmod_event::<TC>(raw, filename_ptr, mode)
}

/// Shared by `sys_enter_chmod` and `sys_enter_fchmodat` above.
#[inline(always)]
fn emit_file_chmod_event<const TC: bool>(
    raw: &RawTracePointContext,
    filename_ptr: u64,
    mode: u64,
) -> Result<u32, u32> {
    if TC {
        build_file_chmod_event::<true>(raw, filename_ptr, mode)
    } else {
        emit_file_chmod_event_inline(raw, filename_ptr, mode)
    }
}

/// `emit_file_chmod_event` for the inline router, out of line as LLVM leaves it on `main`: inlined
/// into `raw_sys_enter` with the other file handlers, it took the router past 700k verified
/// instructions on 7.2 (#351).
#[inline(never)]
fn emit_file_chmod_event_inline(
    raw: &RawTracePointContext,
    filename_ptr: u64,
    mode: u64,
) -> Result<u32, u32> {
    build_file_chmod_event::<false>(raw, filename_ptr, mode)
}

/// The body of `emit_file_chmod_event`, for both routers.
#[inline(always)]
fn build_file_chmod_event<const TC: bool>(
    raw: &RawTracePointContext,
    filename_ptr: u64,
    mode: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CHMOD_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );

        if filename_ptr != 0
            && let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
        {
            // The inline router filters here, on the slice the helper returned, as before #351.
            if !TC && is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
        }
        (*e).mode = mode as u32;

        // Does not return when the slot holds `raw_file_chmod_filter`; an empty slot falls
        // through and the event goes out unfiltered (#351).
        if TC {
            FILE_FILTER_PROGS.tail_call(raw, file_filter::CHMOD);
            output_file_chmod_event(&*e);
        } else {
            output_file_chmod_event(&*e);
        }
    }

    Ok(0)
}

/// Offsets of the `syscalls:sys_enter_chown` tracepoint (`x86_64`/`aarch64`): `filename`(16),
/// `user`(24), `group`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// `x86_64`) via `/sys/kernel/tracing/events/syscalls/sys_enter_chown/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const CHOWN_FILENAME_PTR_OFFSET: usize = arg_offset(0);
const CHOWN_USER_OFFSET: usize = arg_offset(1);
const CHOWN_GROUP_OFFSET: usize = arg_offset(2);

/// Offsets of the `syscalls:sys_enter_lchown` tracepoint (`x86_64`/`aarch64`): identical
/// shape to `sys_enter_chown` above — `filename`(16), `user`(24), `group`(32). Verified
/// on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_lchown/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const LCHOWN_FILENAME_PTR_OFFSET: usize = arg_offset(0);
const LCHOWN_USER_OFFSET: usize = arg_offset(1);
const LCHOWN_GROUP_OFFSET: usize = arg_offset(2);

/// Offsets of the `syscalls:sys_enter_fchownat` tracepoint (`x86_64`/`aarch64`): `dfd`(16),
/// `filename`(24), `user`(32), `group`(40), `flag`(48). Verified on 2026-09-22 on Alpine
/// (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_fchownat/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const FCHOWNAT_FILENAME_PTR_OFFSET: usize = arg_offset(1);
const FCHOWNAT_USER_OFFSET: usize = arg_offset(2);
const FCHOWNAT_GROUP_OFFSET: usize = arg_offset(3);

#[inline(always)]
pub fn sys_enter_chown<const TC: bool>(raw: &RawTracePointContext, ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_chown::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_chown<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(CHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let user: u64 = unsafe { ctx.read_ulong_arg(CHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    let group: u64 = unsafe { ctx.read_ulong_arg(CHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };

    emit_file_chown_event::<TC>(raw, filename_ptr, user, group)
}

#[inline(always)]
pub fn sys_enter_lchown<const TC: bool>(raw: &RawTracePointContext, ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_lchown::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_lchown<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(LCHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let user: u64 = unsafe { ctx.read_ulong_arg(LCHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    let group: u64 = unsafe { ctx.read_ulong_arg(LCHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };

    emit_file_chown_event::<TC>(raw, filename_ptr, user, group)
}

#[inline(always)]
pub fn sys_enter_fchownat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> u32 {
    into_ret(try_sys_enter_fchownat::<TC>(raw, ctx))
}

#[inline(always)]
fn try_sys_enter_fchownat<const TC: bool>(
    raw: &RawTracePointContext,
    ctx: TracePointContext,
) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(FCHOWNAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let user: u64 = unsafe { ctx.read_ulong_arg(FCHOWNAT_USER_OFFSET).map_err(|_| 1u32)? };
    let group: u64 = unsafe {
        ctx.read_ulong_arg(FCHOWNAT_GROUP_OFFSET)
            .map_err(|_| 1u32)?
    };

    emit_file_chown_event::<TC>(raw, filename_ptr, user, group)
}

/// Shared by `sys_enter_chown`, `sys_enter_lchown`, and `sys_enter_fchownat` above.
#[inline(always)]
fn emit_file_chown_event<const TC: bool>(
    raw: &RawTracePointContext,
    filename_ptr: u64,
    user: u64,
    group: u64,
) -> Result<u32, u32> {
    if TC {
        build_file_chown_event::<true>(raw, filename_ptr, user, group)
    } else {
        emit_file_chown_event_inline(raw, filename_ptr, user, group)
    }
}

/// `emit_file_chown_event` for the inline router, out of line as LLVM leaves it on `main`: inlined
/// into `raw_sys_enter` with the other file handlers, it took the router past 700k verified
/// instructions on 7.2 (#351).
#[inline(never)]
fn emit_file_chown_event_inline(
    raw: &RawTracePointContext,
    filename_ptr: u64,
    user: u64,
    group: u64,
) -> Result<u32, u32> {
    build_file_chown_event::<false>(raw, filename_ptr, user, group)
}

/// The body of `emit_file_chown_event`, for both routers.
#[inline(always)]
fn build_file_chown_event<const TC: bool>(
    raw: &RawTracePointContext,
    filename_ptr: u64,
    user: u64,
    group: u64,
) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = CHOWN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );

        if filename_ptr != 0
            && let Ok(path) =
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut (*e).path)
        {
            // The inline router filters here, on the slice the helper returned, as before #351.
            if !TC && is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
        }
        (*e).uid = user as u32;
        (*e).gid = group as u32;

        // Does not return when the slot holds `raw_file_chown_filter`; an empty slot falls
        // through and the event goes out unfiltered (#351).
        if TC {
            FILE_FILTER_PROGS.tail_call(raw, file_filter::CHOWN);
            output_file_chown_event(&*e);
        } else {
            output_file_chown_event(&*e);
        }
    }

    Ok(0)
}

/// The tail of every `chmod` event (#351), reached from `raw_sys_enter` through
/// `FILE_FILTER_PROGS`: the path filter on the event left in `CHMOD_SCRATCH`, then the output. See
/// `raw_file_open_filter`.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_file_chmod_filter(_ctx: RawTracePointContext) -> u32 {
    let Some(e) = CHMOD_SCRATCH.get_ptr(0) else {
        return 0;
    };
    // SAFETY: the per-CPU scratch the tail-calling handler just filled, on the same CPU.
    unsafe {
        finish_file_chmod_event(&*e);
    }
    0
}

/// One `output` copy of a finished event into `FILE_CHMOD_EVENTS`, counting a full ring.
#[inline(always)]
fn output_file_chmod_event(e: &FileChmodEvent) {
    if FILE_CHMOD_EVENTS.output::<FileChmodEvent>(e, 0).is_err() {
        crate::count_ring_drop(sensor_linux_wire::ring::FILE_CHMOD);
    }
}

/// The tail of every `chown` event (#351), reached from `raw_sys_enter` through
/// `FILE_FILTER_PROGS`: the path filter on the event left in `CHOWN_SCRATCH`, then the output. See
/// `raw_file_open_filter`.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_file_chown_filter(_ctx: RawTracePointContext) -> u32 {
    let Some(e) = CHOWN_SCRATCH.get_ptr(0) else {
        return 0;
    };
    // SAFETY: the per-CPU scratch the tail-calling handler just filled, on the same CPU.
    unsafe {
        finish_file_chown_event(&*e);
    }
    0
}

/// One `output` copy of a finished event into `FILE_CHOWN_EVENTS`, counting a full ring.
#[inline(always)]
fn output_file_chown_event(e: &FileChownEvent) {
    if FILE_CHOWN_EVENTS.output::<FileChownEvent>(e, 0).is_err() {
        crate::count_ring_drop(sensor_linux_wire::ring::FILE_CHOWN);
    }
}

/// The filter and the output of a finished `chmod` event: what `raw_file_chmod_filter` does after
/// the tail call, and what the handler does itself in `raw_sys_enter`, the inline variant (#351).
#[inline(always)]
fn finish_file_chmod_event(e: &FileChmodEvent) {
    if stored_path_filtered(&e.path, e.path_len, 0, true) {
        return;
    }
    output_file_chmod_event(e);
}

/// The filter and the output of a finished `chown` event: what `raw_file_chown_filter` does after
/// the tail call, and what the handler does itself in `raw_sys_enter`, the inline variant (#351).
#[inline(always)]
fn finish_file_chown_event(e: &FileChownEvent) {
    if stored_path_filtered(&e.path, e.path_len, 0, true) {
        return;
    }
    output_file_chown_event(e);
}
