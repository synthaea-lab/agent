//! File chmod/chown (issue #262 Phase 2)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{FileChmodEvent, FileChownEvent, is_filtered_path};

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

/// Offsets of the `syscalls:sys_enter_chmod` tracepoint (`x86_64/aarch64)`: `filename`(16),
/// `mode`(24). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_chmod/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const CHMOD_FILENAME_PTR_OFFSET: usize = arg_offset(0);
const CHMOD_MODE_OFFSET: usize = arg_offset(1);

/// Offsets of the `syscalls:sys_enter_fchmodat` tracepoint (`x86_64/aarch64)`: `dfd`(16),
/// `filename`(24), `mode`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// `x86_64`) via `/sys/kernel/tracing/events/syscalls/sys_enter_fchmodat/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const FCHMODAT_FILENAME_PTR_OFFSET: usize = arg_offset(1);
const FCHMODAT_MODE_OFFSET: usize = arg_offset(2);

pub fn sys_enter_chmod(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_chmod(ctx))
}

fn try_sys_enter_chmod(ctx: TracePointContext) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(CHMOD_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let mode: u64 = unsafe { ctx.read_ulong_arg(CHMOD_MODE_OFFSET).map_err(|_| 1u32)? };

    emit_file_chmod_event(&ctx, filename_ptr, mode)
}

pub fn sys_enter_fchmodat(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_fchmodat(ctx))
}

fn try_sys_enter_fchmodat(ctx: TracePointContext) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(FCHMODAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let mode: u64 = unsafe { ctx.read_ulong_arg(FCHMODAT_MODE_OFFSET).map_err(|_| 1u32)? };

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
            if is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
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

/// Offsets of the `syscalls:sys_enter_chown` tracepoint (`x86_64/aarch64)`: `filename`(16),
/// `user`(24), `group`(32). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt,
/// `x86_64`) via `/sys/kernel/tracing/events/syscalls/sys_enter_chown/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const CHOWN_FILENAME_PTR_OFFSET: usize = arg_offset(0);
const CHOWN_USER_OFFSET: usize = arg_offset(1);
const CHOWN_GROUP_OFFSET: usize = arg_offset(2);

/// Offsets of the `syscalls:sys_enter_lchown` tracepoint (`x86_64/aarch64)`: identical
/// shape to `sys_enter_chown` above — `filename`(16), `user`(24), `group`(32). Verified
/// on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_lchown/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const LCHOWN_FILENAME_PTR_OFFSET: usize = arg_offset(0);
const LCHOWN_USER_OFFSET: usize = arg_offset(1);
const LCHOWN_GROUP_OFFSET: usize = arg_offset(2);

/// Offsets of the `syscalls:sys_enter_fchownat` tracepoint (`x86_64/aarch64)`: `dfd`(16),
/// `filename`(24), `user`(32), `group`(40), `flag`(48). Verified on 2026-09-22 on Alpine
/// (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_fchownat/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const FCHOWNAT_FILENAME_PTR_OFFSET: usize = arg_offset(1);
const FCHOWNAT_USER_OFFSET: usize = arg_offset(2);
const FCHOWNAT_GROUP_OFFSET: usize = arg_offset(3);

pub fn sys_enter_chown(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_chown(ctx))
}

fn try_sys_enter_chown(ctx: TracePointContext) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(CHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let user: u64 = unsafe { ctx.read_ulong_arg(CHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    let group: u64 = unsafe { ctx.read_ulong_arg(CHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

pub fn sys_enter_lchown(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_lchown(ctx))
}

fn try_sys_enter_lchown(ctx: TracePointContext) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(LCHOWN_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let user: u64 = unsafe { ctx.read_ulong_arg(LCHOWN_USER_OFFSET).map_err(|_| 1u32)? };
    let group: u64 = unsafe { ctx.read_ulong_arg(LCHOWN_GROUP_OFFSET).map_err(|_| 1u32)? };

    emit_file_chown_event(&ctx, filename_ptr, user, group)
}

pub fn sys_enter_fchownat(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_fchownat(ctx))
}

fn try_sys_enter_fchownat(ctx: TracePointContext) -> Result<u32, u32> {
    let filename_ptr: u64 = unsafe {
        ctx.read_ulong_arg(FCHOWNAT_FILENAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    let user: u64 = unsafe { ctx.read_ulong_arg(FCHOWNAT_USER_OFFSET).map_err(|_| 1u32)? };
    let group: u64 = unsafe {
        ctx.read_ulong_arg(FCHOWNAT_GROUP_OFFSET)
            .map_err(|_| 1u32)?
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
            if is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
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
