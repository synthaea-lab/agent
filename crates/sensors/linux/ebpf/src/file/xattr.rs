//! Extended attributes (issue #262 Phase 3)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{FileRemovexattrEvent, FileSetxattrEvent, is_filtered_path};

use crate::{fill_event_meta, into_ret};

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
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETXATTR_PATHNAME_PTR_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETXATTR_NAME_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const SETXATTR_PATHNAME_PTR_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const SETXATTR_NAME_PTR_OFFSET: usize = 16;

pub fn sys_enter_setxattr(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_setxattr(ctx))
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
            if is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
        }
        if name_ptr != 0
            && let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name)
        {
            (*e).name_len = name.len() as u16;
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

/// Offsets of the `syscalls:sys_enter_removexattr` tracepoint (`x86_64`/`aarch64`):
/// `pathname`(16), `name`(24). Verified on 2026-09-22 on Alpine (kernel
/// 6.18.50-0-virt, `x86_64`) via
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

pub fn sys_enter_removexattr(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_removexattr(ctx))
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
            if is_filtered_path(path, 0, true) {
                return Ok(0);
            }
            (*e).path_len = path.len() as u16;
        }
        if name_ptr != 0
            && let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name)
        {
            (*e).name_len = name.len() as u16;
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
