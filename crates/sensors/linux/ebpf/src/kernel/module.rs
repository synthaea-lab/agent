//! Kernel module load/unload (issue #264)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::KernelModuleEvent;

use crate::{
    arch::{SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
};

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
/// `x86_64/aarch64`) — re-verify against `/format` on any newly supported kernel,
/// same posture as every other offset const in this file.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const INIT_MODULE_LEN_OFFSET: usize = arg_offset(1);

/// Offsets of the `syscalls:sys_enter_finit_module` tracepoint (`fd`, `uargs`,
/// `flags`), assumed standard layout — see `INIT_MODULE_LEN_OFFSET`'s note.
///
/// i686: inferred, not independently verified.
const FINIT_MODULE_FD_OFFSET: usize = arg_offset(0);
const FINIT_MODULE_FLAGS_OFFSET: usize = arg_offset(2);

/// Offsets of the `syscalls:sys_enter_delete_module` tracepoint (`name`,
/// `flags`), assumed standard layout — see `INIT_MODULE_LEN_OFFSET`'s note.
///
/// i686: inferred, not independently verified.
const DELETE_MODULE_NAME_PTR_OFFSET: usize = arg_offset(0);
const DELETE_MODULE_FLAGS_OFFSET: usize = arg_offset(1);

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

        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).action = action;
        (*e).fd = fd;
        (*e).image_len = image_len;
        (*e).flags = flags;

        if name_ptr != 0
            && let Ok(name) = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*e).name)
        {
            (*e).name_len = name.len() as u16;
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

pub fn sys_enter_init_module(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_init_module(ctx))
}

fn try_sys_enter_init_module(ctx: TracePointContext) -> Result<u32, u32> {
    let len: u64 = unsafe {
        ctx.read_ulong_arg(INIT_MODULE_LEN_OFFSET)
            .map_err(|_| 1u32)?
    };

    // `init_module(2)`'s module image lives inside `umod` — the raw memory blob
    // this probe deliberately does not read (see this crate's WIRE_VERSION v12
    // changelog). Only `len` is captured.
    emit_kernel_module_event(&ctx, KERNEL_MODULE_ACTION_LOAD, 0, -1, len, 0)
}

pub fn sys_enter_finit_module(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_finit_module(ctx))
}

fn try_sys_enter_finit_module(ctx: TracePointContext) -> Result<u32, u32> {
    let fd: u64 = unsafe {
        ctx.read_ulong_arg(FINIT_MODULE_FD_OFFSET)
            .map_err(|_| 1u32)?
    };

    let flags: u64 = unsafe {
        ctx.read_ulong_arg(FINIT_MODULE_FLAGS_OFFSET)
            .map_err(|_| 1u32)?
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

pub fn sys_enter_delete_module(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_delete_module(ctx))
}

fn try_sys_enter_delete_module(ctx: TracePointContext) -> Result<u32, u32> {
    let name_ptr: u64 = unsafe {
        ctx.read_ulong_arg(DELETE_MODULE_NAME_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    let flags: u64 = unsafe {
        ctx.read_ulong_arg(DELETE_MODULE_FLAGS_OFFSET)
            .map_err(|_| 1u32)?
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
