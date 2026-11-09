//! Kernel module load/unload (issue #264)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{KernelModuleEvent, TASK_COMM_LEN};

use crate::fill_lineage;

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
/// x86_64/aarch64) — re-verify against `/format` on any newly supported kernel,
/// same posture as every other offset const in this file.
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
