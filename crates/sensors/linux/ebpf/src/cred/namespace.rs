//! Namespace manipulation (issue #266)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::NamespaceEvent;

use crate::fill_event_meta;

/// Ring buffer shared with userspace for `setns`/`unshare` events.
#[map]
static NAMESPACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `NamespaceEvent` (see `EXEC_SCRATCH`).
#[map]
static NAMESPACE_SCRATCH: PerCpuArray<NamespaceEvent> = PerCpuArray::with_max_entries(1, 0);

const NAMESPACE_SYSCALL_SETNS: u8 = 0;
const NAMESPACE_SYSCALL_UNSHARE: u8 = 1;

/// Offsets of the `syscalls:sys_enter_setns` tracepoint (`fd`, `nstype`),
/// assumed standard layout — see `SINGLE_ID_OFFSET`'s note in `identity.rs`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETNS_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SETNS_NSTYPE_OFFSET: usize = 24;
/// i686: inferred, not independently verified.
#[cfg(bpf_target_arch = "x86")]
const SETNS_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const SETNS_NSTYPE_OFFSET: usize = 16;

/// Offset of the `syscalls:sys_enter_unshare` tracepoint's single `flags`
/// argument — assumed standard layout, see `SINGLE_ID_OFFSET`'s note in `identity.rs`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const UNSHARE_FLAGS_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const UNSHARE_FLAGS_OFFSET: usize = 12;

fn emit_namespace_event(ctx: &TracePointContext, syscall: u8, fd: i32, flags: u32) -> u32 {
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return 1,
    };
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let Some(e) = NAMESPACE_SCRATCH.get_ptr_mut(0) else {
        return 1;
    };
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).syscall = syscall;
        (*e).fd = fd;
        (*e).flags = flags;

        if NAMESPACE_EVENTS.output::<NamespaceEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping namespace event"
            );
        }
    }

    0
}

pub fn sys_enter_setns(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = match unsafe { ctx.read_at(SETNS_FD_OFFSET) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = match unsafe { ctx.read_at::<u32>(SETNS_FD_OFFSET) } {
        Ok(v) => v as u64,
        Err(_) => return 1,
    };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let nstype: u64 = match unsafe { ctx.read_at(SETNS_NSTYPE_OFFSET) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    #[cfg(bpf_target_arch = "x86")]
    let nstype: u64 = match unsafe { ctx.read_at::<u32>(SETNS_NSTYPE_OFFSET) } {
        Ok(v) => v as u64,
        Err(_) => return 1,
    };

    emit_namespace_event(&ctx, NAMESPACE_SYSCALL_SETNS, fd as i32, nstype as u32)
}

pub fn sys_enter_unshare(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let flags: u64 = match unsafe { ctx.read_at(UNSHARE_FLAGS_OFFSET) } {
        Ok(v) => v,
        Err(_) => return 1,
    };
    #[cfg(bpf_target_arch = "x86")]
    let flags: u64 = match unsafe { ctx.read_at::<u32>(UNSHARE_FLAGS_OFFSET) } {
        Ok(v) => v as u64,
        Err(_) => return 1,
    };

    emit_namespace_event(&ctx, NAMESPACE_SYSCALL_UNSHARE, -1, flags as u32)
}
