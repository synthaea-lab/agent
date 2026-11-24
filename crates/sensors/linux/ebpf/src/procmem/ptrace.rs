//! `ptrace(2)` calls (issue #265).

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::PtraceEvent;

use crate::{
    arch::{SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
};

/// Ring buffer shared with userspace for `ptrace` events (issue #265).
#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `PtraceEvent` (see `EXEC_SCRATCH`).
#[map]
static PTRACE_SCRATCH: PerCpuArray<PtraceEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_ptrace` tracepoint (`x86_64`/`aarch64`):
/// `request`(16), `pid`(24), `addr`(32), `data`(40). Verified on 2026-09-22 on
/// Arch (kernel 6.6.9-arch1-1, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_ptrace/format`.
///
/// i686: derived from the record layout like every other syscall here, not read from an i686
/// kernel. The first hand-written i686 values started at 16 and read every argument one slot
/// late (#218).
const PTRACE_REQUEST_OFFSET: usize = arg_offset(0);
const PTRACE_PID_OFFSET: usize = arg_offset(1);
const PTRACE_ADDR_OFFSET: usize = arg_offset(2);
const PTRACE_DATA_OFFSET: usize = arg_offset(3);

pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_ptrace(ctx))
}

fn try_sys_enter_ptrace(ctx: TracePointContext) -> Result<u32, u32> {
    let request: u64 = unsafe {
        ctx.read_ulong_arg(PTRACE_REQUEST_OFFSET)
            .map_err(|_| 1u32)?
    };
    let target_pid: u64 = unsafe { ctx.read_ulong_arg(PTRACE_PID_OFFSET).map_err(|_| 1u32)? };
    let addr: u64 = unsafe { ctx.read_ulong_arg(PTRACE_ADDR_OFFSET).map_err(|_| 1u32)? };
    let data: u64 = unsafe { ctx.read_ulong_arg(PTRACE_DATA_OFFSET).map_err(|_| 1u32)? };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = PTRACE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);
        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).request = request;
        (*e).target_pid = target_pid as u32;
        (*e).addr = addr;
        (*e).data = data;

        if PTRACE_EVENTS.output::<PtraceEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping ptrace event"
            );
        }
    }

    Ok(0)
}
