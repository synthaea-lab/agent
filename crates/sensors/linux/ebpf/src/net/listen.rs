//! Socket listen (issue #263 Phase 2)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::SocketListenEvent;

use super::bind::{BIND_ADDR_MAP, BindAddrKey};
use crate::{fill_event_meta, into_ret};

/// Ring buffer shared with userspace for `listen` events.
#[map]
static SOCKET_LISTEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketListenEvent` (see `EXEC_SCRATCH`).
#[map]
static LISTEN_SCRATCH: PerCpuArray<SocketListenEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_listen` tracepoint (`x86_64/aarch64)`: `fd`(16),
/// `backlog`(24). Verified on 2026-09-22 on Alpine (kernel 6.18.50-0-virt, `x86_64`)
/// via `/sys/kernel/tracing/events/syscalls/sys_enter_listen/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LISTEN_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const LISTEN_BACKLOG_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const LISTEN_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const LISTEN_BACKLOG_OFFSET: usize = 16;

pub fn sys_enter_listen(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_listen(ctx))
}

/// `listen(2)` carries no address of its own — correlates against [`BIND_ADDR_MAP`]
/// on `(pid, fd)` to recover the address a prior `bind(2)` claimed. No match still
/// emits the event (a process just started listening is worth reporting on its
/// own), with `addr_resolved: false` and the address fields left zeroed.
fn try_sys_enter_listen(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(LISTEN_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(LISTEN_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let backlog: u64 = unsafe { ctx.read_at(LISTEN_BACKLOG_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let backlog: u64 = unsafe {
        ctx.read_at::<u32>(LISTEN_BACKLOG_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let key = BindAddrKey { pid, fd: fd as u32 };
    let bound = unsafe { BIND_ADDR_MAP.get(&key) }.copied();

    let e = LISTEN_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(&mut (*e).meta, pid, uid_gid, &comm);
        (*e).backlog = backlog as u32;

        if let Some(addr) = bound {
            (*e).laddr_v4 = addr.addr_v4;
            (*e).laddr_v6 = addr.addr_v6;
            (*e).lport = addr.port;
            (*e).is_ipv6 = addr.is_ipv6;
            (*e).addr_resolved = true;
        }

        if SOCKET_LISTEN_EVENTS
            .output::<SocketListenEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping listen event"
            );
        }
    }

    Ok(0)
}
