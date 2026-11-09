//! UDP send (issue #263 Phase 2)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{TASK_COMM_LEN, UdpSendEvent};

use crate::{AF_INET, AF_INET6, fill_lineage};

/// Ring buffer shared with userspace for `sendto` events.
#[map]
static UDP_SEND_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `UdpSendEvent` (see `EXEC_SCRATCH`).
#[map]
static UDP_SEND_SCRATCH: PerCpuArray<UdpSendEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_sendto` tracepoint (x86_64/aarch64): `fd`(16),
/// `buff`(24), `len`(32), `flags`(40), `addr`(48), `addr_len`(56). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, x86_64) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_sendto/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const SENDTO_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const SENDTO_BUF_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const SENDTO_LEN_OFFSET: usize = 32;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const SENDTO_ADDR_PTR_OFFSET: usize = 48;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
pub(crate) const SENDTO_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
pub(crate) const SENDTO_BUF_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
pub(crate) const SENDTO_LEN_OFFSET: usize = 20;
#[cfg(bpf_target_arch = "x86")]
pub(crate) const SENDTO_ADDR_PTR_OFFSET: usize = 28;

pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    match try_sys_enter_sendto(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Mirrors `try_sys_enter_connect`/`try_sys_enter_bind` above for the address read —
/// same family filter, same raw-byte address read (avoids the endianness bug
/// documented on `ConnectEvent`) — plus the requested payload size from `len`.
fn try_sys_enter_sendto(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let len: u64 = unsafe { ctx.read_at(SENDTO_LEN_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let len: u64 = unsafe { ctx.read_at::<u32>(SENDTO_LEN_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_ptr: u64 = unsafe { ctx.read_at(SENDTO_ADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let addr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(SENDTO_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    // NULL addr: a connected-socket send (or plain `send(2)`, which glibc issues as
    // `sendto(fd, buf, len, flags, NULL, 0)`) — no destination to report, same
    // treatment as `connect`/`bind`'s own null-address check.
    if addr_ptr == 0 {
        return Ok(0);
    }

    let family: u16 = match unsafe { bpf_probe_read_user(addr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)? },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = UDP_SEND_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
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
        (*e).is_ipv6 = family == AF_INET6;
        (*e).dport = u16::from_be(port_be);
        (*e).daddr_v4 = v4;
        (*e).daddr_v6 = v6;
        (*e).size = len as u32;

        if UDP_SEND_EVENTS.output::<UdpSendEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping udp send event"
            );
        }
    }

    Ok(0)
}
