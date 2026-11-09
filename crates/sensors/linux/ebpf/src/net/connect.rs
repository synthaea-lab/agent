//! Outbound `connect(2)` on IPv4/IPv6 sockets.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::{info, warn};
use sensor_linux_wire::{ConnectEvent, TASK_COMM_LEN};

use crate::{AF_INET, AF_INET6, fill_lineage};

/// Ring buffer shared with userspace for `connect` events.
#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `ConnectEvent` (see `EXEC_SCRATCH`).
#[map]
static CONNECT_SCRATCH: PerCpuArray<ConnectEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_connect` tracepoint (x86_64). Same stable layout as
/// `sys_enter_openat` (see `file/open.rs`): 8-byte common header, `__syscall_nr`, then the arguments
/// aligned on 8 bytes each — `fd`(16), `uservaddr`(24), `addrlen`(32). Not verified against
/// `/sys/kernel/tracing/events/syscalls/sys_enter_connect/format` on this machine (reading
/// requires root) — to be confirmed before trusting the data outside the lab.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const CONNECT_USERVADDR_PTR_OFFSET: usize = 24;
/// `fd` is the first argument, right after the 16-byte record header (same layout as `bind`'s
/// `BIND_FD_OFFSET` below, which was read from the tracefs `format` file).
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
pub(crate) const CONNECT_FD_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
pub(crate) const CONNECT_FD_OFFSET: usize = 12;

/// On i686, `fd`(12), `uservaddr`(16), `addrlen`(20) are packed without padding (the
/// `uservaddr` pointer is 4 bytes, not 8) — verified on 2026-08-19 via
/// `/sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format` on the target i686
/// kernel (Debian 12 Bookworm, `6.1.0-52-686-pae`).
#[cfg(bpf_target_arch = "x86")]
pub(crate) const CONNECT_USERVADDR_PTR_OFFSET: usize = 16;

pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let uservaddr_ptr: u64 = unsafe {
        ctx.read_at(CONNECT_USERVADDR_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let uservaddr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(CONNECT_USERVADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    if uservaddr_ptr == 0 {
        return Ok(0);
    }

    // `sockaddr.sa_family` is the first field (u16), common to all the variants
    // (sockaddr_in, sockaddr_in6, sockaddr_un...).
    let family: u16 = match unsafe { bpf_probe_read_user(uservaddr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    // `sin_port`/`sin6_port`: same offset (2) in both structs, network byte order.
    let port_be: u16 =
        unsafe { bpf_probe_read_user((uservaddr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    // Address bytes read raw ([u8; N]), not as an integer: `bpf_probe_read_user::<u32>`
    // would apply native (LE) endianness and reverse the displayed address (observed
    // 2026-08-13: 127.0.0.11 shown as "11.0.0.127"). sockaddr_in::sin_addr at +4,
    // sockaddr_in6::sin6_addr at +8.
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe {
                bpf_probe_read_user((uservaddr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)?
            },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((uservaddr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    // Assemble in per-CPU scratch, then one `output` copy (see `try_sys_enter_openat`).
    let e = CONNECT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    let pid = unsafe {
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

        if CONNECT_EVENTS.output::<ConnectEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping connect event"
            );
        }
        (*e).meta.pid
    };

    info!(&ctx, "sensor-linux-ebpf: connect pid={}", pid);
    Ok(0)
}
