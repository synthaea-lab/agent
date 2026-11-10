//! DNS over UDP/53 (issue #458 part 3)
//!
//! A DNS query leaves a process either through the libc resolver (the `getaddrinfo` uprobe of
//! part 1 sees it) or straight through the socket: Go's resolver, musl, Rust resolvers and
//! tools such as `dig`. This path sees the second kind. It reads the first
//! `MAX_DNS_UDP_PAYLOAD` bytes of the datagram at syscall entry, from `sendto(2)` with an
//! address and from `write(2)`/`sendto(2)` without one on a socket this process `connect(2)`ed
//! to port 53 (`DNS_UDP_FDS`). Userspace parses the question. Queries only: the response is not
//! read here. `sendmsg(2)`/`sendmmsg(2)` are not hooked (see `docs/sensors/sources.md`).

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::map,
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::{DnsUdpQueryEvent, MAX_DNS_UDP_PAYLOAD};

use super::{
    connect::{CONNECT_FD_OFFSET, CONNECT_USERVADDR_PTR_OFFSET},
    udp_send::{SENDTO_ADDR_PTR_OFFSET, SENDTO_BUF_OFFSET, SENDTO_FD_OFFSET, SENDTO_LEN_OFFSET},
};
use crate::{
    AF_INET, AF_INET6,
    file::write_delete_rename::{WRITE_BUF_OFFSET, WRITE_COUNT_OFFSET, WRITE_FD_OFFSET},
    fill_event_meta,
    mount_signal::signal::is_agent_own_pid,
};

/// Ring buffer shared with userspace for DNS query datagrams.
#[map]
static DNS_UDP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `DnsUdpQueryEvent` (see `EXEC_SCRATCH`).
#[map]
static DNS_UDP_SCRATCH: PerCpuArray<DnsUdpQueryEvent> = PerCpuArray::with_max_entries(1, 0);

/// Where a socket connected to port 53 goes: the destination, remembered at `connect(2)`.
#[derive(Clone, Copy)]
#[repr(C)]
struct DnsFdEntry {
    daddr_v4: [u8; 4],
    daddr_v6: [u8; 16],
    is_ipv6: bool,
}

/// (thread group id, fd) → the destination of a socket connected to port 53. LRU: a descriptor
/// that is closed is never removed explicitly, so a reused number can still be here until the
/// process connects it elsewhere or it ages out; userspace discards a payload that is not a
/// DNS question, so such a stale entry costs a wasted event, not a wrong one.
#[map]
static DNS_UDP_FDS: LruHashMap<u64, DnsFdEntry> = LruHashMap::with_max_entries(4096, 0);

const DNS_PORT: u16 = 53;
/// A DNS header is 12 bytes: anything shorter is not a message.
const DNS_HEADER_LEN: u64 = 12;

// Every helper below is `#[inline(always)]`, like `emit_mount_event`: a real BPF-to-BPF call is
// something the verifier of some kernels refuses to load.
/// The thread group id in the high half, the descriptor in the low half.
#[inline(always)]
fn dns_fd_key(pid_tgid: u64, fd: u64) -> u64 {
    (pid_tgid & 0xFFFF_FFFF_0000_0000) | (fd & 0xFFFF_FFFF)
}

/// `write(2)`/`sendto(2)` with no address on `fd`: a DNS query when this process connected `fd`
/// to port 53. `buf_offset` is where the buffer pointer sits in the tracepoint record.
#[inline(always)]
fn emit_dns_on_connected_socket(
    ctx: &TracePointContext,
    fd: u64,
    buf_offset: usize,
    len: u64,
) -> Result<u32, u32> {
    let key = dns_fd_key(bpf_get_current_pid_tgid(), fd);
    // SAFETY: the map value is plain data; it is copied out before anything else runs.
    let Some(entry) = (unsafe { DNS_UDP_FDS.get(&key) }).copied() else {
        return Ok(0);
    };
    emit_dns_udp_query(ctx, buf_offset, len, &entry)
}

/// Copies the first bytes of the datagram at `buf_offset` (a user pointer in the tracepoint
/// record) into a `DnsUdpQueryEvent` and sends it. Nothing is sent for a datagram shorter than
/// a DNS header or for a read that fails.
#[inline(always)]
fn emit_dns_udp_query(
    ctx: &TracePointContext,
    buf_offset: usize,
    len: u64,
    dest: &DnsFdEntry,
) -> Result<u32, u32> {
    if len < DNS_HEADER_LEN {
        return Ok(0);
    }
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let buf_ptr: u64 = unsafe { ctx.read_at(buf_offset).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let buf_ptr: u64 = unsafe { ctx.read_at::<u32>(buf_offset).map_err(|_| 1u32)? as u64 };
    if buf_ptr == 0 {
        return Ok(0);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if is_agent_own_pid(pid) {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let e = DNS_UDP_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        // Same bounded single read as the TLS capture: the length is clamped first so the
        // verifier sees an upper bound, and it is one helper call, not a byte loop.
        let to_read = if len as usize > MAX_DNS_UDP_PAYLOAD {
            MAX_DNS_UDP_PAYLOAD
        } else {
            len as usize
        };
        let payload = &mut (*e).payload;
        if bpf_probe_read_user_buf(buf_ptr as *const u8, &mut payload[..to_read]).is_err() {
            return Ok(0);
        }
        (*e).payload_len = to_read as u16;

        fill_event_meta(&mut (*e).meta, pid, uid_gid, &comm);
        (*e).daddr_v4 = dest.daddr_v4;
        (*e).daddr_v6 = dest.daddr_v6;
        (*e).dport = DNS_PORT;
        (*e).is_ipv6 = dest.is_ipv6;

        if DNS_UDP_EVENTS.output::<DnsUdpQueryEvent>(&*e, 0).is_err() {
            warn!(
                ctx,
                "sensor-linux-ebpf: ring buffer full, dropping dns query event"
            );
        }
    }
    Ok(0)
}

/// The destination of the `sockaddr` at `addr_ptr` and its port in host order, or `None` for any
/// other family or an address that cannot be read.
#[inline(always)]
fn read_inet_dest(addr_ptr: u64) -> Option<(DnsFdEntry, u16)> {
    let family: u16 = unsafe { bpf_probe_read_user(addr_ptr as *const u16) }.ok()?;
    if family != AF_INET && family != AF_INET6 {
        return None;
    }
    // Same offsets and raw-byte address reads as `try_sys_enter_connect`.
    let port_be: u16 = unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16) }.ok()?;
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]) }.ok()?,
            [0u8; 16],
        )
    } else {
        (
            [0u8; 4],
            unsafe { bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]) }.ok()?,
        )
    };
    Some((
        DnsFdEntry {
            daddr_v4: v4,
            daddr_v6: v6,
            is_ipv6: family == AF_INET6,
        },
        u16::from_be(port_be),
    ))
}

/// The three entry points of `raw_dns_udp_enter` (raw.rs), a program of its own that is attached
/// only with `--enable-dns-capture`. Kept out of `raw_sys_enter` on purpose: that is one verifier
/// unit shared by every `sys_enter_*` handler, and the verifier of the 5.15 kernel rejects it
/// outright (`E2BIG`, before one instruction) once this code is added to it. Each reads the
/// descriptor and arguments from the synthetic record, as the handlers above do.
///
/// `connect(2)`: remembers a socket connected to port 53, so that a later `write(2)`/`send(2)`
/// without an address is recognised as a DNS query; a connect of the same descriptor to anything
/// else forgets it (a reused descriptor number).
///
/// Recorded at syscall entry, before the kernel has said whether the `connect` worked: one that
/// fails leaves an entry behind. It is bounded (the map is an LRU) and harmless, because userspace
/// drops any payload that is not a DNS query.
pub fn dns_udp_connect(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(CONNECT_FD_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(fd) = (unsafe { ctx.read_at::<u32>(CONNECT_FD_OFFSET) }).map(u64::from) else {
        return 1;
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u64>(CONNECT_USERVADDR_PTR_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u32>(CONNECT_USERVADDR_PTR_OFFSET) }).map(u64::from)
    else {
        return 1;
    };
    let key = dns_fd_key(bpf_get_current_pid_tgid(), fd);
    if addr_ptr != 0
        && let Some((entry, port)) = read_inet_dest(addr_ptr)
        && port == DNS_PORT
    {
        let _ = DNS_UDP_FDS.insert(&key, &entry, 0);
        return 0;
    }
    let _ = DNS_UDP_FDS.remove(&key);
    0
}

/// `write(2)` on a socket this process connected to port 53 (Go's resolver does `connect` then
/// `write`).
pub fn dns_udp_write(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(WRITE_FD_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(fd) = (unsafe { ctx.read_at::<u32>(WRITE_FD_OFFSET) }).map(u64::from) else {
        return 1;
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(count) = (unsafe { ctx.read_at::<u64>(WRITE_COUNT_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(count) = (unsafe { ctx.read_at::<u32>(WRITE_COUNT_OFFSET) }).map(u64::from) else {
        return 1;
    };
    let _ = emit_dns_on_connected_socket(&ctx, fd, WRITE_BUF_OFFSET, count);
    0
}

/// `sendto(2)`: with an address, an unconnected query to port 53 (musl, Rust, `dig`); without
/// one (`send(2)` is `sendto` with a NULL address), a query on a socket connected to port 53.
pub fn dns_udp_sendto(ctx: TracePointContext) -> u32 {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(len) = (unsafe { ctx.read_at::<u64>(SENDTO_LEN_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(len) = (unsafe { ctx.read_at::<u32>(SENDTO_LEN_OFFSET) }).map(u64::from) else {
        return 1;
    };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u64>(SENDTO_ADDR_PTR_OFFSET) }) else {
        return 1;
    };
    #[cfg(bpf_target_arch = "x86")]
    let Ok(addr_ptr) = (unsafe { ctx.read_at::<u32>(SENDTO_ADDR_PTR_OFFSET) }).map(u64::from)
    else {
        return 1;
    };
    if addr_ptr == 0 {
        #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
        let Ok(fd) = (unsafe { ctx.read_at::<u64>(SENDTO_FD_OFFSET) }) else {
            return 1;
        };
        #[cfg(bpf_target_arch = "x86")]
        let Ok(fd) = (unsafe { ctx.read_at::<u32>(SENDTO_FD_OFFSET) }).map(u64::from) else {
            return 1;
        };
        let _ = emit_dns_on_connected_socket(&ctx, fd, SENDTO_BUF_OFFSET, len);
        return 0;
    }
    if let Some((dest, port)) = read_inet_dest(addr_ptr)
        && port == DNS_PORT
    {
        let _ = emit_dns_udp_query(&ctx, SENDTO_BUF_OFFSET, len, &dest);
    }
    0
}
