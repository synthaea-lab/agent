//! Datagram receive (issue #263)
//!
//! Same entry/exit shape as accept: `recvfrom(2)`'s source address is written by the
//! kernel during the call, so `sys_enter_recvfrom` stashes the caller's `addr`
//! pointer and `sys_exit_recvfrom` reads the sender from it on return. `recv(2)` is
//! glibc's `recvfrom(..., NULL, NULL)` and is skipped by the NULL check.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::UdpRecvEvent;

use crate::{AF_INET, AF_INET6, SYS_EXIT_RET_OFFSET, fill_event_meta, into_ret};

/// Ring buffer shared with userspace for `recvfrom` events.
#[map]
static UDP_RECV_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `UdpRecvEvent` (see `EXEC_SCRATCH`).
#[map]
static UDP_RECV_SCRATCH: PerCpuArray<UdpRecvEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed at `sys_enter_recvfrom`, consumed at `sys_exit_recvfrom`, keyed by
/// `pid_tgid`. The kernel writes the sender's address and `*addr_len` only on
/// return, and only for sockets that have a source address: a connected TCP
/// socket leaves both untouched, so the exit probe must check `*addr_len` first.
/// Not part of `sensor-linux-wire`'s ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct RecvfromArgs {
    addr_ptr: u64,
    addr_len_ptr: u64,
}

/// LRU rather than a plain hash: a thread that blocks in `recvfrom` forever leaks
/// its entry, and a full plain map would silently refuse every later insert
/// host-wide. The LRU evicts the stalest stash instead.
#[map]
static RECVFROM_ARGS: LruHashMap<u64, RecvfromArgs> = LruHashMap::with_max_entries(1024, 0);

/// Offsets of `addr`(48) and `addr_len`(56) in `syscalls:sys_enter_recvfrom`
/// (x86_64/aarch64): `fd`(16), `ubuf`(24), `size`(32), `flags`(40), the same layout
/// `sys_enter_sendto` reports. Verified on 2026-10-05 on Alpine (kernel 6.18.50-0-virt,
/// x86_64) via `/sys/kernel/tracing/events/syscalls/sys_enter_recvfrom/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RECVFROM_ADDR_PTR_OFFSET: usize = 48;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const RECVFROM_ADDR_LEN_PTR_OFFSET: usize = 56;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const RECVFROM_ADDR_PTR_OFFSET: usize = 28;
#[cfg(bpf_target_arch = "x86")]
const RECVFROM_ADDR_LEN_PTR_OFFSET: usize = 32;

pub fn sys_enter_recvfrom(ctx: TracePointContext) -> u32 {
    into_ret(stash_recvfrom_addr(&ctx))
}

fn stash_recvfrom_addr(ctx: &TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_ptr: u64 = unsafe { ctx.read_at(RECVFROM_ADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let addr_len_ptr: u64 = unsafe {
        ctx.read_at(RECVFROM_ADDR_LEN_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };
    #[cfg(bpf_target_arch = "x86")]
    let addr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RECVFROM_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    #[cfg(bpf_target_arch = "x86")]
    let addr_len_ptr: u64 = unsafe {
        ctx.read_at::<u32>(RECVFROM_ADDR_LEN_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    if addr_ptr != 0 {
        let args = RecvfromArgs {
            addr_ptr,
            addr_len_ptr,
        };
        let _ = RECVFROM_ARGS.insert(&pid_tgid, &args, 0);
    } else {
        let _ = RECVFROM_ARGS.remove(&pid_tgid);
    }

    Ok(0)
}

pub fn sys_exit_recvfrom(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_exit_recvfrom(ctx))
}

/// No-ops when the matching enter wasn't tracked, the call failed (`ret < 0`), the
/// kernel wrote no source address (`*addr_len == 0`, e.g. a connected TCP socket,
/// whose `addr` buffer still holds whatever the caller put there), or the sender's
/// address family isn't `AF_INET`/`AF_INET6`.
fn try_sys_exit_recvfrom(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let ret: i64 = unsafe { ctx.read_at::<i32>(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? as i64 };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { RECVFROM_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = RECVFROM_ARGS.remove(&pid_tgid);

    if ret < 0 {
        return Ok(0);
    }

    let addr_len: u32 = match unsafe { bpf_probe_read_user(args.addr_len_ptr as *const u32) } {
        Ok(len) => len,
        Err(_) => return Ok(0),
    };
    if addr_len == 0 {
        return Ok(0);
    }
    let addr_ptr = args.addr_ptr;

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

    let e = UDP_RECV_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(&mut (*e).meta, (pid_tgid >> 32) as u32, uid_gid, &comm);
        (*e).peer_addr_v4 = v4;
        (*e).peer_addr_v6 = v6;
        (*e).peer_port = u16::from_be(port_be);
        (*e).is_ipv6 = family == AF_INET6;
        (*e).size = ret as u32;

        if UDP_RECV_EVENTS.output::<UdpRecvEvent>(&*e, 0).is_err() {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping udp recv event"
            );
        }
    }

    Ok(0)
}
