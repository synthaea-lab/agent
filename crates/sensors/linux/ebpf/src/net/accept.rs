//! Socket accept (issue #263 Phase 2)
//!
//! First paired `sys_enter/sys_exit` probe in this crate. Every other probe here is
//! `sys_enter`_*: it reads syscall arguments before the call runs, which is enough
//! because the kernel hasn't touched anything yet. accept(2)/accept4(2) are
//! different — the caller passes a sockaddr buffer that the kernel fills in DURING
//! the call, so the peer address does not exist yet at `sys_enter` time. The standard
//! `sys_exit`_* tracepoint format carries only __`syscall_nr` and the return value, not
//! the original arguments, so `sys_enter_accept{,4`} stashes the caller's
//! (fd, `addr_ptr`) in `ACCEPT_ARGS` (keyed by `pid_tgid`, the same entry/exit
//! correlation pattern already used by the uprobes crate's `SSL_READ_ARGS` for
//! `SSL_read`'s output buffer), and `sys_exit_accept{,4`} reads it back once the kernel
//! has actually written the peer address.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::SocketAcceptEvent;

use crate::{
    AF_INET, AF_INET6,
    arch::{SYS_EXIT_RET_OFFSET, SyscallRecord, arg_offset},
    fill_event_meta, into_ret,
};

/// Ring buffer shared with userspace for `accept`/`accept4` events.
#[map]
static SOCKET_ACCEPT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketAcceptEvent` (see `EXEC_SCRATCH`).
#[map]
static ACCEPT_SCRATCH: PerCpuArray<SocketAcceptEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed at `sys_enter_accept{,4}`, consumed at `sys_exit_accept{,4}`.
#[repr(C)]
#[derive(Clone, Copy)]
struct AcceptArgs {
    fd: u32,
    addr_ptr: u64,
}

/// Correlates `sys_enter_accept{,4}` with its matching `sys_exit_accept{,4}` on the
/// same thread. Not part of `sensor-linux-wire`'s ABI (never read by userspace).
/// A thread that enters `accept()` and never returns retains its entry. An LRU
/// evicts the stalest stash when full so blocked threads cannot blind later
/// accept telemetry host-wide.
#[map]
static ACCEPT_ARGS: LruHashMap<u64, AcceptArgs> = LruHashMap::with_max_entries(1024, 0);

/// Offsets of the `syscalls:sys_enter_accept`/`sys_enter_accept4` tracepoints
/// (`x86_64`/`aarch64`): `fd`(16), `upeer_sockaddr`(24) — identical shape for both
/// (accept4's extra `flags` argument trails at 40, not needed here). Verified on
/// 2026-09-22 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_accept{,4}/format`.
///
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
const ACCEPT_FD_OFFSET: usize = arg_offset(0);
const ACCEPT_ADDR_PTR_OFFSET: usize = arg_offset(1);

pub fn sys_enter_accept(ctx: TracePointContext) -> u32 {
    into_ret(stash_accept_args(&ctx))
}

pub fn sys_enter_accept4(ctx: TracePointContext) -> u32 {
    into_ret(stash_accept_args(&ctx))
}

/// Shared by `sys_enter_accept` and `sys_enter_accept4` — both have the same
/// `fd`/`upeer_sockaddr` layout.
fn stash_accept_args(ctx: &TracePointContext) -> Result<u32, u32> {
    let fd: u64 = unsafe { ctx.read_ulong_arg(ACCEPT_FD_OFFSET).map_err(|_| 1u32)? };

    let addr_ptr: u64 = unsafe {
        ctx.read_ulong_arg(ACCEPT_ADDR_PTR_OFFSET)
            .map_err(|_| 1u32)?
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    if addr_ptr != 0 {
        let args = AcceptArgs {
            fd: fd as u32,
            addr_ptr,
        };
        let _ = ACCEPT_ARGS.insert(&pid_tgid, &args, 0);
    } else {
        let _ = ACCEPT_ARGS.remove(&pid_tgid);
    }

    Ok(0)
}

pub fn sys_exit_accept(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_exit_accept(ctx))
}

pub fn sys_exit_accept4(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_exit_accept(ctx))
}

/// Shared by `sys_exit_accept` and `sys_exit_accept4`. No-ops (returns `Ok(0)`
/// without emitting) when: the matching `sys_enter` wasn't tracked (NULL addr
/// or an evicted stash), the call failed (`ret < 0`), or the peer's address
/// family isn't one this sensor tracks.
fn try_sys_exit_accept(ctx: TracePointContext) -> Result<u32, u32> {
    let ret: i64 = unsafe { ctx.read_long_arg(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { ACCEPT_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = ACCEPT_ARGS.remove(&pid_tgid);

    if ret < 0 {
        return Ok(0);
    }
    let accepted_fd = ret as u32;

    let family: u16 = match unsafe { bpf_probe_read_user(args.addr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((args.addr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe {
                bpf_probe_read_user((args.addr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)?
            },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((args.addr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = ACCEPT_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(&mut (*e).meta, (pid_tgid >> 32) as u32, uid_gid, &comm);
        (*e).listen_fd = args.fd;
        (*e).accepted_fd = accepted_fd;
        (*e).peer_addr_v4 = v4;
        (*e).peer_addr_v6 = v6;
        (*e).peer_port = u16::from_be(port_be);
        (*e).is_ipv6 = family == AF_INET6;

        if SOCKET_ACCEPT_EVENTS
            .output::<SocketAcceptEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping accept event"
            );
        }
    }

    Ok(0)
}
