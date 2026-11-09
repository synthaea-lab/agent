//! Socket creation (issue #263)
//!
//! `socket(domain, type, protocol)`'s three arguments are the caller's own, already
//! available at `sys_enter` — unlike `accept`/`recvfrom` there is no kernel-filled
//! output buffer to wait for. The only reason this still needs the paired
//! `sys_enter`/`sys_exit` shape is that the fd itself is the return value: the entry
//! probe stashes the three arguments, the exit probe reads them back together with
//! the fd and emits on success only.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::map,
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::SocketCreateEvent;

use crate::{SYS_EXIT_RET_OFFSET, fill_event_meta, into_ret};

/// Ring buffer shared with userspace for `socket` events.
#[map]
static SOCKET_CREATE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketCreateEvent` (see `EXEC_SCRATCH`).
#[map]
static SOCKET_CREATE_SCRATCH: PerCpuArray<SocketCreateEvent> = PerCpuArray::with_max_entries(1, 0);

/// Stashed at `sys_enter_socket`, consumed at `sys_exit_socket`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketCreateArgs {
    domain: i32,
    socket_type: i32,
    protocol: i32,
}

/// Correlates `sys_enter_socket` with its matching `sys_exit_socket` on the same
/// thread. Not part of `sensor-linux-wire`'s ABI. A thread that never returns from
/// `socket()` (it can block — `AF_ALG`, some out-of-tree protocol families) keeps
/// its entry; an LRU evicts the stalest one when full, same reasoning as
/// `ACCEPT_ARGS` and `PENDING_SYSCALL_EXIT` (#672).
#[map]
static SOCKET_CREATE_ARGS: LruHashMap<u64, SocketCreateArgs> =
    LruHashMap::with_max_entries(1024, 0);

/// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` (`<bits/socket_type.h>`): the kernel ORs these
/// into the same `type` argument as `SOCK_STREAM`/`SOCK_DGRAM`/etc., so they are
/// masked off before reporting `socket_type` — a caller asking for a non-blocking
/// stream socket should read as `SOCK_STREAM`, not an unrecognized combined value.
const SOCK_CLOEXEC_FLAG: i32 = 0o2000000;
const SOCK_NONBLOCK_FLAG: i32 = 0o4000;

/// `AF_UNIX` (`<bits/socket.h>`): excluded from `socket_create` emission, not from
/// `SocketCreateArgs` capture. Local IPC sockets (systemd, journald, D-Bus, every
/// Unix-domain client) are a large share of all `socket()` calls on a running
/// system and never carry a family/protocol surprise the way `AF_PACKET` or a raw
/// socket does, so emitting one per call is pure correlator-bus volume for zero
/// current consumer, with nothing #263 or this event type needs them for (#714
/// review).
const AF_UNIX: i32 = 1;

/// Offsets of the `syscalls:sys_enter_socket` tracepoint (`x86_64/aarch64)`:
/// `domain`(16), `type`(24), `protocol`(32) — the standard three-plain-argument
/// layout also verified for `tgkill`'s `(tgid, tid, sig)`. Verified on 2026-10-07
/// on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_socket/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SOCKET_DOMAIN_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SOCKET_TYPE_OFFSET: usize = 24;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const SOCKET_PROTOCOL_OFFSET: usize = 32;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const SOCKET_DOMAIN_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const SOCKET_TYPE_OFFSET: usize = 16;
#[cfg(bpf_target_arch = "x86")]
const SOCKET_PROTOCOL_OFFSET: usize = 20;

pub fn sys_enter_socket(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_socket(&ctx))
}

fn try_sys_enter_socket(ctx: &TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let domain: i64 = unsafe { ctx.read_at(SOCKET_DOMAIN_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let domain: i64 = unsafe { ctx.read_at::<i32>(SOCKET_DOMAIN_OFFSET).map_err(|_| 1u32)? as i64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let raw_type: i64 = unsafe { ctx.read_at(SOCKET_TYPE_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let raw_type: i64 = unsafe { ctx.read_at::<i32>(SOCKET_TYPE_OFFSET).map_err(|_| 1u32)? as i64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let protocol: i64 = unsafe { ctx.read_at(SOCKET_PROTOCOL_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let protocol: i64 = unsafe {
        ctx.read_at::<i32>(SOCKET_PROTOCOL_OFFSET)
            .map_err(|_| 1u32)? as i64
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = SocketCreateArgs {
        domain: domain as i32,
        socket_type: (raw_type as i32) & !(SOCK_CLOEXEC_FLAG | SOCK_NONBLOCK_FLAG),
        protocol: protocol as i32,
    };
    let _ = SOCKET_CREATE_ARGS.insert(&pid_tgid, &args, 0);

    Ok(0)
}

pub fn sys_exit_socket(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_exit_socket(ctx))
}

fn try_sys_exit_socket(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let ret: i64 = unsafe { ctx.read_at::<i32>(SYS_EXIT_RET_OFFSET).map_err(|_| 1u32)? as i64 };

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = match unsafe { SOCKET_CREATE_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = SOCKET_CREATE_ARGS.remove(&pid_tgid);

    if ret < 0 || args.domain == AF_UNIX {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let e = SOCKET_CREATE_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(&mut (*e).meta, (pid_tgid >> 32) as u32, uid_gid, &comm);
        (*e).domain = args.domain;
        (*e).socket_type = args.socket_type;
        (*e).protocol = args.protocol;
        (*e).fd = ret as u32;

        if SOCKET_CREATE_EVENTS
            .output::<SocketCreateEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping socket event"
            );
        }
    }

    Ok(0)
}
