//! `bind(2)` on IPv4/IPv6 sockets. Also records the bound address in `BIND_ADDR_MAP` for
//! `listen`.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::warn;
use sensor_linux_wire::SocketBindEvent;

use crate::{AF_INET, AF_INET6, fill_event_meta, into_ret};

/// Ring buffer shared with userspace for `bind` events.
#[map]
static SOCKET_BIND_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch for building one `SocketBindEvent` (see `EXEC_SCRATCH`).
#[map]
static BIND_SCRATCH: PerCpuArray<SocketBindEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offsets of the `syscalls:sys_enter_bind` tracepoint (`x86_64/aarch64)`: `fd`(16),
/// `umyaddr`(24), `addrlen`(32) — identical shape to `sys_enter_connect` above.
/// Verified on 2026-09-21 on Alpine (kernel 6.18.50-0-virt, `x86_64`) via
/// `/sys/kernel/tracing/events/syscalls/sys_enter_bind/format`.
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BIND_FD_OFFSET: usize = 16;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
const BIND_UMYADDR_PTR_OFFSET: usize = 24;
/// i686: inferred, not independently verified (see `sys_enter_open`'s i686 note).
#[cfg(bpf_target_arch = "x86")]
const BIND_FD_OFFSET: usize = 12;
#[cfg(bpf_target_arch = "x86")]
const BIND_UMYADDR_PTR_OFFSET: usize = 16;

/// Key into [`BIND_ADDR_MAP`]: a process's fd table entry is per-process, so the
/// same fd number on two different pids is a different socket.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BindAddrKey {
    pub(crate) pid: u32,
    pub(crate) fd: u32,
}

/// Value in [`BIND_ADDR_MAP`]: the address a prior `bind(2)` on this `(pid, fd)`
/// claimed, same shape as `SocketBindEvent`'s address fields.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BindAddrValue {
    pub(crate) addr_v4: [u8; 4],
    pub(crate) addr_v6: [u8; 16],
    pub(crate) port: u16,
    pub(crate) is_ipv6: bool,
}

/// Correlates a later `listen(2)` back to the address an earlier `bind(2)` on the
/// same `(pid, fd)` claimed — `listen(2)`'s own arguments are just `fd`+`backlog`,
/// no address. Internal to this crate: never read by userspace, so it is not part
/// of `sensor-linux-wire`'s ABI and does not bump `WIRE_VERSION` on its own.
///
/// Entries are never explicitly removed (no `close(2)` probe tracks fd lifetime
/// yet): a `bind()` on a reused fd simply overwrites the old entry, and the
/// map is bounded (`insert` fails silently once full, same graceful-degradation
/// posture as every other best-effort correlation in this file) rather than
/// growing without limit.
#[map]
pub(crate) static BIND_ADDR_MAP: HashMap<BindAddrKey, BindAddrValue> =
    HashMap::with_max_entries(4096, 0);

pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    into_ret(try_sys_enter_bind(ctx))
}

/// Mirrors `try_sys_enter_connect` above field for field — same family filter, same
/// raw-byte address read (avoids the endianness bug documented on `ConnectEvent`),
/// same per-CPU-scratch assembly. Only the wire type, ring buffer, and field names
/// (`laddr`/`lport` vs `daddr`/`dport`) differ. Also records the address into
/// [`BIND_ADDR_MAP`] for `sys_enter_listen` to correlate against later.
fn try_sys_enter_bind(ctx: TracePointContext) -> Result<u32, u32> {
    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let fd: u64 = unsafe { ctx.read_at(BIND_FD_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let fd: u64 = unsafe { ctx.read_at::<u32>(BIND_FD_OFFSET).map_err(|_| 1u32)? as u64 };

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    let umyaddr_ptr: u64 = unsafe { ctx.read_at(BIND_UMYADDR_PTR_OFFSET).map_err(|_| 1u32)? };
    #[cfg(bpf_target_arch = "x86")]
    let umyaddr_ptr: u64 = unsafe {
        ctx.read_at::<u32>(BIND_UMYADDR_PTR_OFFSET)
            .map_err(|_| 1u32)? as u64
    };
    if umyaddr_ptr == 0 {
        return Ok(0);
    }

    let family: u16 = match unsafe { bpf_probe_read_user(umyaddr_ptr as *const u16) } {
        Ok(f) => f,
        Err(_) => return Ok(0),
    };
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();

    let port_be: u16 =
        unsafe { bpf_probe_read_user((umyaddr_ptr + 2) as *const u16).map_err(|_| 1u32)? };
    let (v4, v6): ([u8; 4], [u8; 16]) = if family == AF_INET {
        (
            unsafe { bpf_probe_read_user((umyaddr_ptr + 4) as *const [u8; 4]).map_err(|_| 1u32)? },
            [0u8; 16],
        )
    } else {
        ([0u8; 4], unsafe {
            bpf_probe_read_user((umyaddr_ptr + 8) as *const [u8; 16]).map_err(|_| 1u32)?
        })
    };

    let e = BIND_SCRATCH.get_ptr_mut(0).ok_or(1u32)?;
    unsafe {
        core::ptr::write_bytes(e, 0, 1);

        fill_event_meta(
            &mut (*e).meta,
            (bpf_get_current_pid_tgid() >> 32) as u32,
            uid_gid,
            &comm,
        );
        (*e).is_ipv6 = family == AF_INET6;
        (*e).lport = u16::from_be(port_be);
        (*e).laddr_v4 = v4;
        (*e).laddr_v6 = v6;

        if SOCKET_BIND_EVENTS
            .output::<SocketBindEvent>(&*e, 0)
            .is_err()
        {
            warn!(
                &ctx,
                "sensor-linux-ebpf: ring buffer full, dropping bind event"
            );
        }
    }

    let key = BindAddrKey {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        fd: fd as u32,
    };
    // `BindAddrValue`'s field order (4 + 16 + 2 + bool = 23 bytes of data, but a
    // `u16` field forces the struct's alignment to 2, so its declared size is 24)
    // leaves a 1-byte tail pad that a plain struct literal never writes. That's
    // fine for a value that's only ever read back through this same typed struct
    // — but `bpf_map_update_elem` below copies the map's full declared value_size
    // (24) off the stack, and the verifier tracks stack initialization per byte:
    // on kernel 5.15 it rejects the load with "invalid indirect read from stack
    // ... size 24" because that pad byte was never provably written (issue #390 —
    // reproduced on Ubuntu 22.04/5.15, not on the Alpine 6.18/Arch 6.6 kernels
    // this sensor had been validated against before, so the stricter check isn't
    // universal). Zeroing the whole struct first covers the pad the same way
    // `core::ptr::write_bytes` already does for every ring-buffer scratch struct
    // in this file, just without a `PerCpuArray` backing it.
    let mut value: BindAddrValue = unsafe { core::mem::zeroed() };
    value.addr_v4 = v4;
    value.addr_v6 = v6;
    value.port = u16::from_be(port_be);
    value.is_ipv6 = family == AF_INET6;
    let _ = BIND_ADDR_MAP.insert(&key, &value, 0);

    Ok(0)
}
