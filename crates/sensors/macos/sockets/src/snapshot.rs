//! The macOS-only half: FFI to the C shim and the snapshot entry points.

use std::{
    ffi::{c_char, c_void},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::{
    SocketsError,
    raw::{SocketSnapshotEntry, SocketState},
};

// Mirrors `enum syn_sock_state`.
const SYN_SOCK_STATE_LISTEN: u8 = 1;
const SYN_SOCK_STATE_ESTABLISHED: u8 = 2;

/// Mirrors `syn_sock_record` (`shim/sockets_shim.h`) field-for-field.
#[repr(C)]
struct SynSockRecord {
    pid: i32,
    ppid: i32,
    uid: u32,
    gid: u32,
    path: [c_char; 1024],
    state: u8,
    is_ipv6: u8,
    lport: u16,
    rport: u16,
    laddr: [u8; 16],
    raddr: [u8; 16],
}

type SynSockCb = unsafe extern "C" fn(ctx: *mut c_void, rec: *const SynSockRecord);

unsafe extern "C" {
    fn syn_sockets_snapshot(cb: SynSockCb, ctx: *mut c_void) -> i32;
}

fn addr(is_ipv6: bool, bytes: &[u8; 16], port: u16) -> SocketAddr {
    let ip = if is_ipv6 {
        IpAddr::V6(Ipv6Addr::from(*bytes))
    } else {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    };
    SocketAddr::new(ip, port)
}

/// Collector context for the C walk; no user code runs inside the callback,
/// so nothing can unwind across the FFI boundary.
unsafe extern "C" fn collect(ctx: *mut c_void, rec: *const SynSockRecord) {
    // SAFETY: `ctx` is the `&mut Vec` passed to `syn_sockets_snapshot` below,
    // valid for the whole call; `rec` is valid for this callback per the shim
    // contract.
    let (out, rec) = unsafe { (&mut *ctx.cast::<Vec<SocketSnapshotEntry>>(), &*rec) };
    let path_bytes: &[u8] = {
        // SAFETY: `path` is NUL-terminated by the shim (zeroed struct +
        // proc_pidpath's own termination) within its 1024 bytes.
        let cstr = unsafe { std::ffi::CStr::from_ptr(rec.path.as_ptr()) };
        cstr.to_bytes()
    };
    let is_ipv6 = rec.is_ipv6 != 0;
    out.push(SocketSnapshotEntry {
        pid: rec.pid.max(0).cast_unsigned(),
        ppid: rec.ppid.max(0).cast_unsigned(),
        uid: rec.uid,
        gid: rec.gid,
        process_path: (!path_bytes.is_empty())
            .then(|| String::from_utf8_lossy(path_bytes).into_owned()),
        local: addr(is_ipv6, &rec.laddr, rec.lport),
        remote: addr(is_ipv6, &rec.raddr, rec.rport),
        state: match rec.state {
            SYN_SOCK_STATE_LISTEN => SocketState::Listen,
            SYN_SOCK_STATE_ESTABLISHED => SocketState::Established,
            _ => SocketState::Other,
        },
    });
}

/// Takes one snapshot of every visible process's TCP sockets.
///
/// Visibility follows libproc's rules: unprivileged, only the caller's own
/// processes (plus world-visible metadata) resolve; as root the walk sees the
/// whole table. Partial visibility is returned honestly, never padded.
///
/// # Errors
///
/// [`SocketsError::Snapshot`] only when the initial pid enumeration itself
/// fails — per-process failures (races with exits, permissions) are skips by
/// design.
pub fn snapshot() -> Result<Vec<SocketSnapshotEntry>, SocketsError> {
    let mut out: Vec<SocketSnapshotEntry> = Vec::new();
    // SAFETY: `collect` matches the callback ABI and only dereferences the
    // pointers the shim guarantees valid; `out` outlives the call.
    let rc = unsafe { syn_sockets_snapshot(collect, (&raw mut out).cast::<c_void>()) };
    if rc != 0 {
        return Err(SocketsError::Snapshot(rc));
    }
    Ok(out)
}

/// One [`snapshot`] mapped to [`schema::Event::ListenPort`] events, stamped
/// with `timestamp_ns` as the snapshot time.
///
/// # Errors
///
/// Same failure mode as [`snapshot`], which this wraps.
pub fn listen_port_events(timestamp_ns: u64) -> Result<Vec<schema::Event>, SocketsError> {
    Ok(snapshot()?
        .iter()
        .filter_map(|entry| crate::normalize::listen_port_event(entry, timestamp_ns))
        .collect())
}
