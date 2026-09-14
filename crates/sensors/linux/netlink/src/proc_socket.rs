//! Drives the real `AF_NETLINK`/`NETLINK_CONNECTOR` socket, subscribed to the
//! process-events multicast group (`CN_IDX_PROC`). Linux-only, and root/
//! `CAP_NET_ADMIN`-only: the kernel's `cn_proc_mcast_ctl()` rejects the
//! subscribe request from an unprivileged caller with `EPERM` (confirmed against
//! this dev machine: unprivileged, the send succeeds but the kernel reports the
//! failure back as an `NLMSG_ERROR`; unlike `sock_diag`, there is no
//! unprivileged-subset fallback here).
//!
//! Unlike [`crate::socket`]'s one-shot dump, this is a live subscription: once
//! open, the kernel broadcasts a message for every fork/exec/exit on the system,
//! not just ones this process asked about — [`recv_events`](ProcEventSubscription::recv_events)
//! is meant to be called in a loop by whatever owns the socket's lifetime.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};

pub use crate::socket::NetlinkError;
use crate::{
    proc_events::{
        CN_IDX_PROC, CN_MSG_HDR_LEN, CN_VAL_PROC, CnMsgHeader, PROC_CN_MCAST_LISTEN, ProcEvent,
    },
    wire::{NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, NlMsgHeader},
};

/// Not in every version of the `libc` crate's Linux constant set — see
/// `socket.rs`'s identical note for `NETLINK_SOCK_DIAG`. Value from
/// `<linux/netlink.h>`.
const NETLINK_CONNECTOR: libc::c_int = 11;

/// Bounds how long [`recv_events`](ProcEventSubscription::recv_events) blocks
/// when nothing arrives, so a caller polling this socket (or this module's own
/// test) can't hang forever on a quiet system. A timeout is reported as
/// `Ok(vec![])`, not an error — "no events in this window" is the expected,
/// common case for a live subscription, not a failure.
const RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// An open, subscribed `NETLINK_CONNECTOR` socket. Dropping it closes the fd,
/// which unsubscribes implicitly (the kernel only tracks group membership per
/// open socket, not per explicit `PROC_CN_MCAST_IGNORE` — see the crate doc).
pub struct ProcEventSubscription {
    fd: OwnedFd,
}

impl ProcEventSubscription {
    /// Opens a `NETLINK_CONNECTOR` socket, binds it to the process-events group,
    /// and sends the `PROC_CN_MCAST_LISTEN` subscribe request. The subscribe
    /// itself is fire-and-forget here — a permission failure surfaces on the
    /// first [`recv_events`](Self::recv_events) call instead (see the module
    /// doc), keeping this constructor to the same "open the fd, send one
    /// request" shape as `socket::dump_one_family`.
    ///
    /// # Errors
    ///
    /// [`NetlinkError::Io`] if the socket can't be created, bound, or the
    /// subscribe request can't be sent.
    pub fn open() -> Result<Self, NetlinkError> {
        let fd = open_socket()?;
        set_recv_timeout(&fd, RECV_TIMEOUT)?;
        send_subscribe(&fd)?;
        Ok(Self { fd })
    }

    /// Blocks for up to [`RECV_TIMEOUT`] waiting for the kernel to deliver at
    /// least one datagram, then decodes every proc-connector message it
    /// contains (ordinarily one — the kernel broadcasts each event as its own
    /// packet — but the loop walks every `nlmsghdr` in the buffer regardless,
    /// the same defensive discipline as `socket::read_dump`).
    ///
    /// # Errors
    ///
    /// [`NetlinkError::Io`] if the underlying `recv(2)` fails for a reason
    /// other than the timeout; [`NetlinkError::Kernel`] if the kernel reports a
    /// non-zero `NLMSG_ERROR` — in practice, `EPERM` from a missing
    /// `CAP_NET_ADMIN` on the original subscribe (see the module doc).
    pub fn recv_events(&self) -> Result<Vec<ProcEvent>, NetlinkError> {
        let mut buf = vec![0u8; 64 * 1024];

        // SAFETY: `recv(2)` into a buffer this function owns, with its exact
        // allocated length as the size bound — the kernel never writes past it.
        // The returned count is validated before any byte of `buf` is read.
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                return Ok(Vec::new()); // RECV_TIMEOUT elapsed — no events, not a failure
            }
            return Err(NetlinkError::Io(err));
        }
        let received_len = usize::try_from(n).unwrap_or(0);
        let received = &buf[..received_len];

        let mut events = Vec::new();
        let mut offset = 0usize;
        while let Some(header) = NlMsgHeader::parse(&received[offset..]) {
            let msg_len = header.len as usize;
            if msg_len < NLMSG_HDR_LEN || offset + msg_len > received.len() {
                break; // truncated/malformed frame — stop trusting this buffer
            }
            let payload = &received[offset + NLMSG_HDR_LEN..offset + msg_len];

            match header.msg_type {
                NLMSG_ERROR => {
                    // Byte-by-byte, not `try_into().unwrap()` — no explicit
                    // panic point to document, matching `wire::DiagMsg::parse`.
                    let errno = match payload {
                        [a, b, c, d, ..] => i32::from_ne_bytes([*a, *b, *c, *d]),
                        _ => -1,
                    };
                    if errno != 0 {
                        return Err(NetlinkError::Kernel(errno));
                    }
                    // errno == 0: a plain ACK, not a proc event — skip it and
                    // keep walking the buffer (unlike a dump, this socket's
                    // stream never ends, so there is nothing to break out of).
                }
                // Proc-connector broadcasts carry NLMSG_DONE as their message
                // type by kernel convention (there is no dedicated connector
                // message type) — verified against `cn_proc`'s own broadcast
                // path, not assumed from the request side alone.
                NLMSG_DONE => {
                    if let Some(cn_header) = CnMsgHeader::parse(payload)
                        && cn_header.idx == CN_IDX_PROC
                        && cn_header.val == CN_VAL_PROC
                        && let Some(event) = ProcEvent::parse(&payload[CN_MSG_HDR_LEN..])
                    {
                        events.push(event);
                    }
                }
                _ => {} // an unexpected message type — ignore, don't abort the stream
            }
            offset += (msg_len + 3) & !3; // NLMSG_ALIGN: 4-byte padding
        }

        Ok(events)
    }
}

fn open_socket() -> Result<OwnedFd, NetlinkError> {
    // SAFETY: `socket(2)` with a fixed, valid family/type/protocol triple. The
    // result is checked for the -1 error sentinel before being trusted as a real
    // fd; on success it is immediately handed to `OwnedFd`, which becomes its
    // sole owner (closed on drop) so no descriptor can leak past this function.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, NETLINK_CONNECTOR) };
    if raw < 0 {
        return Err(NetlinkError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` was just verified >= 0 (a freshly-opened, uniquely-owned fd
    // from the `socket(2)` call above), satisfying `from_raw_fd`'s precondition.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: `addr` is zero-initialized `libc::sockaddr_nl`, a plain-old-data C
    // struct with no invalid all-zero bit pattern (every field is an integer).
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // nl_pid = this process's pid, matching the kernel documentation's own
    // sample (Documentation/connector/cn_proc.c): unlike the one-shot sock_diag
    // query, a long-lived subscription is exactly the case that convention
    // exists for.
    addr.nl_pid = std::process::id();
    // nl_groups = CN_IDX_PROC: subscribing to the process-events multicast
    // group is done by setting its own idx value as the bind-time group mask
    // (not a bit-shifted group number) — see the crate doc; verified against
    // the kernel connector sample.
    addr.nl_groups = CN_IDX_PROC;

    // SAFETY: `bind(2)` on the fd this function owns, passing a pointer to a
    // local `sockaddr_nl` whose size exactly matches the `addrlen` argument — the
    // kernel reads, never writes through this pointer for `bind`.
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(NetlinkError::Io(io::Error::last_os_error()));
    }
    Ok(fd)
}

fn set_recv_timeout(fd: &OwnedFd, timeout: Duration) -> Result<(), NetlinkError> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
    };
    // SAFETY: `setsockopt(2)` on the fd this function borrows, with a
    // `libc::timeval` whose size exactly matches the `optlen` argument passed
    // alongside it.
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(NetlinkError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn send_subscribe(fd: &OwnedFd) -> Result<(), NetlinkError> {
    let mcast_op = PROC_CN_MCAST_LISTEN.to_ne_bytes();
    let cn_header = CnMsgHeader {
        idx: CN_IDX_PROC,
        val: CN_VAL_PROC,
        seq: 0,
        ack: 0,
        len: mcast_op.len() as u16,
        flags: 0,
    };
    let nl_header = NlMsgHeader {
        len: (NLMSG_HDR_LEN + CN_MSG_HDR_LEN + mcast_op.len()) as u32,
        // Matching the kernel connector sample again: the request, like the
        // broadcasts it turns on, is framed with NLMSG_DONE rather than a
        // connector-specific message type.
        msg_type: NLMSG_DONE,
        flags: 0,
        seq: 0,
        pid: std::process::id(),
    };

    let mut buf = Vec::with_capacity(nl_header.len as usize);
    buf.extend_from_slice(&nl_header.to_bytes());
    buf.extend_from_slice(&cn_header.to_bytes());
    buf.extend_from_slice(&mcast_op);

    // SAFETY: `send(2)` on a fd this function borrows (still owned by the
    // caller), with a pointer/length pair taken from a `Vec` we just built —
    // the length passed matches the buffer exactly.
    let sent = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
    if sent < 0 {
        return Err(NetlinkError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    /// Integration-style: exercises the real socket against this dev machine's
    /// kernel, skips itself when not root/`CAP_NET_ADMIN` rather than requiring
    /// a specific dev/CI privilege level to build and test — same discipline as
    /// `sensor-linux-journal`'s `journalctl`-presence skip (issue #93's
    /// precedent).
    ///
    /// Does **not** assert against a specific spawned child's pid — same
    /// discipline as `socket::query_tcp_sockets_against_the_real_kernel`
    /// ("doesn't assert a specific socket is present"). A dev sandbox under
    /// concurrent load (confirmed on this machine via an ad hoc reference
    /// client while scoping this module: dozens of unrelated fork/exec/exit
    /// broadcasts per second) can miss one specific short-lived child's own
    /// three broadcasts to a freshly-opened, not-yet-fully-registered
    /// subscription — a real race in a busy environment, not a decode bug: the
    /// same reference client, reading the *system's* live traffic rather than
    /// one pid, decoded fork/exec/exit correctly every time, matching what
    /// `proc_events`'s synthetic tests already pin against the kernel struct
    /// layout. What this test proves is the live plumbing (socket, subscribe,
    /// recv, decode) end to end — spawning a child is just a reliable way to
    /// guarantee *some* fresh activity exists to observe.
    #[test]
    fn observes_live_fork_exec_and_exit_broadcasts() {
        let sub = match ProcEventSubscription::open() {
            Ok(sub) => sub,
            Err(e) => {
                eprintln!("skipping: could not open the connector socket: {e}");
                return;
            }
        };

        let mut child = Command::new("true")
            .spawn()
            .expect("spawning `true` must succeed on any POSIX system");
        child.wait().expect("waiting for `true` must succeed");

        let mut saw_fork = false;
        let mut saw_exec = false;
        let mut saw_exit = false;
        let mut saw_permission_error = false;

        // Wall-clock deadline, not a fixed round count: each `recv_events`
        // call returns one datagram — ordinarily one event (see the module
        // doc) — and on a busy system FORK broadcasts vastly outnumber EXEC
        // (observed on this dev machine: roughly 4:1), so a small fixed round
        // count can exhaust itself on FORK/EXIT alone before an EXEC happens
        // to land. 10 s comfortably covers that on any system with the
        // ambient process activity a live subscription is meant to observe;
        // a genuinely idle system still bails out via RECV_TIMEOUT well
        // before then instead of hanging.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if saw_fork && saw_exec && saw_exit {
                break;
            }
            match sub.recv_events() {
                Ok(events) => {
                    for event in events {
                        match event {
                            ProcEvent::Fork { .. } => saw_fork = true,
                            ProcEvent::Exec { .. } => saw_exec = true,
                            ProcEvent::Exit { .. } => saw_exit = true,
                            ProcEvent::Other(_) => {}
                        }
                    }
                }
                Err(NetlinkError::Kernel(errno)) if errno == libc::EPERM => {
                    saw_permission_error = true;
                    break;
                }
                Err(e) => panic!("unexpected netlink error: {e}"),
            }
        }

        if saw_permission_error {
            eprintln!(
                "skipping: kernel rejected the subscribe with EPERM — needs root/CAP_NET_ADMIN"
            );
            return;
        }

        assert!(saw_fork, "no PROC_EVENT_FORK observed on this system");
        assert!(saw_exec, "no PROC_EVENT_EXEC observed on this system");
        assert!(saw_exit, "no PROC_EVENT_EXIT observed on this system");
    }
}
