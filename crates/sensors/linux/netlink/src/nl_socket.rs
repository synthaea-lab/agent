//! The one `AF_NETLINK` socket this crate's three readers share: open and bind, send one message,
//! read a dump. Linux-only: there is no netlink on any other platform.
//!
//! What differs between the readers is only data: the netlink protocol, the socket type, the
//! address it binds to, and what to make of each message. `sock_diag` and conntrack are one-shot
//! dumps over this socket's [`read_dump`](NetlinkSocket::read_dump); the proc connector is a live
//! subscription that reads datagrams with [`recv`](NetlinkSocket::recv) and walks them itself.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};

use crate::{
    frame::netlink_messages,
    wire::{NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, NlMsgHeader},
};

/// Errors from driving the real netlink socket.
#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    // Not `#[from]`: that would also make the I/O error this error's `source()`, and the message
    // already prints it, so a reporter walking the chain would print it twice. The `From` impl
    // below is written by hand for that reason.
    #[error("netlink I/O error: {0}")]
    /// A socket or I/O operation failed.
    Io(io::Error),
    /// The kernel replied with `NLMSG_ERROR` and this non-zero errno, positive
    /// (`libc::EPERM`, not the `-EPERM` on the wire).
    #[error("kernel returned NLMSG_ERROR (errno {0})")]
    Kernel(i32),
}

impl From<io::Error> for NetlinkError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The errno an `NLMSG_ERROR` payload (`struct nlmsgerr`) carries, as a positive
/// value comparable with `libc::EPERM` and friends. `0` means an ACK.
///
/// The kernel writes the errno negated (`-EPERM`), so it is flipped here once
/// for every socket in this crate. A payload too short to hold the field is
/// reported as `EBADMSG`.
pub(crate) fn nlmsg_error_errno(payload: &[u8]) -> i32 {
    match payload {
        [a, b, c, d, ..] => i32::from_ne_bytes([*a, *b, *c, *d]).wrapping_neg(),
        _ => libc::EBADMSG,
    }
}

/// Where a socket binds. Both fields `0` is "let the kernel pick the address, no multicast
/// group": right for a single-shot query. A long-lived subscriber names itself (its pid, by the
/// kernel's own samples) and the group it listens to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bind {
    pub(crate) pid: u32,
    pub(crate) groups: u32,
}

impl Bind {
    /// A single-shot query socket: the kernel assigns the address, and no group is joined.
    pub(crate) const QUERY: Self = Self { pid: 0, groups: 0 };
}

/// An open, bound `AF_NETLINK` socket. Dropping it closes the descriptor.
pub(crate) struct NetlinkSocket {
    fd: OwnedFd,
}

/// What reading one received buffer of a dump decided.
#[derive(Debug, PartialEq, Eq)]
enum DumpStep {
    /// The dump goes on: read the next datagram.
    Continue,
    /// `NLMSG_DONE`, or an ACK: the dump is over.
    Finished,
}

impl NetlinkSocket {
    /// Opens a socket of `protocol` (`NETLINK_SOCK_DIAG`, ...) and `sock_type`, and binds it.
    ///
    /// # Errors
    ///
    /// [`NetlinkError::Io`] if the socket cannot be created or bound.
    pub(crate) fn open(
        protocol: libc::c_int,
        sock_type: libc::c_int,
        bind: Bind,
    ) -> Result<Self, NetlinkError> {
        // SAFETY: `socket(2)` with a fixed, valid family/type/protocol triple. The
        // result is checked for the -1 error sentinel before being trusted as a real
        // fd; on success it is immediately handed to `OwnedFd`, which becomes its
        // sole owner (closed on drop) so no descriptor can leak past this function.
        let raw = unsafe { libc::socket(libc::AF_NETLINK, sock_type, protocol) };
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
        addr.nl_pid = bind.pid;
        addr.nl_groups = bind.groups;

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
        Ok(Self { fd })
    }

    /// Bounds how long [`recv`](Self::recv) blocks when nothing arrives.
    ///
    /// # Errors
    ///
    /// [`NetlinkError::Io`] if the option cannot be set.
    pub(crate) fn set_recv_timeout(&self, timeout: Duration) -> Result<(), NetlinkError> {
        // `as _` rather than naming `libc::time_t`/`libc::suseconds_t` directly: both
        // aliases are deprecated on musl (Alpine) -- 32-bit today, becoming 64-bit in a
        // future musl/libc-crate release -- so inferring the field type from the struct
        // literal instead keeps this correct on both without an `#[allow(deprecated)]`.
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as _,
            tv_usec: timeout.subsec_micros() as _,
        };
        // SAFETY: `setsockopt(2)` on the fd this function borrows, with a
        // `libc::timeval` whose size exactly matches the `optlen` argument passed
        // alongside it.
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
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

    /// Sends one netlink message: a header built from the arguments, then `body`.
    ///
    /// # Errors
    ///
    /// [`NetlinkError::Io`] if `send(2)` fails.
    pub(crate) fn send_message(
        &self,
        msg_type: u16,
        flags: u16,
        seq: u32,
        pid: u32,
        body: &[u8],
    ) -> Result<(), NetlinkError> {
        let header = NlMsgHeader {
            len: (NLMSG_HDR_LEN + body.len()) as u32,
            msg_type,
            flags,
            seq,
            pid,
        };
        let mut buf = Vec::with_capacity(NLMSG_HDR_LEN + body.len());
        buf.extend_from_slice(&header.to_bytes());
        buf.extend_from_slice(body);

        // SAFETY: `send(2)` on the fd this socket owns, with a pointer/length pair taken from a
        // `Vec` we just built — the length passed matches the buffer exactly.
        let sent = unsafe { libc::send(self.fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
        if sent < 0 {
            return Err(NetlinkError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// One `recv(2)` into `buf`: how many bytes arrived. The error is the raw one, so a caller
    /// can tell a receive timeout (`WouldBlock`/`TimedOut`) from a failure.
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `recv(2)` into a buffer the caller owns, with its exact length as the size
        // bound — the kernel never writes past it. The returned count is validated (>= 0)
        // before it is used as a length.
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// Reads a dump until its `NLMSG_DONE` (or an ACK) and collects what `on_message` makes of
    /// each message: `(type, payload)` in, `Some(record)` to keep one, `None` to skip it. The
    /// callback sees only data messages; `NLMSG_DONE` and `NLMSG_ERROR` are handled here.
    ///
    /// # Errors
    ///
    /// [`NetlinkError::Io`] if a `recv(2)` fails; [`NetlinkError::Kernel`] if the kernel replies
    /// with a non-zero `NLMSG_ERROR`.
    pub(crate) fn read_dump<T>(
        &self,
        mut on_message: impl FnMut(u16, &[u8]) -> Option<T>,
    ) -> Result<Vec<T>, NetlinkError> {
        let mut entries = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let received_len = self.recv(&mut buf)?;
            let step = read_dump_buffer(&buf[..received_len], &mut on_message, &mut entries)?;
            if step == DumpStep::Finished {
                return Ok(entries);
            }
        }
    }
}

/// Reads the messages of one received buffer of a dump into `entries`.
fn read_dump_buffer<T>(
    received: &[u8],
    on_message: &mut impl FnMut(u16, &[u8]) -> Option<T>,
    entries: &mut Vec<T>,
) -> Result<DumpStep, NetlinkError> {
    for message in netlink_messages(received) {
        // A frame whose header cannot be trusted ends this buffer. The dump itself goes on: the
        // next datagram starts at a message boundary of its own.
        let Ok((msg_type, payload)) = message else {
            break;
        };
        match msg_type {
            NLMSG_DONE => return Ok(DumpStep::Finished),
            NLMSG_ERROR => {
                let errno = nlmsg_error_errno(payload);
                if errno != 0 {
                    return Err(NetlinkError::Kernel(errno));
                }
                return Ok(DumpStep::Finished); // errno == 0 is an ACK, not a dump record
            }
            _ => entries.extend(on_message(msg_type, payload)),
        }
    }
    Ok(DumpStep::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let header = NlMsgHeader {
            len: (NLMSG_HDR_LEN + payload.len()) as u32,
            msg_type,
            flags: 0,
            seq: 1,
            pid: 0,
        };
        let mut out = header.to_bytes().to_vec();
        out.extend_from_slice(payload);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    /// Keeps the first payload byte of every message of type 20; skips the rest.
    fn read(buf: &[u8]) -> (Result<DumpStep, NetlinkError>, Vec<u8>) {
        let mut entries = Vec::new();
        let step = read_dump_buffer(
            buf,
            &mut |msg_type, payload| (msg_type == 20).then(|| payload[0]),
            &mut entries,
        );
        (step, entries)
    }

    #[test]
    fn nlmsg_error_errno_flips_the_kernels_negative_errno() {
        let mut payload = (-libc::EPERM).to_ne_bytes().to_vec();
        payload.extend_from_slice(&[0u8; NLMSG_HDR_LEN]); // the echoed request header
        assert_eq!(nlmsg_error_errno(&payload), libc::EPERM);
    }

    #[test]
    fn nlmsg_error_errno_reads_zero_as_an_ack() {
        assert_eq!(nlmsg_error_errno(&0i32.to_ne_bytes()), 0);
    }

    #[test]
    fn nlmsg_error_errno_reports_a_truncated_payload_as_ebadmsg() {
        assert_eq!(nlmsg_error_errno(&[0xff, 0xff]), libc::EBADMSG);
        assert_eq!(nlmsg_error_errno(&[]), libc::EBADMSG);
    }

    #[test]
    fn error_messages_and_sources_are_what_callers_have_always_seen() {
        use std::error::Error as _;

        let kernel = NetlinkError::Kernel(libc::EPERM);
        assert_eq!(kernel.to_string(), "kernel returned NLMSG_ERROR (errno 1)");
        assert!(kernel.source().is_none());

        let io = NetlinkError::from(io::Error::other("boom"));
        assert_eq!(io.to_string(), "netlink I/O error: boom");
        assert!(
            io.source().is_none(),
            "the message already carries the cause"
        );
    }

    #[test]
    fn a_dump_buffer_collects_records_and_asks_for_more() {
        let mut buf = message(20, &[1, 0, 0, 0]);
        buf.extend(message(20, &[2, 0, 0, 0]));
        let (step, entries) = read(&buf);
        assert_eq!(step.unwrap(), DumpStep::Continue);
        assert_eq!(entries, [1, 2]);
    }

    #[test]
    fn done_finishes_the_dump_and_nothing_after_it_is_read() {
        let mut buf = message(20, &[1, 0, 0, 0]);
        buf.extend(message(NLMSG_DONE, &[0, 0, 0, 0]));
        buf.extend(message(20, &[2, 0, 0, 0]));
        let (step, entries) = read(&buf);
        assert_eq!(step.unwrap(), DumpStep::Finished);
        assert_eq!(entries, [1]);
    }

    #[test]
    fn an_error_message_with_a_non_zero_errno_fails_the_dump() {
        let mut payload = (-libc::EPERM).to_ne_bytes().to_vec();
        payload.extend_from_slice(&[0u8; NLMSG_HDR_LEN]);
        let (step, _) = read(&message(NLMSG_ERROR, &payload));
        assert!(matches!(step, Err(NetlinkError::Kernel(e)) if e == libc::EPERM));
    }

    #[test]
    fn an_error_message_with_errno_zero_is_an_ack_and_finishes_the_dump() {
        let mut payload = 0i32.to_ne_bytes().to_vec();
        payload.extend_from_slice(&[0u8; NLMSG_HDR_LEN]);
        let (step, entries) = read(&message(NLMSG_ERROR, &payload));
        assert_eq!(step.unwrap(), DumpStep::Finished);
        assert!(entries.is_empty());
    }

    #[test]
    fn a_message_the_callback_skips_does_not_abort_the_dump() {
        let mut buf = message(99, &[7, 0, 0, 0]);
        buf.extend(message(20, &[1, 0, 0, 0]));
        let (step, entries) = read(&buf);
        assert_eq!(step.unwrap(), DumpStep::Continue);
        assert_eq!(entries, [1]);
    }

    #[test]
    fn a_malformed_frame_ends_its_buffer_but_not_the_dump() {
        let mut buf = message(20, &[1, 0, 0, 0]);
        let mut bad = message(20, &[2, 0, 0, 0]);
        bad[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        buf.extend(bad);
        buf.extend(message(NLMSG_DONE, &[0, 0, 0, 0]));
        let (step, entries) = read(&buf);
        assert_eq!(
            step.unwrap(),
            DumpStep::Continue,
            "the DONE after it is not trusted"
        );
        assert_eq!(entries, [1]);
    }

    #[test]
    fn an_empty_buffer_asks_for_more() {
        let (step, entries) = read(&[]);
        assert_eq!(step.unwrap(), DumpStep::Continue);
        assert!(entries.is_empty());
    }
}
