//! `NETLINK_AUDIT` socket for receiving auditd events.
//!
//! Requires `CAP_AUDIT_READ` (or root). Read-only - no `AUDIT_SET` commands.

use std::os::unix::io::{AsRawFd, RawFd};

const AF_NETLINK: i32 = 16;
const NETLINK_AUDIT: i32 = 9;
const AUDIT_NLGRP_READLOG: u32 = 1; // Multicast group for receiving audit logs

/// Receive buffer requested for the socket. The default (`net.core.rmem_default`,
/// 208 KiB on Debian 12) holds fewer than ten execs with one long argument (~25 KB of
/// records each), so a burst of them overran it and the multicast group dropped most
/// of the burst (#237). 8 MiB holds a few hundred.
const SOCKET_RECEIVE_BYTES: usize = 8 * 1024 * 1024;

/// Size of the buffer a caller passes to [`AuditSocket::recv`]. The kernel does not cap
/// a record at libaudit's `AUDIT_MESSAGE_TEXT_MAX` (8,560): a `PATH` record whose name
/// is hex-encoded is twice the name's length. A record longer than this still arrives,
/// cut, and `recv` reports it.
pub(crate) const RECV_BUFFER_LEN: usize = 64 * 1024;

/// One datagram read by [`AuditSocket::recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Bytes written into the caller's buffer.
    pub len: usize,
    /// The datagram was longer than the buffer: only its first `len` bytes arrived.
    pub truncated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("netlink socket error: {0}")]
    Netlink(i32), // errno
    #[error("failed to parse audit message: {0}")]
    Parse(String),
}

pub struct AuditSocket {
    fd: RawFd,
}

impl AuditSocket {
    /// Opens `NETLINK_AUDIT` socket and subscribes to the READLOG multicast group.
    /// Requires `CAP_AUDIT_READ` (or root).
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Netlink` if socket creation, bind, or filter fails.
    pub fn open() -> Result<Self, AuditError> {
        // SAFETY: socket(2) with valid AF_NETLINK family and NETLINK_AUDIT protocol.
        // Result checked for -1 error sentinel before being trusted.
        let fd = unsafe {
            libc::socket(
                AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_AUDIT,
            )
        };

        if fd < 0 {
            // SAFETY: __errno_location returns a valid pointer to thread-local errno
            let errno = unsafe { *libc::__errno_location() };
            return Err(AuditError::Netlink(errno));
        }

        // SAFETY: addr is zero-initialized libc::sockaddr_nl, a POD C struct
        // with no invalid all-zero bit pattern.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0; // Let kernel assign
        addr.nl_groups = 1 << (AUDIT_NLGRP_READLOG - 1); // Subscribe to audit log multicast group

        // SAFETY: bind(2) on owned fd, passing pointer to local sockaddr_nl
        // whose size matches addrlen argument.
        let ret = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            // SAFETY: __errno_location returns a valid pointer to thread-local errno
            let errno = unsafe { *libc::__errno_location() };
            // SAFETY: fd is owned by this function and close is called exactly once
            unsafe {
                libc::close(fd);
            }
            return Err(AuditError::Netlink(errno));
        }

        match grow_receive_buffer(fd, SOCKET_RECEIVE_BYTES) {
            // The kernel reports twice what it accepted, so a full grant reads `2 * requested`.
            Some(granted) if granted >= SOCKET_RECEIVE_BYTES.saturating_mul(2) => tracing::info!(
                requested = SOCKET_RECEIVE_BYTES,
                granted,
                "sensor-linux-audit: socket receive buffer"
            ),
            // Without CAP_NET_ADMIN, SO_RCVBUF is capped at `net.core.rmem_max`, and the
            // burst loss of #237 comes back on a host that keeps that limit low.
            Some(granted) => tracing::warn!(
                requested = SOCKET_RECEIVE_BYTES,
                granted,
                "sensor-linux-audit: socket receive buffer capped by net.core.rmem_max (no \
                 CAP_NET_ADMIN for SO_RCVBUFFORCE); bursts of long execs may be dropped"
            ),
            // Not fatal: the socket works at the default size, it only drops more under a burst.
            None => tracing::warn!(
                requested = SOCKET_RECEIVE_BYTES,
                "sensor-linux-audit: could not size the socket receive buffer"
            ),
        }

        Ok(Self { fd })
    }

    /// Non-blocking read of one audit message.
    ///
    /// Returns `EAGAIN`/`EWOULDBLOCK` errno when no message is available.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Netlink` if recv fails.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Received, AuditError> {
        // SAFETY: recv(2) on owned fd, writing into caller-provided buffer.
        // The kernel writes at most buf.len() bytes; with MSG_TRUNC it returns the
        // datagram's real length, which may exceed buf.len().
        // MSG_DONTWAIT prevents blocking on spurious epoll wakeups (issue #247).
        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };

        if n < 0 {
            // SAFETY: __errno_location returns a valid pointer to thread-local errno
            let errno = unsafe { *libc::__errno_location() };
            return Err(AuditError::Netlink(errno));
        }

        // Non-negative after the check above.
        let real = n.unsigned_abs();
        Ok(Received {
            len: real.min(buf.len()),
            truncated: real > buf.len(),
        })
    }
}

/// Raises `fd`'s receive buffer to `bytes`: `SO_RCVBUFFORCE` first, which a process with
/// `CAP_NET_ADMIN` may use past `net.core.rmem_max` (the packaged unit grants it as an
/// ambient capability; root has it), else `SO_RCVBUF`, which the kernel caps there. Returns
/// the size the kernel reports afterwards (it doubles the request for bookkeeping), or
/// `None` if neither call took.
fn grow_receive_buffer(fd: RawFd, bytes: usize) -> Option<usize> {
    let requested = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX);
    let set = |option: libc::c_int| {
        // SAFETY: setsockopt(2) on a caller-owned fd, with a pointer to a local c_int
        // and its exact size.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                std::ptr::addr_of!(requested).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };
    if set(libc::SO_RCVBUFFORCE) != 0 && set(libc::SO_RCVBUF) != 0 {
        return None;
    }
    let mut granted: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt(2) on a caller-owned fd, writing at most `len` bytes into a
    // local c_int whose size `len` holds.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of_mut!(granted).cast(),
            &raw mut len,
        )
    };
    (ret == 0).then(|| usize::try_from(granted).unwrap_or(0))
}

impl AsRawFd for AuditSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(test)]
impl AuditSocket {
    /// Wraps an already-open fd (e.g. one end of a `socketpair`) instead of a real
    /// `NETLINK_AUDIT` socket, so `AvcReader`'s poll/drain loop can be exercised in
    /// a test without `CAP_AUDIT_READ` (#780 review). `recv`/`poll` work on any
    /// socket fd, netlink or not — only `open`'s bind is netlink-specific.
    pub(crate) fn from_raw_fd_for_test(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl Drop for AuditSocket {
    fn drop(&mut self) {
        // SAFETY: fd owned by this struct, closed exactly once on drop.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connected pair of datagram sockets, closed when the returned sockets drop.
    fn datagram_pair() -> (AuditSocket, AuditSocket) {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: socketpair(2) writes two fds into a local two-element array.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair");
        (
            AuditSocket::from_raw_fd_for_test(fds[0]),
            AuditSocket::from_raw_fd_for_test(fds[1]),
        )
    }

    fn send(socket: &AuditSocket, bytes: &[u8]) {
        // SAFETY: send(2) on a test-owned fd from a live slice and its length.
        let n = unsafe { libc::send(socket.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) };
        assert_eq!(n, bytes.len() as isize, "send");
    }

    #[test]
    fn a_datagram_longer_than_the_buffer_is_reported_truncated() {
        // #237: a record past the receive buffer used to be parsed as if it were whole.
        let (writer, mut reader) = datagram_pair();
        send(&writer, &[b'a'; 100]);
        let mut buf = [0u8; 10];
        let got = reader.recv(&mut buf).expect("recv");
        assert_eq!(
            got,
            Received {
                len: 10,
                truncated: true
            }
        );
        assert_eq!(buf, [b'a'; 10]);
    }

    #[test]
    fn a_datagram_that_fits_is_not_truncated() {
        let (writer, mut reader) = datagram_pair();
        send(&writer, b"audit(1.2:3): argc=1");
        let mut buf = [0u8; RECV_BUFFER_LEN];
        let got = reader.recv(&mut buf).expect("recv");
        assert_eq!(
            got,
            Received {
                len: 20,
                truncated: false
            }
        );
    }

    /// `net.core.rmem_max`, the cap `SO_RCVBUF` applies without `CAP_NET_ADMIN`.
    fn rmem_max() -> usize {
        std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .expect("read rmem_max")
            .trim()
            .parse()
            .expect("rmem_max is a number")
    }

    /// Whether this process may use `SO_RCVBUFFORCE`, asked of a throwaway socket so the
    /// answer does not depend on the code under test.
    fn may_force_receive_buffer() -> bool {
        let (_writer, probe) = datagram_pair();
        let size: libc::c_int = 4096;
        // SAFETY: setsockopt(2) on a socket this function owns, with a pointer to a local
        // c_int and its exact size.
        let ret = unsafe {
            libc::setsockopt(
                probe.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                std::ptr::addr_of!(size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        ret == 0
    }

    #[test]
    fn the_receive_buffer_is_sized_to_the_request_or_the_rmem_max_cap() {
        // The kernel stores twice the accepted size. With CAP_NET_ADMIN the force call
        // takes the whole request; without it SO_RCVBUF takes at most rmem_max. Leaving
        // the buffer at its default (the #237 bug) matches neither.
        let (_writer, reader) = datagram_pair();
        let accepted = if may_force_receive_buffer() {
            SOCKET_RECEIVE_BYTES
        } else {
            SOCKET_RECEIVE_BYTES.min(rmem_max())
        };
        let granted =
            grow_receive_buffer(reader.as_raw_fd(), SOCKET_RECEIVE_BYTES).expect("SO_RCVBUF takes");
        assert_eq!(granted, 2 * accepted);
    }

    #[test]
    fn socket_opens_when_privileged() {
        match AuditSocket::open() {
            Ok(_) => {
                // Socket opened successfully - test passed
            }
            Err(AuditError::Netlink(errno)) if errno == libc::EPERM || errno == libc::EACCES => {
                eprintln!("skipping: needs root/CAP_AUDIT_READ (errno: {errno})");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
