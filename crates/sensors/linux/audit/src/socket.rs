//! `NETLINK_AUDIT` socket for receiving auditd events.
//!
//! Requires `CAP_AUDIT_READ` (or root). Read-only - no `AUDIT_SET` commands.

use std::os::unix::io::{AsRawFd, RawFd};

const AF_NETLINK: i32 = 16;
const NETLINK_AUDIT: i32 = 9;
const AUDIT_NLGRP_READLOG: u32 = 1;  // Multicast group for receiving audit logs

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("netlink socket error: {0}")]
    Netlink(i32),  // errno
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
        addr.nl_pid = 0;  // Let kernel assign
        addr.nl_groups = 1 << (AUDIT_NLGRP_READLOG - 1);  // Subscribe to audit log multicast group

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
            unsafe { libc::close(fd); }
            return Err(AuditError::Netlink(errno));
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
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, AuditError> {
        // SAFETY: recv(2) on owned fd, writing into caller-provided buffer.
        // The kernel writes at most buf.len() bytes.
        // MSG_DONTWAIT prevents blocking on spurious epoll wakeups (issue #247).
        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };

        if n < 0 {
            // SAFETY: __errno_location returns a valid pointer to thread-local errno
            let errno = unsafe { *libc::__errno_location() };
            return Err(AuditError::Netlink(errno));
        }

        Ok(n as usize)
    }
}

impl AsRawFd for AuditSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for AuditSocket {
    fn drop(&mut self) {
        // SAFETY: fd owned by this struct, closed exactly once on drop.
        unsafe { libc::close(self.fd); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
