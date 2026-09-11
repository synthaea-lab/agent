//! Drives the real `AF_NETLINK`/`NETLINK_SOCK_DIAG` socket. Linux-only: there is
//! no netlink on any other platform.
//!
//! Two dumps per call (IPv4 then IPv6) rather than one: `inet_diag_req_v2` takes a
//! single `sdiag_family`, so querying both address families needs two separate
//! requests — confirmed against the kernel header, not assumed.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::wire::{
    AF_INET, AF_INET6, DIAG_MSG_LEN, DiagMsg, DiagRequestV2, IPPROTO_TCP, NLM_F_DUMP,
    NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, NlMsgHeader, SOCK_DIAG_BY_FAMILY,
};

/// Not in every version of the `libc` crate's Linux constant set — defined
/// locally rather than risk it being absent. Value from `<linux/netlink.h>`.
const NETLINK_SOCK_DIAG: libc::c_int = 4;

/// Errors from driving the real netlink socket.
#[derive(Debug)]
pub enum NetlinkError {
    Io(io::Error),
    /// The kernel replied with `NLMSG_ERROR` and this non-zero errno.
    Kernel(i32),
}

impl std::fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "netlink I/O error: {e}"),
            Self::Kernel(errno) => write!(f, "kernel returned NLMSG_ERROR (errno {errno})"),
        }
    }
}

impl std::error::Error for NetlinkError {}

impl From<io::Error> for NetlinkError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Queries listening and established TCP sockets (IPv4 and IPv6) via
/// `NETLINK_SOCK_DIAG`.
///
/// # Errors
///
/// [`NetlinkError::Io`] if the socket can't be created or a read/write fails;
/// [`NetlinkError::Kernel`] if the kernel replies with a non-zero `NLMSG_ERROR`.
pub fn query_tcp_sockets(states: u32) -> Result<Vec<DiagMsg>, NetlinkError> {
    let mut all = Vec::new();
    for family in [AF_INET, AF_INET6] {
        all.extend(dump_one_family(family, states)?);
    }
    Ok(all)
}

fn dump_one_family(family: u8, states: u32) -> Result<Vec<DiagMsg>, NetlinkError> {
    let fd = open_socket()?;
    send_request(&fd, family, states)?;
    read_dump(&fd)
}

fn open_socket() -> Result<OwnedFd, NetlinkError> {
    // SAFETY: `socket(2)` with a fixed, valid family/type/protocol triple. The
    // result is checked for the -1 error sentinel before being trusted as a real
    // fd; on success it is immediately handed to `OwnedFd`, which becomes its
    // sole owner (closed on drop) so no descriptor can leak past this function.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_SOCK_DIAG) };
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
    // nl_pid = 0: let the kernel assign one. This is a single-shot query socket,
    // not a long-lived subscriber that needs a stable, predictable address.

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

fn send_request(fd: &OwnedFd, family: u8, states: u32) -> Result<(), NetlinkError> {
    let req = DiagRequestV2 {
        family,
        protocol: IPPROTO_TCP,
        states,
    }
    .to_bytes();
    let header = NlMsgHeader {
        len: (NLMSG_HDR_LEN + req.len()) as u32,
        msg_type: SOCK_DIAG_BY_FAMILY,
        flags: NLM_F_REQUEST | NLM_F_DUMP,
        seq: 1,
        pid: 0,
    };
    let mut buf = Vec::with_capacity(NLMSG_HDR_LEN + req.len());
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(&req);

    // SAFETY: `send(2)` on a fd this function borrows (still owned by the caller),
    // with a pointer/length pair taken from a `Vec` we just built — the length
    // passed matches the buffer exactly.
    let sent = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
    if sent < 0 {
        return Err(NetlinkError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn read_dump(fd: &OwnedFd) -> Result<Vec<DiagMsg>, NetlinkError> {
    let mut entries = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];

    'recv: loop {
        // SAFETY: `recv(2)` into a buffer this function owns, with its exact
        // allocated length as the size bound — the kernel never writes past it.
        // The returned count is validated (>= 0) before any byte of `buf` is read.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(NetlinkError::Io(io::Error::last_os_error()));
        }
        let received_len = usize::try_from(n).unwrap_or(0);
        let received = &buf[..received_len];

        let mut offset = 0usize;
        while let Some(header) = NlMsgHeader::parse(&received[offset..]) {
            let msg_len = header.len as usize;
            if msg_len < NLMSG_HDR_LEN || offset + msg_len > received.len() {
                break; // truncated/malformed frame — stop trusting this buffer
            }
            let payload = &received[offset + NLMSG_HDR_LEN..offset + msg_len];
            match header.msg_type {
                NLMSG_DONE => break 'recv,
                NLMSG_ERROR => {
                    let errno = payload
                        .get(0..4)
                        .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                        .unwrap_or(-1);
                    if errno != 0 {
                        return Err(NetlinkError::Kernel(errno));
                    }
                    break 'recv; // errno == 0 is an ACK, not a dump record
                }
                SOCK_DIAG_BY_FAMILY => {
                    if payload.len() >= DIAG_MSG_LEN
                        && let Some(msg) = DiagMsg::parse(payload)
                    {
                        entries.push(msg);
                    }
                }
                _ => {} // an unexpected message type — ignore, don't abort the dump
            }
            // NLMSG_ALIGN: messages are padded to 4-byte boundaries.
            offset += (msg_len + 3) & !3;
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{TCP_ESTABLISHED, TCP_LISTEN};

    /// Not a mock — the real socket, exercised against whatever this dev/CI
    /// machine's own TCP stack happens to have open right now. Doesn't assert a
    /// specific socket is present (nondeterministic); proves the dump completes,
    /// terminates on `NLMSG_DONE`, and every returned record parses to a
    /// consistent, well-formed [`DiagMsg`].
    #[test]
    fn query_tcp_sockets_against_the_real_kernel() {
        let states = (1u32 << TCP_ESTABLISHED) | (1u32 << TCP_LISTEN);
        let result = query_tcp_sockets(states);
        let entries = result.expect("sock_diag query must succeed unprivileged");
        for entry in &entries {
            assert!(
                entry.state == TCP_LISTEN || entry.state == TCP_ESTABLISHED,
                "kernel returned a state outside the requested mask: {}",
                entry.state
            );
        }
    }
}
