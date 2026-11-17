//! Drives the real `AF_NETLINK`/`NETLINK_SOCK_DIAG` socket. Linux-only: there is
//! no netlink on any other platform.
//!
//! Two dumps per call (IPv4 then IPv6) rather than one: `inet_diag_req_v2` takes a
//! single `sdiag_family`, so querying both address families needs two separate
//! requests — confirmed against the kernel header, not assumed.

use crate::{
    nl_socket::{Bind, NetlinkError, NetlinkSocket},
    wire::{
        AF_INET, AF_INET6, DIAG_MSG_LEN, DiagMsg, DiagRequestV2, IPPROTO_TCP, NLM_F_DUMP,
        NLM_F_REQUEST, SOCK_DIAG_BY_FAMILY,
    },
};

/// Not in every version of the `libc` crate's Linux constant set — defined
/// locally rather than risk it being absent. Value from `<linux/netlink.h>`.
const NETLINK_SOCK_DIAG: libc::c_int = 4;

/// Queries listening and established TCP sockets (IPv4 and IPv6) via
/// `NETLINK_SOCK_DIAG`.
///
/// # Errors
///
/// [`NetlinkError::Io`] if the socket can't be created or a read/write fails;
/// [`NetlinkError::Kernel`] if the kernel replies with a non-zero `NLMSG_ERROR`.
pub fn query_tcp_sockets(states: u32) -> Result<Vec<DiagMsg>, NetlinkError> {
    query_sockets(IPPROTO_TCP, states)
}

/// Same dump for any `IPPROTO_*` `sock_diag` serves (TCP and UDP here).
///
/// # Errors
///
/// See [`query_tcp_sockets`].
pub fn query_sockets(protocol: u8, states: u32) -> Result<Vec<DiagMsg>, NetlinkError> {
    let mut all = Vec::new();
    for family in [AF_INET, AF_INET6] {
        all.extend(dump_one_family(family, protocol, states)?);
    }
    Ok(all)
}

fn dump_one_family(family: u8, protocol: u8, states: u32) -> Result<Vec<DiagMsg>, NetlinkError> {
    // nl_pid = 0: let the kernel assign one. This is a single-shot query socket,
    // not a long-lived subscriber that needs a stable, predictable address.
    let socket = NetlinkSocket::open(NETLINK_SOCK_DIAG, libc::SOCK_RAW, Bind::QUERY)?;
    let request = DiagRequestV2 {
        family,
        protocol,
        states,
    }
    .to_bytes();
    socket.send_message(
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        1,
        0,
        &request,
    )?;
    socket.read_dump(|msg_type, payload| {
        if msg_type == SOCK_DIAG_BY_FAMILY && payload.len() >= DIAG_MSG_LEN {
            DiagMsg::parse(payload)
        } else {
            None // an unexpected message type — ignore, don't abort the dump
        }
    })
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
