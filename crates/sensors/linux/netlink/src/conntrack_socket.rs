//! Drives the real `AF_NETLINK`/`NETLINK_NETFILTER` socket to dump the
//! kernel's conntrack table (`ctnetlink`, subsystem `NFNL_SUBSYS_CTNETLINK`).
//! Linux-only. One-shot dump, same shape as [`crate::socket::query_tcp_sockets`]
//! — a caller decides the polling cadence, this module just takes one
//! snapshot per call.
//!
//! Unprivileged reachability: **not yet characterized** — every capture taken
//! while building this module ran as root (this dev machine's `edr-lab`
//! sandbox default). Unlike `sock_diag` (confirmed unprivileged) or proc
//! connector (confirmed root-only, `EPERM` from the kernel), whether an
//! unprivileged caller can read the conntrack table depends on the running
//! kernel's `net.netfilter.nf_conntrack_*` sysctls and namespace, which
//! varies by distro — left for the caller to discover via the `Err` this
//! module returns rather than asserted here.
//!
//! **Requires `net.netfilter.nf_conntrack_acct=1`** for [`ConntrackFlow::counters_orig`]/
//! [`counters_reply`](crate::conntrack_attrs::ConntrackFlow::counters_reply) to
//! ever be `Some` — confirmed on this dev machine: disabled by default, no
//! `CTA_COUNTERS_*` attribute appears in the dump at all until it is turned
//! on. This module does not toggle it; a beacon-detection caller needing byte/
//! packet accounting must ensure it is enabled on the target host.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub use crate::socket::NetlinkError;
use crate::{
    conntrack_attrs::ConntrackFlow,
    wire::{NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, NlMsgHeader},
};

/// Not in every version of the `libc` crate's Linux constant set — see
/// `socket.rs`'s identical note for `NETLINK_SOCK_DIAG`. Value from
/// `<linux/netlink.h>`.
const NETLINK_NETFILTER: libc::c_int = 12;

/// `NFNL_SUBSYS_CTNETLINK` from `<linux/netfilter/nfnetlink.h>`.
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
/// `IPCTNL_MSG_CT_GET` from `<linux/netfilter/nfnetlink_conntrack.h>` — the
/// request type this module sends.
const IPCTNL_MSG_CT_GET: u16 = 1;
/// `IPCTNL_MSG_CT_NEW` — despite the name, this is also the message type the
/// kernel uses for each existing entry returned by a `CT_GET` dump (a
/// `ctnetlink` naming quirk, confirmed against a real dump on this dev
/// machine: every entry in a `CT_GET` reply carries this type, not
/// `IPCTNL_MSG_CT_GET`).
const IPCTNL_MSG_CT_NEW: u16 = 0;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// `struct nfgenmsg` — 4 bytes: `nfgen_family` (u8), `version` (u8, always
/// `NFNETLINK_V0` = 0), `res_id` (u16, unused for a `CT_GET` dump — left 0).
const NFGENMSG_LEN: usize = 4;

/// Dumps the kernel's conntrack table for both IPv4 and IPv6 (two separate
/// requests — `nfgenmsg.nfgen_family` takes one family per dump, the same
/// constraint `sock_diag`'s `inet_diag_req_v2` has, see
/// `socket::query_tcp_sockets`'s doc).
///
/// # Errors
///
/// See [`NetlinkError`] — a request fails as a whole (rather than returning a
/// partial list) if the kernel can't be reached, or replies with a non-zero
/// `NLMSG_ERROR` (e.g. `ENOPROTOOPT` if `nf_conntrack_netlink` isn't loaded).
pub fn dump() -> Result<Vec<ConntrackFlow>, NetlinkError> {
    let mut all = Vec::new();
    for family in [AF_INET, AF_INET6] {
        all.extend(dump_one_family(family)?);
    }
    Ok(all)
}

fn dump_one_family(family: u8) -> Result<Vec<ConntrackFlow>, NetlinkError> {
    let fd = open_socket()?;
    send_request(&fd, family)?;
    read_dump(&fd)
}

fn open_socket() -> Result<OwnedFd, NetlinkError> {
    // SAFETY: `socket(2)` with a fixed, valid family/type/protocol triple. The
    // result is checked for the -1 error sentinel before being trusted as a real
    // fd; on success it is immediately handed to `OwnedFd`, which becomes its
    // sole owner (closed on drop) so no descriptor can leak past this function.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
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
    // nl_pid = 0: let the kernel assign one — a single-shot dump socket, not a
    // long-lived subscriber (contrast `proc_socket::open_socket`).

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

fn send_request(fd: &OwnedFd, family: u8) -> Result<(), NetlinkError> {
    // nfgen_family, version = NFNETLINK_V0, res_id = 0 (unused for CT_GET).
    let nfgenmsg = [family, 0, 0, 0];
    let header = NlMsgHeader {
        len: (NLMSG_HDR_LEN + NFGENMSG_LEN) as u32,
        msg_type: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
        flags: NLM_F_REQUEST | NLM_F_DUMP,
        seq: 1,
        pid: 0,
    };
    let mut buf = Vec::with_capacity(NLMSG_HDR_LEN + NFGENMSG_LEN);
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(&nfgenmsg);

    // SAFETY: `send(2)` on a fd this function borrows (still owned by the
    // caller), with a pointer/length pair taken from a `Vec` we just built —
    // the length passed matches the buffer exactly.
    let sent = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
    if sent < 0 {
        return Err(NetlinkError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn read_dump(fd: &OwnedFd) -> Result<Vec<ConntrackFlow>, NetlinkError> {
    let mut entries = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let ct_new_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;

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
                    // Byte-by-byte, not `try_into().unwrap()` — no explicit
                    // panic point to document, matching `wire::DiagMsg::parse`.
                    let errno = match payload {
                        [a, b, c, d, ..] => i32::from_ne_bytes([*a, *b, *c, *d]),
                        _ => -1,
                    };
                    if errno != 0 {
                        return Err(NetlinkError::Kernel(errno));
                    }
                    break 'recv; // errno == 0 is an ACK, not a dump record
                }
                t if t == ct_new_type => {
                    if payload.len() >= NFGENMSG_LEN
                        && let Some(flow) = ConntrackFlow::parse(&payload[NFGENMSG_LEN..])
                    {
                        entries.push(flow);
                    }
                }
                _ => {} // an unexpected message type — ignore, don't abort the dump
            }
            offset += (msg_len + 3) & !3; // NLMSG_ALIGN: 4-byte padding
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration-style: exercises the real socket against this dev
    /// machine's kernel, skips itself when the kernel refuses the request
    /// (module not loaded, no `CAP_NET_ADMIN`, ...) rather than requiring a
    /// specific dev/CI privilege level or kernel config to build and test —
    /// same discipline as `sensor-linux-journal`'s `journalctl`-presence skip.
    #[test]
    fn dump_against_the_real_kernel_produces_well_formed_flows() {
        let entries = match dump() {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("skipping: conntrack dump failed on this machine: {e}");
                return;
            }
        };
        // Nondeterministic which flows exist right now (and this dev sandbox
        // starts with an empty table until real traffic passes through a
        // netfilter ruleset — see the module doc) — the property that must
        // hold regardless: every returned protocol/port combination is
        // internally consistent (a tuple with ports also has a transport
        // protocol number, never a bare zero from a parsing bug).
        for flow in &entries {
            if flow.orig.src_port.is_some() || flow.orig.dst_port.is_some() {
                assert_ne!(flow.orig.protocol, 0, "ports present but protocol 0");
            }
        }
    }
}
