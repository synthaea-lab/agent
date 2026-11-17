//! Drives the real `AF_NETLINK`/`NETLINK_NETFILTER` socket to dump the
//! kernel's conntrack table (`ctnetlink`, subsystem `NFNL_SUBSYS_CTNETLINK`).
//! Linux-only. One-shot dump, same shape as [`crate::socket::query_tcp_sockets`]
//! — a caller decides the polling cadence, this module just takes one
//! snapshot per call.
//!
//! Unprivileged reachability: **not yet characterized** — every capture taken
//! while building this module ran as root (the development sandbox's
//! default). Unlike `sock_diag` (confirmed unprivileged) or proc
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

pub use crate::nl_socket::NetlinkError;
use crate::{
    conntrack_attrs::ConntrackFlow,
    nl_socket::{Bind, NetlinkSocket},
    wire::{NLM_F_DUMP, NLM_F_REQUEST},
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
    // nl_pid = 0: let the kernel assign one — a single-shot dump socket, not a
    // long-lived subscriber (contrast `proc_socket::open`).
    let socket = NetlinkSocket::open(NETLINK_NETFILTER, libc::SOCK_RAW, Bind::QUERY)?;
    // nfgen_family, version = NFNETLINK_V0, res_id = 0 (unused for CT_GET).
    let nfgenmsg = [family, 0, 0, 0];
    socket.send_message(
        (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
        NLM_F_REQUEST | NLM_F_DUMP,
        1,
        0,
        &nfgenmsg,
    )?;
    let ct_new_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
    socket.read_dump(|msg_type, payload| {
        if msg_type == ct_new_type && payload.len() >= NFGENMSG_LEN {
            ConntrackFlow::parse(&payload[NFGENMSG_LEN..])
        } else {
            None // an unexpected message type — ignore, don't abort the dump
        }
    })
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
