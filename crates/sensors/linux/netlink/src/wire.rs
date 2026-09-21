//! Byte-level encode/decode for the two netlink structures this crate speaks:
//! `inet_diag_req_v2` (the query we send) and `inet_diag_msg` (each socket record
//! the kernel replies with) — see `<linux/inet_diag.h>`. Pure, allocation-light,
//! and unit-tested against a real capture (this dev machine's own `sock_diag` query,
//! cross-checked against `ss`'s output for the same socket) rather than only the
//! header's documented layout.
//!
//! Field endianness follows the kernel ABI exactly, which is easy to get subtly
//! wrong: the netlink header and most `inet_diag` integer fields are host byte
//! order (`to_ne_bytes`/`from_ne_bytes` — netlink is a local-machine IPC
//! mechanism, not a wire protocol), but `idiag_sport`/`idiag_dport` are `__be16`
//! (`to_be_bytes`/`from_be_bytes`), inherited from the original `struct sockaddr_in`
//! convention. Getting this wrong doesn't fail loudly — it silently byte-swaps
//! ports — which is exactly why the tests pin real captured bytes rather than only
//! exercising the encode/decode round trip against each other.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Netlink message header size — `struct nlmsghdr` is always 16 bytes.
pub const NLMSG_HDR_LEN: usize = 16;
/// The kernel replied with an error (or, with `errno == 0`, an ACK).
pub const NLMSG_ERROR: u16 = 2;
/// End of a multi-message dump.
pub const NLMSG_DONE: u16 = 3;
/// `SOCK_DIAG_BY_FAMILY` — the one request/response type this crate uses.
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_ROOT | NLM_F_MATCH` — "dump everything matching the request", not one
/// specific socket.
pub const NLM_F_DUMP: u16 = 0x100 | 0x200;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;

/// Bit position convention shared by the request's `states` mask and the
/// response's `idiag_state` field: the TCP state's own numeric value (from
/// `<net/tcp_states.h>`: `TCP_ESTABLISHED = 1` .. `TCP_LISTEN = 10`), not
/// state-1. Verified against a real response: a LISTEN socket came back with
/// `state == 10`, matching the `1 << 10` bit this crate set in the request mask
/// that included it.
pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_LISTEN: u8 = 10;

/// Netlink message header, common to every message on the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlMsgHeader {
    pub len: u32,
    pub msg_type: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

impl NlMsgHeader {
    #[must_use]
    pub fn to_bytes(self) -> [u8; NLMSG_HDR_LEN] {
        let mut buf = [0u8; NLMSG_HDR_LEN];
        buf[0..4].copy_from_slice(&self.len.to_ne_bytes());
        buf[4..6].copy_from_slice(&self.msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        buf
    }

    /// Parses the first [`NLMSG_HDR_LEN`] bytes of `buf`. `None` if `buf` is
    /// too short — the caller is walking a stream, and this means "no more whole
    /// messages here", not a hard error.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < NLMSG_HDR_LEN {
            return None;
        }
        // Byte-by-byte, not `try_into().unwrap()` — same rule as every other
        // parser in this crate: no explicit panic point to document.
        Some(Self {
            len: u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]),
            msg_type: u16::from_ne_bytes([buf[4], buf[5]]),
            flags: u16::from_ne_bytes([buf[6], buf[7]]),
            seq: u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]),
            pid: u32::from_ne_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }
}

/// `struct inet_diag_req_v2` — the query we send. `states` is a bitmask (see
/// [`TCP_ESTABLISHED`]/[`TCP_LISTEN`]); the embedded `inet_diag_sockid` is left as
/// "match everything" (zeroed address/port/interface, cookie = all-ones per
/// `INET_DIAG_NOCOOKIE`) — this crate always dumps, never targets one socket.
#[derive(Debug, Clone, Copy)]
pub struct DiagRequestV2 {
    pub family: u8,
    pub protocol: u8,
    pub states: u32,
}

/// `4 (family/protocol/ext/pad) + 4 (states) + 48 (inet_diag_sockid)`.
pub const DIAG_REQ_LEN: usize = 56;

impl DiagRequestV2 {
    #[must_use]
    pub fn to_bytes(self) -> [u8; DIAG_REQ_LEN] {
        let mut buf = [0u8; DIAG_REQ_LEN];
        buf[0] = self.family;
        buf[1] = self.protocol;
        // buf[2] = idiag_ext = 0: no extended attributes (TCP info, congestion
        // algorithm, ...) — out of this crate's scope.
        // buf[3] = pad.
        buf[4..8].copy_from_slice(&self.states.to_ne_bytes());
        // sockid at buf[8..56]: sport/dport/src/dst/interface left zeroed
        // ("match any"); cookie (buf[48..56]) set to INET_DIAG_NOCOOKIE.
        buf[48..56].copy_from_slice(&[0xff; 8]);
        buf
    }
}

/// `struct inet_diag_msg` — one socket's state as of the snapshot. Only the base
/// struct is parsed; extended attributes past byte [`DIAG_MSG_LEN`] (unrequested,
/// since `idiag_ext = 0` above) are not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagMsg {
    pub family: u8,
    pub state: u8,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub uid: u32,
    pub inode: u32,
}

/// `4 (family/state/timer/retrans) + 48 (inet_diag_sockid) + 20 (expires/rqueue/
/// wqueue/uid/inode)`.
pub const DIAG_MSG_LEN: usize = 72;

impl DiagMsg {
    /// Parses the base fields from `payload` (the netlink message body, after the
    /// 16-byte header). `None` if `payload` is shorter than [`DIAG_MSG_LEN`], or
    /// `idiag_family` is neither `AF_INET` nor `AF_INET6` (this crate only speaks
    /// TCP/IP; a third family here would mean a request this code never sent).
    #[must_use]
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < DIAG_MSG_LEN {
            return None;
        }
        let family = payload[0];
        let state = payload[1];
        // Indexed byte-by-byte (not `try_into().unwrap()` on a slice) so there is
        // no explicit panic point to document: the length check above already
        // guarantees every index used below is in bounds.
        let local_port = u16::from_be_bytes([payload[4], payload[5]]);
        let remote_port = u16::from_be_bytes([payload[6], payload[7]]);
        let local = parse_addr(family, &payload[8..24])?;
        let remote = parse_addr(family, &payload[24..40])?;
        let uid = u32::from_ne_bytes([payload[64], payload[65], payload[66], payload[67]]);
        let inode = u32::from_ne_bytes([payload[68], payload[69], payload[70], payload[71]]);
        Some(Self {
            family,
            state,
            local,
            local_port,
            remote,
            remote_port,
            uid,
            inode,
        })
    }
}

/// `idiag_src`/`idiag_dst` are always 16 bytes: an IPv4 address occupies the
/// first 4 (network byte order), IPv6 uses all 16.
fn parse_addr(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET => {
            let octets: [u8; 4] = bytes[0..4].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        AF_INET6 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // Real capture: `inet_diag_msg` for the systemd-resolved DNS listener
    // (127.0.0.54:53, LISTEN), taken from this dev machine's own sock_diag query
    // and cross-checked against `ss -tln` showing the same address at the same
    // time. state=10=TCP_LISTEN, uid=991, inode=78967 all verified by hand against
    // this exact byte sequence before being written into this test.
    const REAL_LISTEN_SOCKET_HEX: &str = "020a0000003500007f00003600000000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000100000df03000077340100";

    #[test]
    fn parses_a_real_listen_socket_record() {
        let bytes = hex_to_bytes(REAL_LISTEN_SOCKET_HEX);
        let msg = DiagMsg::parse(&bytes).unwrap();
        assert_eq!(msg.family, AF_INET);
        assert_eq!(msg.state, TCP_LISTEN);
        assert_eq!(msg.local, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 54)));
        assert_eq!(msg.local_port, 53);
        assert_eq!(msg.remote, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(msg.remote_port, 0);
        assert_eq!(msg.uid, 991);
        assert_eq!(msg.inode, 78967);
    }

    #[test]
    fn parse_rejects_a_truncated_payload() {
        let bytes = hex_to_bytes(REAL_LISTEN_SOCKET_HEX);
        assert!(DiagMsg::parse(&bytes[..DIAG_MSG_LEN - 1]).is_none());
    }

    #[test]
    fn parse_ignores_trailing_extended_attributes() {
        // The real capture this fixture comes from actually had 100 bytes (72
        // base + 28 bytes of rtattr extensions this crate doesn't request but the
        // kernel default-includes on some paths). Parsing must not choke on the
        // extra tail.
        let mut bytes = hex_to_bytes(REAL_LISTEN_SOCKET_HEX);
        bytes.extend_from_slice(&[0xAA; 28]);
        let msg = DiagMsg::parse(&bytes).unwrap();
        assert_eq!(msg.inode, 78967);
    }

    #[test]
    fn ipv6_address_uses_all_sixteen_bytes() {
        let mut bytes = hex_to_bytes(REAL_LISTEN_SOCKET_HEX);
        bytes[0] = AF_INET6;
        // ::1 in the local-address slot (payload[8..24]).
        bytes[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let msg = DiagMsg::parse(&bytes).unwrap();
        assert_eq!(msg.local, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn unknown_family_is_rejected() {
        let mut bytes = hex_to_bytes(REAL_LISTEN_SOCKET_HEX);
        bytes[0] = 99; // neither AF_INET nor AF_INET6
        assert!(DiagMsg::parse(&bytes).is_none());
    }

    #[test]
    fn request_encodes_family_protocol_states_and_nocookie() {
        let req = DiagRequestV2 {
            family: AF_INET,
            protocol: IPPROTO_TCP,
            states: (1 << TCP_ESTABLISHED) | (1 << TCP_LISTEN),
        }
        .to_bytes();
        assert_eq!(req.len(), DIAG_REQ_LEN);
        assert_eq!(req[0], AF_INET);
        assert_eq!(req[1], IPPROTO_TCP);
        assert_eq!(
            u32::from_ne_bytes(req[4..8].try_into().unwrap()),
            (1 << TCP_ESTABLISHED) | (1 << TCP_LISTEN)
        );
        assert_eq!(&req[48..56], &[0xff; 8]); // INET_DIAG_NOCOOKIE
    }

    #[test]
    fn header_round_trips() {
        let header = NlMsgHeader {
            len: 116,
            msg_type: SOCK_DIAG_BY_FAMILY,
            flags: 0x2,
            seq: 1,
            pid: 0,
        };
        let bytes = header.to_bytes();
        assert_eq!(NlMsgHeader::parse(&bytes), Some(header));
    }

    #[test]
    fn header_parse_rejects_a_short_buffer() {
        assert_eq!(NlMsgHeader::parse(&[0u8; 15]), None);
    }
}
