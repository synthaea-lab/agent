//! Owned Rust shape of one listening socket, plus the byte-order decoding of the
//! IP Helper rows — cross-platform on purpose so it is unit-testable on any host
//! (the same raw/normalize split as the Linux and macOS siblings).

use std::net::SocketAddr;

/// One listening TCP or bound UDP socket from a snapshot. The IP Helper table
/// attributes the socket to its owning pid; `ppid` and `process_name` come from
/// the process snapshot taken alongside it and are `None` when that process was
/// not found there (exited mid-poll, or the snapshot failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    /// Executable file name (`svchost.exe`) — `Toolhelp32` gives the name, not
    /// the full path.
    pub process_name: Option<String>,
    pub local: SocketAddr,
    /// `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17) — which IP Helper table this
    /// entry came from (<https://github.com/synthaea-lab/edr-agent/issues/40>).
    pub protocol: u8,
}

/// The default Windows dynamic (ephemeral) port range, 49152-65535, the same for
/// UDP and TCP on IPv4 and IPv6 since Vista (`netsh int ipv4 show dynamicport udp`
/// prints `start 49152, 16384 ports` on an untouched host; measured on the
/// Windows 11 dev host of the <https://github.com/synthaea-lab/edr-agent/issues/40> capture).
///
/// Fixed rather than read from the host: no documented API returns the range,
/// and getting it wrong only moves noise, never blindness. An administrator who
/// moves the range down (say to 10000) makes client sockets in 10000-49151 look
/// like services, so they reach LISTENER-DRIFT: noise. A socket at 49152 or above
/// is dropped whatever the host's setting.
pub const EPHEMERAL_UDP_PORTS: core::ops::RangeInclusive<u16> = 49152..=65535;

/// Whether `entry` is a socket LISTENER-DRIFT should see (<https://github.com/synthaea-lab/edr-agent/issues/40>).
///
/// Every TCP entry is: the TCP table is already filtered to listeners. A UDP
/// entry is kept only when its port is outside [`EPHEMERAL_UDP_PORTS`].
/// `GetExtendedUdpTable` lists every bound UDP endpoint, client sockets
/// included, and on the capture host the ephemeral ones were the bulk of the
/// table. They were also long-lived (bound for the whole capture), so "still
/// bound on the next poll" does not separate them from a service. A service
/// a client must find has a fixed port, and fixed ports sit below the range.
///
/// The cost, stated in `docs/sensors/windows.md`: a UDP listener that binds
/// a port in the ephemeral range on purpose is invisible to LISTENER-DRIFT. Its
/// traffic still reaches the ETW network stream.
#[must_use]
pub fn is_drift_relevant(entry: &ListenerEntry) -> bool {
    entry.protocol != schema::IPPROTO_UDP || !EPHEMERAL_UDP_PORTS.contains(&entry.local.port())
}

/// `dwLocalAddr` holds the IPv4 address in network byte order, as stored in
/// memory — its native-endian bytes are the octets.
#[cfg(any(windows, test))]
pub(crate) fn ipv4_from_row(dw_addr: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(dw_addr.to_ne_bytes())
}

/// `dwLocalPort` holds the port in network byte order in its first two bytes;
/// the upper two are undefined per the IP Helper documentation and ignored.
#[cfg(any(windows, test))]
pub(crate) fn port_from_row(dw_port: u32) -> u16 {
    let bytes = dw_port.to_ne_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// Builds the `u32` the way Windows lays it out in memory.
    fn row_u32(bytes: [u8; 4]) -> u32 {
        u32::from_ne_bytes(bytes)
    }

    #[test]
    fn ipv4_octets_decode_in_network_order() {
        assert_eq!(
            ipv4_from_row(row_u32([192, 168, 1, 10])),
            Ipv4Addr::new(192, 168, 1, 10)
        );
    }

    #[test]
    fn port_decodes_from_network_order_low_bytes() {
        // 445 = 0x01BD, stored big-endian in the first two bytes.
        assert_eq!(port_from_row(row_u32([0x01, 0xBD, 0, 0])), 445);
    }

    fn udp(port: u16) -> ListenerEntry {
        ListenerEntry {
            pid: 4,
            ppid: None,
            process_name: None,
            local: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
            protocol: schema::IPPROTO_UDP,
        }
    }

    #[test]
    fn a_udp_socket_on_a_fixed_port_reaches_listener_drift() {
        for port in [53, 123, 5353, 49151] {
            assert!(is_drift_relevant(&udp(port)), "udp/{port}");
        }
    }

    #[test]
    fn a_udp_socket_on_an_ephemeral_port_is_a_client_not_a_listener() {
        for port in [49152, 56346, 65535] {
            assert!(!is_drift_relevant(&udp(port)), "udp/{port}");
        }
    }

    #[test]
    fn a_tcp_listener_on_an_ephemeral_port_still_reaches_listener_drift() {
        let mut entry = udp(56346);
        entry.protocol = schema::IPPROTO_TCP;
        assert!(is_drift_relevant(&entry));
    }

    #[test]
    fn port_ignores_undefined_upper_bytes() {
        assert_eq!(port_from_row(row_u32([0x11, 0x5C, 0xDE, 0xAD])), 4444);
    }
}
