//! Owned Rust shape of one listening socket, plus the byte-order decoding of the
//! IP Helper rows — cross-platform on purpose so it is unit-testable on any host
//! (the same raw/normalize split as the Linux and macOS siblings).

use std::net::SocketAddr;

/// One listening TCP socket from a snapshot. The IP Helper table attributes the
/// socket to its owning pid; `ppid` and `process_name` come from the process
/// snapshot taken alongside it and are `None` when that process was not found
/// there (exited mid-poll, or the snapshot failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    /// Executable file name (`svchost.exe`) — `Toolhelp32` gives the name, not
    /// the full path.
    pub process_name: Option<String>,
    pub local: SocketAddr,
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

    #[test]
    fn port_ignores_undefined_upper_bytes() {
        assert_eq!(port_from_row(row_u32([0x11, 0x5C, 0xDE, 0xAD])), 4444);
    }
}
