//! Microsoft-Windows-Kernel-Network: which ids the sensor reads, and the flow each record
//! names. The ids follow the manifest (Windows 11 26300), confirmed live in the #253 review:
//! 12/28 are TCP connection attempts, 42/58 UDP sends; 14 is a TCP v4 retransmit and 26 a
//! TCP v6 data send, neither read.

use std::net::IpAddr;

use crate::payload::PayloadFields;

/// The address family of a record: its `daddr` is a `UInt32` for v4, 16 bytes for v6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpFamily {
    V4,
    V6,
}

/// The Kernel-Network records the sensor reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkEvent {
    /// EID 12 (v4) / 28 (v6), "connection attempted".
    TcpConnect(IpFamily),
    /// EID 42 (v4) / 58 (v6), "bytes transmitted" over UDP.
    UdpSend(IpFamily),
}

impl NetworkEvent {
    /// Every id [`Self::from_id`] reads: the provider's event-id filter.
    pub(crate) const EVENT_IDS: [u16; 4] = [12, 28, 42, 58];

    pub(crate) fn from_id(event_id: u16) -> Option<Self> {
        match event_id {
            12 => Some(Self::TcpConnect(IpFamily::V4)),
            28 => Some(Self::TcpConnect(IpFamily::V6)),
            42 => Some(Self::UdpSend(IpFamily::V4)),
            58 => Some(Self::UdpSend(IpFamily::V6)),
            _ => None,
        }
    }

    pub(crate) fn family(self) -> IpFamily {
        match self {
            Self::TcpConnect(family) | Self::UdpSend(family) => family,
        }
    }
}

/// The flow a record names: the process, the destination and the source port that tells
/// parallel connections apart, and the bytes a send carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flow {
    pub(crate) pid: u32,
    pub(crate) daddr: IpAddr,
    pub(crate) dport: u16,
    pub(crate) sport: u16,
    pub(crate) size: u32,
}

/// The record's flow; `None` without a usable destination (an unspecified address, `0`
/// or `::`, or a v6 one that is not 16 bytes). Ports arrive in network byte order.
pub(crate) fn flow(family: IpFamily, fields: &impl PayloadFields) -> Option<Flow> {
    Some(Flow {
        pid: fields.u32("PID").unwrap_or(0),
        daddr: destination(family, fields)?,
        dport: fields.u16("dport").unwrap_or(0).swap_bytes(),
        sport: fields.u16("sport").unwrap_or(0).swap_bytes(),
        size: fields.u32("size").unwrap_or(0),
    })
}

fn destination(family: IpFamily, fields: &impl PayloadFields) -> Option<IpAddr> {
    match family {
        // The v4 address is in memory order: `to_ne_bytes` keeps it.
        IpFamily::V4 => fields
            .u32("daddr")
            .filter(|&raw| raw != 0)
            .map(|raw| IpAddr::from(raw.to_ne_bytes())),
        IpFamily::V6 => {
            let bytes = <[u8; 16]>::try_from(fields.bytes("daddr")?).ok()?;
            Some(IpAddr::from(bytes)).filter(|daddr| !daddr.is_unspecified())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::payload::test_fields::{Fields, Value};

    #[test]
    fn the_event_id_filter_is_exactly_the_ids_read() {
        for event_id in 0..=u16::MAX {
            assert_eq!(
                NetworkEvent::EVENT_IDS.contains(&event_id),
                NetworkEvent::from_id(event_id).is_some(),
                "EID {event_id}"
            );
        }
    }

    #[test]
    fn connection_attempts_and_udp_sends_map_by_family_as_the_manifest_names_them() {
        assert_eq!(
            NetworkEvent::from_id(12),
            Some(NetworkEvent::TcpConnect(IpFamily::V4))
        );
        assert_eq!(
            NetworkEvent::from_id(28),
            Some(NetworkEvent::TcpConnect(IpFamily::V6))
        );
        assert_eq!(
            NetworkEvent::from_id(42),
            Some(NetworkEvent::UdpSend(IpFamily::V4))
        );
        assert_eq!(
            NetworkEvent::from_id(58),
            Some(NetworkEvent::UdpSend(IpFamily::V6))
        );
    }

    #[test]
    fn the_v6_ids_read_a_v6_destination() {
        let families: Vec<_> = NetworkEvent::EVENT_IDS
            .iter()
            .filter_map(|&event_id| NetworkEvent::from_id(event_id))
            .map(NetworkEvent::family)
            .collect();

        assert_eq!(
            families,
            [IpFamily::V4, IpFamily::V6, IpFamily::V4, IpFamily::V6]
        );
    }

    #[test]
    fn a_tcp_retransmit_or_a_tcp_data_send_is_not_read() {
        assert_eq!(NetworkEvent::from_id(14), None, "TCPv4 retransmit");
        assert_eq!(NetworkEvent::from_id(26), None, "TCPv6 data sent");
    }

    fn record(daddr: Value) -> Fields {
        Fields::of(&[
            ("PID", Value::U32(4242)),
            ("size", Value::U32(8)),
            ("daddr", daddr),
            ("dport", Value::U16(53_u16.swap_bytes())),
            ("sport", Value::U16(50_000_u16.swap_bytes())),
        ])
    }

    #[test]
    fn a_v4_record_names_its_flow_in_host_byte_order() {
        let daddr = u32::from_ne_bytes([192, 0, 2, 10]);

        let flow = flow(IpFamily::V4, &record(Value::U32(daddr))).expect("a destination");

        assert_eq!(
            flow,
            Flow {
                pid: 4242,
                daddr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                dport: 53,
                sport: 50_000,
                size: 8,
            }
        );
    }

    #[test]
    fn a_v6_record_reads_its_sixteen_byte_destination() {
        let flow = flow(
            IpFamily::V6,
            &record(Value::Bytes(Ipv6Addr::LOCALHOST.octets().to_vec())),
        )
        .expect("a destination");

        assert_eq!(flow.daddr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(flow.dport, 53);
    }

    #[test]
    fn a_record_without_a_usable_destination_names_no_flow() {
        assert_eq!(flow(IpFamily::V4, &record(Value::U32(0))), None);
        assert_eq!(
            flow(
                IpFamily::V6,
                &record(Value::Bytes(Ipv6Addr::UNSPECIFIED.octets().to_vec()))
            ),
            None
        );
        assert_eq!(flow(IpFamily::V6, &record(Value::Bytes(vec![0; 4]))), None);
        assert_eq!(flow(IpFamily::V6, &record(Value::U32(1))), None);
    }
}
