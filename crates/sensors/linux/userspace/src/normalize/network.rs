//! Socket records: connect, bind, listen, accept, and UDP in both directions.

use schema::{
    ConnectEvent, ContainerContext, DnsQueryEvent, Event, SocketAcceptEvent, SocketBindEvent,
    SocketCreateEvent, SocketListenEvent, UdpRecvEvent, UdpSendEvent,
};
use sensor_linux_wire as wire;

use super::meta;
use crate::dns_udp;

/// Maps a `wire::ConnectEvent` to `Event::Connect`. The destination is read as IPv6 or IPv4 according to `is_ipv6`.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn connect(
    event: &wire::ConnectEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let daddr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.daddr_v6.into())
    } else {
        std::net::IpAddr::V4(event.daddr_v4.into())
    };
    Event::Connect(ConnectEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        daddr,
        dport: event.dport,
    })
}

/// Maps a `wire::SocketBindEvent` to `Event::SocketBind`. The local address is read as IPv6 or IPv4 according to `is_ipv6`.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn socket_bind(
    event: &wire::SocketBindEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let laddr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.laddr_v6.into())
    } else {
        std::net::IpAddr::V4(event.laddr_v4.into())
    };
    Event::SocketBind(SocketBindEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        local_addr: laddr,
        local_port: event.lport,
    })
}

/// Maps a `wire::UdpSendEvent` to `Event::UdpSend`. `size` is the datagram length; the destination follows `is_ipv6`.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn udp_send(
    event: &wire::UdpSendEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let daddr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.daddr_v6.into())
    } else {
        std::net::IpAddr::V4(event.daddr_v4.into())
    };
    Event::UdpSend(UdpSendEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        daddr,
        dport: event.dport,
        size: event.size,
    })
}

/// A DNS query sent over a socket to port 53 (#458 part 3), as the platform-neutral
/// [`DnsQueryEvent`] the `getaddrinfo` uprobe also produces. `None` when the bytes are not a DNS
/// query: a descriptor number reused after its socket closed, or any other stream the kernel side
/// could not tell from one (see [`crate::dns_udp`]).
///
/// Queries only. The response is not captured, so `result` is `None`, `results` is empty and
/// `status` is `0`: that says "nothing failed that we saw", not "the lookup succeeded". The same
/// private-TLD redaction as the uprobe path applies, to the name as the process wrote it.
#[must_use]
pub fn dns_udp_query(
    event: &wire::DnsUdpQueryEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Option<Event> {
    let captured = usize::from(event.payload_len).min(wire::MAX_DNS_UDP_PAYLOAD);
    let question = dns_udp::parse_query(&event.payload[..captured])?;
    Some(Event::DnsQuery(DnsQueryEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        query: dns_udp::redact_private_tld(question.name),
        qtype: u32::from(question.qtype),
        result: None,
        results: Vec::new(),
        results_truncated: false,
        status: 0,
    }))
}

/// Maps a `wire::UdpRecvEvent` to `Event::UdpRecv`. `peer_addr`/`peer_port` are the sender's; `size` is the datagram length.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn udp_recv(
    event: &wire::UdpRecvEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let peer_addr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.peer_addr_v6.into())
    } else {
        std::net::IpAddr::V4(event.peer_addr_v4.into())
    };
    Event::UdpRecv(UdpRecvEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        peer_addr,
        peer_port: event.peer_port,
        size: event.size,
    })
}

/// Maps a `wire::SocketListenEvent` to `Event::SocketListen`. `local_addr`/`local_port` are `None` when the probe could not correlate a prior `bind` (`addr_resolved` false).
/// `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn socket_listen(
    event: &wire::SocketListenEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let (local_addr, local_port) = if event.addr_resolved {
        let addr = if event.is_ipv6 {
            std::net::IpAddr::V6(event.laddr_v6.into())
        } else {
            std::net::IpAddr::V4(event.laddr_v4.into())
        };
        (Some(addr), Some(event.lport))
    } else {
        (None, None)
    };
    Event::SocketListen(SocketListenEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        local_addr,
        local_port,
        backlog: event.backlog,
    })
}

/// Maps a `wire::SocketAcceptEvent` to `Event::SocketAccept`. Carries the listening and accepted fds and the peer address; emitted only on success.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn socket_accept(
    event: &wire::SocketAcceptEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let peer_addr = if event.is_ipv6 {
        std::net::IpAddr::V6(event.peer_addr_v6.into())
    } else {
        std::net::IpAddr::V4(event.peer_addr_v4.into())
    };
    Event::SocketAccept(SocketAcceptEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        listen_fd: event.listen_fd,
        accepted_fd: event.accepted_fd,
        peer_addr,
        peer_port: event.peer_port,
    })
}

/// Maps a `wire::SocketCreateEvent` to `Event::SocketCreate`. `domain`, `socket_type` and `protocol` are the raw `socket(2)` arguments; `fd` is the one returned.
/// `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn socket_create(
    event: &wire::SocketCreateEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::SocketCreate(SocketCreateEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        domain: event.domain,
        socket_type: event.socket_type,
        protocol: event.protocol,
        fd: event.fd,
    })
}
