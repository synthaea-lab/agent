//! Live validation against the real IP Helper table (Windows only): bind
//! ephemeral TCP listeners and UDP sockets in this test process, snapshot,
//! and require the walk to find them attributed to us with the right
//! protocol. Runs in the default suite on Windows — no privileges needed,
//! which is the point of this source.

#![cfg(windows)]

use std::net::{SocketAddr, TcpListener, UdpSocket};

use sensor_windows_sockets::{
    EPHEMERAL_UDP_PORTS, ListenerEntry, listen_port_events_for_drift, snapshot, snapshot_for_drift,
};

/// A TCP listener and a UDP socket bound to the **same** `127.0.0.1` port number. TCP and
/// UDP ports are independent, so this is legal, and it is what makes the protocol tests
/// deterministic: the tests in this binary run in parallel threads of one process, and an
/// assertion that "no UDP entry shares the TCP port" or "no entry has the UDP port" could
/// be broken by another test's ephemeral socket (or any process's) landing on that number
/// by chance (review of #1008). With both on one address, nothing else can hold the TCP
/// side, so the count of this process's entries at that address is exact.
fn tcp_and_udp_on_one_port() -> (TcpListener, UdpSocket, SocketAddr) {
    for _ in 0..16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral listener");
        let addr = listener.local_addr().unwrap();
        // The UDP side of that number may already be taken by someone else: try another.
        if let Ok(socket) = UdpSocket::bind(addr) {
            return (listener, socket, addr);
        }
    }
    panic!("no 127.0.0.1 port free for both TCP and UDP after 16 tries");
}

/// A UDP socket on `127.0.0.1` at a fixed port below [`EPHEMERAL_UDP_PORTS`], the way a
/// service binds. Tries ports downward from the top of the fixed range until one is free.
fn udp_on_a_fixed_port() -> UdpSocket {
    let below = *EPHEMERAL_UDP_PORTS.start();
    (below - 2000..below)
        .rev()
        .find_map(|port| UdpSocket::bind(("127.0.0.1", port)).ok())
        .expect("a free 127.0.0.1 UDP port below the ephemeral range")
}

/// The protocols of this process's entries at `addr`, sorted.
fn own_protocols_at(entries: &[ListenerEntry], addr: SocketAddr) -> Vec<u8> {
    let me = std::process::id();
    let mut protocols: Vec<u8> = entries
        .iter()
        .filter(|e| e.pid == me && e.local == addr)
        .map(|e| e.protocol)
        .collect();
    protocols.sort_unstable();
    protocols
}

#[test]
fn own_ipv4_listener_appears_attributed_to_this_process() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral listener");
    let port = listener.local_addr().unwrap().port();
    let me = std::process::id();

    let entries = snapshot().expect("snapshot must succeed unprivileged");
    let mine = entries
        .iter()
        .find(|e| e.pid == me && e.local.port() == port)
        .unwrap_or_else(|| {
            panic!(
                "own listener on port {port} not found among {} entries",
                entries.len()
            )
        });

    assert_eq!(mine.local.ip().to_string(), "127.0.0.1");
    assert!(
        mine.ppid.is_some_and(|ppid| ppid > 0),
        "toolhelp must resolve our parent"
    );
    let name = mine.process_name.as_deref().expect("own name must resolve");
    assert!(
        name.starts_with("live_snapshot"),
        "name should be this test binary, got {name}"
    );
    drop(listener);
}

#[test]
fn own_ipv6_listener_appears_with_its_port_decoded() {
    let Ok(listener) = TcpListener::bind("[::1]:0") else {
        return; // IPv6 disabled on this host — nothing to validate.
    };
    let port = listener.local_addr().unwrap().port();
    let me = std::process::id();

    let entries = snapshot().expect("snapshot");
    assert!(
        entries
            .iter()
            .any(|e| e.pid == me && e.local.port() == port && e.local.is_ipv6()),
        "own IPv6 listener on port {port} not found"
    );
    drop(listener);
}

#[test]
fn own_udp_socket_appears_attributed_with_udp_protocol() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP socket");
    let addr = socket.local_addr().unwrap();

    let entries = snapshot().expect("snapshot must succeed unprivileged");
    assert_eq!(
        own_protocols_at(&entries, addr),
        [17],
        "own UDP socket at {addr} not found among {} entries",
        entries.len()
    );
    drop(socket);
}

#[test]
fn own_tcp_listener_is_still_distinguished_from_udp() {
    let (listener, socket, addr) = tcp_and_udp_on_one_port();
    let entries = snapshot().expect("snapshot");
    assert_eq!(
        own_protocols_at(&entries, addr),
        [6, 17],
        "one TCP and one UDP entry at {addr}, told apart by protocol"
    );
    drop(listener);
    drop(socket);
}

#[test]
fn an_ephemeral_udp_socket_is_left_out_of_the_drift_snapshot_but_its_tcp_twin_is_not() {
    // The OS hands a `:0` bind a port from the dynamic range, the way a client
    // socket gets one, so the UDP side is what the #676 filter must drop.
    let (listener, socket, addr) = tcp_and_udp_on_one_port();
    assert!(
        EPHEMERAL_UDP_PORTS.contains(&addr.port()),
        "the OS assigned {addr} outside the default dynamic range; was the host's range changed?"
    );

    let entries = snapshot_for_drift().expect("snapshot_for_drift must succeed unprivileged");
    assert_eq!(
        own_protocols_at(&entries, addr),
        [6],
        "the TCP listener only, at {addr}"
    );
    drop(listener);
    drop(socket);
}

#[test]
fn a_udp_socket_on_a_fixed_port_reaches_the_drift_events() {
    let socket = udp_on_a_fixed_port();
    let addr = socket.local_addr().unwrap();
    let me = std::process::id();

    let events = listen_port_events_for_drift(1_790_000_000_000_000_000).expect("events");
    let found = events.iter().any(|e| {
        matches!(e, schema::Event::ListenPort(l)
            if l.meta.pid == me && l.local_addr == addr.ip() && l.local_port == addr.port()
               && l.protocol == schema::IPPROTO_UDP
               && l.meta.timestamp_ns == 1_790_000_000_000_000_000)
    });
    assert!(
        found,
        "own UDP socket at {addr} must reach the drift events"
    );
    drop(socket);
}
