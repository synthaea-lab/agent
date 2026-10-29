//! Live validation against the real IP Helper table (Windows only): bind
//! ephemeral TCP listeners and UDP sockets in this test process, snapshot,
//! and require the walk to find them attributed to us with the right
//! protocol. Runs in the default suite on Windows — no privileges needed,
//! which is the point of this source.

#![cfg(windows)]

use std::net::{SocketAddr, TcpListener, UdpSocket};

use sensor_windows_sockets::{listen_port_events, listen_port_events_tcp, snapshot, snapshot_tcp};

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
    // A bound UDP socket is not a "listener", but GetExtendedUdpTable has no
    // such filter — this is the real, unfiltered mechanism issue #676 asks
    // for; the noise problem it also names (DNS client sockets, ephemeral
    // ports) is a separate, deliberately deferred filter, not tested here.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP socket");
    let port = socket.local_addr().unwrap().port();
    let me = std::process::id();

    let entries = snapshot().expect("snapshot must succeed unprivileged");
    let mine = entries
        .iter()
        .find(|e| e.pid == me && e.local.port() == port && e.protocol == 17)
        .unwrap_or_else(|| {
            panic!(
                "own UDP socket on port {port} not found among {} entries",
                entries.len()
            )
        });

    assert_eq!(mine.local.ip().to_string(), "127.0.0.1");
    assert_eq!(mine.protocol, 17, "IPPROTO_UDP");
    drop(socket);
}

#[test]
fn own_tcp_listener_is_still_distinguished_from_udp() {
    let (listener, socket, addr) = tcp_and_udp_on_one_port();
    let me = std::process::id();

    let entries = snapshot().expect("snapshot");
    let mut protocols: Vec<u8> = entries
        .iter()
        .filter(|e| e.pid == me && e.local == addr)
        .map(|e| e.protocol)
        .collect();
    protocols.sort_unstable();
    assert_eq!(
        protocols,
        [6, 17],
        "one TCP and one UDP entry at {addr}, told apart by protocol"
    );
    drop(listener);
    drop(socket);
}

#[test]
fn snapshot_tcp_finds_the_same_tcp_listener_as_snapshot_but_no_udp() {
    // The agent's own entry point (review of #1008, #676 part 2): it must see
    // what `snapshot` sees on the TCP side, and never fetch/report a UDP entry
    // at all — not "reports it and relies on a filter downstream."
    let (listener, socket, addr) = tcp_and_udp_on_one_port();
    let me = std::process::id();

    let entries = snapshot_tcp().expect("snapshot_tcp must succeed unprivileged");
    let mine: Vec<u8> = entries
        .iter()
        .filter(|e| e.pid == me && e.local == addr)
        .map(|e| e.protocol)
        .collect();
    assert_eq!(
        mine,
        [6],
        "exactly the TCP listener at {addr}, not the UDP socket bound beside it"
    );
    assert!(
        entries.iter().all(|e| e.protocol == 6),
        "every snapshot_tcp entry must be IPPROTO_TCP"
    );
    drop(listener);
    drop(socket);
}

#[test]
fn listen_port_events_tcp_carries_the_listener_but_not_a_udp_socket() {
    let (listener, socket, addr) = tcp_and_udp_on_one_port();
    let me = std::process::id();

    let events = listen_port_events_tcp(1_790_000_000_000_000_000).expect("events");
    let mine: Vec<u8> = events
        .iter()
        .filter_map(|e| match e {
            schema::Event::ListenPort(l)
                if l.meta.pid == me && l.local_addr == addr.ip() && l.local_port == addr.port() =>
            {
                Some(l.protocol)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        mine,
        [6],
        "exactly the TCP listener at {addr}, not the UDP socket bound beside it"
    );
    drop(listener);
    drop(socket);
}

#[test]
fn listen_port_events_carry_the_listener_as_a_schema_event() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral listener");
    let port = listener.local_addr().unwrap().port();
    let me = std::process::id();

    let events = listen_port_events(1_790_000_000_000_000_000).expect("events");
    let found = events.iter().any(|e| {
        matches!(e, schema::Event::ListenPort(l)
            if l.meta.pid == me && l.local_port == port
               && l.meta.timestamp_ns == 1_790_000_000_000_000_000)
    });
    assert!(found, "own listener must normalize into Event::ListenPort");
    drop(listener);
}
