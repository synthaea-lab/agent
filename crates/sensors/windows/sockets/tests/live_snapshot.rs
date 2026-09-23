//! Live validation against the real IP Helper table (Windows only): bind
//! ephemeral listeners in this test process, snapshot, and require the walk to
//! find them attributed to us. Runs in the default suite on Windows — no
//! privileges needed, which is the point of this source.

#![cfg(windows)]

use std::net::TcpListener;

use sensor_windows_sockets::{listen_port_events, snapshot};

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
