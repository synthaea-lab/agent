//! Live validation against the real libproc walk (macOS only): bind an
//! ephemeral listener in this test process, snapshot, and require the walk to
//! find it with full self-attribution. Runs in the default suite on macOS —
//! no privileges, no entitlement, which is the whole point of this sensor.

#![cfg(target_os = "macos")]

use std::net::TcpListener;

use sensor_macos_sockets::{SocketState, listen_port_events, snapshot};

#[test]
fn our_own_listener_appears_with_full_attribution() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral listener");
    let port = listener.local_addr().unwrap().port();
    let me = std::process::id();

    let entries = snapshot().expect("snapshot must succeed unprivileged");
    let mine = entries
        .iter()
        .find(|e| e.pid == me && e.local.port() == port && e.state == SocketState::Listen)
        .unwrap_or_else(|| {
            panic!(
                "own listener on port {port} not found among {} entries",
                entries.len()
            )
        });

    assert_eq!(mine.local.ip().to_string(), "127.0.0.1");
    assert!(mine.ppid > 0, "libproc must resolve the real ppid");
    // SAFETY: geteuid has no preconditions.
    assert_eq!(mine.uid, unsafe { libc_geteuid() });
    let path = mine.process_path.as_deref().expect("own path must resolve");
    assert!(
        path.ends_with("live_snapshot") || path.contains("live_snapshot-"),
        "path should be this test binary, got {path}"
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

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}
