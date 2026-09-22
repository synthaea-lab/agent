//! End-to-end tests: spin up a real [`Server`], connect a real
//! [`Client`], call every endpoint. Serves as the executable proof that
//! the transport + framing + protocol layers agree.
//!
//! Two `#[cfg(...)]` gates:
//!
//! - **`#[cfg(unix)]`** on the UDS end-to-end — the test needs to bind
//!   a Unix socket in a writable dir.
//! - **`#[cfg(windows)]`** on the named-pipe end-to-end — same shape,
//!   different endpoint syntax and different privilege check.
//!
//! In both cases the peer auth check (`check_authorized`) is expected
//! to pass because the test process typically runs as the same user as
//! the "server" (root on a CI runner, elevated user on a Windows dev
//! box). A non-privileged runner sees the test skipped via
//! `#[ignore]`-conditional wiring rather than a false failure — see
//! the individual test's guard.

use ipc::{Client, ClientError, Server, StubHandler};

/// Skip the current test with a printed message. Used when the runner
/// process is not privileged enough to exercise the happy path (root
/// on Unix, elevated on Windows).
macro_rules! skip_test {
    ($($arg:tt)*) => {{
        eprintln!("skipping: {}", format!($($arg)*));
        return;
    }};
}

fn unique_endpoint() -> String {
    // A per-run identifier so parallel `cargo test` runs and repeat
    // invocations don't collide on the pipe / socket path.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\synthaea-ipc-test-{pid}-{nanos}")
    }
    #[cfg(unix)]
    {
        format!("/tmp/synthaea-ipc-test-{pid}-{nanos}.sock")
    }
}

async fn spawn_server(endpoint: String) -> tokio::task::JoinHandle<()> {
    let ep = endpoint.clone();
    tokio::spawn(async move {
        let server = Server::new(ep, StubHandler::default());
        // `run` returns `Result<Infallible, _>`, so an `Ok` arm is
        // unreachable and the `let-else` catches only the error path
        // — a bind failure that will surface to the caller as an
        // "unreachable endpoint" on `Client::connect`.
        let Err(e) = server.run().await;
        eprintln!("server exited: {e:?}");
    })
}

/// The core happy-path test. Spawns a server, connects a client, hits
/// every endpoint. Skipped cleanly when the test process is not
/// privileged enough to pass the peer-auth check — the server rejects
/// the connection with `Unauthorized` and this test skips rather than
/// falsely failing on a non-root / non-elevated runner.
#[tokio::test]
async fn round_trip_every_endpoint() {
    let endpoint = unique_endpoint();
    let _server = spawn_server(endpoint.clone()).await;

    // Small yield to let the listener finish binding before we connect.
    // The correct fix is a proper "ready" signal from `Server::run` —
    // deferred to when the server API is stable enough to justify one.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut client = match Client::connect(&endpoint, "e2e-test").await {
        Ok(c) => c,
        Err(ClientError::Refused(msg)) if msg.contains("Unauthorized") => {
            skip_test!("peer-auth rejected the test process (need root on Unix / elevated on Windows)");
        }
        Err(e) => panic!("unexpected connect failure: {e:?}"),
    };

    let status = client.status().await.expect("status should succeed");
    assert!(status.pipeline_healthy);
    assert!(status.agent_version.starts_with("stub-"));

    let health = client
        .sensor_health()
        .await
        .expect("sensor_health should succeed");
    assert_eq!(health.sensors, vec![]);

    let dets = client
        .recent_detections(5)
        .await
        .expect("recent_detections should succeed");
    assert_eq!(dets.detections, vec![]);

    let policy = client
        .policy_version()
        .await
        .expect("policy_version should succeed");
    assert_eq!(policy.schema_version, 1);
    assert!(policy.policy_version.is_none());
    // Cleanup: the socket file on Unix stays after the test; not a
    // correctness issue (the endpoint is per-run) but cargo test's tmp
    // dir would accumulate. Remove best-effort.
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&endpoint);
    }
}

/// Version mismatch: a client that sends a `version` the server does
/// not implement is refused during handshake with
/// [`ipc::WireError::UnsupportedVersion`]. Exercises the error path
/// end-to-end.
///
/// This test still requires a peer-auth pass (the server checks
/// credentials BEFORE reading the client's version), so it skips on a
/// non-privileged runner for the same reason as `round_trip_every_endpoint`.
#[tokio::test]
async fn client_with_wrong_version_is_refused() {
    use ipc::protocol::{ClientHello, PROTOCOL_VERSION, WireError};
    let endpoint = unique_endpoint();
    let _server = spawn_server(endpoint.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let bad_version = PROTOCOL_VERSION + 1000;
    let stream = match ipc::stream::connect(&endpoint).await {
        Ok(s) => s,
        Err(e) => panic!("connect failed: {e:?}"),
    };
    let (mut read, mut write) = tokio::io::split(stream);
    ipc::frame::write_message(
        &mut write,
        &ClientHello {
            version: bad_version,
            client_name: "bad-version-client".to_string(),
        },
    )
    .await
    .expect("write hello");

    let mut reader = tokio::io::BufReader::new(&mut read);
    let reply: Option<WireError> = ipc::frame::read_message(&mut reader)
        .await
        .expect("read reply");
    // Peer-auth runs before the handshake, so a non-privileged runner
    // sees `Unauthorized` first. Skip cleanly in that case; the
    // handshake path is exercised by the unit test in `server`.
    match reply {
        Some(WireError::UnsupportedVersion { server_version }) => {
            assert_eq!(server_version, PROTOCOL_VERSION);
        }
        Some(WireError::Unauthorized) => {
            skip_test!("peer-auth rejected the test process before the handshake");
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&endpoint);
    }
}
