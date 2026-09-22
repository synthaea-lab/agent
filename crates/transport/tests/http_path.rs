//! The HTTP path end to end against a real local server — coverage showed the
//! client and `upload_once`'s ack/skip/backoff arms were only ever exercised
//! by unit tests with mock drains and no live socket. A ~50-line
//! `std::net::TcpListener` server (no test-only dependency) serves canned
//! responses, so these tests pin the behaviors the at-least-once contract
//! hangs on:
//!
//! - 200 → every batch uploaded, then exactly one `ack`.
//! - 4xx (permanent) → `skip` (poison escape), no `ack`, non-retryable error.
//! - 5xx (transient) → neither `ack` nor `skip`, retryable error, failure
//!   counter drives backoff.
//! - connection refused → retryable, drain untouched.

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use schema::{Event, ExecEvent};
use transport::{EventDrain, EventUploader, TransportClient, TransportConfig};

/// Serves `count` requests on an ephemeral port, always answering with
/// `status` and `body`, then exits. Returns the base URL.
fn canned_server(status: u16, body: &'static str, count: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for _ in 0..count {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            // Read until the header terminator, then the Content-Length body —
            // enough HTTP for a canned test server, not a real one.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            let body_len = loop {
                let Ok(n) = stream.read(&mut chunk) else {
                    return;
                };
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]);
                    let len = headers
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .map(String::from)
                        })
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    break (pos + 4, len);
                }
            };
            while buf.len() < body_len.0 + body_len.1 {
                let Ok(n) = stream.read(&mut chunk) else {
                    return;
                };
                buf.extend_from_slice(&chunk[..n]);
            }
            let reason = if status == 200 { "OK" } else { "NOPE" };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}")
}

struct CountingDrain {
    events: Vec<Event>,
    acked: Arc<AtomicU32>,
    skipped: Arc<AtomicU32>,
}

impl EventDrain for CountingDrain {
    fn drain(&mut self) -> std::io::Result<Vec<Event>> {
        // Re-deliver until acked or skipped, like the real spool.
        Ok(self.events.clone())
    }

    fn ack(&mut self) -> std::io::Result<()> {
        self.acked.fetch_add(1, Ordering::SeqCst);
        self.events.clear();
        Ok(())
    }

    fn skip(&mut self) -> std::io::Result<()> {
        self.skipped.fetch_add(1, Ordering::SeqCst);
        self.events.clear();
        Ok(())
    }
}

fn uploader_against(
    url: &str,
    events: Vec<Event>,
) -> (EventUploader<CountingDrain>, Arc<AtomicU32>, Arc<AtomicU32>) {
    let acked = Arc::new(AtomicU32::new(0));
    let skipped = Arc::new(AtomicU32::new(0));
    let drain = CountingDrain {
        events,
        acked: Arc::clone(&acked),
        skipped: Arc::clone(&skipped),
    };
    let mut config = TransportConfig::new(url);
    config.request_timeout = std::time::Duration::from_secs(5);
    let client = TransportClient::new(config).unwrap();
    (EventUploader::new(client, drain), acked, skipped)
}

fn events(n: usize) -> Vec<Event> {
    (0..n)
        .map(|i| {
            Event::Exec(ExecEvent {
                cmdline: format!("proc-{i}"),
                ..schema::fixtures::exec()
            })
        })
        .collect()
}

#[test]
fn success_uploads_every_batch_then_acks_once() {
    // 250 events at the default batch size of 100 = 3 requests, one ack.
    let url = canned_server(200, r#"{"accepted":100,"batch_id":null}"#, 3);
    let (mut uploader, acked, skipped) = uploader_against(&url, events(250));

    assert_eq!(uploader.upload_once().unwrap(), 250);
    assert_eq!(acked.load(Ordering::SeqCst), 1, "one ack after ALL batches");
    assert_eq!(skipped.load(Ordering::SeqCst), 0);
    assert!(!uploader.is_failing());
}

#[test]
fn permanent_rejection_skips_the_poison_batch_and_never_acks() {
    let url = canned_server(400, r#"{"error":"malformed"}"#, 1);
    let (mut uploader, acked, skipped) = uploader_against(&url, events(3));

    let err = uploader.upload_once().expect_err("400 must surface");
    assert!(!err.is_retryable(), "4xx is permanent");
    assert_eq!(skipped.load(Ordering::SeqCst), 1, "poison escape hatch");
    assert_eq!(acked.load(Ordering::SeqCst), 0, "never ack what failed");
}

#[test]
fn transient_server_error_leaves_the_drain_untouched_for_redelivery() {
    let url = canned_server(500, r#"{"error":"try later"}"#, 1);
    let (mut uploader, acked, skipped) = uploader_against(&url, events(3));

    let err = uploader.upload_once().expect_err("500 must surface");
    assert!(err.is_retryable(), "5xx is transient");
    assert_eq!(acked.load(Ordering::SeqCst), 0);
    assert_eq!(skipped.load(Ordering::SeqCst), 0, "redelivery, not loss");
    assert!(uploader.is_failing());
    assert!(uploader.backoff_duration() > std::time::Duration::ZERO);
}

#[test]
fn connection_refused_is_retryable_and_loses_nothing() {
    // Bind then drop: the port is closed, connect() is refused.
    let url = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let (mut uploader, acked, skipped) = uploader_against(&url, events(2));

    let err = uploader.upload_once().expect_err("refused must surface");
    assert!(err.is_retryable(), "unreachable server is the nominal case");
    assert_eq!(acked.load(Ordering::SeqCst), 0);
    assert_eq!(skipped.load(Ordering::SeqCst), 0);
}
