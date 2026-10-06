//! The HTTP path end to end against a real local server — coverage showed the
//! client and `upload_once`'s ack/skip/backoff arms were only ever exercised
//! by unit tests with mock drains and no live socket. A ~50-line
//! `std::net::TcpListener` server (no test-only dependency) serves canned
//! responses, so these tests pin the behaviors the at-least-once contract
//! hangs on:
//!
//! - 200 → every batch uploaded, then exactly one `ack`.
//! - 4xx (permanent) → `skip` (poison escape), no `ack`, non-retryable error.
//! - 5xx (transient), under `max_drain_attempts` → neither `ack` nor `skip`,
//!   retryable error, failure counter drives backoff.
//! - 5xx repeated `max_drain_attempts` times on the same segment → `skip`,
//!   so a permanently-500ing segment can't wedge newer segments forever.
//! - connection refused → retryable, drain untouched.
//! - connection refused repeated → gated on the separate, larger
//!   `max_network_drain_attempts` budget, not `max_drain_attempts` (issue
//!   #394): never having reached the server is weaker poison-segment
//!   evidence than a 5xx it actually sent.
//! - 200 with an unparseable body → retryable, but gated on `max_drain_attempts`
//!   like a 5xx, not `max_network_drain_attempts` — the server was reached and
//!   answered, so this isn't a connectivity blip (issue #414 follow-up).

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use schema::{
    Event, ExecEvent,
    detection::{Detection, DetectionSource, Severity},
};
use transport::{EventDrain, EventUploader, TransportClient, TransportConfig};

/// Reads one request until the header terminator, then its Content-Length
/// body — enough HTTP for a canned test server, not a real one. Returns
/// nothing usable on a closed connection; callers just stop.
fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let (header_end, body_len) = loop {
        let Ok(n) = stream.read(&mut chunk) else {
            return String::new();
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
    while buf.len() < header_end + body_len {
        let Ok(n) = stream.read(&mut chunk) else {
            return String::new();
        };
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buf[..header_end]).into_owned()
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = if status == 200 { "OK" } else { "NOPE" };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// Same shape as [`write_response`] but for a binary body — content
/// artifact downloads aren't JSON.
fn write_binary_response(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let reason = if status == 200 { "OK" } else { "NOPE" };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}

/// Reads one request and returns its request line (e.g. `GET /path?a=b
/// HTTP/1.1`) — enough to assert on the query string a client actually sent,
/// without a full HTTP parser.
fn read_request_line(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let Ok(n) = stream.read(&mut chunk) else {
            return String::new();
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    text.lines().next().unwrap_or_default().to_string()
}

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
            let _ = read_request(&mut stream);
            write_response(&mut stream, status, body);
        }
    });
    format!("http://{addr}")
}

/// Serves one canned `(status, body)` response per accepted connection, in
/// order, then exits once the list is exhausted.
fn sequenced_server(responses: Vec<(u16, &'static str)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for (status, body) in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = read_request(&mut stream);
            write_response(&mut stream, status, body);
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

fn detection() -> Detection {
    Detection {
        timestamp_ns: 1_700_000_000_000_000_000,
        severity: Severity::High,
        title: "Unusual process chain".into(),
        source: DetectionSource::Correlator {
            case_id: "42:python".into(),
        },
        score: Some(0.91),
        attributions: Vec::new(),
        techniques: vec!["T1059".into()],
        events: events(1),
    }
}

#[test]
fn structured_detection_upload_uses_the_server_route_and_acceptance_contract() {
    let url = canned_server(200, r#"{"status":"accepted"}"#, 1);
    let config = TransportConfig::new(&url);
    assert_eq!(
        config.detection_url(),
        format!("{url}/api/ingest/detection")
    );
    let client = TransportClient::new(config).unwrap();
    client.upload_detection(&detection()).unwrap();
}

#[test]
fn structured_detection_upload_rejects_an_unexpected_server_response() {
    let url = canned_server(200, r#"{"status":"ignored"}"#, 1);
    let client = TransportClient::new(TransportConfig::new(&url)).unwrap();
    let err = client.upload_detection(&detection()).unwrap_err();
    assert!(matches!(err, transport::TransportError::InvalidResponse(_)));
}

#[test]
fn structured_detection_retry_sends_a_stable_idempotency_key() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let headers = read_request(&mut stream);
        write_response(&mut stream, 200, r#"{"status":"accepted"}"#);
        headers
    });
    let client = TransportClient::new(TransportConfig::new(&url)).unwrap();
    let key = "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a";
    client.upload_detection_with_key(&detection(), key).unwrap();
    let headers = server.join().unwrap().to_ascii_lowercase();
    assert!(headers.contains(&format!("idempotency-key: {key}")));
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

#[test]
fn connection_refused_repeated_is_skipped_only_at_the_larger_network_budget() {
    // Issue #394: before this fix, a pure connectivity failure counted
    // toward the same `max_drain_attempts` budget as a 5xx, so a segment
    // could be skipped — and its events lost — after ~15s of a VPN
    // reconnect or DNS hiccup, even though the server was never actually
    // reached, let alone rejected anything.
    let max_attempts = transport::DEFAULT_MAX_DRAIN_ATTEMPTS;
    let max_network_attempts = transport::DEFAULT_MAX_NETWORK_DRAIN_ATTEMPTS;
    assert!(
        max_network_attempts > max_attempts,
        "the network budget must be the larger of the two, or this test proves nothing"
    );

    // Bind then drop: the port stays closed for the uploader's lifetime.
    let url = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let (mut uploader, acked, skipped) = uploader_against(&url, events(2));

    for attempt in 1..max_network_attempts {
        let err = uploader.upload_once().expect_err("refused must surface");
        assert!(err.is_retryable(), "connection refused is transient");
        assert_eq!(
            skipped.load(Ordering::SeqCst),
            0,
            "must not skip before max_network_drain_attempts (attempt {attempt}), \
             even past max_drain_attempts ({max_attempts})"
        );
    }
    // The Nth attempt hits max_network_drain_attempts and skips.
    let err = uploader.upload_once().expect_err("refused must surface");
    assert!(err.is_retryable(), "connection refused is transient");
    assert_eq!(
        skipped.load(Ordering::SeqCst),
        1,
        "network budget exhausted — forward progress restored"
    );
    assert_eq!(acked.load(Ordering::SeqCst), 0);
}

#[test]
fn unparseable_200_body_repeated_is_skipped_at_the_shorter_server_budget() {
    // Issue #414 follow-up: a 2xx with a body that fails to parse (e.g. a
    // misconfigured reverse proxy answering 200 with an HTML error page) used
    // to be classified as `Network`, getting the long connectivity budget —
    // and being retried, and potentially ingested, up to
    // `max_network_drain_attempts` times — even though the server was
    // reached and answered. It must behave like a 5xx: retryable, but gated
    // on the shorter `max_drain_attempts`.
    let max_attempts = transport::DEFAULT_MAX_DRAIN_ATTEMPTS;
    let max_network_attempts = transport::DEFAULT_MAX_NETWORK_DRAIN_ATTEMPTS;

    let url = canned_server(200, "not valid json", max_attempts as usize);
    let (mut uploader, acked, skipped) = uploader_against(&url, events(2));

    for attempt in 1..max_attempts {
        let err = uploader.upload_once().expect_err("bad body must surface");
        assert!(err.is_retryable(), "an unparseable body is transient");
        assert!(
            !err.is_network_error(),
            "the server was reached and answered — not a connectivity blip"
        );
        assert_eq!(
            skipped.load(Ordering::SeqCst),
            0,
            "must not skip before max_drain_attempts (attempt {attempt})"
        );
    }
    let err = uploader.upload_once().expect_err("bad body must surface");
    assert!(err.is_retryable(), "an unparseable body is transient");
    assert!(!err.is_network_error());
    assert_eq!(
        skipped.load(Ordering::SeqCst),
        1,
        "must skip at the shorter server budget ({max_attempts}), not the \
         much larger network one ({max_network_attempts})"
    );
    assert_eq!(acked.load(Ordering::SeqCst), 0);
}

/// A drain backed by several segments, like the real spool: `drain` always
/// re-delivers the front segment, `ack`/`skip` pop it and expose the next one.
struct MultiSegmentDrain {
    segments: std::collections::VecDeque<Vec<Event>>,
    acked: Arc<AtomicU32>,
    skipped: Arc<AtomicU32>,
}

impl EventDrain for MultiSegmentDrain {
    fn drain(&mut self) -> std::io::Result<Vec<Event>> {
        Ok(self.segments.front().cloned().unwrap_or_default())
    }

    fn ack(&mut self) -> std::io::Result<()> {
        self.segments.pop_front();
        self.acked.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn skip(&mut self) -> std::io::Result<()> {
        self.segments.pop_front();
        self.skipped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn poison_segment_that_always_500s_is_skipped_after_max_attempts_and_newer_segments_flow() {
    let max_attempts = transport::DEFAULT_MAX_DRAIN_ATTEMPTS;

    // The first segment's server responses always 500, `max_attempts` times
    // in a row; the second segment's request finally gets a 200.
    let mut responses: Vec<(u16, &'static str)> =
        vec![(500, r#"{"error":"try later"}"#); max_attempts as usize];
    responses.push((200, r#"{"accepted":1,"batch_id":null}"#));
    let url = sequenced_server(responses);

    let acked = Arc::new(AtomicU32::new(0));
    let skipped = Arc::new(AtomicU32::new(0));
    let mut segments = std::collections::VecDeque::new();
    segments.push_back(events(3)); // the poison segment
    segments.push_back(events(1)); // healthy segment behind it
    let drain = MultiSegmentDrain {
        segments,
        acked: Arc::clone(&acked),
        skipped: Arc::clone(&skipped),
    };
    let mut config = TransportConfig::new(&url);
    config.request_timeout = std::time::Duration::from_secs(5);
    let client = TransportClient::new(config).unwrap();
    let mut uploader = EventUploader::new(client, drain);

    for attempt in 1..max_attempts {
        let err = uploader.upload_once().expect_err("500 must surface");
        assert!(err.is_retryable(), "5xx is transient");
        assert_eq!(
            skipped.load(Ordering::SeqCst),
            0,
            "must not skip before max_drain_attempts (attempt {attempt})"
        );
    }
    // The Nth attempt hits max_drain_attempts and skips within that same call.
    let err = uploader.upload_once().expect_err("500 must surface");
    assert!(err.is_retryable(), "5xx is transient");
    assert_eq!(skipped.load(Ordering::SeqCst), 1, "poison segment skipped");
    assert_eq!(acked.load(Ordering::SeqCst), 0);

    // Forward progress restored: the healthy segment behind it now uploads.
    assert_eq!(uploader.upload_once().unwrap(), 1, "newer segment flows");
    assert_eq!(acked.load(Ordering::SeqCst), 1);
    assert!(
        !uploader.is_failing(),
        "failure counter resets once the poison segment is gone"
    );
}

#[test]
fn poison_batch_not_in_the_first_slot_still_reaches_max_drain_attempts() {
    // Regression for the #315 fix's own bug (found in PR #349 review): a
    // segment larger than `batch_size` splits into several upload requests
    // per `upload_once` call. Before the fix, `consecutive_failures` reset
    // to 0 on every successful BATCH, not just a successful call — so a
    // call whose first batch(es) succeed before a later one fails erased
    // the count from every earlier failed call on this same still-unacked
    // segment, and `max_drain_attempts` was never reached unless the
    // poison record happened to sit in the segment's very first batch. The
    // test above (`poison_segment_that_always_500s...`) couldn't catch this
    // class of bug: both its segments are smaller than `batch_size`, so
    // every call only ever produces one request.
    let max_attempts = transport::DEFAULT_MAX_DRAIN_ATTEMPTS;

    // Each call sends exactly 2 requests: batch 1 (200) then batch 2 (500)
    // — the call returns as soon as a batch fails, so batch 3 (the segment
    // has 5 events at batch_size=2: batches of 2, 2, 1) is never requested.
    let mut responses: Vec<(u16, &'static str)> = Vec::new();
    for _ in 0..max_attempts {
        responses.push((200, r#"{"accepted":2,"batch_id":null}"#));
        responses.push((500, r#"{"error":"try later"}"#));
    }
    let url = sequenced_server(responses);

    let acked = Arc::new(AtomicU32::new(0));
    let skipped = Arc::new(AtomicU32::new(0));
    let mut segments = std::collections::VecDeque::new();
    segments.push_back(events(5));
    let drain = MultiSegmentDrain {
        segments,
        acked: Arc::clone(&acked),
        skipped: Arc::clone(&skipped),
    };
    let mut config = TransportConfig::new(&url);
    config.request_timeout = std::time::Duration::from_secs(5);
    config.batch_size = 2;
    let client = TransportClient::new(config).unwrap();
    let mut uploader = EventUploader::new(client, drain);

    for attempt in 1..max_attempts {
        let err = uploader
            .upload_once()
            .expect_err("the second batch's 500 must surface");
        assert!(err.is_retryable(), "5xx is transient");
        assert_eq!(
            skipped.load(Ordering::SeqCst),
            0,
            "must not skip before max_drain_attempts (attempt {attempt}) \
             — the first batch's success must not have erased earlier attempts"
        );
    }
    let err = uploader
        .upload_once()
        .expect_err("the second batch's 500 must surface");
    assert!(err.is_retryable(), "5xx is transient");
    assert_eq!(
        skipped.load(Ordering::SeqCst),
        1,
        "poison segment skipped even though its poison batch isn't the first"
    );
    assert_eq!(acked.load(Ordering::SeqCst), 0);
}

// ── get_json (issue #30/#73's content-manifest fetch) ──────────────────────

#[derive(Debug, serde::Deserialize, PartialEq)]
struct Widget {
    name: String,
    count: u32,
}

#[test]
fn get_json_fetches_and_deserializes_a_200_response() {
    let url = canned_server(200, r#"{"name":"beacon","count":3}"#, 1);
    let client = TransportClient::new(TransportConfig::new(&url)).unwrap();

    let widget: Widget = client.get_json(&url).unwrap();
    assert_eq!(
        widget,
        Widget {
            name: "beacon".to_string(),
            count: 3,
        }
    );
}

#[test]
fn get_json_surfaces_a_retryable_error_on_5xx() {
    let url = canned_server(500, r#"{"error":"try later"}"#, 1);
    let client = TransportClient::new(TransportConfig::new(&url)).unwrap();

    let err = client
        .get_json::<Widget>(&url)
        .expect_err("500 must surface");
    assert!(err.is_retryable(), "5xx is transient");
}

#[test]
fn get_json_surfaces_a_non_retryable_error_on_4xx() {
    let url = canned_server(404, r#"{"error":"not found"}"#, 1);
    let client = TransportClient::new(TransportConfig::new(&url)).unwrap();

    let err = client
        .get_json::<Widget>(&url)
        .expect_err("404 must surface");
    assert!(!err.is_retryable(), "4xx is permanent");
}

#[test]
fn get_json_rejects_a_response_that_is_not_valid_json_for_the_target_type() {
    // The server was reached and answered — a body that doesn't fit the
    // expected shape is `InvalidResponse`, not `Network`: reached-and-answered,
    // so it must not get the longer connectivity-blip retry budget (#414).
    let url = canned_server(200, r#"{"unexpected":"shape"}"#, 1);
    let client = TransportClient::new(TransportConfig::new(&url)).unwrap();

    let err = client
        .get_json::<Widget>(&url)
        .expect_err("missing required fields must fail to deserialize");
    assert!(
        matches!(err, transport::TransportError::InvalidResponse(_)),
        "got {err:?}"
    );
    assert!(!err.is_network_error(), "reached-and-answered, not a blip");
}

// ── get_bytes (issue #30/#73's content artifact download) ──────────────────

#[test]
fn get_bytes_fetches_the_raw_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_request(&mut stream);
        write_binary_response(&mut stream, 200, b"rule-file-bytes");
    });
    let url = format!("http://{addr}/api/content/artifact");
    let client = TransportClient::new(TransportConfig::new(format!("http://{addr}"))).unwrap();

    let bytes = client.get_bytes(&url, &[], 1024).unwrap();
    assert_eq!(bytes, b"rule-file-bytes");
    handle.join().unwrap();
}

#[test]
fn get_bytes_percent_encodes_query_parameters() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let line = read_request_line(&mut stream);
        write_binary_response(&mut stream, 200, b"ok");
        line
    });
    let url = format!("http://{addr}/api/content/artifact");
    let client = TransportClient::new(TransportConfig::new(format!("http://{addr}"))).unwrap();

    let _ = client
        .get_bytes(&url, &[("path", "rules/a b.sigma"), ("sha256", "ab")], 1024)
        .unwrap();
    let line = handle.join().unwrap();
    assert!(
        line.contains("path=rules%2Fa%20b.sigma") || line.contains("path=rules%2Fa+b.sigma"),
        "query must be percent-encoded, got: {line}"
    );
    assert!(line.contains("sha256=ab"));
}

#[test]
fn get_bytes_rejects_a_body_larger_than_the_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_request(&mut stream);
        write_binary_response(&mut stream, 200, &[0u8; 100]);
    });
    let url = format!("http://{addr}/api/content/artifact");
    let client = TransportClient::new(TransportConfig::new(format!("http://{addr}"))).unwrap();

    let err = client
        .get_bytes(&url, &[], 10)
        .expect_err("a 100-byte body must not fit a 10-byte limit");
    assert!(matches!(err, transport::TransportError::InvalidResponse(_)));
}
