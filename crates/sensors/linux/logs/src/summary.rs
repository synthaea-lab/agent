//! Per-window summary of one access-log source (ADR-0022 §3).
//!
//! The server sees requests that matched no signature only through this: counters and
//! the clients with the most failing requests. Bounded by construction: the tracked
//! client table stops growing at [`MAX_TRACKED_CLIENTS`] (a scan from a /16 must not
//! grow agent memory), and the ranking is [`TOP_CLIENTS`] long.

use std::collections::HashMap;
use std::net::IpAddr;

use schema::{EventMeta, HttpClientCount, HttpSummaryEvent, User};

use crate::{AccessRecord, http::HTTP_LOG_COMM};

/// Window length, in seconds, ADR-0022 §3.
pub const WINDOW_SECS: u32 = 60;
/// Distinct client addresses tracked per window; further ones are counted in
/// `requests` but not in `distinct_clients` or the ranking.
pub const MAX_TRACKED_CLIENTS: usize = 4096;
/// Length of the failing-clients ranking.
pub const TOP_CLIENTS: usize = 5;

/// Accumulates one source's requests and yields a [`HttpSummaryEvent`] per window.
#[derive(Debug)]
pub struct Summarizer {
    source: String,
    window_ns: u64,
    window_start_ns: Option<u64>,
    requests: u32,
    status_4xx: u32,
    status_5xx: u32,
    /// Client address to its failing-request count in this window.
    clients: HashMap<IpAddr, u32>,
}

impl Summarizer {
    /// `source` is the declared log path, carried on the event.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            window_ns: u64::from(WINDOW_SECS) * 1_000_000_000,
            window_start_ns: None,
            requests: 0,
            status_4xx: 0,
            status_5xx: 0,
            clients: HashMap::new(),
        }
    }

    /// Counts one request. The window starts at its first request.
    pub fn observe(&mut self, record: &AccessRecord, now_ns: u64) {
        self.window_start_ns.get_or_insert(now_ns);
        self.requests = self.requests.saturating_add(1);
        let failed = match record.status {
            400..=499 => {
                self.status_4xx = self.status_4xx.saturating_add(1);
                true
            }
            500..=599 => {
                self.status_5xx = self.status_5xx.saturating_add(1);
                true
            }
            _ => false,
        };
        if let Ok(client) = record.client.parse::<IpAddr>() {
            if let Some(failures) = self.clients.get_mut(&client) {
                *failures = failures.saturating_add(u32::from(failed));
            } else if self.clients.len() < MAX_TRACKED_CLIENTS {
                self.clients.insert(client, u32::from(failed));
            }
        }
    }

    /// Ends the window and returns its summary once `now_ns` is a full window past
    /// its first request; `None` otherwise, and for a window with no request (a quiet
    /// log is normal, ADR-0022 decision 4, and an empty summary says nothing).
    pub fn tick(&mut self, now_ns: u64) -> Option<HttpSummaryEvent> {
        let start = self.window_start_ns?;
        if now_ns.saturating_sub(start) < self.window_ns {
            return None;
        }
        let mut ranked: Vec<HttpClientCount> = self
            .clients
            .iter()
            .filter(|(_, failures)| **failures > 0)
            .map(|(client, failures)| HttpClientCount {
                client: *client,
                failures: *failures,
            })
            .collect();
        ranked.sort_by(|a, b| b.failures.cmp(&a.failures).then(a.client.cmp(&b.client)));
        ranked.truncate(TOP_CLIENTS);

        let event = HttpSummaryEvent {
            meta: EventMeta {
                pid: 0,
                ppid: 0,
                user: User::Unknown,
                timestamp_ns: now_ns,
                comm: HTTP_LOG_COMM.to_owned(),
                container: None,
                process_generation: None,
                parent_process_generation: None,
            },
            source: self.source.clone(),
            window_secs: WINDOW_SECS,
            requests: self.requests,
            status_4xx: self.status_4xx,
            status_5xx: self.status_5xx,
            distinct_clients: u32::try_from(self.clients.len()).unwrap_or(u32::MAX),
            top_clients: ranked,
        };
        self.window_start_ns = None;
        self.requests = 0;
        self.status_4xx = 0;
        self.status_5xx = 0;
        self.clients.clear();
        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessFormat, parse_access_line};

    const SEC: u64 = 1_000_000_000;

    fn rec(client: &str, status: u16) -> AccessRecord {
        let line = format!(r#"{client} - - [t] "GET / HTTP/1.1" {status} 1"#);
        parse_access_line(&line, AccessFormat::Common).unwrap()
    }

    #[test]
    fn a_window_counts_statuses_clients_and_ranks_failures() {
        let mut s = Summarizer::new("/var/log/nginx/access.log");
        let t0 = 100 * SEC;
        for _ in 0..5 {
            s.observe(&rec("198.51.100.7", 404), t0);
        }
        for _ in 0..2 {
            s.observe(&rec("198.51.100.8", 500), t0);
        }
        s.observe(&rec("203.0.113.1", 200), t0);
        s.observe(&rec("2001:db8::5", 200), t0);

        assert!(s.tick(t0 + 59 * SEC).is_none(), "window not over yet");
        let e = s.tick(t0 + 60 * SEC).unwrap();
        assert_eq!((e.requests, e.status_4xx, e.status_5xx), (9, 5, 2));
        assert_eq!(e.distinct_clients, 4);
        assert_eq!(e.source, "/var/log/nginx/access.log");
        assert_eq!(e.window_secs, 60);
        let ranked: Vec<(String, u32)> = e
            .top_clients
            .iter()
            .map(|c| (c.client.to_string(), c.failures))
            .collect();
        assert_eq!(
            ranked,
            [
                ("198.51.100.7".to_owned(), 5),
                ("198.51.100.8".to_owned(), 2)
            ],
            "only clients with failures are ranked, worst first"
        );
    }

    #[test]
    fn the_window_resets_and_a_quiet_one_yields_nothing() {
        let mut s = Summarizer::new("x");
        s.observe(&rec("203.0.113.1", 200), 10 * SEC);
        assert!(s.tick(80 * SEC).is_some());
        assert!(s.tick(500 * SEC).is_none(), "no request, no summary");
        s.observe(&rec("203.0.113.2", 200), 600 * SEC);
        let e = s.tick(660 * SEC).unwrap();
        assert_eq!(
            (e.requests, e.distinct_clients),
            (1, 1),
            "nothing carried over"
        );
    }

    #[test]
    fn tracked_clients_are_bounded_but_requests_are_still_counted() {
        let mut s = Summarizer::new("x");
        for i in 0..(MAX_TRACKED_CLIENTS + 100) {
            let ip = format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255);
            s.observe(&rec(&ip, 404), SEC);
        }
        let e = s.tick(61 * SEC).unwrap();
        assert_eq!(e.requests as usize, MAX_TRACKED_CLIENTS + 100);
        assert_eq!(e.distinct_clients as usize, MAX_TRACKED_CLIENTS);
        assert_eq!(e.top_clients.len(), TOP_CLIENTS);
    }

    #[test]
    fn a_host_name_client_counts_as_a_request_not_as_a_client() {
        let mut s = Summarizer::new("x");
        let line = r#"www.example.org - - [t] "GET / HTTP/1.1" 404 1"#;
        s.observe(&parse_access_line(line, AccessFormat::Common).unwrap(), SEC);
        let e = s.tick(61 * SEC).unwrap();
        assert_eq!(
            (e.requests, e.distinct_clients, e.top_clients.len()),
            (1, 0, 0)
        );
    }
}
