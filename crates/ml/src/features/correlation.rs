//! Correlation features for the T1 behavior scorer — the "multi-events per pid"
//! vector, Rust mirror of `ml/synthaea_ml/features/correlation.py`.
//!
//! A second, complementary signal to [`super::cmdline`], never merged into one model
//! (2026-08-27 decision): the two vectors differ in temporal availability (a cmdline
//! is ready the instant an `Exec` arrives; this one only once the correlator window
//! is populated) and in statistical nature. Same parity discipline as the cmdline
//! seam — locked by `ml/tests/fixtures/correlation_golden.jsonl`.
//!
//! No trained model ships against this yet: it needs a dedicated benign multi-event
//! capture campaign (#44), not the isolated-cmdline baselines we have. The extractor
//! and its parity are migrated now so the training data can be scored the moment it
//! exists.

use std::collections::HashSet;

use correlator::EventBus;
use schema::Event;

/// Write intent on a `FileOpen` — mirror of `correlator`'s crate-private
/// `is_file_write` and of `correlation.py::_is_file_write`. Duplicated deliberately:
/// the correlator does not export it, and a bit test is cheaper to mirror than to
/// plumb a new public API through the platform boundary.
fn is_file_write(event: &Event) -> bool {
    const O_WRONLY: u32 = 0o1;
    const O_RDWR: u32 = 0o2;
    const O_CREAT: u32 = 0o100;
    match event {
        Event::FileOpen(f) => f.flags & (O_WRONLY | O_RDWR | O_CREAT) != 0,
        _ => false,
    }
}

/// Feature names in output order — must match `correlation.py::FEATURE_NAMES`.
pub const FEATURE_NAMES: [&str; 8] = [
    "spawn_count",
    "connect_count",
    "filewrite_count",
    "unique_daddr_count",
    "unique_dport_count",
    "has_full_chain",
    "span_s",
    "event_count",
];

/// The 8-feature correlation vector for `pid` over the bus's current window, in
/// [`FEATURE_NAMES`] order. Pid filtering happens here (mirror of the Python side
/// taking the whole window), via [`EventBus::events_for_pid`].
#[must_use]
pub fn extract_features(bus: &EventBus, pid: u32) -> [f32; 8] {
    let events: Vec<&Event> = bus.events_for_pid(pid).collect();

    let spawn_count = events
        .iter()
        .filter(|e| matches!(e, Event::Exec(_)))
        .count();
    let connect_count = events
        .iter()
        .filter(|e| matches!(e, Event::Connect(_)))
        .count();
    let filewrite_count = events.iter().filter(|e| is_file_write(e)).count();

    let mut daddrs = HashSet::new();
    let mut dports = HashSet::new();
    for e in &events {
        if let Event::Connect(c) = e {
            daddrs.insert(c.daddr);
            dports.insert(c.dport);
        }
    }

    let has_full_chain = if spawn_count >= 1 && connect_count >= 1 && filewrite_count >= 1 {
        1.0
    } else {
        0.0
    };

    let span_s = match (
        events.iter().map(|e| e.meta().timestamp_ns).min(),
        events.iter().map(|e| e.meta().timestamp_ns).max(),
    ) {
        (Some(min), Some(max)) => (max - min) as f32 / 1_000_000_000.0,
        _ => 0.0,
    };

    [
        spawn_count as f32,
        connect_count as f32,
        filewrite_count as f32,
        daddrs.len() as f32,
        dports.len() as f32,
        has_full_chain,
        span_s,
        events.len() as f32,
    ]
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use schema::{ConnectEvent, EventMeta, ExecEvent, FileOpenEvent, User};

    use super::*;

    fn meta(pid: u32, ts_ns: u64) -> EventMeta {
        EventMeta {
            pid,
            ppid: 0,
            user: User::Unix { uid: 0, gid: 0 },
            timestamp_ns: ts_ns,
            comm: "proc".into(),
        }
    }

    fn exec(pid: u32, ts_ns: u64) -> Event {
        Event::Exec(ExecEvent {
            meta: meta(pid, ts_ns),
            image_path: String::new(),
            cmdline: String::new(),
            argv: vec![],
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
        })
    }

    fn connect(pid: u32, ts_ns: u64, dport: u16) -> Event {
        Event::Connect(ConnectEvent {
            meta: meta(pid, ts_ns),
            daddr: "127.0.0.1".parse().unwrap(),
            dport,
        })
    }

    fn file_write(pid: u32, ts_ns: u64) -> Event {
        Event::FileOpen(FileOpenEvent {
            meta: meta(pid, ts_ns),
            path: String::new(),
            flags: 0o1 | 0o100, // O_WRONLY | O_CREAT
        })
    }

    #[test]
    fn empty_vector_for_absent_pid() {
        let bus = EventBus::new(Duration::from_secs(60));
        assert_eq!(extract_features(&bus, 1234), [0.0; 8]);
    }

    #[test]
    fn full_chain_sets_has_full_chain() {
        let mut bus = EventBus::new(Duration::from_secs(60));
        bus.push(exec(99, 0));
        bus.push(connect(99, 1_000_000_000, 4444));
        bus.push(file_write(99, 2_000_000_000));

        let f = extract_features(&bus, 99);
        assert_eq!(f[0], 1.0, "spawn_count");
        assert_eq!(f[1], 1.0, "connect_count");
        assert_eq!(f[2], 1.0, "filewrite_count");
        assert_eq!(f[5], 1.0, "has_full_chain");
        assert_eq!(f[6], 2.0, "span_s");
        assert_eq!(f[7], 3.0, "event_count");
    }

    #[test]
    fn unique_destinations_counted_once() {
        let mut bus = EventBus::new(Duration::from_secs(60));
        bus.push(connect(7, 0, 4444));
        bus.push(connect(7, 1_000_000_000, 4444)); // same dest
        bus.push(connect(7, 2_000_000_000, 8080)); // different port

        let f = extract_features(&bus, 7);
        assert_eq!(f[1], 3.0, "connect_count");
        assert_eq!(f[3], 1.0, "unique_daddr_count");
        assert_eq!(f[4], 2.0, "unique_dport_count");
    }

    #[test]
    fn pids_are_isolated() {
        let mut bus = EventBus::new(Duration::from_secs(60));
        bus.push(exec(1, 0));
        bus.push(connect(2, 1_000_000_000, 4444));
        assert_eq!(extract_features(&bus, 1)[1], 0.0);
        assert_eq!(extract_features(&bus, 2)[0], 0.0);
    }
}
