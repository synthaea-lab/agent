//! Correlation features for the T2 behaviour scorer — the "multi-events per pid"
//! vector, Rust mirror of `ml/synthaea_ml/features/correlation.py`.
//!
//! A second, complementary signal to [`super::cmdline`], never merged into one model
//! (2026-08-27 decision): the two vectors differ in temporal availability (a cmdline
//! is ready the instant an `Exec` arrives; this one only once the correlator window
//! is populated) and in statistical nature. Parity with the Python definition is
//! pinned end-to-end by `crates/ml/tests/capture_parity.rs` (a real `events.jsonl`
//! capture → these vectors, checked against the Python aggregator's output).
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

/// Event variants this vector is built from — process spawn, outbound connect, file
/// open, netlink-observed flow (ADR-0008). `span_s` and `event_count` are computed
/// over these only: the Python aggregator (`aggregate_correlation._flatten`,
/// `RAW_EVENT_TYPES`) drops every other category before windowing, so counting e.g. a
/// `DnsQuery` here would silently inflate both features relative to the training
/// vectors.
///
/// ADR-0008 side effect: gating the whole vector on this filter means `event_count`
/// and `span_s` grow for any process with netlink traffic, not just the two fields
/// `NetworkFlow` feeds below. `connect_count` (T1's `BehaviorVector`) is unaffected —
/// it filters on `Event::Connect` explicitly, independent of this gate.
fn is_modeled(event: &Event) -> bool {
    matches!(
        event,
        Event::Exec(_) | Event::Connect(_) | Event::FileOpen(_) | Event::NetworkFlow(_)
    )
}

/// The 8-feature correlation vector for `pid` over the bus's current window, in
/// [`FEATURE_NAMES`] order. Pid filtering happens here (mirror of the Python side
/// taking the whole window), via [`EventBus::events_for_pid`].
#[must_use]
pub fn extract_features(bus: &EventBus, pid: u32) -> [f32; 8] {
    let events: Vec<&Event> = bus.events_for_pid(pid).filter(|e| is_modeled(e)).collect();

    let spawn_count = events
        .iter()
        .filter(|e| matches!(e, Event::Exec(_)))
        .count();
    let connect_count = events
        .iter()
        .filter(|e| matches!(e, Event::Connect(_)))
        .count();
    let filewrite_count = events.iter().filter(|e| is_file_write(e)).count();

    // ADR-0008: NetworkFlow (netlink) and Connect are absorbed into the same
    // daddr/dport sets — one count of "distinct destinations touched", regardless of
    // which sensor captured them (mirrors BEACON's check_beacon/check_beacon_flow
    // convergence on shared state).
    let mut daddrs = HashSet::new();
    let mut dports = HashSet::new();
    for e in &events {
        match e {
            Event::Connect(c) => {
                daddrs.insert(c.daddr);
                dports.insert(c.dport);
            }
            Event::NetworkFlow(f) => {
                daddrs.insert(f.daddr);
                dports.insert(f.dport);
            }
            _ => {}
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

    use schema::{
        ConnectEvent, DnsQueryEvent, EventMeta, ExecEvent, FileOpenEvent, NetworkFlowEvent, User,
    };

    use super::*;

    fn meta(pid: u32, ts_ns: u64) -> EventMeta {
        EventMeta {
            pid,
            user: User::Unix { uid: 0, gid: 0 },
            timestamp_ns: ts_ns,
            comm: "proc".into(),
            ..schema::fixtures::meta()
        }
    }

    fn exec(pid: u32, ts_ns: u64) -> Event {
        Event::Exec(ExecEvent {
            meta: meta(pid, ts_ns),
            ..schema::fixtures::exec()
        })
    }

    fn connect(pid: u32, ts_ns: u64, dport: u16) -> Event {
        Event::Connect(ConnectEvent {
            meta: meta(pid, ts_ns),
            daddr: "127.0.0.1".parse().unwrap(),
            dport,
        })
    }

    fn network_flow(pid: u32, ts_ns: u64, daddr: &str, dport: u16) -> Event {
        Event::NetworkFlow(NetworkFlowEvent {
            meta: meta(pid, ts_ns),
            local_port: 54321,
            daddr: daddr.parse().unwrap(),
            dport,
            protocol: 6,
            ..schema::fixtures::network_flow()
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
    fn network_flow_absorbed_into_same_daddr_dport_sets_as_connect() {
        // ADR-0008: Connect and NetworkFlow share one "distinct destinations" count —
        // an attacker whose traffic is seen only by netlink still shows up here.
        let mut bus = EventBus::new(Duration::from_secs(60));
        bus.push(connect(7, 0, 4444));
        bus.push(network_flow(7, 1_000_000_000, "10.0.0.1", 4444)); // same dest as connect
        bus.push(network_flow(7, 2_000_000_000, "10.0.0.2", 9999)); // netlink-only dest

        let f = extract_features(&bus, 7);
        assert_eq!(f[3], 3.0, "unique_daddr_count spans Connect + NetworkFlow");
        assert_eq!(f[4], 2.0, "unique_dport_count spans Connect + NetworkFlow");
        assert_eq!(
            f[7], 3.0,
            "event_count includes NetworkFlow (is_modeled gate)"
        );
    }

    #[test]
    fn non_modeled_events_do_not_perturb_span_or_count() {
        // The Python aggregator drops DnsQuery et al. before windowing; span_s and
        // event_count here must match — a later, unrelated DNS lookup must not
        // stretch the span or bump the count.
        let mut bus = EventBus::new(Duration::from_secs(60));
        bus.push(exec(5, 0));
        bus.push(connect(5, 1_000_000_000, 443));
        bus.push(Event::DnsQuery(DnsQueryEvent {
            meta: meta(5, 9_000_000_000),
            query: "c2.test".into(),
            qtype: 1,
            result: None,
            status: 0,
        }));

        let f = extract_features(&bus, 5);
        assert_eq!(f[7], 2.0, "event_count counts only modeled events");
        assert_eq!(f[6], 1.0, "span_s ignores the later DNS lookup");
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
