//! The T1 behavior vector: cmdline (9) + correlation (8) + lineage (6) = 23 features,
//! in that order. The Rust mirror of `ml/synthaea_ml/features/t1.py` (issue #617).
//!
//! One process incarnation `(pid, generation)` yields one vector: the command line and
//! the parent lineage come from its most recent exec in the bus window, the correlation
//! block from that incarnation's events. Both lookups go through
//! [`EventBus::events_for_pid`], so a recycled pid's earlier life feeds neither the
//! counts nor the parent that is scored (#590): two known, different generations never
//! mix, a missing stamp keeps the pid-only behavior.
//!
//! A parity seam like the other extractors: `ml/tests/fixtures/t1_golden.jsonl` is
//! produced by Python (`gen_t1_parity.py`) and checked from both sides. A T1 model
//! trained on the Python vectors only scores consistently here if they match.

use correlator::EventBus;
use schema::{Event, ExecEvent};

use super::{cmdline, correlation, lineage};

/// Number of features in the T1 vector.
pub const FEATURE_COUNT: usize = 23;

/// Feature names in vector order: cmdline, then correlation, then lineage.
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = {
    let mut names = [""; FEATURE_COUNT];
    let mut i = 0;
    while i < 9 {
        names[i] = cmdline::FEATURE_NAMES[i];
        i += 1;
    }
    let mut j = 0;
    while j < 8 {
        names[9 + j] = correlation::FEATURE_NAMES[j];
        j += 1;
    }
    let mut k = 0;
    while k < 6 {
        names[17 + k] = lineage::FEATURE_NAMES[k];
        k += 1;
    }
    names
};

/// The 23-feature T1 vector for the process incarnation `(pid, generation)` over the
/// bus's current window, or `None` when the window holds no exec for it: without one
/// there is no command line and no lineage to score (the Python dataset builder skips
/// such an incarnation the same way).
#[must_use]
pub fn extract_features(bus: &EventBus, pid: u32, generation: Option<u64>) -> Option<[f32; 23]> {
    let exec = latest_exec(bus, pid, generation)?;
    let mut out = [0.0_f32; FEATURE_COUNT];
    out[..9].copy_from_slice(&cmdline::extract_features(&exec.ml_cmdline()));
    out[9..17].copy_from_slice(&correlation::extract_features(bus, pid, generation));
    out[17..].copy_from_slice(&lineage::extract_features(exec));
    Some(out)
}

/// The incarnation's most recent exec. On equal timestamps the earlier one in the
/// window wins, like Python's `max(..., key=ts_ns)`.
fn latest_exec(bus: &EventBus, pid: u32, generation: Option<u64>) -> Option<&ExecEvent> {
    bus.events_for_pid(pid, generation)
        .filter_map(|event| match event {
            Event::Exec(exec) => Some(exec),
            _ => None,
        })
        .fold(None, |best: Option<&ExecEvent>, exec| match best {
            Some(b) if b.meta.timestamp_ns >= exec.meta.timestamp_ns => Some(b),
            _ => Some(exec),
        })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use schema::{ConnectEvent, EventMeta, ExecEvent, fixtures};

    use super::*;

    fn exec(pid: u32, generation: Option<u64>, ts: u64, parent: &str, cmd: &str) -> Event {
        Event::Exec(ExecEvent {
            meta: EventMeta {
                pid,
                process_generation: generation,
                timestamp_ns: ts,
                ..fixtures::meta()
            },
            parent_comm: Some(parent.into()),
            cmdline: cmd.into(),
            ..fixtures::exec()
        })
    }

    fn connect(pid: u32, generation: Option<u64>, ts: u64) -> Event {
        Event::Connect(ConnectEvent {
            meta: EventMeta {
                pid,
                process_generation: generation,
                timestamp_ns: ts,
                ..fixtures::meta()
            },
            ..fixtures::connect()
        })
    }

    fn bus(events: Vec<Event>) -> EventBus {
        let mut bus = EventBus::new(Duration::from_secs(60));
        for event in events {
            bus.push(event);
        }
        bus
    }

    #[test]
    fn names_are_cmdline_then_correlation_then_lineage() {
        assert_eq!(FEATURE_NAMES.len(), 23);
        assert_eq!(FEATURE_NAMES[0], cmdline::FEATURE_NAMES[0]);
        assert_eq!(FEATURE_NAMES[9], correlation::FEATURE_NAMES[0]);
        assert_eq!(FEATURE_NAMES[17], lineage::FEATURE_NAMES[0]);
        assert_eq!(FEATURE_NAMES[22], lineage::FEATURE_NAMES[5]);
        assert!(FEATURE_NAMES.iter().all(|n| !n.is_empty()));
    }

    #[test]
    fn no_exec_for_the_incarnation_yields_no_vector() {
        let bus = bus(vec![connect(7, Some(1), 1)]);
        assert!(extract_features(&bus, 7, Some(1)).is_none());
        assert!(extract_features(&bus, 99, None).is_none());
    }

    #[test]
    fn a_recycled_pids_earlier_parent_is_not_scored_as_the_new_process() {
        let bus = bus(vec![
            exec(9, Some(1), 10, "nginx", "sh"),
            connect(9, Some(1), 11),
            exec(9, Some(2), 20, "bash", "ls"),
        ]);
        let first = extract_features(&bus, 9, Some(1)).unwrap();
        let second = extract_features(&bus, 9, Some(2)).unwrap();
        // lineage block: parent_comm_is_webserver (index 19) and _is_shell (18)
        assert_eq!((first[19], first[18]), (1.0, 0.0));
        assert_eq!((second[19], second[18]), (0.0, 1.0));
        // correlation block: connect_count (index 10) must not leak into the new life
        assert_eq!((first[10], second[10]), (1.0, 0.0));
    }

    #[test]
    fn without_a_generation_the_latest_exec_of_the_pid_supplies_the_lineage() {
        let bus = bus(vec![
            exec(9, None, 10, "nginx", "sh"),
            exec(9, None, 20, "bash", "ls"),
        ]);
        let v = extract_features(&bus, 9, None).unwrap();
        assert_eq!(
            (v[19], v[18]),
            (0.0, 1.0),
            "the later exec (bash parent) wins"
        );
    }
}
