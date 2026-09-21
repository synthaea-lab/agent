//! Protected-resource monitoring (issue #71, capability 3): the agent watches its own
//! on-disk footprint through the live event stream, and treats a write-intent open of
//! one of those paths by any process other than itself as a high-severity detection —
//! "any non-`updater` writer" per the issue, though no updater (#30) exists yet to name
//! as the one legitimate exception, so today every foreign writer qualifies.
//!
//! Scope is deliberately limited to paths this agent process can know for certain at
//! its own runtime: its own executable (`std::env::current_exe`) plus the
//! alerts/events/heartbeat files it was launched with. It does **not** cover the
//! watchdog binary or the systemd unit/OpenRC install surface — those live in
//! `watchdog`'s own path resolution (`watchdog/src/service/linux.rs`), and naming them
//! here would mean either guessing the packaging layout or a cross-binary dependency,
//! neither of which this pass takes on; `watchdog::tamper` (#103) already covers that
//! surface from the install/supervise side. True deletion is also out of scope:
//! `FileOpenEvent` only observes `open(2)`, so this catches a foreign write, truncate,
//! or overwrite, not a foreign `rm`/`rename` — both gaps stay tracked by issue #71
//! rather than being silently implied as covered.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use schema::{Event, sensor::EventSink};

use crate::sink::DetectionSink;

/// Builds the set of paths this process treats as its own protected resources.
/// Best-effort on the executable path: `current_exe` can fail (rare — e.g. the binary
/// was unlinked out from under a running process), in which case the binary just isn't
/// watched rather than failing agent startup over a self-protection nicety.
pub(crate) fn protected_paths(alerts: &Path, events: &Path) -> Vec<PathBuf> {
    let mut paths = vec![
        alerts.to_path_buf(),
        events.to_path_buf(),
        crate::heartbeat::heartbeat_path_for(alerts),
    ];
    if let Ok(exe) = std::env::current_exe() {
        paths.push(exe);
    }
    paths
}

/// Wraps an inner [`EventSink`]: every event is forwarded unchanged, but a
/// [`Event::FileOpen`] is first checked against `protected` — a write-intent open of
/// one of those paths from any pid other than this process's own fires a real alert
/// through `sink`, the same `alerts.ndjson` path a rule/correlator/Sigma finding uses.
pub(crate) struct ProtectedResourceGuard<S> {
    inner: S,
    own_pid: u32,
    protected: Arc<[PathBuf]>,
    sink: Arc<DetectionSink>,
}

impl<S> ProtectedResourceGuard<S> {
    pub(crate) fn new(inner: S, protected: Vec<PathBuf>, sink: Arc<DetectionSink>) -> Self {
        Self {
            inner,
            own_pid: std::process::id(),
            protected: protected.into(),
            sink,
        }
    }
}

impl<S: EventSink> EventSink for ProtectedResourceGuard<S> {
    fn on_event(&self, event: Event) {
        if let Event::FileOpen(ref open) = event
            && open.meta.pid != self.own_pid
            && rules::has_write_intent(open.flags)
            && self
                .protected
                .iter()
                .any(|p| matches_protected(p, &open.path))
        {
            self.sink.emit(
                "T1562",
                &format!(
                    "pid {} (`{}`) opened protected agent resource {} for write",
                    open.meta.pid, open.meta.comm, open.path
                ),
            );
        }
        self.inner.on_event(event);
    }
}

/// `observed` may be relative to an unresolved directory file descriptor (the same
/// known eBPF-collector limitation `rules::check_persistence_write` tolerates) —
/// matching by path-component suffix, rather than full equality, handles a shortened
/// fragment while still comparing whole components (unlike a raw string suffix, which
/// would wrongly match `"myagent"` against a protected path ending in `"agent"`).
fn matches_protected(protected: &Path, observed: &str) -> bool {
    !observed.is_empty() && protected.ends_with(Path::new(observed))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingSink(Arc<AtomicUsize>);

    impl EventSink for CountingSink {
        fn on_event(&self, _event: Event) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn open_event(pid: u32, comm: &str, path: &str, flags: u32) -> Event {
        Event::FileOpen(schema::FileOpenEvent {
            meta: schema::EventMeta {
                pid,
                ppid: 1,
                comm: comm.to_string(),
                ..schema::fixtures::meta()
            },
            path: path.to_string(),
            flags,
        })
    }

    const O_WRONLY: u32 = 0o1;
    const O_RDONLY: u32 = 0o0;

    #[test]
    fn matches_protected_tolerates_a_dfd_relative_suffix() {
        assert!(matches_protected(Path::new("/opt/synthaea/agent"), "agent"));
        assert!(!matches_protected(
            Path::new("/opt/synthaea/agent"),
            "myagent"
        ));
        assert!(!matches_protected(Path::new("/opt/synthaea/agent"), ""));
    }

    #[test]
    fn a_foreign_write_to_a_protected_path_fires_an_alert() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let alerts_dir =
            std::env::temp_dir().join(format!("protected-test-{}", std::process::id()));
        std::fs::create_dir_all(&alerts_dir).unwrap();
        let alerts = alerts_dir.join("alerts.ndjson");
        let events = alerts_dir.join("events.jsonl");
        let sink = Arc::new(DetectionSink::new(rules::RuleState::new(), &alerts, &events).unwrap());

        let guard = ProtectedResourceGuard::new(
            CountingSink(forwarded.clone()),
            protected_paths(&alerts, &events),
            sink,
        );

        guard.on_event(open_event(9999, "evil", "alerts.ndjson", O_WRONLY));

        assert_eq!(
            forwarded.load(Ordering::Relaxed),
            1,
            "must still forward the event"
        );
        let written = std::fs::read_to_string(&alerts).unwrap();
        assert!(
            written.contains("T1562"),
            "expected a T1562 alert, got: {written}"
        );
        assert!(written.contains("evil"));

        let _ = std::fs::remove_dir_all(&alerts_dir);
    }

    #[test]
    fn own_writes_never_alert() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let alerts_dir =
            std::env::temp_dir().join(format!("protected-test-self-{}", std::process::id()));
        std::fs::create_dir_all(&alerts_dir).unwrap();
        let alerts = alerts_dir.join("alerts.ndjson");
        let events = alerts_dir.join("events.jsonl");
        let sink = Arc::new(DetectionSink::new(rules::RuleState::new(), &alerts, &events).unwrap());

        let guard = ProtectedResourceGuard::new(
            CountingSink(forwarded.clone()),
            protected_paths(&alerts, &events),
            sink,
        );

        guard.on_event(open_event(
            std::process::id(),
            "agent",
            "alerts.ndjson",
            O_WRONLY,
        ));

        let written = std::fs::read_to_string(&alerts).unwrap();
        assert!(
            !written.contains("T1562"),
            "must not alert on its own writes, got: {written}"
        );

        let _ = std::fs::remove_dir_all(&alerts_dir);
    }

    #[test]
    fn a_read_only_open_never_alerts() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let alerts_dir =
            std::env::temp_dir().join(format!("protected-test-read-{}", std::process::id()));
        std::fs::create_dir_all(&alerts_dir).unwrap();
        let alerts = alerts_dir.join("alerts.ndjson");
        let events = alerts_dir.join("events.jsonl");
        let sink = Arc::new(DetectionSink::new(rules::RuleState::new(), &alerts, &events).unwrap());

        let guard = ProtectedResourceGuard::new(
            CountingSink(forwarded.clone()),
            protected_paths(&alerts, &events),
            sink,
        );

        guard.on_event(open_event(9999, "cat", "alerts.ndjson", O_RDONLY));

        let written = std::fs::read_to_string(&alerts).unwrap();
        assert!(
            !written.contains("T1562"),
            "a mere read must not alert, got: {written}"
        );

        let _ = std::fs::remove_dir_all(&alerts_dir);
    }
}
