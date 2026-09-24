//! The single funnel every alert goes through (issue #388): operator-visible
//! stderr line, the `alerts.ndjson` log, and an in-memory ring buffer of the
//! most recent alerts that the IPC `recent_detections` endpoint serves to
//! `cli detections`.
//!
//! Before #388, three call sites wrote alerts on their own (`DetectionSink::emit`,
//! the YARA scan worker, and YARA-triggered quarantine), each repeating the
//! `eprintln!` + `alert_log.write` pair. Routing all three through
//! [`AlertLog::record`] makes it impossible for an alert to reach the log file
//! but miss the CLI view (or the reverse).

use std::{collections::VecDeque, sync::Mutex};

use sinks::{AlertRecord, JsonlWriter};

/// How many recent alerts the agent keeps in memory for `cli detections`.
/// Equal to `ipc::RECENT_DETECTIONS_HARD_LIMIT`, the most a client can ask
/// for in one call (asserted by a test in `ipc_handler`).
pub(crate) const RECENT_ALERTS_CAPACITY: usize = 256;

/// One alert as kept in memory for the CLI. Mirrors [`AlertRecord`] field for
/// field; kept as the agent's own type so this module does not depend on the
/// IPC wire format (the handler maps it to `ipc::DetectionSummary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecentAlert {
    pub(crate) emitted_at_ns: u64,
    pub(crate) technique: String,
    pub(crate) message: String,
}

/// Bounded, oldest-first buffer of the most recent alerts. When full, pushing
/// evicts the oldest entry — a long-running agent keeps a constant memory
/// footprint (no unbounded growth, per the project's long-lived-agent rule).
pub(crate) struct RecentAlerts {
    capacity: usize,
    inner: Mutex<VecDeque<RecentAlert>>,
}

impl RecentAlerts {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    pub(crate) fn push(&self, alert: RecentAlert) {
        if self.capacity == 0 {
            return;
        }
        let mut buf = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buf.len() == self.capacity {
            buf.pop_front();
        }
        buf.push_back(alert);
    }

    /// The `limit` most recent alerts, oldest first (the order the IPC
    /// protocol documents for `RecentDetectionsResponse`).
    pub(crate) fn latest(&self, limit: usize) -> Vec<RecentAlert> {
        let buf = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let skip = buf.len().saturating_sub(limit);
        buf.iter().skip(skip).cloned().collect()
    }
}

/// The alert writer shared by the detection sink, the YARA worker, and
/// quarantine. Cheap to share behind an `Arc`.
pub(crate) struct AlertLog {
    file: JsonlWriter,
    recent: RecentAlerts,
}

impl AlertLog {
    pub(crate) fn open(path: &std::path::Path, recent_capacity: usize) -> std::io::Result<Self> {
        Ok(Self {
            file: JsonlWriter::open(path)?,
            recent: RecentAlerts::new(recent_capacity),
        })
    }

    /// Records one alert everywhere it must appear. Highlighted on stderr
    /// (stdout carries nothing in run mode) so an alert is not lost in
    /// terminal noise.
    pub(crate) fn record(&self, technique: &str, message: String) {
        eprintln!("\x1b[1;31m[ALERT] {technique} — {message}\x1b[0m");
        let emitted_at_ns = schema::time::now_ns();
        self.file.write(&AlertRecord {
            timestamp_ns: emitted_at_ns,
            technique: technique.to_string(),
            message: message.clone(),
        });
        self.recent.push(RecentAlert {
            emitted_at_ns,
            technique: technique.to_string(),
            message,
        });
    }

    pub(crate) fn latest(&self, limit: usize) -> Vec<RecentAlert> {
        self.recent.latest(limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(n: u64) -> RecentAlert {
        RecentAlert {
            emitted_at_ns: n,
            technique: format!("T{n}"),
            message: format!("m{n}"),
        }
    }

    #[test]
    fn keeps_at_most_capacity_evicting_the_oldest() {
        let buf = RecentAlerts::new(3);
        for n in 1..=5 {
            buf.push(alert(n));
        }
        let got: Vec<u64> = buf.latest(10).iter().map(|a| a.emitted_at_ns).collect();
        assert_eq!(got, vec![3, 4, 5]);
    }

    #[test]
    fn latest_returns_the_newest_entries_oldest_first() {
        let buf = RecentAlerts::new(10);
        for n in 1..=5 {
            buf.push(alert(n));
        }
        let got: Vec<u64> = buf.latest(2).iter().map(|a| a.emitted_at_ns).collect();
        assert_eq!(got, vec![4, 5]);
    }

    #[test]
    fn empty_buffer_and_zero_limit_return_nothing() {
        let buf = RecentAlerts::new(4);
        assert!(buf.latest(5).is_empty());
        buf.push(alert(1));
        assert!(buf.latest(0).is_empty());
    }

    #[test]
    fn zero_capacity_never_stores() {
        let buf = RecentAlerts::new(0);
        buf.push(alert(1));
        assert!(buf.latest(10).is_empty());
    }

    #[test]
    fn record_reaches_both_the_file_and_the_recent_buffer() {
        let dir = std::env::temp_dir().join(format!("synthaea-alerts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alerts.ndjson");
        let log = AlertLog::open(&path, 8).unwrap();
        log.record("T1543.003", "service installed".to_string());

        let recent = log.latest(8);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].technique, "T1543.003");
        assert_eq!(recent[0].message, "service installed");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("T1543.003"));
        assert!(on_disk.contains("service installed"));
    }
}
