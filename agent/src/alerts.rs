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

use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

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
    /// Whether the stderr line carries the whole message (`run --alert-details`, #319).
    stderr_details: AtomicBool,
}

impl AlertLog {
    pub(crate) fn open(path: &std::path::Path, recent_capacity: usize) -> std::io::Result<Self> {
        Ok(Self {
            file: JsonlWriter::open(path)?,
            recent: RecentAlerts::new(recent_capacity),
            stderr_details: AtomicBool::new(false),
        })
    }

    /// Prints the whole message on stderr from now on, not just its summary
    /// (`run --alert-details`). The file and the recent buffer always get it.
    pub(crate) fn set_stderr_details(&self, details: bool) {
        self.stderr_details.store(details, Ordering::Relaxed);
    }

    /// Records one alert everywhere it must appear. Highlighted on stderr
    /// (stdout carries nothing in run mode) so an alert is not lost in
    /// terminal noise. `alerts.ndjson` and `cli detections` get the full
    /// message; stderr gets [`stderr_alert_line`], which by default leaves out
    /// the message body (#319: a rule message embeds the command line).
    pub(crate) fn record(&self, technique: &str, message: String) {
        let details = self.stderr_details.load(Ordering::Relaxed);
        eprintln!(
            "\x1b[1;31m{}\x1b[0m",
            stderr_alert_line(technique, &message, details)
        );
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

pub(crate) fn format_alert_line(technique: &str, message: &str) -> String {
    format!("[ALERT] {technique} — {message}")
}

/// The stderr form of an alert. With `details`, the whole message, as in the
/// file. Without (the default), the technique and, when the message starts the
/// way rule messages do (`pid=<n> comm=<name>: …`), that pid and comm: an event's
/// payload never reaches the terminal at default verbosity (CLAUDE.md, #319),
/// and the message body is where rules put the command line.
pub(crate) fn stderr_alert_line(technique: &str, message: &str, details: bool) -> String {
    if details {
        return format_alert_line(technique, message);
    }
    match process_identity(message) {
        Some(identity) => format!("[ALERT] {technique} — {identity} (details in alerts.ndjson)"),
        None => format!("[ALERT] {technique} (details in alerts.ndjson)"),
    }
}

/// `pid=<n> comm=<name>` from the head of a rule message, or `None` when the
/// message does not start that way. `comm` is what the process named itself, so
/// it ends at the first `": "` (a `comm` containing one is cut there, which shows
/// less, never more) and control characters are replaced, so a crafted name
/// cannot drive the terminal.
fn process_identity(message: &str) -> Option<String> {
    let rest = message.strip_prefix("pid=")?;
    let digits = rest.find(|c: char| !c.is_ascii_digit())?;
    if digits == 0 {
        return None;
    }
    let (pid, rest) = rest.split_at(digits);
    let rest = rest.strip_prefix(" comm=")?;
    let comm = &rest[..rest.find(": ")?];
    let comm: String = comm
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    Some(format!("pid={pid} comm={comm}"))
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

    /// A real rule message, so the summary is pinned to the format rules
    /// actually produce, not to a hand-written copy of it.
    fn base64_alert_message() -> String {
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = 4242;
        exec.meta.comm = "bash".into();
        exec.cmdline = "base64 -d payload.b64 --token=S3cret".into();
        let alerts = rules::evaluate_exec(&exec);
        let alert = alerts
            .iter()
            .find(|a| a.technique == "T1059.004")
            .expect("the base64 rule fires on this command line");
        alert.message.clone()
    }

    #[test]
    fn the_default_stderr_line_names_the_process_but_not_the_command_line() {
        let message = base64_alert_message();
        let line = stderr_alert_line("T1059.004", &message, false);
        assert_eq!(
            line,
            "[ALERT] T1059.004 — pid=4242 comm=bash (details in alerts.ndjson)"
        );
    }

    #[test]
    fn alert_details_prints_the_whole_message() {
        let message = base64_alert_message();
        assert_eq!(
            stderr_alert_line("T1059.004", &message, true),
            format_alert_line("T1059.004", &message)
        );
        assert!(stderr_alert_line("T1059.004", &message, true).contains("base64 -d"));
    }

    #[test]
    fn a_message_without_a_process_prefix_prints_the_technique_only() {
        for message in [
            "service installed",
            "pid= comm=x: no digits",
            "pid=12comm=x: no space",
            "pid=12 comm=no-separator",
            "",
        ] {
            assert_eq!(
                stderr_alert_line("T1543.003", message, false),
                "[ALERT] T1543.003 (details in alerts.ndjson)",
                "{message:?}"
            );
        }
    }

    #[test]
    fn a_crafted_comm_cannot_drive_the_terminal_or_smuggle_text() {
        let line = stderr_alert_line("T1059", "pid=7 comm=a\x1b[2Jb: curl -u a:S3cret h", false);
        assert_eq!(
            line,
            "[ALERT] T1059 — pid=7 comm=a?[2Jb (details in alerts.ndjson)"
        );
        // A comm that itself contains ": " is cut at the first one: less shown, never more.
        let line = stderr_alert_line("T1059", "pid=7 comm=x: y: curl -u a:S3cret h", false);
        assert_eq!(
            line,
            "[ALERT] T1059 — pid=7 comm=x (details in alerts.ndjson)"
        );
    }

    #[test]
    fn the_file_keeps_the_whole_message_whatever_the_stderr_setting() {
        let dir =
            std::env::temp_dir().join(format!("synthaea-alerts-details-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alerts.ndjson");
        let _ = std::fs::remove_file(&path);
        let log = AlertLog::open(&path, 8).unwrap();
        let message = base64_alert_message();
        log.record("T1059.004", message.clone());
        log.set_stderr_details(true);
        log.record("T1059.004", message.clone());

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.matches("base64 -d payload.b64").count(), 2);
        assert!(log.latest(8).iter().all(|alert| alert.message == message));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
