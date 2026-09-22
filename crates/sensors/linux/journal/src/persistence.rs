//! Maps a systemd unit's first-observed start into `schema::FileOpenEvent`
//! with [`schema::FLAG_PERSISTENCE_SYSTEMD_ARTIFACT`] set — the Linux side of
//! the same "reuse `FileOpenEvent` + a flag" shape `sensor-windows-eventlog`
//! uses for its own service-install event (7045, `FLAG_PERSISTENCE_ARTIFACT`),
//! rather than inventing a new `schema::Event` variant (see [`crate::auth`]'s
//! module doc for why that decision was deliberately left open until now).
//!
//! Deliberately narrower than "every [`JournalEvent::UnitStarted`]": journald's
//! `JOB_TYPE=start`/`JOB_RESULT=done` fires on *every* start of a unit, install
//! or routine restart alike — unlike Windows' 7045, which the Service Control
//! Manager only writes once, at actual registration. Firing a persistence
//! alert on every `cron.service` restart would be a correctness bug, not
//! fidelity to Windows' shape. [`UnitPersistenceTracker`] closes that gap the
//! pragmatic way: only the first start of a given unit *observed by this agent
//! process* counts as new — a unit already running before the agent started,
//! or already reported once, is routine lifecycle noise from here on. This is
//! an approximation of "just installed", not a true install signal (an agent
//! restart forgets what it had already seen) — see
//! [`schema::FLAG_PERSISTENCE_SYSTEMD_ARTIFACT`]'s own doc for the full
//! caveat. Good enough for issue #93's "case-attachable context" bar.

use std::collections::HashSet;

use schema::{Event, EventMeta, FLAG_PERSISTENCE_SYSTEMD_ARTIFACT, FileOpenEvent, User};

use crate::{JournalEvent, JournalRecord};

/// Tracks which unit names this agent process has already reported a start
/// for, so [`UnitPersistenceTracker::observe`] only emits once per unit per
/// agent lifetime. Not persisted across restarts — see the module doc.
#[derive(Debug, Default)]
pub struct UnitPersistenceTracker {
    seen: HashSet<String>,
}

impl UnitPersistenceTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `record`/`event` come from the same [`crate::classify::classify`] call
    /// as [`crate::auth::to_auth_event`] ([`crate::tail::ClassifiedJournal`]
    /// always yields them paired). Returns `Some` only for a
    /// [`JournalEvent::UnitStarted`] whose unit name this tracker has not
    /// already observed.
    #[must_use]
    pub fn observe(&mut self, record: &JournalRecord, event: &JournalEvent) -> Option<Event> {
        let JournalEvent::UnitStarted { unit } = event else {
            return None;
        };
        let unit = unit.clone()?;
        if !self.seen.insert(unit.clone()) {
            return None;
        }
        Some(Event::FileOpen(FileOpenEvent {
            meta: EventMeta {
                // Job-completion records are emitted by the system (or user)
                // manager itself — PID 1 for the system manager, the only case
                // this crate currently tails (see the crate doc's Status
                // section on `UNIT` vs `USER_UNIT`). Not fabricated: this is
                // what the reporting process always is for this record shape,
                // not a guess at unknown data.
                pid: record
                    .pid
                    .as_deref()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(1),
                ppid: 0,
                user: User::Unknown,
                timestamp_ns: record.realtime_us.saturating_mul(1_000),
                comm: unit.clone(),
                container: None,
            },
            path: unit,
            flags: FLAG_PERSISTENCE_SYSTEMD_ARTIFACT,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_record;

    fn record_with(fields: &[(&str, &str)]) -> JournalRecord {
        let mut obj = serde_json::Map::new();
        obj.insert("__CURSOR".into(), "c".into());
        obj.insert("__REALTIME_TIMESTAMP".into(), "1000".into());
        obj.insert("MESSAGE".into(), "irrelevant for this mapping test".into());
        for (k, v) in fields {
            obj.insert((*k).to_string(), (*v).into());
        }
        let line = serde_json::to_string(&obj).unwrap();
        parse_record(&line).unwrap()
    }

    #[test]
    fn first_start_of_a_unit_is_reported() {
        let record = record_with(&[]);
        let event = JournalEvent::UnitStarted {
            unit: Some("sshd.service".into()),
        };
        let mut tracker = UnitPersistenceTracker::new();
        let Some(Event::FileOpen(file_open)) = tracker.observe(&record, &event) else {
            panic!("first start of a unit must be reported");
        };
        assert_eq!(file_open.meta.comm, "sshd.service");
        assert_eq!(file_open.path, "sshd.service");
        assert_eq!(file_open.flags, FLAG_PERSISTENCE_SYSTEMD_ARTIFACT);
    }

    #[test]
    fn second_start_of_the_same_unit_is_not_reported_again() {
        let record = record_with(&[]);
        let event = JournalEvent::UnitStarted {
            unit: Some("cron.service".into()),
        };
        let mut tracker = UnitPersistenceTracker::new();
        assert!(tracker.observe(&record, &event).is_some());
        assert!(
            tracker.observe(&record, &event).is_none(),
            "a routine restart of an already-seen unit must not re-alert"
        );
    }

    #[test]
    fn different_units_are_tracked_independently() {
        let record = record_with(&[]);
        let mut tracker = UnitPersistenceTracker::new();
        let sshd = JournalEvent::UnitStarted {
            unit: Some("sshd.service".into()),
        };
        let cron = JournalEvent::UnitStarted {
            unit: Some("cron.service".into()),
        };
        assert!(tracker.observe(&record, &sshd).is_some());
        assert!(tracker.observe(&record, &cron).is_some());
    }

    #[test]
    fn unit_stopped_or_failed_is_never_reported() {
        // Only a start is ever "case-attachable persistence context" — a stop
        // or a failed start is not a new artifact appearing.
        let record = record_with(&[]);
        let mut tracker = UnitPersistenceTracker::new();
        let stopped = JournalEvent::UnitStopped {
            unit: Some("sshd.service".into()),
        };
        let failed = JournalEvent::UnitFailed {
            unit: Some("broken.service".into()),
        };
        assert!(tracker.observe(&record, &stopped).is_none());
        assert!(tracker.observe(&record, &failed).is_none());
    }

    #[test]
    fn missing_unit_name_is_not_reported() {
        let record = record_with(&[]);
        let event = JournalEvent::UnitStarted { unit: None };
        let mut tracker = UnitPersistenceTracker::new();
        assert!(tracker.observe(&record, &event).is_none());
    }

    #[test]
    fn reporter_pid_defaults_to_the_system_manager() {
        // No `_PID` field on a real job-completion record (see `record.rs`'s
        // own real-capture test) — pid 1 is not a fabrication here, it's what
        // the system manager always is.
        let record = record_with(&[]);
        let event = JournalEvent::UnitStarted {
            unit: Some("sshd.service".into()),
        };
        let mut tracker = UnitPersistenceTracker::new();
        let Some(Event::FileOpen(file_open)) = tracker.observe(&record, &event) else {
            panic!("must report");
        };
        assert_eq!(file_open.meta.pid, 1);
    }
}
