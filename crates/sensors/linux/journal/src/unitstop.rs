//! Maps the stop of a security tool's systemd unit into [`schema::UnitStopEvent`]
//! (T1562.001, #1085): the journal's answer to "did the stop
//! happen", which the exec rule (`check_security_tool_stop`, it reads the command line) cannot
//! say, and which also sees a stop that never went through a command line (D-Bus, an API).
//!
//! `unit` and `meta.comm` carry the unit name. It is an event of its own, not a flag on a
//! `FileOpenEvent`: a raw `openat` flag can carry any bit, so an unprivileged open could set it.
//! **The journal names no actor.** `_PID`/`_UID` on a job record are the manager's (PID 1, root)
//! whoever asked for the stop, so the event says a stop happened, not who did it.
//!
//! Filtered here, not in the rules: every unit stops at every reboot, and only the units of
//! [`schema::SECURITY_SERVICES`] are worth an event. Three checks, each with a test that fails
//! without it:
//! - the event is a [`JournalEvent::UnitStopped`];
//! - the record was written by the **system** manager (`_PID=1`, not a `systemd --user`
//!   manager): `classify` already refuses a client's forged job record, and a user can still
//!   name a user unit `falco.service` and stop it, which is no security tool stopping;
//! - the unit, lowercased and without `.service`, is in the list.

use schema::{Event, EventMeta, SECURITY_SERVICES, UnitStopEvent, User};

use crate::{JournalEvent, JournalRecord};

/// `Some` for a stop of a unit of [`SECURITY_SERVICES`] reported by the system manager.
#[must_use]
pub fn to_unit_stop_event(record: &JournalRecord, event: &JournalEvent) -> Option<Event> {
    let JournalEvent::UnitStopped { unit } = event else {
        return None;
    };
    if record.pid.as_deref() != Some("1") || record.from_user_manager {
        return None;
    }
    let unit = unit.clone()?;
    let lowered = unit.to_lowercase();
    let name = lowered.strip_suffix(".service").unwrap_or(&lowered);
    if !SECURITY_SERVICES.contains(&name) {
        return None;
    }
    Some(Event::UnitStop(UnitStopEvent {
        meta: EventMeta {
            pid: 1,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: record.realtime_us.saturating_mul(1_000),
            comm: unit.clone(),
            container: None,
            process_generation: None,
            parent_process_generation: None,
        },
        unit,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{classify, parse_record};

    fn record_with(fields: &[(&str, &str)]) -> JournalRecord {
        let mut obj = serde_json::Map::new();
        obj.insert("__CURSOR".into(), "c".into());
        obj.insert("__REALTIME_TIMESTAMP".into(), "2000".into());
        obj.insert("MESSAGE".into(), "irrelevant for this mapping test".into());
        for (k, v) in fields {
            obj.insert((*k).to_string(), (*v).into());
        }
        parse_record(&serde_json::to_string(&obj).unwrap()).unwrap()
    }

    fn stop(unit: &str) -> JournalEvent {
        JournalEvent::UnitStopped {
            unit: Some(unit.into()),
        }
    }

    #[test]
    fn a_stop_of_a_listed_unit_is_reported() {
        let record = record_with(&[("_PID", "1"), ("UNIT", "auditd.service")]);
        let Some(Event::UnitStop(stop_event)) =
            to_unit_stop_event(&record, &stop("auditd.service"))
        else {
            panic!("a stop of auditd must be reported");
        };
        assert_eq!(stop_event.unit, "auditd.service");
        assert_eq!(stop_event.meta.comm, "auditd.service");
        assert_eq!(stop_event.meta.pid, 1);
        assert_eq!(stop_event.meta.timestamp_ns, 2_000_000);
    }

    #[test]
    fn the_unit_is_matched_without_suffix_and_in_any_case() {
        let record = record_with(&[("_PID", "1"), ("UNIT", "x")]);
        assert!(to_unit_stop_event(&record, &stop("falco")).is_some());
        assert!(to_unit_stop_event(&record, &stop("Falco.service")).is_some());
    }

    #[test]
    fn a_unit_outside_the_list_is_not_reported() {
        let record = record_with(&[("_PID", "1"), ("UNIT", "cron.service")]);
        assert!(to_unit_stop_event(&record, &stop("cron.service")).is_none());
        // A near miss of a listed name is not the listed name.
        assert!(to_unit_stop_event(&record, &stop("falco-extra.service")).is_none());
    }

    #[test]
    fn only_a_stop_is_reported() {
        let record = record_with(&[("_PID", "1")]);
        let started = JournalEvent::UnitStarted {
            unit: Some("auditd.service".into()),
        };
        let failed = JournalEvent::UnitFailed {
            unit: Some("auditd.service".into()),
        };
        assert!(to_unit_stop_event(&record, &started).is_none());
        assert!(to_unit_stop_event(&record, &failed).is_none());
    }

    #[test]
    fn a_stop_without_a_unit_name_is_not_reported() {
        let record = record_with(&[("_PID", "1")]);
        assert!(to_unit_stop_event(&record, &JournalEvent::UnitStopped { unit: None }).is_none());
    }

    #[test]
    fn a_user_manager_unit_named_like_a_security_tool_is_not_reported() {
        // Any user can create `~/.config/systemd/user/falco.service` and stop it.
        let record = record_with(&[
            ("_PID", "2101"),
            ("_COMM", "systemd"),
            ("USER_UNIT", "falco.service"),
        ]);
        assert!(record.from_user_manager);
        assert!(to_unit_stop_event(&record, &stop("falco.service")).is_none());
    }

    #[test]
    fn a_user_unit_record_is_not_reported_even_from_pid_1() {
        // The mapper does not rely on `classify` to refuse a `USER_UNIT` from PID 1.
        let record = record_with(&[("_PID", "1"), ("USER_UNIT", "falco.service")]);
        assert!(to_unit_stop_event(&record, &stop("falco.service")).is_none());
    }

    #[test]
    fn a_record_from_another_pid_is_not_reported() {
        // Defence in depth: `classify` already refuses this record; the mapper does not rely
        // on every caller going through it.
        let record = record_with(&[("_PID", "4242"), ("UNIT", "auditd.service")]);
        assert!(to_unit_stop_event(&record, &stop("auditd.service")).is_none());
        let record = record_with(&[("UNIT", "auditd.service")]);
        assert!(to_unit_stop_event(&record, &stop("auditd.service")).is_none());
    }

    #[test]
    fn a_forged_stop_record_never_reaches_an_event() {
        // End to end through `classify`: the `logger`-style record is not even a `UnitStopped`.
        let forged = record_with(&[
            ("_PID", "4242"),
            ("_COMM", "logger"),
            ("JOB_TYPE", "stop"),
            ("JOB_RESULT", "done"),
            ("UNIT", "auditd.service"),
        ]);
        assert!(classify(&forged).is_none());
        let real = record_with(&[
            ("_PID", "1"),
            ("_COMM", "systemd"),
            ("JOB_TYPE", "stop"),
            ("JOB_RESULT", "done"),
            ("UNIT", "auditd.service"),
        ]);
        let event = classify(&real).expect("the manager's own record classifies");
        assert!(to_unit_stop_event(&real, &event).is_some());
    }
}
