//! Maps [`JournalEvent`]s into [`schema::AuthEvent`] — the shared logon/session
//! shape Windows Security-log logons also normalize into (issue #94,
//! `docs/adr/0005-windows-logon-events-shared-auth-event-type.md`). Deliberately
//! narrow, mirroring `sensor-windows-eventlog`'s own discipline (see its
//! `sensor.rs`): a category with a field this mapping needs but can't extract is
//! skipped (`None`) rather than fabricated.
//!
//! **Not every allowlisted [`JournalEvent`] maps to an `AuthEvent`:**
//! - [`JournalEvent::PamSessionOpened`]/[`JournalEvent::PamSessionClosed`] for the
//!   `"sshd"` and `"sudo"` PAM services are the *same real action* as
//!   [`JournalEvent::SshAccepted`]/[`JournalEvent::SudoCommand`] — mapping both
//!   would double-count one login/privilege-elevation as two `AuthEvent`s. Only
//!   `"su"` (no dedicated classifier — [`ExplicitCredentials`](schema::AuthKind)
//!   is the closest existing signal for "became another user") and `"login"`
//!   (local console, not covered elsewhere) get a PAM-session-based mapping.
//! - Unit lifecycle ([`JournalEvent::UnitStarted`]/`Stopped`/`Failed`) has no
//!   `schema::Event` variant yet — a Linux-only "service lifecycle" shape would
//!   preempt the same cross-platform decision `AuthEvent` itself needed (ADR-0005),
//!   and Windows' service-install/lifecycle event reconciliation is active work
//!   in progress (issue #224) — left unmapped rather than invented unilaterally.

use schema::{AuthEvent, AuthKind, AuthOutcome, EventMeta, User};

use crate::{JournalEvent, JournalRecord};

/// `record`/`event` come from the same [`crate::classify::classify`] call
/// ([`crate::tail::ClassifiedJournal`] always yields them paired) — `record` for
/// the reporting process's identity, `event` for what happened.
#[must_use]
pub fn to_auth_event(record: &JournalRecord, event: &JournalEvent) -> Option<AuthEvent> {
    let (outcome, kind, target_user, source_address) = match event {
        JournalEvent::SshAccepted { user, source_addr } => (
            AuthOutcome::Success,
            AuthKind::Logon,
            user.clone()?,
            parse_addr(source_addr),
        ),
        JournalEvent::SshFailed { user, source_addr } => (
            AuthOutcome::Failure,
            AuthKind::LogonFailure,
            user.clone()?,
            parse_addr(source_addr),
        ),
        JournalEvent::SudoCommand { target_user, .. } => {
            let target_user = target_user.clone()?;
            // Default target (no `-u`) is root — plain privilege elevation.
            // Any other explicit target is the same "became someone else" signal
            // as `su`, per AuthKind::ExplicitCredentials's own doc.
            let kind = if target_user == "root" {
                AuthKind::PrivilegedSession
            } else {
                AuthKind::ExplicitCredentials
            };
            (AuthOutcome::Success, kind, target_user, None)
        }
        JournalEvent::PamSessionOpened {
            service,
            target_user,
        } if service == "su" => (
            AuthOutcome::Success,
            AuthKind::ExplicitCredentials,
            target_user.clone()?,
            None,
        ),
        JournalEvent::PamSessionOpened {
            service,
            target_user,
        } if service == "login" => (
            AuthOutcome::Success,
            AuthKind::Logon,
            target_user.clone()?,
            None,
        ),
        _ => return None,
    };

    Some(AuthEvent {
        meta: reporter_meta(record)?,
        outcome,
        kind,
        target_user,
        target_user_sid: None, // Linux: no SID concept.
        source_address,
        status_code: None, // Nothing informative beyond `outcome`/`kind` today.
    })
}

/// Identity of the reporting process (`sshd`, `sudo`, ...) — not the account being
/// authenticated, see [`schema::AuthEvent::meta`]'s own doc. `None` if `_PID`/`_UID`
/// aren't both present (never observed in practice for journald's own trusted
/// fields, but not fabricated if missing).
fn reporter_meta(record: &JournalRecord) -> Option<EventMeta> {
    let pid: u32 = record.pid.as_deref()?.parse().ok()?;
    let uid: u32 = record.uid.as_deref()?.parse().ok()?;
    let user = match record.gid.as_deref().and_then(|g| g.parse().ok()) {
        Some(gid) => User::Unix { uid, gid },
        None => User::Unknown,
    };
    Some(EventMeta {
        pid,
        // journald has no `_PPID` trusted field. This is a session/auth-subsystem
        // event, not a process-lineage one (same reasoning as
        // `sensor-windows-eventlog` hardcoding 0 for its own `AuthEvent`s).
        ppid: 0,
        user,
        timestamp_ns: record.realtime_us.saturating_mul(1_000),
        comm: record
            .syslog_identifier
            .clone()
            .unwrap_or_else(|| "journald".to_string()),
        container: None, // Auth subsystem events aren't attributed to a container.
    })
}

fn parse_addr(addr: &Option<String>) -> Option<core::net::IpAddr> {
    addr.as_deref().and_then(|s| s.parse().ok())
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
    fn ssh_accepted_maps_to_logon_success() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            ("_PID", "4242"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::SshAccepted {
            user: Some("alice".into()),
            source_addr: Some("10.0.0.5".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.outcome, AuthOutcome::Success);
        assert_eq!(auth.kind, AuthKind::Logon);
        assert_eq!(auth.target_user, "alice");
        assert_eq!(auth.meta.pid, 4242);
        assert_eq!(auth.meta.comm, "sshd");
        assert_eq!(
            auth.source_address,
            Some("10.0.0.5".parse::<core::net::IpAddr>().unwrap())
        );
    }

    #[test]
    fn ssh_failed_maps_to_logon_failure() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            ("_PID", "4242"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::SshFailed {
            user: Some("root".into()),
            source_addr: Some("10.0.0.5".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.outcome, AuthOutcome::Failure);
        assert_eq!(auth.kind, AuthKind::LogonFailure);
        assert_eq!(auth.target_user, "root");
    }

    #[test]
    fn sudo_to_root_is_privileged_session() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let event = JournalEvent::SudoCommand {
            invoking_user: Some("lab".into()),
            target_user: Some("root".into()),
            command: Some("/bin/echo hi".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.kind, AuthKind::PrivilegedSession);
        assert_eq!(auth.target_user, "root");
    }

    #[test]
    fn sudo_to_other_user_is_explicit_credentials() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let event = JournalEvent::SudoCommand {
            invoking_user: Some("lab".into()),
            target_user: Some("deploy".into()),
            command: Some("/bin/echo hi".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.kind, AuthKind::ExplicitCredentials);
        assert_eq!(auth.target_user, "deploy");
    }

    #[test]
    fn su_pam_session_is_explicit_credentials() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "su"),
            ("_PID", "200"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let event = JournalEvent::PamSessionOpened {
            service: "su".into(),
            target_user: Some("root".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.kind, AuthKind::ExplicitCredentials);
    }

    #[test]
    fn sshd_pam_session_is_not_double_mapped() {
        // Same real login as SshAccepted — must not also produce an AuthEvent here.
        let record = record_with(&[("SYSLOG_IDENTIFIER", "sshd"), ("_PID", "1"), ("_UID", "0")]);
        let event = JournalEvent::PamSessionOpened {
            service: "sshd".into(),
            target_user: Some("alice".into()),
        };
        assert!(to_auth_event(&record, &event).is_none());
    }

    #[test]
    fn unit_lifecycle_has_no_mapping() {
        let record = record_with(&[("_PID", "1"), ("_UID", "0")]);
        let event = JournalEvent::UnitStarted {
            unit: Some("sshd.service".into()),
        };
        assert!(to_auth_event(&record, &event).is_none());
    }

    #[test]
    fn missing_pid_skips_mapping_rather_than_fabricating_one() {
        let record = record_with(&[("SYSLOG_IDENTIFIER", "sshd"), ("_UID", "0")]);
        let event = JournalEvent::SshAccepted {
            user: Some("alice".into()),
            source_addr: None,
        };
        assert!(to_auth_event(&record, &event).is_none());
    }
}
