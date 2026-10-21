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
//! - Unit lifecycle ([`JournalEvent::UnitStarted`]/`Stopped`/`Failed`) never maps
//!   into an `AuthEvent` — a login/session shape is the wrong fit for "a service
//!   started". [`crate::persistence::UnitPersistenceTracker`] maps a unit's first
//!   observed start into `schema::FileOpenEvent` instead, once issue #224
//!   (Windows' own service-lifecycle event reconciliation) confirmed the
//!   precedent to follow (reuse `FileOpenEvent` + a flag, no new `Event`
//!   variant) — see that module's doc.

use schema::{AuthEvent, AuthKind, AuthOutcome, EventMeta, User};

use crate::{JournalEvent, JournalRecord};

/// Whether `record` was written by the program `program` (`"sudo"`/`"su"`), going
/// by `_COMM` rather than `SYSLOG_IDENTIFIER`, which the logging client chooses
/// freely (`logger -t sudo 'pam_unix(sudo:auth): authentication failure; ...
/// user=root'` is a line any local user can write; its `_COMM` is `logger`).
/// This stops that trivial case, but **`_COMM` is not a full identity check**
/// (review of #838, Sollykhan 2026-10-19, point 1 — a correction to this
/// comment's own prior claim that it was "trusted"): journald stamps it
/// kernel-side from `/proc/<pid>/comm`, which the client cannot set through the
/// log *content*, but can still set by what it execs as, or via
/// `prctl(PR_SET_NAME)` — `cp /usr/bin/logger /tmp/sudo; /tmp/sudo -t sudo
/// '...'` gets `_COMM=sudo` for free. This check is still worth keeping (it is
/// free, and it blocks the common case), but the real security boundary for
/// `sudo`'s own join is `rules::sudo` keying on the trusted `_UID` instead of
/// any name — see that module's doc. `su`'s join stays on the target name
/// (narrower exposure, see the same doc), so this check is still its only
/// line of defense there. A record with no `_COMM` is accepted: journald
/// stamps it on every record that comes from a process, so only a fixture
/// built by hand lacks it.
fn emitted_by(record: &JournalRecord, program: &str) -> bool {
    record.comm.as_deref().is_none_or(|comm| comm == program)
}

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
            if !emitted_by(record, "sudo") {
                return None;
            }
            let real_target = target_user.clone()?;
            // Default target (no `-u`) is root — plain privilege elevation.
            // Any other explicit target is the same "became someone else" signal
            // as `su`, per AuthKind::ExplicitCredentials's own doc.
            let kind = if real_target == "root" {
                AuthKind::PrivilegedSession
            } else {
                AuthKind::ExplicitCredentials
            };
            // Reports the real `-u` target, per `AuthEvent::target_user`'s own
            // contract ("the account being authenticated as/into" — differing
            // from `meta.user` "is the whole signal"). A prior version of this
            // mapping swapped in the invoking account instead, so a sudo success
            // would key identically to the `pam_unix(sudo:auth)` failures that
            // preceded it (PAM only ever authenticates *sudo's invoker*, never
            // learning the `-u` target on a failure) — but `target_user` is also
            // what an analyst reads as "who this event is about", and silently
            // meaning the invoker there, for every ordinary `sudo -u x` success,
            // was wrong (review of #838, Sollykhan 2026-10-19, point
            // 4: `sudo -u postgres psql` reported `target_user="solka"`, the
            // invoker, with `postgres` nowhere in the event). The join this swap
            // existed for now keys on `meta.user`'s uid instead (trusted, from
            // `_UID` — confirmed by a live capture, same for the PAM failure line
            // and this `COMMAND=` line, across a real wrong-then-right sudo on
            // Fedora 43/sudo 1.9.17p2 — see `rules::sudo`), so this field is free
            // to mean what the schema says again.
            (AuthOutcome::Success, kind, real_target, None)
        }
        JournalEvent::PamSessionOpened {
            service,
            target_user,
        } if service == "su" => {
            if !emitted_by(record, "su") {
                return None;
            }
            (
                AuthOutcome::Success,
                AuthKind::ExplicitCredentials,
                target_user.clone()?,
                None,
            )
        }
        JournalEvent::PamSessionOpened {
            service,
            target_user,
        } if service == "login" => (
            AuthOutcome::Success,
            AuthKind::Logon,
            target_user.clone()?,
            None,
        ),
        // `classify` only emits this for the "sudo"/"su" services (sshd's own PAM
        // auth failure would double-count `SshFailed`), so no service guard is
        // needed here beyond the sender check. The account is `classify_pam`'s
        // `" user="` field: for `su` the real target (PAM checks the target's own
        // password); for `sudo` the invoker (PAM checks the invoker's own
        // password, never learning the `-u` target on a failure) — in both
        // cases the only account PAM actually checked, so reporting it here
        // matches `target_user`'s "account being authenticated as/into"
        // contract even for `sudo` (unlike the `SudoCommand` success arm,
        // nothing is swapped here). `rules::sudo`'s join no longer depends on
        // this matching the success side's `target_user` for `sudo` — see that
        // module. For `sudo` a line without `user=` still names the invoker
        // through `logname=` (the same account there), so it is not dropped;
        // `su` has no such stand-in (`logname=` is who typed the password, not
        // whose it was), so a `su` failure with no `user=` is skipped, not
        // fabricated.
        JournalEvent::PamAuthFailure {
            service,
            invoking_user,
            target_user,
        } => {
            if !emitted_by(record, service) {
                return None;
            }
            let account = if service == "sudo" {
                target_user.clone().or_else(|| invoking_user.clone())
            } else {
                target_user.clone()
            }?;
            (AuthOutcome::Failure, AuthKind::LogonFailure, account, None)
        }
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
        process_generation: None,
        parent_process_generation: None,
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
    fn sudo_to_root_is_privileged_session_naming_the_real_target() {
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
        // `target_user` is the real `-u` target, not the invoker (review of
        // #838, Sollykhan 2026-10-19, point 4) — `rules::sudo` keys its join
        // on `meta.user`'s uid instead, not on this field.
        assert_eq!(auth.target_user, "root");
        assert_eq!(
            auth.meta.user,
            User::Unix {
                uid: 1001,
                gid: 1001
            }
        );
    }

    #[test]
    fn sudo_to_other_user_is_explicit_credentials_naming_the_real_target() {
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
    fn a_sudo_failure_and_the_success_after_it_share_the_same_trusted_uid() {
        // The invoker (uid 1000) fails sudo, then succeeds as root. The PAM
        // failure line never names `root` — `pam_unix(sudo:auth)` only
        // authenticates the invoker — and `target_user` no longer tries to
        // make the two sides match on a parsed name (#838 point 4): confirmed
        // live on Fedora 43/sudo 1.9.17p2 (a real wrong-then-right sudo), the
        // trusted `_UID` is 1001 (the test invoker there) on both the
        // `pam_unix(sudo:auth)` failure line and the `COMMAND=` success line,
        // which `rules::sudo` now keys its join on instead of either side's
        // `target_user` — see that module.
        let failure_record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "6805"),
            ("_UID", "1000"),
            ("_GID", "1000"),
        ]);
        let failure = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("omss".into()),
            target_user: Some("omss".into()),
        };
        let failure_auth = to_auth_event(&failure_record, &failure).expect("should map");

        let success_record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "6810"),
            ("_UID", "1000"),
            ("_GID", "1000"),
        ]);
        let success = JournalEvent::SudoCommand {
            invoking_user: Some("omss".into()),
            target_user: Some("root".into()),
            command: Some("/bin/whoami".into()),
        };
        let success_auth = to_auth_event(&success_record, &success).expect("should map");

        assert_eq!(failure_auth.meta.user, success_auth.meta.user);
        assert_eq!(
            failure_auth.meta.user,
            User::Unix {
                uid: 1000,
                gid: 1000
            }
        );
        // Not a join key any more, but still correct per `target_user`'s own
        // contract: the failure names who PAM actually checked (the invoker,
        // `omss`); the success names the real escalation target (`root`).
        assert_eq!(failure_auth.target_user, "omss");
        assert_eq!(success_auth.target_user, "root");
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
    fn pam_auth_failure_for_sudo_maps_to_logon_failure() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        // `pam_unix(sudo:auth)` authenticates the invoker's own password, so a
        // real failure's `" user="` field (`target_user` here) names the
        // invoker, never the `-u` target (#838) — `target_user: Some("root")`
        // with a different `invoking_user` is not a line `classify_pam` ever
        // actually produces for `sudo`.
        let event = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("lab".into()),
            target_user: Some("lab".into()),
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.outcome, AuthOutcome::Failure);
        assert_eq!(auth.kind, AuthKind::LogonFailure);
        assert_eq!(auth.target_user, "lab");
        assert_eq!(auth.source_address, None);
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

    // --- who actually wrote the line (`_COMM`, not the spoofable identifier) -----

    #[test]
    fn a_sudo_line_written_by_another_program_is_not_mapped() {
        // `logger -t sudo '...'` sets `SYSLOG_IDENTIFIER=sudo` freely, but the
        // trusted `_COMM` is `logger`: a local user must not be able to feed the
        // sudo/su join with fabricated failures or successes (#838 review).
        let spoofed = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_COMM", "logger"),
            ("_PID", "100"),
            ("_UID", "1001"),
            ("_GID", "1001"),
        ]);
        let failure = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("victim".into()),
            target_user: Some("victim".into()),
        };
        let success = JournalEvent::SudoCommand {
            invoking_user: Some("victim".into()),
            target_user: Some("root".into()),
            command: Some("/bin/id".into()),
        };
        let su_session = JournalEvent::PamSessionOpened {
            service: "su".into(),
            target_user: Some("root".into()),
        };
        assert!(to_auth_event(&spoofed, &failure).is_none());
        assert!(to_auth_event(&spoofed, &success).is_none());
        assert!(to_auth_event(&spoofed, &su_session).is_none());
    }

    #[test]
    fn a_sudo_line_written_by_sudo_itself_is_mapped() {
        let genuine = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_COMM", "sudo"),
            ("_PID", "100"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let success = JournalEvent::SudoCommand {
            invoking_user: Some("lab".into()),
            target_user: Some("root".into()),
            command: Some("/bin/id".into()),
        };
        let auth = to_auth_event(&genuine, &success).expect("should map");
        assert_eq!(auth.target_user, "root");
    }

    #[test]
    fn a_sudo_failure_without_user_falls_back_to_logname() {
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            ("_PID", "100"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::PamAuthFailure {
            service: "sudo".into(),
            invoking_user: Some("lab".into()),
            target_user: None,
        };
        let auth = to_auth_event(&record, &event).expect("should map");
        assert_eq!(auth.target_user, "lab");
        assert_eq!(auth.outcome, AuthOutcome::Failure);
    }

    #[test]
    fn a_su_failure_without_user_is_skipped_not_guessed() {
        // For `su`, `logname=` is who typed the password, not whose account it was
        // checked against, so it cannot stand in for the missing `user=`.
        let record = record_with(&[
            ("SYSLOG_IDENTIFIER", "su"),
            ("_PID", "100"),
            ("_UID", "0"),
            ("_GID", "0"),
        ]);
        let event = JournalEvent::PamAuthFailure {
            service: "su".into(),
            invoking_user: Some("lab".into()),
            target_user: None,
        };
        assert!(to_auth_event(&record, &event).is_none());
    }
}
