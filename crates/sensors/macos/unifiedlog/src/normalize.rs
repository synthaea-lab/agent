//! Maps classified unified-log records into `schema` events: sudo →
//! [`schema::AuthEvent`] (the shared shape Windows logons and Linux journal
//! auth normalize into, ADR-0005 — the sudo mapping semantics deliberately
//! mirror `sensor-linux-journal::auth` so the same real action produces the
//! same event on both platforms), TCC pairs → [`schema::TccDecisionEvent`],
//! Gatekeeper scans → [`schema::GatekeeperVerdictEvent`].

use schema::{
    AuthEvent, AuthKind, AuthOutcome, Event, EventMeta, GatekeeperVerdictEvent, TccDecisionEvent,
    User,
};

use crate::{
    UnifiedLogEvent,
    record::{LogRecord, image_basename},
    tcc::TccJoiner,
};

/// TCC `authValue` meaning "allowed" (2) or "limited" (3) — both are grants.
fn tcc_allowed(auth_value: u32) -> bool {
    auth_value == 2 || auth_value == 3
}

/// Identity of the reporting process (`sudo`, `tccd`, `syspolicyd`). The
/// unified log carries the logger's uid but not its gid; gid 0 is factual for
/// the uid-0 daemons this crate allowlists, and for a per-user daemon the
/// user stays honest as `Unknown` rather than carrying a fabricated gid
/// (same "never fabricate" discipline as the journal sensor's
/// `reporter_meta`).
fn reporter_meta(record: &LogRecord) -> Option<EventMeta> {
    let pid = record.pid?;
    let user = match record.uid {
        Some(0) => User::Unix { uid: 0, gid: 0 },
        _ => User::Unknown,
    };
    Some(EventMeta {
        pid,
        // The unified log does not carry the logger's ppid — same reasoning
        // as `sensor-windows-eventlog` and the journal sensor: this is a
        // subsystem-report event, not a process-lineage one.
        ppid: 0,
        user,
        timestamp_ns: record.timestamp_ns,
        comm: image_basename(&record.process_image_path).to_string(),
        container: None,
    })
}

/// Maps one classified record to its schema event. `joiner` carries the TCC
/// context state across calls; a [`UnifiedLogEvent::TccContext`] returns
/// `None` (it only feeds the joiner), as does a result with no joinable
/// context (counted by the joiner rather than fabricating a service).
#[must_use]
pub fn normalize(
    record: &LogRecord,
    event: &UnifiedLogEvent,
    joiner: &mut TccJoiner,
) -> Option<Event> {
    match event {
        UnifiedLogEvent::SudoCommand { target_user, .. } => {
            let target_user = target_user.clone()?;
            // Mirrors sensor-linux-journal::auth: default target (root) is
            // plain privilege elevation; an explicit other target is the
            // "became someone else" signal.
            let kind = if target_user == "root" {
                AuthKind::PrivilegedSession
            } else {
                AuthKind::ExplicitCredentials
            };
            Some(Event::Auth(AuthEvent {
                meta: reporter_meta(record)?,
                outcome: AuthOutcome::Success,
                kind,
                target_user,
                target_user_sid: None,
                source_address: None,
                status_code: None,
            }))
        }
        UnifiedLogEvent::SudoFailure { target_user, .. } => Some(Event::Auth(AuthEvent {
            meta: reporter_meta(record)?,
            outcome: AuthOutcome::Failure,
            kind: AuthKind::LogonFailure,
            target_user: target_user.clone()?,
            target_user_sid: None,
            source_address: None,
            status_code: None,
        })),
        UnifiedLogEvent::TccContext { msg_id, service } => {
            joiner.on_context(msg_id.clone(), service.clone());
            None
        }
        UnifiedLogEvent::TccResult {
            msg_id,
            auth_value,
            auth_reason,
        } => {
            let service = joiner.on_result(msg_id)?;
            Some(Event::TccDecision(TccDecisionEvent {
                meta: reporter_meta(record)?,
                service,
                allowed: tcc_allowed(*auth_value),
                auth_value: *auth_value,
                auth_reason: *auth_reason,
                // The public log stream redacts the requesting client on the
                // records this crate parses; never fabricated.
                client: None,
            }))
        }
        UnifiedLogEvent::GatekeeperScan {
            target,
            team_id,
            signing_id,
            result_code,
        } => Some(Event::GatekeeperVerdict(GatekeeperVerdictEvent {
            meta: reporter_meta(record)?,
            target: target.clone(),
            team_id: team_id.clone(),
            signing_id: signing_id.clone(),
            result_code: *result_code,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(process_image_path: &str, message: &str) -> LogRecord {
        LogRecord {
            message: message.to_string(),
            subsystem: String::new(),
            process_image_path: process_image_path.to_string(),
            pid: Some(28438),
            uid: Some(0),
            timestamp_ns: 1_790_068_345_248_383_000,
            event_type: "logEvent".to_string(),
        }
    }

    #[test]
    fn sudo_to_root_maps_to_privileged_session() {
        let mut joiner = TccJoiner::new();
        let event = UnifiedLogEvent::SudoCommand {
            invoking_user: Some("florianamette".into()),
            target_user: Some("root".into()),
            command: Some("/usr/bin/whoami".into()),
        };
        let Some(Event::Auth(auth)) = normalize(&record("/usr/bin/sudo", ""), &event, &mut joiner)
        else {
            panic!("must map to Event::Auth");
        };
        assert_eq!(auth.outcome, AuthOutcome::Success);
        assert_eq!(auth.kind, AuthKind::PrivilegedSession);
        assert_eq!(auth.target_user, "root");
        assert_eq!(auth.meta.comm, "sudo");
        assert_eq!(auth.meta.user, User::Unix { uid: 0, gid: 0 });
    }

    #[test]
    fn sudo_to_other_user_is_explicit_credentials() {
        let mut joiner = TccJoiner::new();
        let event = UnifiedLogEvent::SudoCommand {
            invoking_user: Some("florianamette".into()),
            target_user: Some("deploy".into()),
            command: None,
        };
        assert!(matches!(
            normalize(&record("/usr/bin/sudo", ""), &event, &mut joiner),
            Some(Event::Auth(a)) if a.kind == AuthKind::ExplicitCredentials
        ));
    }

    #[test]
    fn sudo_failure_maps_to_logon_failure() {
        let mut joiner = TccJoiner::new();
        let event = UnifiedLogEvent::SudoFailure {
            invoking_user: Some("florianamette".into()),
            target_user: Some("root".into()),
        };
        assert!(matches!(
            normalize(&record("/usr/bin/sudo", ""), &event, &mut joiner),
            Some(Event::Auth(a))
                if a.outcome == AuthOutcome::Failure && a.kind == AuthKind::LogonFailure
        ));
    }

    #[test]
    fn tcc_context_then_result_emits_one_joined_decision() {
        let mut joiner = TccJoiner::new();
        let tccd = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd";
        assert_eq!(
            normalize(
                &record(tccd, ""),
                &UnifiedLogEvent::TccContext {
                    msg_id: "988.7025".into(),
                    service: "kTCCServiceScreenCapture".into(),
                },
                &mut joiner,
            ),
            None,
            "a context alone is not an event"
        );
        let Some(Event::TccDecision(tcc)) = normalize(
            &record(tccd, ""),
            &UnifiedLogEvent::TccResult {
                msg_id: "988.7025".into(),
                auth_value: 2,
                auth_reason: Some(11),
            },
            &mut joiner,
        ) else {
            panic!("joined result must map to Event::TccDecision");
        };
        assert_eq!(tcc.service, "kTCCServiceScreenCapture");
        assert!(tcc.allowed);
        assert_eq!(tcc.auth_value, 2);
        assert_eq!(tcc.meta.comm, "tccd");
    }

    #[test]
    fn tcc_denial_maps_allowed_false() {
        let mut joiner = TccJoiner::new();
        joiner.on_context("438.631".into(), "kTCCServiceSystemPolicyAllFiles".into());
        let Some(Event::TccDecision(tcc)) = normalize(
            &record(
                "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
                "",
            ),
            &UnifiedLogEvent::TccResult {
                msg_id: "438.631".into(),
                auth_value: 0,
                auth_reason: Some(12),
            },
            &mut joiner,
        ) else {
            panic!("must map");
        };
        assert!(!tcc.allowed);
    }

    #[test]
    fn tcc_result_without_context_is_skipped_and_counted() {
        let mut joiner = TccJoiner::new();
        assert_eq!(
            normalize(
                &record(
                    "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
                    ""
                ),
                &UnifiedLogEvent::TccResult {
                    msg_id: "1.1".into(),
                    auth_value: 2,
                    auth_reason: None,
                },
                &mut joiner,
            ),
            None
        );
        assert_eq!(joiner.unmatched_results, 1);
    }

    #[test]
    fn gatekeeper_scan_maps_with_raw_code() {
        let mut joiner = TccJoiner::new();
        let Some(Event::GatekeeperVerdict(gk)) = normalize(
            &record("/usr/libexec/syspolicyd", ""),
            &UnifiedLogEvent::GatekeeperScan {
                target: "com.evil.dropper".into(),
                team_id: Some("ABCDE12345".into()),
                signing_id: Some("com.evil.dropper".into()),
                result_code: 2,
            },
            &mut joiner,
        ) else {
            panic!("must map to Event::GatekeeperVerdict");
        };
        assert_eq!(gk.result_code, 2);
        assert_eq!(gk.meta.comm, "syspolicyd");
    }

    #[test]
    fn per_user_daemon_uid_is_not_fabricated_into_a_gid() {
        let mut joiner = TccJoiner::new();
        let mut r = record("/usr/bin/sudo", "");
        r.uid = Some(501);
        let event = UnifiedLogEvent::SudoCommand {
            invoking_user: None,
            target_user: Some("root".into()),
            command: None,
        };
        let Some(Event::Auth(auth)) = normalize(&r, &event, &mut joiner) else {
            panic!("must map");
        };
        assert_eq!(auth.meta.user, User::Unknown);
    }

    #[test]
    fn missing_pid_skips_mapping_rather_than_fabricating_one() {
        let mut joiner = TccJoiner::new();
        let mut r = record("/usr/bin/sudo", "");
        r.pid = None;
        let event = UnifiedLogEvent::SudoCommand {
            invoking_user: None,
            target_user: Some("root".into()),
            command: None,
        };
        assert_eq!(normalize(&r, &event, &mut joiner), None);
    }
}
