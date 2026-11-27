//! Security-log logons into authentication events.

use schema::{AuthEvent, AuthKind, AuthOutcome, Event, EventMeta, User, time::now_ns};

use super::BlockOutcome;
use crate::xml::{self, LogonEvent};

/// The "Microsoft-Windows-Security-Auditing" provider that writes 4624/4625/
/// 4648/4672 runs inside the LSA subsystem process, not the account's own
/// process — see [`LogonEvent`]'s doc. `EventMeta::comm` names that reporting
/// process rather than leaving it blank.
pub(crate) const LSASS_COMM: &str = "lsass.exe";

pub(crate) fn normalize_logon(block: &str) -> BlockOutcome {
    let Some(logon) = xml::parse_logon_block(block) else {
        return BlockOutcome::Unparseable;
    };
    BlockOutcome::from_optional(logon.record_id, to_auth_event(&logon))
}

/// Maps a parsed [`LogonEvent`] to the normalized [`Event::Auth`], or `None`
/// when the event carries no usable account identity (a shape this module does
/// not yet understand — skip rather than report a hollow event).
pub(crate) fn to_auth_event(logon: &LogonEvent) -> Option<Event> {
    let (kind, outcome) = match logon.event_id {
        4624 => (AuthKind::Logon, AuthOutcome::Success),
        4625 => (AuthKind::LogonFailure, AuthOutcome::Failure),
        // 4648 fires when explicit credentials are used to attempt a logon; it
        // carries no pass/fail status of its own (whether the attempt actually
        // succeeded is a separate 4624/4625), so it is reported as `Success`
        // meaning "the explicit-credential attempt was observed", not "and it
        // succeeded".
        4648 => (AuthKind::ExplicitCredentials, AuthOutcome::Success),
        // 4672 only fires for a logon that already succeeded.
        4672 => (AuthKind::PrivilegedSession, AuthOutcome::Success),
        _ => return None,
    };

    // 4672 has no Target* fields — the Subject *is* the account granted the
    // special privileges (see `LogonEvent`'s doc).
    let (target_user, target_user_sid) = if logon.event_id == 4672 {
        (
            logon.subject_user_name.clone(),
            logon.subject_user_sid.clone(),
        )
    } else {
        (
            logon.target_user_name.clone(),
            logon.target_user_sid.clone(),
        )
    };
    let target_user = target_user?;

    let source_address = logon.ip_address.as_deref().and_then(|s| s.parse().ok());
    let status_code = match (&logon.status, &logon.sub_status) {
        (Some(status), Some(sub)) => Some(format!("{status}/{sub}")),
        (Some(status), None) => Some(status.clone()),
        (None, Some(sub)) => Some(sub.clone()),
        (None, None) => None,
    };
    let user = match &logon.subject_user_sid {
        Some(sid) => User::Windows {
            sid: sid.clone(),
            integrity_level: None,
        },
        None => User::Unknown,
    };

    Some(Event::Auth(AuthEvent {
        meta: EventMeta {
            pid: logon.pid,
            ppid: 0,
            user,
            timestamp_ns: logon.time_created_ns.unwrap_or_else(now_ns),
            comm: LSASS_COMM.to_string(),
            container: None, // attributed by the ETW sensor only (https://github.com/synthaea-lab/agent/issues/39)
            process_generation: None,
            parent_process_generation: None,
        },
        outcome,
        kind,
        target_user,
        target_user_sid,
        source_address,
        status_code,
    }))
}
