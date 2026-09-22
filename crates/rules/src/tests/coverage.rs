//! Coverage-pack wave 1 (issues #377/#379/#381): masquerading, recovery
//! inhibit, log clearing (exec + file halves), and the auth-failure burst.

use schema::{AuthEvent, AuthKind, AuthOutcome, FileDeleteEvent};

use super::*;
use crate::{
    check_log_clear_exec, check_log_file_delete, check_masquerading, check_recovery_inhibit,
    evaluate_file_delete,
};

fn exec_with_path(image_path: &str, comm: &str) -> ExecEvent {
    let mut event = exec_event("irrelevant");
    event.image_path = image_path.to_string();
    event.meta.comm = comm.to_string();
    event
}

// --- T1036.005 masquerading -------------------------------------------------

#[test]
fn system_binary_name_outside_its_home_alerts() {
    let event = exec_with_path("/tmp/.hidden/bash", "bash");
    let alert = check_masquerading(&event).expect("bash in /tmp must alert");
    assert_eq!(alert.technique, "T1036.005");
    assert!(alert.message.contains("/tmp/.hidden/bash"));
}

#[test]
fn system_binary_in_its_legitimate_home_stays_silent() {
    assert!(check_masquerading(&exec_with_path("/bin/bash", "bash")).is_none());
    assert!(check_masquerading(&exec_with_path("/usr/sbin/sshd", "sshd")).is_none());
}

#[test]
fn windows_masquerade_is_case_insensitive() {
    let event = exec_with_path("C:\\Users\\Public\\SvcHost.exe", "SvcHost.exe");
    let alert = check_masquerading(&event).expect("svchost outside System32 must alert");
    assert_eq!(alert.technique, "T1036.005");
    assert!(
        check_masquerading(&exec_with_path(
            "C:\\Windows\\System32\\svchost.exe",
            "svchost.exe"
        ))
        .is_none(),
        "the real svchost must stay silent"
    );
}

#[test]
fn relative_or_truncated_paths_are_skipped_not_guessed() {
    // The Linux dfd limitation: a relative path can't prove location either way.
    assert!(check_masquerading(&exec_with_path("bash", "bash")).is_none());
    assert!(check_masquerading(&exec_with_path("subdir\\svchost.exe", "svchost.exe")).is_none());
}

#[test]
fn unlisted_names_never_alert_wherever_they_run() {
    assert!(check_masquerading(&exec_with_path("/tmp/build-helper", "build-helper")).is_none());
}

// --- T1490 recovery inhibit -------------------------------------------------

#[test]
fn shadow_copy_deletion_alerts() {
    let event = exec_event("vssadmin.exe Delete Shadows /All /Quiet");
    let alert = check_recovery_inhibit(&event).expect("must alert");
    assert_eq!(alert.technique, "T1490");
}

#[test]
fn shadow_copy_listing_stays_silent() {
    // Every token must match — admins list shadows constantly.
    assert!(check_recovery_inhibit(&exec_event("vssadmin list shadows")).is_none());
}

#[test]
fn time_machine_snapshot_destruction_alerts() {
    let event = exec_event("tmutil deletelocalsnapshots /");
    assert_eq!(
        check_recovery_inhibit(&event)
            .expect("must alert")
            .technique,
        "T1490"
    );
}

// --- T1070.002 log clearing (exec half) ------------------------------------

#[test]
fn windows_event_log_clear_alerts() {
    let event = exec_event("wevtutil cl Security");
    assert_eq!(
        check_log_clear_exec(&event).expect("must alert").technique,
        "T1070.002"
    );
}

#[test]
fn macos_unified_log_erase_alerts() {
    assert!(check_log_clear_exec(&exec_event("/usr/bin/log erase --all")).is_some());
}

#[test]
fn journald_vacuum_alerts_but_status_queries_do_not() {
    assert!(check_log_clear_exec(&exec_event("journalctl --vacuum-time=1s")).is_some());
    assert!(check_log_clear_exec(&exec_event("journalctl -u sshd -f")).is_none());
}

// --- T1070.002 log clearing (file-deletion half) ----------------------------

fn file_delete(path: &str) -> FileDeleteEvent {
    FileDeleteEvent {
        meta: meta(),
        path: path.to_string(),
    }
}

#[test]
fn deleting_a_log_file_alerts() {
    let alert = check_log_file_delete(&file_delete("/var/log/auth.log")).expect("must alert");
    assert_eq!(alert.technique, "T1070.002");
    // The dispatcher carries it too.
    assert_eq!(
        evaluate_file_delete(&file_delete("/var/log/auth.log")).len(),
        1
    );
}

#[test]
fn journal_and_evtx_paths_alert() {
    assert!(check_log_file_delete(&file_delete("/var/log/journal/abc/system.journal")).is_some());
    assert!(
        check_log_file_delete(&file_delete(
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        ))
        .is_some()
    );
}

#[test]
fn ordinary_deletions_stay_silent() {
    assert!(check_log_file_delete(&file_delete("/tmp/build.o")).is_none());
    assert!(evaluate_file_delete(&file_delete("/home/u/notes.txt")).is_empty());
}

// --- T1110 auth-failure burst -----------------------------------------------

fn auth_failure(target: &str, source: Option<&str>, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            ..meta()
        },
        outcome: AuthOutcome::Failure,
        kind: AuthKind::LogonFailure,
        target_user: target.to_string(),
        target_user_sid: None,
        source_address: source.map(|s| s.parse().unwrap()),
        status_code: None,
    }
}

#[test]
fn failure_burst_alerts_once_per_window() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..AUTH_FAILURE_THRESHOLD as u64 + 2 {
        alerts.extend(state.on_auth(&auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000)));
    }
    assert_eq!(alerts.len(), 1, "one alert per window, not one per failure");
    assert_eq!(alerts[0].technique, "T1110");
    assert!(alerts[0].message.contains("root"));
    assert!(alerts[0].message.contains("10.0.0.5"));
}

#[test]
fn below_threshold_stays_silent() {
    let mut state = RuleState::new();
    for i in 0..u64::from(AUTH_FAILURE_THRESHOLD - 1) {
        assert!(
            state
                .on_auth(&auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000))
                .is_empty()
        );
    }
}

#[test]
fn distinct_sources_do_not_pool_into_one_burst() {
    // 3 failures each from two sources must not sum past the threshold —
    // the key is (target, source), or every busy VPN gateway would alert.
    let mut state = RuleState::new();
    for i in 0..3u64 {
        assert!(
            state
                .on_auth(&auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000))
                .is_empty()
        );
        assert!(
            state
                .on_auth(&auth_failure("root", Some("10.0.0.6"), i * 1_000_000_000))
                .is_empty()
        );
    }
}

#[test]
fn successes_never_count_toward_the_burst() {
    let mut state = RuleState::new();
    for i in 0..20u64 {
        let mut event = auth_failure("root", Some("10.0.0.5"), i * 1_000_000_000);
        event.outcome = AuthOutcome::Success;
        event.kind = AuthKind::Logon;
        assert!(state.on_auth(&event).is_empty());
    }
}

#[test]
fn sourceless_local_failures_burst_under_their_own_key() {
    // Console logons carry no source address (honest, per the schema doc) —
    // they count under a distinct "local" key, never a fabricated loopback.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..u64::from(AUTH_FAILURE_THRESHOLD) {
        alerts.extend(state.on_auth(&auth_failure("admin", None, i * 1_000_000_000)));
    }
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("local"));
}
