//! sudo/su success-after-failures rule (#381): T1548.003 for `sudo`,
//! T1110.001 for `su` (review of #838, Sollykhan 2026-10-19, non-blocking).

use schema::{AuthEvent, AuthKind, AuthOutcome, User, fixtures};

use super::*;
use crate::exclusions::{
    AUTH_FAILURE_THRESHOLD, SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD,
    SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS,
};

const SEC: u64 = 1_000_000_000;
const THRESHOLD: u64 = SUDO_SUCCESS_AFTER_FAILURES_THRESHOLD as u64;

/// `comm` defaults to `"sudo"`: `RuleState::on_auth` only joins a failure or a
/// `PrivilegedSession`/`ExplicitCredentials` success into the sudo/su burst
/// when the reporting process is `sudo` or `su` — every test in
/// this file that means to exercise the join needs that, same as a real
/// journal record would carry it (`AuthEvent::meta.comm` is the syslog
/// identifier, `sensor-linux-journal::auth::reporter_meta`).
fn failure(target_user: &str, ts: u64) -> AuthEvent {
    failure_from("sudo", target_user, ts)
}

fn failure_from(comm: &str, target_user: &str, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            comm: comm.to_string(),
            ..meta()
        },
        outcome: AuthOutcome::Failure,
        kind: AuthKind::LogonFailure,
        target_user: target_user.to_string(),
        ..fixtures::auth()
    }
}

fn success(target_user: &str, kind: AuthKind, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            comm: "sudo".to_string(),
            ..meta()
        },
        outcome: AuthOutcome::Success,
        kind,
        target_user: target_user.to_string(),
        ..fixtures::auth()
    }
}

/// Like [`failure`]/[`success`] but with an overridden invoker uid — needed
/// for any test about *sudo's* own join, which keys on `meta.user`'s uid, not
/// on `target_user` (review of #838, Sollykhan 2026-10-19, point 1; every
/// other test in this file shares `meta()`'s fixed uid 1000, which is fine
/// for them since none of them assert on sudo-side identity separation).
fn sudo_failure_as(uid: u32, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            comm: "sudo".to_string(),
            user: User::Unix { uid, gid: uid },
            ..meta()
        },
        outcome: AuthOutcome::Failure,
        kind: AuthKind::LogonFailure,
        target_user: "root".to_string(),
        ..fixtures::auth()
    }
}

fn sudo_success_as(uid: u32, kind: AuthKind, ts: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            timestamp_ns: ts,
            comm: "sudo".to_string(),
            user: User::Unix { uid, gid: uid },
            ..meta()
        },
        outcome: AuthOutcome::Success,
        kind,
        target_user: "root".to_string(),
        ..fixtures::auth()
    }
}

#[test]
fn privileged_session_after_five_failures_alerts_once_per_window() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }

    let alerts = state.on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1548.003");
    assert_eq!(alerts[0].severity, schema::detection::Severity::Medium);
    // `meta()`'s fixed test uid, not `target_user` — sudo's join keys on the
    // trusted invoker uid (review of #838, Sollykhan 2026-10-19, point 1).
    assert!(alerts[0].message.contains("sudo invoker_uid=1000"));
    assert!(alerts[0].message.contains("5 failed authentications"));
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 11 * SEC))
            .is_empty()
    );
}

#[test]
fn explicit_credentials_success_also_joins_the_burst() {
    // `su`/`sudo -u other` map to `ExplicitCredentials`, not `PrivilegedSession`
    // (schema::AuthKind's own doc) — both must complete the join.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("deploy", i * SEC));
    }
    let alerts = state.on_auth(&success("deploy", AuthKind::ExplicitCredentials, 10 * SEC));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1548.003");
}

#[test]
fn a_plain_logon_success_does_not_join_the_burst() {
    // `AuthKind::Logon` (e.g. a plain `login`/`su` session, not an elevation) is
    // not the signal T1548.003 is about.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::Logon, 10 * SEC))
            .is_empty()
    );
}

#[test]
fn a_windows_identity_success_does_not_join_the_local_burst() {
    // This join is for local (Unix) privilege escalation; a Windows success
    // reaches the rules through `rdp_success`/`on_session`, not here.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    let mut windows_success = success("root", AuthKind::PrivilegedSession, 10 * SEC);
    windows_success.meta.user = User::Windows {
        sid: "S-1-5-18".into(),
        integrity_level: None,
    };
    assert!(state.on_auth(&windows_success).is_empty());
}

#[test]
fn failures_from_a_windows_identity_do_not_feed_the_local_join() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        let mut windows_failure = failure("root", i * SEC);
        windows_failure.meta.user = User::Windows {
            sid: "S-1-5-18".into(),
            integrity_level: None,
        };
        state.on_auth(&windows_failure);
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC))
            .is_empty()
    );
}

#[test]
fn distinct_sudo_invokers_do_not_share_the_burst() {
    // Sudo's own join keys on the trusted invoker uid, not `target_user`
    // (review of #838, Sollykhan 2026-10-19, point 1) — same `target_user`
    // ("root") on both sides, but a different invoker uid, must not join.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&sudo_failure_as(1000, i * SEC));
    }
    assert!(
        state
            .on_auth(&sudo_success_as(
                2000,
                AuthKind::ExplicitCredentials,
                10 * SEC
            ))
            .is_empty(),
        "a different invoker uid must not inherit uid 1000's sudo failures"
    );
}

#[test]
fn distinct_su_targets_do_not_share_the_burst() {
    // Unlike `sudo`, `su` still keys on the target name, unaffected by the
    // #838 point-1 fix (same invoker uid on both sides here, per `failure`/
    // `success`'s shared `meta()`) — see `crate::sudo`'s module doc for why.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure_from("su", "root", i * SEC));
    }
    let mut alice = success("alice", AuthKind::ExplicitCredentials, 10 * SEC);
    alice.meta.comm = "su".to_string();
    assert!(state.on_auth(&alice).is_empty());
}

#[test]
fn su_success_after_failures_for_the_same_target_reports_password_guessing() {
    // `su` has no cache to abuse, so the join reports T1110.001, not sudo's
    // T1548.003 (review of #838, Sollykhan 2026-10-19, non-blocking).
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure_from("su", "root", i * SEC));
    }
    let mut root = success("root", AuthKind::ExplicitCredentials, 10 * SEC);
    root.meta.comm = "su".to_string();
    let alerts = state.on_auth(&root);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1110.001");
    assert!(alerts[0].message.starts_with("su target=root:"));
}

#[test]
fn below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC))
            .is_empty()
    );
}

#[test]
fn failures_outside_the_window_do_not_count() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    let late = SUDO_SUCCESS_AFTER_FAILURES_WINDOW_NS + 10 * SEC;
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, late))
            .is_empty()
    );
}

#[test]
fn success_delivered_before_the_last_failure_still_alerts() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC))
            .is_empty(),
        "four failures are not enough yet"
    );

    let alerts = state.on_auth(&failure("root", 6 * SEC));
    let sudo: Vec<_> = alerts
        .iter()
        .filter(|a| a.technique == "T1548.003")
        .collect();
    assert_eq!(sudo.len(), 1, "the late failure completes the join");
}

#[test]
fn sshd_failures_do_not_feed_the_sudo_su_join() {
    // sshd's own PAM auth failure maps to `SshFailed`/`LogonFailure` too, and
    // both it and a sudo/su failure carry `User::Unix` — only `meta.comm`
    // (the reporting process) tells them apart. Five sshd
    // failures for "root", then a real sudo success for "root", must not
    // alert: the join has nothing genuine behind it.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure_from("sshd", "root", i * SEC));
    }
    assert!(
        state
            .on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC))
            .is_empty(),
        "sshd failures must not complete the sudo/su join"
    );
}

#[test]
fn an_attacker_controlled_sshd_username_cannot_evict_real_sudo_history() {
    // Before the comm filter, a flood of distinct sshd usernames (attacker-
    // controlled, unlike a local sudo/su invoker) could evict a real sudo
    // target's bounded history out of `SudoSuccessAfterFailures` before its
    // success arrived (`sudo.rs`'s `TARGETS_CAP`). With sshd kept
    // out of the join entirely, this many distinct sshd "failures" must do
    // nothing to root's own, unrelated sudo failures.
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    for i in 0..10_000u64 {
        state.on_auth(&failure_from(
            "sshd",
            &format!("attacker{i}"),
            (THRESHOLD + i) * SEC,
        ));
    }
    let alerts = state.on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC));
    assert_eq!(
        alerts.len(),
        1,
        "root's real sudo failures must still be there"
    );
}

#[test]
fn failure_timestamped_after_the_success_does_not_count() {
    let mut state = RuleState::new();
    for i in 0..THRESHOLD - 1 {
        state.on_auth(&failure("root", i * SEC));
    }
    state.on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC));

    let alerts = state.on_auth(&failure("root", 11 * SEC));
    assert!(
        alerts.iter().all(|a| a.technique != "T1548.003"),
        "a failure after the success is not a failure before it"
    );
}

#[test]
fn a_su_spray_of_throwaway_names_cannot_evict_real_sudo_history() {
    // Unlike an sshd name, a `su <name>` failure does reach the join (it is a real
    // `su` PAM line), and a local user chooses the name. Its own bounded history
    // keeps that spray away from `sudo`'s (#838 review).
    let mut state = RuleState::new();
    for i in 0..THRESHOLD {
        state.on_auth(&failure("root", i * SEC));
    }
    for i in 0..10_000u64 {
        state.on_auth(&failure_from(
            "su",
            &format!("spray{i}"),
            (THRESHOLD + i) * SEC,
        ));
    }
    let alerts = state.on_auth(&success("root", AuthKind::PrivilegedSession, 10 * SEC));
    assert_eq!(
        alerts.len(),
        1,
        "root's real sudo failures must survive a su spray"
    );
}

#[test]
fn local_sudo_failures_also_feed_the_generic_t1110_burst() {
    // `AuthEvent` failures from sudo/su reach `on_auth`'s generic burst counter as
    // well (key: target account, source "local"): five wrong sudo passwords in the
    // window raise T1110 on their own, whether or not a success ever follows. That
    // is deliberate (local password guessing is T1110), and it is separate from the
    // T1548.003 join, which needs the success (#838 review).
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..u64::from(AUTH_FAILURE_THRESHOLD) {
        alerts.extend(state.on_auth(&failure("lab", i * SEC)));
    }
    let burst: Vec<_> = alerts.iter().filter(|a| a.technique == "T1110").collect();
    assert_eq!(burst.len(), 1);
    assert!(burst[0].message.contains("target=lab source=local"));
    assert!(alerts.iter().all(|a| a.technique != "T1548.003"));
}
