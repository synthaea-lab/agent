//! FIRST-SEEN-LOGON (T1078, #376): the first successful logon of an account after the
//! learning window.

use schema::{AuthEvent, AuthKind, AuthOutcome, User, detection::Severity};

use super::*;
use crate::exclusions::LOGON_LEARNING_NS;

const HOUR: u64 = 3_600_000_000_000;

fn logon(user: &str, ts: u64) -> AuthEvent {
    AuthEvent {
        target_user: user.to_string(),
        meta: EventMeta {
            timestamp_ns: ts,
            ..schema::fixtures::meta()
        },
        ..schema::fixtures::auth()
    }
}

fn first_seen(state: &mut RuleState, user: &str, ts: u64) -> Vec<crate::Alert> {
    state
        .on_auth(&logon(user, ts))
        .into_iter()
        .filter(|a| a.technique == "T1078")
        .collect()
}

/// A state whose learning window is over: `alice` logged on at t = 0 and it is 25 h later.
fn after_the_window() -> (RuleState, u64) {
    let mut state = RuleState::new();
    assert!(first_seen(&mut state, "alice", 0).is_empty());
    (state, 25 * HOUR)
}

#[test]
fn an_account_first_seen_after_the_window_alerts_once() {
    let (mut state, now) = after_the_window();
    let mut event = logon("mallory", now);
    event.source_address = Some("203.0.113.9".parse().unwrap());
    let alerts: Vec<_> = state
        .on_auth(&event)
        .into_iter()
        .filter(|a| a.technique == "T1078")
        .collect();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].severity, Severity::Low);
    assert!(
        alerts[0].message.contains("mallory"),
        "{}",
        alerts[0].message
    );
    assert!(
        alerts[0].message.contains("203.0.113.9"),
        "{}",
        alerts[0].message
    );
    // It is in the baseline now.
    assert!(first_seen(&mut state, "mallory", now + HOUR).is_empty());
}

#[test]
fn accounts_seen_inside_the_window_are_learned_without_an_alert() {
    let mut state = RuleState::new();
    assert!(first_seen(&mut state, "alice", 0).is_empty());
    assert!(first_seen(&mut state, "bob", HOUR).is_empty());
    assert!(first_seen(&mut state, "carol", LOGON_LEARNING_NS - 1).is_empty());
    // After the window those three are known.
    for user in ["alice", "bob", "carol"] {
        assert!(first_seen(&mut state, user, 30 * HOUR).is_empty(), "{user}");
    }
    assert_eq!(first_seen(&mut state, "dave", 30 * HOUR).len(), 1);
}

#[test]
fn the_window_is_measured_from_the_first_logon_of_any_account_generic_included() {
    let mut state = RuleState::new();
    // Only `root` logs on for a day; the clock started with it.
    assert!(first_seen(&mut state, "root", 0).is_empty());
    assert!(first_seen(&mut state, "root", 12 * HOUR).is_empty());
    assert_eq!(
        first_seen(&mut state, "mallory", LOGON_LEARNING_NS).len(),
        1
    );
}

#[test]
fn generic_accounts_never_alert() {
    let (mut state, now) = after_the_window();
    for user in [
        "root",
        "SYSTEM",
        "NT AUTHORITY\\SYSTEM",
        "CORP\\Administrator",
        "WS01$",
        "DWM-2",
        "ANONYMOUS LOGON",
        "ubuntu",
        "ec2-user",
        "admin",
    ] {
        assert!(first_seen(&mut state, user, now).is_empty(), "{user}");
    }
}

#[test]
fn vagrant_is_not_generic() {
    let (mut state, now) = after_the_window();
    assert_eq!(first_seen(&mut state, "vagrant", now).len(), 1);
}

#[test]
fn a_failed_logon_never_counts_however_new_the_name() {
    let (mut state, now) = after_the_window();
    let mut event = logon("mallory", now);
    event.outcome = AuthOutcome::Failure;
    event.kind = AuthKind::LogonFailure;
    assert!(state.on_auth(&event).iter().all(|a| a.technique != "T1078"));
    // The failed name did not enter the baseline either: the first success still alerts.
    assert_eq!(first_seen(&mut state, "mallory", now + HOUR).len(), 1);
}

#[test]
fn sudo_su_and_privileged_sessions_are_not_logons() {
    let (mut state, now) = after_the_window();
    for kind in [AuthKind::ExplicitCredentials, AuthKind::PrivilegedSession] {
        let mut event = logon("mallory", now);
        event.kind = kind;
        event.meta.comm = "su".to_string();
        assert!(state.on_auth(&event).iter().all(|a| a.technique != "T1078"));
    }
    assert_eq!(first_seen(&mut state, "mallory", now + HOUR).len(), 1);
}

#[test]
fn the_account_is_compared_without_regard_to_case() {
    let (mut state, now) = after_the_window();
    assert!(first_seen(&mut state, "ALICE", now).is_empty());
    assert_eq!(first_seen(&mut state, "Mallory", now).len(), 1);
    assert!(first_seen(&mut state, "mallory", now + HOUR).is_empty());
}

#[test]
fn a_windows_logon_is_covered_too() {
    let mut state = RuleState::new();
    let windows = |user: &str, ts: u64| {
        let mut event = logon(user, ts);
        event.meta.user = User::Windows {
            sid: "S-1-5-21-1-2-3-1001".to_string(),
            integrity_level: None,
        };
        event
    };
    assert!(state.on_auth(&windows("CORP\\alice", 0)).is_empty());
    let alerts = state.on_auth(&windows("CORP\\bob", 25 * HOUR));
    assert_eq!(
        alerts.iter().filter(|a| a.technique == "T1078").count(),
        1,
        "{alerts:?}"
    );
}

#[test]
fn an_empty_account_name_is_ignored() {
    let (mut state, now) = after_the_window();
    assert!(first_seen(&mut state, "", now).is_empty());
}

#[test]
fn an_event_older_than_the_baseline_start_is_inside_the_window() {
    let mut state = RuleState::new();
    assert!(first_seen(&mut state, "alice", 100 * HOUR).is_empty());
    assert!(first_seen(&mut state, "bob", 0).is_empty());
}

#[test]
fn the_baseline_is_bounded_and_an_evicted_account_is_first_seen_again() {
    let (mut state, now) = after_the_window();
    for i in 0..(COUNTER_CAP + 10) {
        first_seen(&mut state, &format!("user{i}"), now);
    }
    // `alice` was the oldest entry and is gone; the newest are still known.
    assert_eq!(first_seen(&mut state, "alice", now + HOUR).len(), 1);
    assert!(first_seen(&mut state, &format!("user{}", COUNTER_CAP + 9), now + HOUR).is_empty());
}

#[test]
fn the_failure_burst_and_the_first_seen_alert_are_independent() {
    let (mut state, now) = after_the_window();
    let mut techniques = Vec::new();
    for i in 0..u64::from(AUTH_FAILURE_THRESHOLD) {
        let mut event = logon("mallory", now + i);
        event.outcome = AuthOutcome::Failure;
        event.kind = AuthKind::LogonFailure;
        techniques.extend(state.on_auth(&event).iter().map(|a| a.technique));
    }
    techniques.extend(
        state
            .on_auth(&logon("mallory", now + HOUR))
            .iter()
            .map(|a| a.technique),
    );
    assert_eq!(techniques, ["T1110", "T1078"]);
}

#[test]
fn the_outcome_gates_the_rule_on_its_own() {
    // No sensor pairs a failed outcome with `AuthKind::Logon`; the rule still must not trust
    // the kind alone: a failure's user name is chosen by whoever tries it.
    let (mut state, now) = after_the_window();
    let mut event = logon("mallory", now);
    event.outcome = AuthOutcome::Failure;
    assert!(state.on_auth(&event).iter().all(|a| a.technique != "T1078"));
}

// ODD-HOUR-LOGON (T1078, #376): a logon outside the host-local working hours.

/// 2026-10-30 00:00:00 UTC, in nanoseconds.
const MIDNIGHT_UTC: u64 = 1_793_318_400 * 1_000_000_000;

fn odd_hour(state: &mut RuleState, user: &str, ts: u64) -> Vec<crate::Alert> {
    state
        .on_auth(&logon(user, ts))
        .into_iter()
        .filter(|a| a.message.contains("outside the working hours"))
        .collect()
}

/// A state that knows the host is on UTC+2, and has long finished learning `alice`.
fn utc_plus_two() -> RuleState {
    let mut state = RuleState::new();
    assert!(state.set_local_utc_offset_minutes(120));
    state
}

#[test]
fn a_logon_at_night_in_host_local_time_alerts() {
    let mut state = utc_plus_two();
    // 01:30 UTC is 03:30 on the host.
    let alerts = odd_hour(&mut state, "mallory", MIDNIGHT_UTC + HOUR + HOUR / 2);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].technique, "T1078");
    assert_eq!(alerts[0].severity, Severity::Low);
    assert!(
        alerts[0].message.contains("mallory"),
        "{}",
        alerts[0].message
    );
    assert!(alerts[0].message.contains("03:00"), "{}", alerts[0].message);
}

#[test]
fn a_logon_in_working_hours_is_silent() {
    let mut state = utc_plus_two();
    // 12:00 UTC is 14:00 on the host.
    assert!(odd_hour(&mut state, "alice", MIDNIGHT_UTC + 12 * HOUR).is_empty());
}

#[test]
fn the_hour_is_the_hosts_not_utc() {
    // 06:00 UTC: working hours in UTC+2 (08:00), night in UTC-5 (01:00).
    let ts = MIDNIGHT_UTC + 6 * HOUR;
    let mut east = utc_plus_two();
    assert!(odd_hour(&mut east, "alice", ts).is_empty());
    let mut west = RuleState::new();
    assert!(west.set_local_utc_offset_minutes(-300));
    assert_eq!(odd_hour(&mut west, "alice", ts).len(), 1);
}

#[test]
fn the_working_window_includes_its_start_and_excludes_its_end() {
    let mut state = utc_plus_two();
    // 05:00 UTC = 07:00 local: in. 18:00 UTC = 20:00 local: out.
    assert!(odd_hour(&mut state, "alice", MIDNIGHT_UTC + 5 * HOUR).is_empty());
    assert_eq!(
        odd_hour(&mut state, "bob", MIDNIGHT_UTC + 18 * HOUR).len(),
        1
    );
    // 04:59 UTC = 06:59 local: out.
    assert_eq!(
        odd_hour(
            &mut state,
            "carol",
            MIDNIGHT_UTC + 5 * HOUR - 60_000_000_000
        )
        .len(),
        1
    );
}

#[test]
fn without_a_utc_offset_the_rule_is_off() {
    let mut state = RuleState::new();
    assert!(odd_hour(&mut state, "mallory", MIDNIGHT_UTC + 2 * HOUR).is_empty());
}

#[test]
fn an_offset_no_timezone_has_is_refused_and_the_rule_stays_off() {
    let mut state = RuleState::new();
    for minutes in [841, -721, i32::MAX, i32::MIN] {
        assert!(!state.set_local_utc_offset_minutes(minutes), "{minutes}");
    }
    assert!(odd_hour(&mut state, "mallory", MIDNIGHT_UTC + 2 * HOUR).is_empty());
    assert!(state.set_local_utc_offset_minutes(840));
    assert!(state.set_local_utc_offset_minutes(-720));
}

#[test]
fn one_alert_per_account_per_night_then_again_the_next() {
    let mut state = utc_plus_two();
    let night = MIDNIGHT_UTC + 22 * HOUR; // 00:00 local
    assert_eq!(odd_hour(&mut state, "mallory", night).len(), 1);
    assert!(odd_hour(&mut state, "mallory", night + HOUR).is_empty());
    assert!(odd_hour(&mut state, "MALLORY", night + 2 * HOUR).is_empty());
    // Another account is its own finding.
    assert_eq!(odd_hour(&mut state, "dave", night + HOUR).len(), 1);
    // The next night, 24 h later.
    assert_eq!(odd_hour(&mut state, "mallory", night + 24 * HOUR).len(), 1);
}

/// A Windows logon whose account name is localized (the accented French name of SYSTEM on a
/// French Windows, which arrives with the accented letter replaced by U+FFFD) is the local
/// SYSTEM account by its SID alone: it must not alert, at night (found on a French Windows,
/// #1091) nor as a first-seen account.
#[test]
fn a_localized_service_account_is_generic_by_its_sid() {
    let localized = "Syst\u{FFFD}me";
    let system = |user: &str, sid: Option<&str>, ts: u64| AuthEvent {
        target_user_sid: sid.map(str::to_string),
        ..logon(user, ts)
    };
    let mut state = utc_plus_two();
    for sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"] {
        let alerts = state.on_auth(&system(localized, Some(sid), MIDNIGHT_UTC + 22 * HOUR));
        assert!(
            alerts.iter().all(|a| a.technique != "T1078"),
            "{sid}: {alerts:?}"
        );
    }
    // The same name with a user's SID, or with none, is an ordinary account.
    for sid in [Some("S-1-5-21-1-2-3-1001"), None] {
        let alerts = state.on_auth(&system(localized, sid, MIDNIGHT_UTC + 22 * HOUR));
        assert_eq!(
            alerts.iter().filter(|a| a.technique == "T1078").count(),
            1,
            "{sid:?}"
        );
        state = utc_plus_two();
    }
    // As a first-seen account after the learning window.
    let (mut state, later) = after_the_window();
    let alerts = state.on_auth(&system(localized, Some("S-1-5-18"), later));
    assert!(alerts.iter().all(|a| a.technique != "T1078"), "{alerts:?}");
}

#[test]
fn generic_accounts_never_alert_at_night() {
    let mut state = utc_plus_two();
    for user in [
        "root",
        "SYSTEM",
        "NT AUTHORITY\\SYSTEM",
        "ubuntu",
        "WS01$",
        "",
    ] {
        assert!(
            odd_hour(&mut state, user, MIDNIGHT_UTC + 22 * HOUR).is_empty(),
            "{user}"
        );
    }
    // `vagrant` is not generic, as for FIRST-SEEN-LOGON.
    assert_eq!(
        odd_hour(&mut state, "vagrant", MIDNIGHT_UTC + 22 * HOUR).len(),
        1
    );
}

#[test]
fn a_failed_logon_or_a_privileged_session_at_night_is_not_a_logon() {
    let mut state = utc_plus_two();
    let at = MIDNIGHT_UTC + 22 * HOUR;
    let mut failure = logon("mallory", at);
    failure.outcome = AuthOutcome::Failure;
    let mut sudo = logon("mallory", at);
    sudo.kind = AuthKind::PrivilegedSession;
    let mut explicit = logon("mallory", at);
    explicit.kind = AuthKind::ExplicitCredentials;
    for event in [failure, sudo, explicit] {
        let alerts = state.on_auth(&event);
        assert!(
            alerts
                .iter()
                .all(|a| !a.message.contains("outside the working hours")),
            "{alerts:?}"
        );
    }
}

#[test]
fn a_first_logon_at_night_raises_both_findings_independently() {
    let mut state = utc_plus_two();
    assert!(first_seen(&mut state, "alice", MIDNIGHT_UTC + 12 * HOUR).is_empty());
    // 25 h later, 15:00 UTC the next day is 17:00 local: only first-seen.
    let day = MIDNIGHT_UTC + 12 * HOUR + 25 * HOUR;
    assert_eq!(first_seen(&mut state, "erin", day).len(), 1);
    // The same account at 23:00 local, two days on, is known: only odd-hour.
    let night = MIDNIGHT_UTC + 48 * HOUR + 21 * HOUR;
    let alerts = state.on_auth(&logon("erin", night));
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].message.contains("outside the working hours"));
    // A brand new account at night raises both.
    let alerts = state.on_auth(&logon("frank", night + HOUR));
    assert_eq!(alerts.len(), 2, "{alerts:?}");
}

// ODD-HOUR-LOGON, platform zone and daylight saving (#1088).

/// Central Europe in 2026: CET (UTC+1), CEST (UTC+2) from 29 March 01:00 UTC to 25 October
/// 01:00 UTC. A stand-in for the platform's conversion, which the rules receive as a function.
fn central_europe(secs: i64) -> Option<i32> {
    const SPRING: i64 = 1_774_746_000;
    const AUTUMN: i64 = 1_792_890_000;
    Some(if (SPRING..AUTUMN).contains(&secs) {
        120
    } else {
        60
    })
}

fn no_answer(_secs: i64) -> Option<i32> {
    None
}

fn no_such_zone(_secs: i64) -> Option<i32> {
    Some(900)
}

const NOW_SECS: i64 = 1_793_318_400;

fn paris() -> RuleState {
    let mut state = RuleState::new();
    assert!(state.set_local_zone(central_europe, NOW_SECS));
    state
}

// 2026-03-28 05:30 UTC and 2026-03-30 05:30 UTC: the same clock time in UTC, either side of
// the spring change. 06:30 CET is before the working day, 07:30 CEST is inside it.
const BEFORE_SPRING: u64 = 1_774_675_800_000_000_000;
const AFTER_SPRING: u64 = 1_774_848_600_000_000_000;
// 2026-10-24 18:30 UTC and 2026-10-26 18:30 UTC, either side of the autumn change:
// 20:30 CEST is after the working day, 19:30 CET is inside it.
const BEFORE_AUTUMN: u64 = 1_792_866_600_000_000_000;
const AFTER_AUTUMN: u64 = 1_793_039_400_000_000_000;

#[test]
fn the_same_utc_time_is_judged_by_the_zones_rules_at_that_instant_in_spring() {
    let mut state = paris();
    let before = odd_hour(&mut state, "mallory", BEFORE_SPRING);
    assert_eq!(before.len(), 1, "06:30 CET is before 07:00: {before:?}");
    assert!(before[0].message.contains("06:00"), "{}", before[0].message);
    assert!(
        odd_hour(&mut state, "alice", AFTER_SPRING).is_empty(),
        "07:30 CEST is inside the working hours"
    );
}

#[test]
fn the_same_utc_time_is_judged_by_the_zones_rules_at_that_instant_in_autumn() {
    let mut state = paris();
    let before = odd_hour(&mut state, "mallory", BEFORE_AUTUMN);
    assert_eq!(before.len(), 1, "20:30 CEST is after 20:00: {before:?}");
    assert!(before[0].message.contains("20:00"), "{}", before[0].message);
    assert!(
        odd_hour(&mut state, "alice", AFTER_AUTUMN).is_empty(),
        "19:30 CET is inside the working hours"
    );
}

#[test]
fn a_fixed_offset_overrides_the_platform_zone_in_either_order() {
    // 2026-10-30 08:00 UTC: 09:00 in Central Europe (inside the working hours), 03:00 at UTC-5.
    let ts = MIDNIGHT_UTC + 8 * HOUR;
    let mut zone_then_fixed = RuleState::new();
    assert!(zone_then_fixed.set_local_zone(central_europe, NOW_SECS));
    assert!(zone_then_fixed.set_local_utc_offset_minutes(-300));
    assert_eq!(odd_hour(&mut zone_then_fixed, "mallory", ts).len(), 1);

    let mut fixed_then_zone = RuleState::new();
    assert!(fixed_then_zone.set_local_utc_offset_minutes(-300));
    assert!(fixed_then_zone.set_local_zone(central_europe, NOW_SECS));
    assert_eq!(odd_hour(&mut fixed_then_zone, "mallory", ts).len(), 1);

    // The zone alone sees working hours at that instant.
    assert!(odd_hour(&mut paris(), "mallory", ts).is_empty());
}

#[test]
fn a_zone_with_no_answer_now_is_refused_and_the_rule_stays_off() {
    let mut state = RuleState::new();
    assert!(!state.set_local_zone(no_answer, NOW_SECS));
    assert!(!state.set_local_zone(no_such_zone, NOW_SECS));
    assert!(odd_hour(&mut state, "mallory", MIDNIGHT_UTC + 2 * HOUR).is_empty());
}

#[test]
fn a_refused_zone_keeps_the_one_the_rule_had() {
    let mut state = paris();
    assert!(!state.set_local_zone(no_answer, NOW_SECS));
    assert_eq!(odd_hour(&mut state, "mallory", BEFORE_SPRING).len(), 1);
}

#[test]
fn an_instant_the_zone_cannot_convert_is_silent_not_utc() {
    // The zone answered for "now" and not for this instant: no alert, no fallback to UTC.
    fn only_recent(secs: i64) -> Option<i32> {
        (secs >= 1_790_000_000).then_some(60)
    }
    let mut state = RuleState::new();
    assert!(state.set_local_zone(only_recent, NOW_SECS));
    // 01:00 UTC on 2026-03-30 would be night in UTC and in CEST alike.
    assert!(odd_hour(&mut state, "mallory", 1_774_832_400_000_000_000).is_empty());
    assert_eq!(
        odd_hour(&mut state, "mallory", MIDNIGHT_UTC + 2 * HOUR).len(),
        1
    );
}

#[test]
fn a_zone_answer_no_timezone_has_is_ignored_at_that_instant() {
    fn wild_later(secs: i64) -> Option<i32> {
        Some(if secs > NOW_SECS { 900 } else { 60 })
    }
    let mut state = RuleState::new();
    assert!(state.set_local_zone(wild_later, NOW_SECS));
    // 12:00 UTC: read as UTC+15 it would be 03:00, an alert; no timezone has that offset.
    assert!(
        odd_hour(
            &mut state,
            "mallory",
            MIDNIGHT_UTC + 40 * 24 * HOUR + 12 * HOUR
        )
        .is_empty()
    );
}
