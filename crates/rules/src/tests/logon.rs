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

// ODD-HOUR-LOGON, the operator's window and exempt accounts (#1089).

/// UTC+2, working hours `start..end` local; `MIDNIGHT_UTC + h * HOUR` is `h + 2` o'clock local.
fn with_window(start: u32, end: u32) -> RuleState {
    let mut state = utc_plus_two();
    assert!(state.set_work_hours(start, end));
    state
}

/// A logon at `local_hour` o'clock on the UTC+2 host, 30 minutes in.
fn at_local(local_hour: u64) -> u64 {
    MIDNIGHT_UTC + (local_hour + 22) % 24 * HOUR + HOUR / 2
}

#[test]
fn a_night_shift_window_wraps_midnight() {
    // [22, 6): 22:00 to 06:00 is ordinary, the day is not.
    let mut state = with_window(22, 6);
    assert!(
        odd_hour(&mut state, "nina", at_local(22)).is_empty(),
        "22:30 is in"
    );
    assert!(
        odd_hour(&mut state, "nina", at_local(23)).is_empty(),
        "23:30 is in"
    );
    assert!(
        odd_hour(&mut state, "nina", at_local(3)).is_empty(),
        "03:30 is in"
    );
    assert!(
        odd_hour(&mut state, "nina", at_local(5)).is_empty(),
        "05:30 is in"
    );
    // 06:30 is out (the end is excluded) and 21:30 is out (before the start).
    assert_eq!(
        odd_hour(&mut state, "mallory", at_local(6)).len(),
        1,
        "06:30"
    );
    assert_eq!(odd_hour(&mut state, "dave", at_local(21)).len(), 1, "21:30");
    assert_eq!(odd_hour(&mut state, "erin", at_local(12)).len(), 1, "noon");
}

#[test]
fn a_declared_window_replaces_the_default_in_both_directions() {
    // 18:30 is outside [9, 17) but inside the default 07:00-20:00; 08:30 the other way round.
    let mut narrow = with_window(9, 17);
    assert_eq!(odd_hour(&mut narrow, "mallory", at_local(18)).len(), 1);
    assert_eq!(odd_hour(&mut narrow, "dave", at_local(8)).len(), 1);
    assert!(odd_hour(&mut narrow, "alice", at_local(9)).is_empty());
    let mut wide = with_window(5, 23);
    assert!(odd_hour(&mut wide, "alice", at_local(21)).is_empty());
    assert!(odd_hour(&mut wide, "bob", at_local(5)).is_empty());
    assert_eq!(odd_hour(&mut wide, "mallory", at_local(23)).len(), 1);
}

#[test]
fn a_round_the_clock_window_never_alerts() {
    let mut state = with_window(0, 24);
    for hour in 0..24 {
        assert!(
            odd_hour(&mut state, &format!("u{hour}"), at_local(hour)).is_empty(),
            "{hour}"
        );
    }
}

#[test]
fn a_window_that_is_not_one_is_refused_and_the_default_stays() {
    let mut state = utc_plus_two();
    for (start, end) in [(24, 6), (7, 25), (7, 0), (8, 8), (0, 0), (u32::MAX, 1)] {
        assert!(!state.set_work_hours(start, end), "{start}..{end}");
    }
    // The default 07:00-20:00 still applies: 12:30 silent, 03:30 an alert.
    assert!(odd_hour(&mut state, "alice", at_local(12)).is_empty());
    assert_eq!(odd_hour(&mut state, "mallory", at_local(3)).len(), 1);
}

fn exempt(accounts: &[&str]) -> RuleState {
    let mut state = utc_plus_two();
    state.set_odd_hour_exempt_accounts(
        &accounts
            .iter()
            .map(|a| (*a).to_string())
            .collect::<Vec<_>>(),
    );
    state
}

#[test]
fn an_exempt_account_is_silent_at_night_and_another_account_still_alerts() {
    let mut state = exempt(&["svc_backup"]);
    assert!(odd_hour(&mut state, "svc_backup", at_local(3)).is_empty());
    assert_eq!(odd_hour(&mut state, "mallory", at_local(3)).len(), 1);
}

#[test]
fn nothing_is_exempt_until_the_operator_says_so() {
    let mut state = utc_plus_two();
    assert_eq!(odd_hour(&mut state, "svc_backup", at_local(3)).len(), 1);
}

#[test]
fn exempt_accounts_match_without_case() {
    let mut state = exempt(&["SVC_Backup"]);
    assert!(odd_hour(&mut state, "svc_backup", at_local(3)).is_empty());
    assert!(odd_hour(&mut state, "SVC_BACKUP", at_local(3)).is_empty());
    // A near miss is another account.
    assert_eq!(odd_hour(&mut state, "svc_backup2", at_local(3)).len(), 1);
    assert_eq!(odd_hour(&mut state, "xsvc_backup", at_local(3)).len(), 1);
}

/// An event that does report a domain is matched on the whole string, so a bare entry does not
/// reach it. No sensor reports `DOMAIN\name` for a logon today (see the next test; an SSSD host
/// logs `user@realm`, which is another string a bare entry does not match either), so this guards
/// the matcher, not a threat the agent can meet yet.
#[test]
fn a_bare_exempt_entry_does_not_exempt_the_same_name_under_a_domain() {
    let mut state = exempt(&["svc_backup"]);
    for user in [
        "CORP\\svc_backup",
        "WORKGROUP\\svc_backup",
        "DESKTOP-X\\svc_backup",
        "svc_backup@corp.com",
    ] {
        assert_eq!(odd_hour(&mut state, user, at_local(3)).len(), 1, "{user}");
    }
}

/// A Windows 4624 reaches the rule as the bare `TargetUserName` plus the account's SID (checked
/// live, 2026-11-03). A local account an intruder creates under an exempt name looks the same
/// to the rule apart from a SID it does not read, so it is exempted too. This pins that, so
/// binding an entry to the SID shows up as a deliberate change to this test.
#[test]
fn a_bare_exempt_entry_exempts_a_local_account_of_that_name_whatever_its_sid() {
    let mut state = exempt(&["svc_backup"]);
    let sensor_shaped = |user: &str, sid: &str| AuthEvent {
        target_user_sid: Some(sid.to_string()),
        ..logon(user, at_local(3))
    };
    let odd_hour_alerts = |state: &mut RuleState, event: &AuthEvent| {
        state
            .on_auth(event)
            .into_iter()
            .filter(|a| a.message.contains("outside the working hours"))
            .count()
    };
    // The account the operator meant, and a look-alike created under another authority.
    for sid in [
        "S-1-5-21-1111111111-2222222222-3333333333-1004",
        "S-1-5-21-4444444444-5555555555-6666666666-1001",
    ] {
        let event = sensor_shaped("svc_backup", sid);
        assert_eq!(odd_hour_alerts(&mut state, &event), 0, "{sid}");
    }
    // The control: the same event shape under a name that is not listed still alerts.
    let control = sensor_shaped("mallory", "S-1-5-21-4444444444-5555555555-6666666666-1002");
    assert_eq!(odd_hour_alerts(&mut state, &control), 1);
}

const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

/// An `AuthEvent` shaped like the Windows sensor's output: the bare name plus the account's SID.
fn odd_hour_with_sid(state: &mut RuleState, user: &str, sid: Option<&str>, ts: u64) -> usize {
    let event = AuthEvent {
        target_user_sid: sid.map(str::to_string),
        ..logon(user, ts)
    };
    state
        .on_auth(&event)
        .into_iter()
        .filter(|a| a.message.contains("outside the working hours"))
        .count()
}

#[test]
fn an_entry_bound_to_a_sid_exempts_only_the_account_with_that_sid() {
    let own = format!("{DOMAIN_SID}-1004");
    let mut state = exempt(&[&format!("svc_backup|{own}")]);
    // The account the operator meant.
    assert_eq!(
        odd_hour_with_sid(&mut state, "svc_backup", Some(&own), at_local(3)),
        0
    );
    // The same name under another authority: a local account an intruder created.
    let other = "S-1-5-21-4444444444-5555555555-6666666666-1001";
    assert_eq!(
        odd_hour_with_sid(&mut state, "svc_backup", Some(other), at_local(3)),
        1
    );
}

#[test]
fn an_entry_bound_to_a_sid_does_not_exempt_an_event_that_carries_none() {
    let mut state = exempt(&[&format!("svc_backup|{DOMAIN_SID}-1004")]);
    // Linux and macOS logons have no SID: a SID-bound entry never matches them.
    assert_eq!(
        odd_hour_with_sid(&mut state, "svc_backup", None, at_local(3)),
        1
    );
}

#[test]
fn a_sid_prefix_entry_exempts_the_name_below_that_prefix_only() {
    let mut state = exempt(&[&format!("svc_backup|{DOMAIN_SID}-*")]);
    assert_eq!(
        odd_hour_with_sid(
            &mut state,
            "svc_backup",
            Some(&format!("{DOMAIN_SID}-1004")),
            at_local(3)
        ),
        0
    );
    // Not an exact match of the prefix text, and not below it.
    let mut state = exempt(&[&format!("svc_backup|{DOMAIN_SID}-*")]);
    assert_eq!(
        odd_hour_with_sid(
            &mut state,
            "svc_backup",
            Some("S-1-5-21-9-9-9-1004"),
            at_local(3)
        ),
        1
    );
    // A longer authority that merely starts with the same digits is not below the prefix.
    let mut state = exempt(&[&format!("svc_backup|{DOMAIN_SID}-*")]);
    assert_eq!(
        odd_hour_with_sid(
            &mut state,
            "svc_backup",
            Some(&format!("{DOMAIN_SID}9-1004")),
            at_local(3)
        ),
        1
    );
}

#[test]
fn an_entry_with_a_malformed_sid_is_dropped_not_read_as_the_bare_name() {
    for bad in [
        "svc_backup|not-a-sid",
        "svc_backup|S-1-",
        "svc_backup|S-1-5--1",
        "svc_backup|S-1-5-21-1*",
        "|S-1-5-21-1-2-3-1004",
    ] {
        let mut state = utc_plus_two();
        let kept = state.set_odd_hour_exempt_accounts(&[bad.to_string()]);
        assert_eq!(kept, 0, "{bad}");
        // Reading it as the bare name would have exempted more than the operator wrote.
        assert_eq!(
            odd_hour(&mut state, "svc_backup", at_local(3)).len(),
            1,
            "{bad}"
        );
    }
}

#[test]
fn a_bare_entry_does_not_match_a_upn_or_a_slash_form() {
    let mut state = exempt(&["svc_backup"]);
    assert_eq!(
        odd_hour(&mut state, "svc_backup@corp.com", at_local(3)).len(),
        1
    );
    assert_eq!(
        odd_hour(&mut state, "corp/svc_backup", at_local(3)).len(),
        1
    );
}

#[test]
fn the_exempt_list_is_bounded_in_the_rules_too() {
    let mut state = utc_plus_two();
    let mut accounts: Vec<String> = (0..70).map(|i| format!("svc{i}")).collect();
    accounts.insert(3, "   ".into()); // blank: dropped, does not use a slot
    accounts.insert(5, "x".repeat(257)); // over-long: dropped
    let kept = state.set_odd_hour_exempt_accounts(&accounts);
    assert_eq!(kept, 64, "truncated to the cap, not refused");
    assert!(
        odd_hour(&mut state, "svc0", at_local(3)).is_empty(),
        "inside the cap"
    );
    assert!(
        odd_hour(&mut state, "svc63", at_local(3)).is_empty(),
        "the 64th entry"
    );
    assert_eq!(
        odd_hour(&mut state, "svc64", at_local(3)).len(),
        1,
        "past the cap"
    );
}

#[test]
fn an_exempt_skip_is_counted_and_an_ordinary_logon_is_not() {
    let mut state = exempt(&["svc_backup"]);
    assert_eq!(state.odd_hour_exempt_skips(), 0);
    assert!(odd_hour(&mut state, "svc_backup", at_local(12)).is_empty()); // inside the window
    assert_eq!(
        state.odd_hour_exempt_skips(),
        0,
        "an ordinary-hour logon is not a skip"
    );
    assert!(odd_hour(&mut state, "svc_backup", at_local(3)).is_empty());
    assert!(odd_hour(&mut state, "svc_backup", at_local(4)).is_empty());
    assert_eq!(state.odd_hour_exempt_skips(), 2);
    assert_eq!(odd_hour(&mut state, "mallory", at_local(3)).len(), 1);
    assert_eq!(
        state.odd_hour_exempt_skips(),
        2,
        "an alerted logon is not a skip"
    );
}

/// An odd local minute: `h:m` local on the day of `at_local`.
fn at_local_min(local_hour: u64, minute: u64) -> u64 {
    MIDNIGHT_UTC + (local_hour + 22) % 24 * HOUR + minute * 60_000_000_000
}

#[test]
fn a_declared_wrapping_window_is_exact_at_its_edges() {
    // [22, 6): 22:00 is the first ordinary minute, 06:00 the first odd one.
    let mut state = with_window(22, 6);
    for (user, hour, minute, odd) in [
        ("edge_a", 21, 59, true),
        ("edge_b", 22, 0, false),
        ("edge_c", 5, 59, false),
        ("edge_d", 6, 0, true),
    ] {
        assert_eq!(
            odd_hour(&mut state, user, at_local_min(hour, minute)).len(),
            usize::from(odd),
            "{hour:02}:{minute:02}"
        );
    }
}

#[test]
fn the_exempt_entry_grammar_matches_the_vectors_the_config_load_uses() {
    const VECTORS: &str = include_str!("../../../config/data/exempt-entry-vectors.txt");
    let mut checked = 0;
    for line in VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (kind, entry) = line.split_once('\t').expect(line);
        let mut state = utc_plus_two();
        let kept = state.set_odd_hour_exempt_accounts(&[entry.to_string()]);
        assert_eq!(kept, usize::from(kind == "ok"), "{line:?}");
        checked += 1;
    }
    assert!(checked >= 10, "the table was read: {checked}");
}

/// A `tracing` writer into a buffer, to read what the rules log.
#[derive(Clone, Default)]
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&'a self) -> LogCapture {
        self.clone()
    }
}

fn logs_at(level: tracing::Level, run: impl FnOnce()) -> String {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(level)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = capture.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

fn suppressed_logons_under_one_exempt_name() {
    let real = format!("{DOMAIN_SID}-1004");
    let lookalike = "S-1-5-21-4444444444-5555555555-6666666666-1001";
    let mut state = exempt(&["svc_backup"]);
    // The real account, then a look-alike under another SID within its quiet period, then the real
    // one again.
    odd_hour_with_sid(&mut state, "svc_backup", Some(&real), at_local_min(3, 10));
    odd_hour_with_sid(
        &mut state,
        "svc_backup",
        Some(lookalike),
        at_local_min(3, 20),
    );
    odd_hour_with_sid(&mut state, "svc_backup", Some(&real), at_local_min(3, 30));
}

#[test]
fn a_lookalike_sid_under_an_exempt_name_leaves_its_own_line_within_the_quiet_period() {
    let out = logs_at(
        tracing::Level::DEBUG,
        suppressed_logons_under_one_exempt_name,
    );
    let lines: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("exempt account"))
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "one per (name, SID), the repeat is throttled:\n{out}"
    );
    assert!(lines.iter().any(|l| l.contains("-1004")), "{out}");
    assert!(lines.iter().any(|l| l.contains("-1001")), "{out}");
}

#[test]
fn the_exempt_log_line_at_info_carries_no_account_and_no_sid() {
    let out = logs_at(
        tracing::Level::INFO,
        suppressed_logons_under_one_exempt_name,
    );
    assert!(out.contains("skips="), "the count is at info:\n{out}");
    assert!(!out.contains("svc_backup"), "no account at info:\n{out}");
    assert!(!out.contains("S-1-5-21"), "no SID at info:\n{out}");
}

#[test]
fn a_domain_qualified_exemption_matches_only_that_domain() {
    let mut state = exempt(&["CORP\\oncall"]);
    assert!(odd_hour(&mut state, "corp\\ONCALL", at_local(3)).is_empty());
    assert_eq!(odd_hour(&mut state, "OTHER\\oncall", at_local(3)).len(), 1);
    assert_eq!(odd_hour(&mut state, "oncall", at_local(3)).len(), 1);
}

#[test]
fn declaring_the_exempt_accounts_again_replaces_the_list_and_ignores_blanks() {
    let mut state = exempt(&["alice"]);
    state.set_odd_hour_exempt_accounts(&["bob".to_string(), String::new(), "  ".to_string()]);
    assert_eq!(odd_hour(&mut state, "alice", at_local(3)).len(), 1);
    assert!(odd_hour(&mut state, "bob", at_local(3)).is_empty());
    // A blank entry exempts nobody: not an account whose name is empty after the domain.
    assert_eq!(odd_hour(&mut state, "CORP\\", at_local(3)).len(), 1);
    assert_eq!(odd_hour(&mut state, "carol", at_local(3)).len(), 1);
}

#[test]
fn the_exemption_is_only_the_odd_hour_rules_first_seen_still_alerts() {
    let mut state = exempt(&["svc_backup"]);
    // Learning starts at the first logon (12:00 local) and ends 24 h later; then 03:00 local.
    assert!(
        state
            .on_auth(&logon("alice", MIDNIGHT_UTC + 10 * HOUR))
            .is_empty()
    );
    let alerts = state.on_auth(&logon("svc_backup", MIDNIGHT_UTC + 49 * HOUR));
    assert!(
        alerts
            .iter()
            .any(|a| a.technique == "T1078" && !a.message.contains("outside the working hours")),
        "first-seen must still see the exempt account: {alerts:?}"
    );
    assert!(
        alerts
            .iter()
            .all(|a| !a.message.contains("outside the working hours")),
        "{alerts:?}"
    );
}

#[test]
fn a_well_known_service_sid_under_an_exempt_name_is_generic_not_an_exempt_skip() {
    // The generic check runs before the exempt check: a localized SYSTEM logon is generic by its
    // SID, so it is neither an alert nor counted as an exempt skip.
    let mut state = exempt(&["système"]);
    assert_eq!(
        odd_hour_with_sid(&mut state, "système", Some("S-1-5-18"), at_local(3)),
        0
    );
    assert_eq!(state.odd_hour_exempt_skips(), 0);
}
