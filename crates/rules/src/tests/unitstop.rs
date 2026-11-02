//! UNEXPLAINED-UNIT-STOP (T1562.001, #1085): a security unit stopped that no exec, restart or
//! shutdown explains. One test per condition, and one per boundary of each, so that removing a
//! condition or moving its window fails a test that names it.

use super::*;
use crate::{
    Alert, Severity,
    unitstop::{CLOCK_SKEW_NS, EXEC_LOOKBACK_NS, SHUTDOWN_WINDOW_NS, START_WITHIN_NS},
};

const SEC: u64 = 1_000_000_000;
/// A time well past the epoch, so `at - EXEC_LOOKBACK_NS` never saturates in these tests.
const T0: u64 = 10_000 * SEC;

fn stopped(unit: &str, at: u64) -> schema::FileOpenEvent {
    let mut event = file_open_event_full(0, unit, unit, schema::FLAG_UNIT_STOPPED, at);
    event.meta.ppid = 0;
    event
}

fn exec(command: &str, at: u64) -> schema::ExecEvent {
    let comm = command.split_whitespace().next().unwrap();
    exec_event_full(3000, 600, comm, command, at)
}

/// What the unit stop at `T0` raises once `events` have gone by and the stream clock is far
/// past its wait. `events` are `(command, time)` execs, fed before the stop, so the order is
/// the caller's to choose: the rule judges at the end of the wait.
fn judged(unit: &str, execs: &[(&str, u64)]) -> Vec<Alert> {
    let mut state = RuleState::new();
    for (command, at) in execs.iter().filter(|(_, at)| *at <= T0) {
        state.on_exec(&exec(command, *at));
    }
    state.on_file_open(&stopped(unit, T0));
    // Execs after the stop (a start, a late arrival) come in before the wait ends.
    for (command, at) in execs.iter().filter(|(_, at)| *at > T0) {
        state.on_exec(&exec(command, *at));
    }
    // Nothing is due while the wait is running (an exec past its end moves the clock itself).
    if execs.iter().all(|(_, at)| *at < T0 + START_WITHIN_NS) {
        assert!(
            state.take_due_unit_stops().is_empty(),
            "judged before the wait ended"
        );
    }
    state.on_exec(&exec("true", T0 + START_WITHIN_NS + SEC));
    state
        .take_due_unit_stops()
        .into_iter()
        .map(|(_, alert)| alert)
        .collect()
}

fn assert_alerts_once(alerts: &[Alert], unit: &str) {
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].technique, "T1562.001");
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert!(alerts[0].message.contains(unit), "{}", alerts[0].message);
}

#[test]
fn a_stop_with_no_exec_start_or_shutdown_alerts_once_and_names_the_unit() {
    assert_alerts_once(&judged("auditd.service", &[]), "auditd");
    assert_alerts_once(&judged("falco", &[]), "falco");
}

#[test]
fn a_stop_waits_for_the_stream_clock_before_it_is_judged() {
    let mut state = RuleState::new();
    state.on_file_open(&stopped("auditd.service", T0));
    state.on_exec(&exec("true", T0 + START_WITHIN_NS - SEC));
    assert!(state.take_due_unit_stops().is_empty());
    state.on_exec(&exec("true", T0 + START_WITHIN_NS));
    let due = state.take_due_unit_stops();
    assert_eq!(due.len(), 1);
    assert_eq!(
        due[0].0.meta.timestamp_ns, T0,
        "attributed to its own event"
    );
    assert!(state.take_due_unit_stops().is_empty(), "judged once");
}

// --- condition (a): an exec stopped the same unit just before ----------------------------------

#[test]
fn a_systemctl_stop_of_the_same_unit_explains_the_stop_and_is_not_alerted_twice() {
    let command = "systemctl stop auditd";
    assert!(judged("auditd.service", &[(command, T0 - 2 * SEC)]).is_empty());
    // The exec rule already raised its one alert for that command.
    let exec_alerts: Vec<_> = crate::evaluate_exec(&exec(command, T0 - 2 * SEC))
        .into_iter()
        .filter(|a| a.technique == "T1562.001")
        .collect();
    assert_eq!(exec_alerts.len(), 1, "{exec_alerts:?}");
}

#[test]
fn every_form_of_stop_the_exec_rule_reads_explains_the_stop() {
    for command in [
        "systemctl disable --now auditd",
        "systemctl mask --now auditd",
        "systemctl stop auditd.service",
        "service auditd stop",
    ] {
        assert!(
            judged("auditd.service", &[(command, T0 - SEC)]).is_empty(),
            "{command}"
        );
    }
}

#[test]
fn a_stop_of_another_unit_does_not_explain_the_stop() {
    assert_alerts_once(
        &judged("auditd.service", &[("systemctl stop falco", T0 - SEC)]),
        "auditd",
    );
    assert_alerts_once(
        &judged("auditd.service", &[("systemctl stop nginx", T0 - SEC)]),
        "auditd",
    );
}

#[test]
fn an_exec_stop_older_than_the_lookback_does_not_explain_the_stop() {
    let command = "systemctl stop auditd";
    assert!(judged("auditd.service", &[(command, T0 - EXEC_LOOKBACK_NS)]).is_empty());
    assert_alerts_once(
        &judged("auditd.service", &[(command, T0 - EXEC_LOOKBACK_NS - SEC)]),
        "auditd",
    );
}

#[test]
fn an_exec_stop_a_clock_skew_after_the_record_still_explains_it_but_not_much_later() {
    let command = "systemctl stop auditd";
    assert!(judged("auditd.service", &[(command, T0 + CLOCK_SKEW_NS)]).is_empty());
    assert_alerts_once(
        &judged("auditd.service", &[(command, T0 + CLOCK_SKEW_NS + SEC)]),
        "auditd",
    );
}

#[test]
fn the_order_the_exec_and_the_journal_event_arrive_in_does_not_matter() {
    // The exec is timestamped before the stop but drained after it: both inside the wait.
    let mut state = RuleState::new();
    state.on_file_open(&stopped("auditd.service", T0));
    state.on_exec(&exec("systemctl stop auditd", T0 - SEC));
    state.on_exec(&exec("true", T0 + START_WITHIN_NS + SEC));
    assert!(state.take_due_unit_stops().is_empty());
}

// --- condition (b): the unit started again within the wait -------------------------------------

#[test]
fn a_start_within_the_wait_explains_the_stop() {
    for command in [
        "systemctl start auditd",
        "systemctl start auditd.service",
        "systemctl enable --now auditd",
        "service auditd start",
        "invoke-rc.d auditd start",
        "deb-systemd-invoke start auditd.service",
        "systemctl reload-or-restart auditd",
    ] {
        assert!(
            judged("auditd.service", &[(command, T0 + 30 * SEC)]).is_empty(),
            "{command}"
        );
    }
}

#[test]
fn a_start_after_the_wait_does_not_explain_the_stop() {
    assert_alerts_once(
        &judged(
            "auditd.service",
            &[("systemctl start auditd", T0 + START_WITHIN_NS + SEC)],
        ),
        "auditd",
    );
}

#[test]
fn a_start_before_the_stop_does_not_explain_it() {
    // Started a minute earlier and still running: it is the stop that is unexplained.
    assert_alerts_once(
        &judged(
            "auditd.service",
            &[("systemctl start auditd", T0 - 60 * SEC)],
        ),
        "auditd",
    );
}

#[test]
fn a_start_of_another_unit_does_not_explain_the_stop() {
    assert_alerts_once(
        &judged("auditd.service", &[("systemctl start falco", T0 + 5 * SEC)]),
        "auditd",
    );
}

#[test]
fn a_restart_just_before_the_stop_explains_it() {
    for command in [
        "systemctl restart auditd",
        "systemctl try-restart auditd.service",
        "service auditd restart",
        "invoke-rc.d auditd restart",
        "deb-systemd-invoke restart auditd.service",
    ] {
        assert!(
            judged("auditd.service", &[(command, T0 - SEC)]).is_empty(),
            "{command}"
        );
    }
    // A restart is a stop and a start: asked long before, it is not this stop's.
    assert_alerts_once(
        &judged(
            "auditd.service",
            &[("systemctl restart auditd", T0 - EXEC_LOOKBACK_NS - SEC)],
        ),
        "auditd",
    );
}

// --- condition (c): the host is shutting down --------------------------------------------------

#[test]
fn a_shutdown_just_before_explains_the_stops_of_every_unit() {
    for command in [
        "shutdown -h now",
        "shutdown -r now",
        "reboot",
        "poweroff",
        "halt",
        "systemctl reboot",
        "systemctl poweroff",
        "systemctl kexec",
        "init 0",
        "telinit 6",
    ] {
        for unit in ["auditd.service", "falco", "clamav-daemon.service"] {
            assert!(
                judged(unit, &[(command, T0 - 20 * SEC)]).is_empty(),
                "{command} / {unit}"
            );
        }
    }
}

#[test]
fn a_shutdown_outside_the_window_does_not_explain_the_stop() {
    assert_alerts_once(
        &judged(
            "auditd.service",
            &[("reboot", T0 - SHUTDOWN_WINDOW_NS - SEC)],
        ),
        "auditd",
    );
    assert!(judged("auditd.service", &[("reboot", T0 - SHUTDOWN_WINDOW_NS)]).is_empty());
}

#[test]
fn a_command_that_does_not_shut_the_host_down_is_not_a_shutdown() {
    for command in [
        "shutdown -k now",
        "shutdown -c",
        "systemctl status reboot.target",
        "init 3",
        "systemctl stop nginx",
    ] {
        assert_alerts_once(
            &judged("auditd.service", &[(command, T0 - 5 * SEC)]),
            "auditd",
        );
    }
}

// --- what is not reached ----------------------------------------------------------------------

#[test]
fn a_unit_that_is_not_listed_is_not_queued_or_judged() {
    for unit in [
        "nginx.service",
        "postgresql",
        "auditd-helper.service",
        "sshd",
    ] {
        assert!(judged(unit, &[]).is_empty(), "{unit}");
    }
}

#[test]
fn a_file_open_without_the_flag_is_not_a_stop() {
    let mut state = RuleState::new();
    let mut event = stopped("auditd.service", T0);
    event.flags = 0;
    state.on_file_open(&event);
    state.on_exec(&exec("true", T0 + START_WITHIN_NS + SEC));
    assert!(state.take_due_unit_stops().is_empty());
}

#[test]
fn a_flooded_queue_stays_bounded_and_every_unexplained_stop_still_alerts() {
    let mut state = RuleState::new();
    let n = 200;
    for i in 0..n {
        state.on_file_open(&stopped("auditd.service", T0 + i));
    }
    state.on_exec(&exec("true", T0 + n + START_WITHIN_NS + SEC));
    assert_eq!(state.take_due_unit_stops().len(), n as usize);
}
