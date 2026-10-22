//! SSH-FANOUT (T1021.004, #378): outbound SSH to many distinct hosts from one lineage. Each
//! `ssh` is its own process with one connect, so the rule needs the lineage the process was
//! exec'd under: the cases are built as an exec followed by that process's connect.

use super::*;
use crate::{Alert, Severity};

const SEC: u64 = 1_000_000_000;
const SHELL: u32 = 900;

fn fanout(alerts: Vec<Alert>) -> Vec<Alert> {
    alerts
        .into_iter()
        .filter(|a| a.technique == "T1021.004")
        .collect()
}

/// Runs `ssh <host>` as pid `pid` under `ppid` at second `at`, and its connect to `host`:`port`.
fn ssh(
    state: &mut RuleState,
    pid: u32,
    ppid: u32,
    host: [u8; 4],
    port: u16,
    at: u64,
) -> Vec<Alert> {
    state.on_exec(&exec_event_full(pid, ppid, "ssh", "ssh target", at * SEC));
    fanout(state.on_connect(&connect_event_full(pid, "ssh", host, port, at * SEC)))
}

#[test]
fn ssh_to_eight_distinct_hosts_from_one_shell_alerts_once() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..10u8 {
        alerts.extend(ssh(
            &mut state,
            1000 + u32::from(i),
            SHELL,
            [10, 0, 0, i + 1],
            22,
            u64::from(i),
        ));
    }
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert!(
        alerts[0].message.contains("8 distinct hosts"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn seven_hosts_do_not_alert() {
    let mut state = RuleState::new();
    for i in 0..7u8 {
        assert!(
            ssh(
                &mut state,
                1100 + u32::from(i),
                SHELL,
                [10, 0, 0, i + 1],
                22,
                u64::from(i)
            )
            .is_empty()
        );
    }
}

#[test]
fn the_same_host_over_and_over_is_one_host() {
    // A deploy loop that opens many sessions to one server.
    let mut state = RuleState::new();
    for i in 0..40u32 {
        assert!(ssh(&mut state, 1200 + i, SHELL, [10, 0, 0, 1], 22, u64::from(i)).is_empty());
    }
}

#[test]
fn hosts_reached_from_different_shells_are_not_added_together() {
    let mut state = RuleState::new();
    for i in 0..12u8 {
        let alerts = ssh(
            &mut state,
            1300 + u32::from(i),
            2000 + u32::from(i),
            [10, 0, 0, i + 1],
            22,
            u64::from(i),
        );
        assert!(alerts.is_empty());
    }
}

#[test]
fn hosts_spread_over_several_minutes_do_not_alert() {
    let mut state = RuleState::new();
    for i in 0..12u8 {
        let alerts = ssh(
            &mut state,
            1400 + u32::from(i),
            SHELL,
            [10, 0, 0, i + 1],
            22,
            u64::from(i) * 30,
        );
        assert!(alerts.is_empty());
    }
}

#[test]
fn other_ports_and_loopback_are_not_ssh_fanout() {
    let mut state = RuleState::new();
    for i in 0..12u8 {
        assert!(
            ssh(
                &mut state,
                1500 + u32::from(i),
                SHELL,
                [10, 0, 0, i + 1],
                2222,
                u64::from(i)
            )
            .is_empty()
        );
    }
    for i in 0..12u8 {
        assert!(
            ssh(
                &mut state,
                1600 + u32::from(i),
                SHELL,
                [127, 0, 0, i + 1],
                22,
                u64::from(i)
            )
            .is_empty()
        );
    }
}

#[test]
fn a_process_the_rules_never_saw_exec_has_no_lineage_and_is_not_counted() {
    // Started before the agent: only its connects are seen.
    let mut state = RuleState::new();
    for i in 0..12u8 {
        let alerts = fanout(state.on_connect(&connect_event_full(
            1700 + u32::from(i),
            "ssh",
            [10, 0, 0, i + 1],
            22,
            u64::from(i) * SEC,
        )));
        assert!(alerts.is_empty());
    }
}

#[test]
fn ssh_started_through_one_shot_shells_is_one_lineage() {
    // `for h in ...; do sh -c "ssh $h ..."; done` from a web shell or a script runner:
    // every ssh has its own `sh -c` as parent, and the shells share the runner.
    let runner = 80;
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..9u8 {
        let sh = 3000 + 2 * u32::from(i);
        state.on_exec(&exec_event_full(
            sh,
            runner,
            "sh",
            "sh -c ssh",
            u64::from(i) * SEC,
        ));
        alerts.extend(ssh(
            &mut state,
            sh + 1,
            sh,
            [10, 0, 0, i + 1],
            22,
            u64::from(i),
        ));
    }
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn a_pid_reused_by_another_process_keeps_no_stale_lineage() {
    // pid 4000 was exec'd as ssh under SHELL (generation 1); the pid is reused (generation
    // 2) by a process that connects to port 22 without having been seen exec'd.
    let mut state = RuleState::new();
    let mut event = exec_event_full(4000, SHELL, "ssh", "ssh a", 0);
    event.meta.process_generation = Some(1);
    state.on_exec(&event);
    for i in 0..12u8 {
        let mut connect = connect_event_full(4000, "x", [10, 0, 0, i + 1], 22, u64::from(i) * SEC);
        connect.meta.process_generation = Some(2);
        assert!(fanout(state.on_connect(&connect)).is_empty());
    }
}
