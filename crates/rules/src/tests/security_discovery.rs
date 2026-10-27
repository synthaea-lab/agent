//! SECURITY-DISCOVERY (T1518.001, #378): three distinct security-software discovery commands
//! from one lineage in a minute. One such command is a hardening check; the set is a host
//! being sized up.

use super::*;
use crate::{Alert, Severity};

const SEC: u64 = 1_000_000_000;
const SHELL: u32 = 600;

/// The T1518.001 alerts of running `commands` (one per `step` seconds) under `SHELL`.
fn run(commands: &[&str], step: u64) -> Vec<Alert> {
    let mut state = RuleState::new();
    commands
        .iter()
        .enumerate()
        .flat_map(|(i, c)| {
            let comm = c.split_whitespace().next().unwrap();
            state.on_exec(&exec_event_full(
                2000 + i as u32,
                SHELL,
                comm,
                c,
                i as u64 * step * SEC,
            ))
        })
        .filter(|a| a.technique == "T1518.001")
        .collect()
}

#[test]
fn three_posture_commands_alert_once_and_name_them() {
    let alerts = run(&["getenforce", "aa-status", "auditctl -l", "sestatus"], 1);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].severity, Severity::Low);
    for name in ["getenforce", "aa-status", "auditctl"] {
        assert!(alerts[0].message.contains(name), "{}", alerts[0].message);
    }
}

#[test]
fn one_or_two_commands_are_a_hardening_check_not_a_set() {
    assert!(run(&["getenforce"], 1).is_empty());
    assert!(run(&["getenforce", "sestatus"], 1).is_empty());
}

#[test]
fn three_lookups_of_three_products_alert() {
    let alerts = run(
        &[
            "pgrep -l falcon-sensor",
            "systemctl status sentinelone",
            "ps aux | grep -i carbonblack",
        ],
        1,
    );
    // The third line is one `ps` with a pipe the shell would have split; the argument text
    // still names the product.
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn several_commands_about_the_same_product_are_one_label() {
    assert!(
        run(
            &[
                "pgrep falcon-sensor",
                "systemctl status falcon-sensor",
                "ls /opt/crowdstrike",
                "grep -r crowdstrike /etc",
            ],
            1,
        )
        .is_empty()
    );
}

#[test]
fn the_windows_forms_count() {
    let alerts = run(
        &[
            "powershell -Command Get-MpComputerStatus",
            "netsh advfirewall show allprofiles",
            "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayname",
        ],
        1,
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn the_same_programs_with_other_arguments_are_not_discovery() {
    assert!(
        run(
            &[
                "auditctl -a always,exit -S execve",
                "csrutil enable",
                "spctl --add /Applications/x.app",
                "netsh advfirewall set allprofiles state on",
                "systemextensionsctl reset",
                "mdatp scan quick",
            ],
            1,
        )
        .is_empty()
    );
}

#[test]
fn a_program_that_does_not_look_things_up_does_not_count_a_product_name() {
    assert!(
        run(
            &["cat sophos.txt", "vim crowdstrike.conf", "echo sentinelone"],
            1
        )
        .is_empty()
    );
}

#[test]
fn commands_spread_over_minutes_do_not_alert() {
    assert!(run(&["getenforce", "aa-status", "auditctl -l", "sestatus"], 40).is_empty());
}

#[test]
fn commands_of_different_parents_are_not_added_together() {
    let mut state = RuleState::new();
    for (i, c) in ["getenforce", "aa-status", "auditctl -l", "sestatus"]
        .iter()
        .enumerate()
    {
        let comm = c.split_whitespace().next().unwrap();
        let alerts = state.on_exec(&exec_event_full(
            2100 + i as u32,
            700 + i as u32,
            comm,
            c,
            i as u64 * SEC,
        ));
        assert!(alerts.iter().all(|a| a.technique != "T1518.001"), "{c}");
    }
}

#[test]
fn a_second_set_after_the_window_alerts_again() {
    let mut state = RuleState::new();
    let mut total = 0;
    for round in 0..2u64 {
        for (i, c) in ["getenforce", "aa-status", "auditctl -l"]
            .iter()
            .enumerate()
        {
            let comm = c.split_whitespace().next().unwrap();
            total += state
                .on_exec(&exec_event_full(
                    2200 + (round * 10) as u32 + i as u32,
                    SHELL,
                    comm,
                    c,
                    (round * 200 + i as u64) * SEC,
                ))
                .iter()
                .filter(|a| a.technique == "T1518.001")
                .count();
        }
    }
    assert_eq!(total, 2);
}
