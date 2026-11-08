//! Impact context (#973): a service-stop burst corroborates a later T1486 finding, and a
//! shutdown or reboot (T1529) is context for an Impact finding, never a finding of its own.

use super::*;
use crate::{
    Alert, Severity,
    impactctx::{BURST_TO_RENAME_WINDOW_NS, IMPACT_TO_SHUTDOWN_WINDOW_NS, shutdown_command},
};

const SEC: u64 = 1_000_000_000;
const SHELL: u32 = 600;
const ENCRYPTOR: u32 = 9000;
const FIVE: &str = "systemctl stop mysqld postgresql veeam postfix nginx";

fn t(alerts: &[Alert], technique: &str) -> Vec<Alert> {
    alerts
        .iter()
        .filter(|a| a.technique == technique)
        .cloned()
        .collect()
}

/// A service-stop burst from the lineage of `shell`, at `at_s`.
fn burst(state: &mut RuleState, shell: u32, pid: u32, at_s: u64) -> Vec<Alert> {
    state.on_exec(&exec_event_full(pid, shell, "systemctl", FIVE, at_s * SEC))
}

/// The encryptor starts under `shell`, then renames `count` files from `at_s` on.
fn encrypt(state: &mut RuleState, shell: u32, pid: u32, count: u32, at_s: u64) -> Vec<Alert> {
    state.on_exec(&exec_event_full(
        pid,
        shell,
        "encryptor",
        "./encryptor",
        at_s * SEC,
    ));
    renames(state, pid, count, at_s)
}

fn renames(state: &mut RuleState, pid: u32, count: u32, at_s: u64) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for i in 0..count {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            pid,
            "encryptor",
            &format!("/home/u/f{i}.docx"),
            &format!("/home/u/f{i}.docx.locked"),
            at_s * SEC + u64::from(i) * 100_000_000,
        )));
    }
    alerts
}

fn command(
    state: &mut RuleState,
    shell: u32,
    pid: u32,
    comm: &str,
    cmdline: &str,
    at_s: u64,
) -> Vec<Alert> {
    state.on_exec(&exec_event_full(pid, shell, comm, cmdline, at_s * SEC))
}

fn shutdown_of(cmdline: &str) -> Option<String> {
    let comm = cmdline.split_whitespace().next().unwrap_or("");
    shutdown_command(&exec_event_full(5, 1, comm, cmdline, 0))
}

// --- item 2: the burst corroborates the mass rename --------------------------------------

#[test]
fn a_burst_then_mass_renames_from_one_lineage_is_named_on_the_t1486_finding() {
    let mut state = RuleState::new();
    assert_eq!(t(&burst(&mut state, SHELL, 2000, 0), "T1489").len(), 1);
    let alerts = encrypt(
        &mut state,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        30,
    );
    let found = t(&alerts, "T1486");
    assert_eq!(found.len(), 1, "{alerts:?}");
    assert!(
        found[0].message.contains("corroborated"),
        "{}",
        found[0].message
    );
    assert!(
        found[0].message.contains("SERVICE-STOP-BURST"),
        "{}",
        found[0].message
    );
    assert!(
        found[0].message.contains("5 distinct services"),
        "{}",
        found[0].message
    );
}

#[test]
fn the_corroboration_changes_neither_the_technique_the_severity_nor_the_alert_count() {
    // What the damage manifest and the reflex kill read: the technique, the event, the count.
    let mut plain = RuleState::new();
    let without = encrypt(
        &mut plain,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        30,
    );
    let mut state = RuleState::new();
    burst(&mut state, SHELL, 2000, 0);
    let with = encrypt(
        &mut state,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        30,
    );
    assert_eq!(without.len(), with.len());
    let (a, b) = (&t(&without, "T1486")[0], &t(&with, "T1486")[0]);
    assert_eq!((a.technique, a.severity), (b.technique, b.severity));
    assert_eq!(b.severity, Severity::Critical);
    assert!(!a.message.contains("corroborated"));
    assert_eq!(
        state.touched_files(ENCRYPTOR, None).len(),
        plain.touched_files(ENCRYPTOR, None).len(),
        "the damage manifest is the same"
    );
}

#[test]
fn a_burst_does_not_lower_the_rename_threshold() {
    let mut state = RuleState::new();
    burst(&mut state, SHELL, 2000, 0);
    let alerts = encrypt(
        &mut state,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD - 1,
        30,
    );
    assert!(t(&alerts, "T1486").is_empty(), "{alerts:?}");
}

#[test]
fn a_burst_alone_never_raises_t1486() {
    let mut state = RuleState::new();
    let alerts = burst(&mut state, SHELL, 2000, 0);
    assert!(t(&alerts, "T1486").is_empty());
}

#[test]
fn mass_renames_without_a_burst_carry_no_corroboration() {
    let mut state = RuleState::new();
    let alerts = encrypt(
        &mut state,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        30,
    );
    assert!(!t(&alerts, "T1486")[0].message.contains("SERVICE-STOP"));
}

#[test]
fn a_burst_from_another_lineage_does_not_corroborate() {
    let mut state = RuleState::new();
    burst(&mut state, 700, 2000, 0);
    let alerts = encrypt(
        &mut state,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        30,
    );
    assert!(!t(&alerts, "T1486")[0].message.contains("SERVICE-STOP"));
}

#[test]
fn a_burst_older_than_the_window_does_not_corroborate() {
    let mut state = RuleState::new();
    burst(&mut state, SHELL, 2000, 0);
    let late = BURST_TO_RENAME_WINDOW_NS / SEC + 1;
    let alerts = encrypt(
        &mut state,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        late,
    );
    assert!(!t(&alerts, "T1486")[0].message.contains("SERVICE-STOP"));
}

#[test]
fn a_burst_after_the_renames_does_not_corroborate_them() {
    let mut state = RuleState::new();
    let alerts = encrypt(&mut state, SHELL, ENCRYPTOR, RANSOMWARE_RENAME_THRESHOLD, 0);
    assert!(!t(&alerts, "T1486")[0].message.contains("SERVICE-STOP"));
    // The finding is already out and is not edited: the later burst is a finding of its own.
    assert_eq!(t(&burst(&mut state, SHELL, 2000, 10), "T1489").len(), 1);
}

#[test]
fn the_shell_loop_shape_is_corroborated_too() {
    let mut state = RuleState::new();
    burst(&mut state, SHELL, 2000, 0);
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        let pid = 5000 + i;
        state.on_exec(&exec_event_full(
            pid,
            SHELL,
            "mv",
            "mv a b",
            20 * SEC + u64::from(i),
        ));
        let mut event = file_rename_event_full(
            pid,
            "mv",
            &format!("/h/f{i}"),
            &format!("/h/f{i}.locked"),
            20 * SEC + u64::from(i) * 100_000_000,
        );
        event.meta.ppid = SHELL;
        alerts.extend(state.on_file_rename(&event));
    }
    let found = t(&alerts, "T1486");
    assert_eq!(found.len(), 1, "{alerts:?}");
    assert!(
        found[0].message.contains("SERVICE-STOP-BURST"),
        "{}",
        found[0].message
    );
}

#[test]
fn a_process_the_agent_never_saw_exec_has_no_lineage_and_gets_no_corroboration() {
    let mut state = RuleState::new();
    burst(&mut state, SHELL, 2000, 0);
    let alerts = renames(&mut state, 4242, RANSOMWARE_RENAME_THRESHOLD, 30);
    assert!(!t(&alerts, "T1486")[0].message.contains("SERVICE-STOP"));
}

#[test]
fn the_burst_memory_is_bounded_and_an_evicted_lineage_is_forgotten() {
    let mut state = RuleState::new();
    for i in 0..=(COUNTER_CAP as u32) {
        burst(&mut state, 10_000 + i, 100_000 + i, 0);
    }
    // The first lineage was evicted, the last one is remembered.
    let first = 10_000;
    let last = 10_000 + COUNTER_CAP as u32;
    let a = encrypt(
        &mut state,
        first,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        30,
    );
    assert!(!t(&a, "T1486")[0].message.contains("SERVICE-STOP"));
    let b = encrypt(
        &mut state,
        last,
        ENCRYPTOR + 1,
        RANSOMWARE_RENAME_THRESHOLD,
        30,
    );
    assert!(t(&b, "T1486")[0].message.contains("SERVICE-STOP"));
}

// --- item 1: T1529 as context -------------------------------------------------------------

/// A T1486 finding from the lineage of `SHELL` at second 0.
fn impacted() -> RuleState {
    let mut state = RuleState::new();
    let alerts = encrypt(&mut state, SHELL, ENCRYPTOR, RANSOMWARE_RENAME_THRESHOLD, 0);
    assert_eq!(t(&alerts, "T1486").len(), 1);
    state
}

#[test]
fn a_reboot_after_a_t1486_finding_from_the_same_lineage_is_reported_as_context() {
    let mut state = impacted();
    let alerts = command(&mut state, SHELL, 9100, "reboot", "reboot", 60);
    let found = t(&alerts, "T1529");
    assert_eq!(found.len(), 1, "{alerts:?}");
    assert_eq!(
        found[0].severity,
        Severity::Low,
        "a verdict must not rise on it"
    );
    assert!(found[0].message.contains("T1486"), "{}", found[0].message);
    assert!(found[0].message.contains("context"), "{}", found[0].message);
}

#[test]
fn a_reboot_run_by_the_encryptor_itself_is_context_too() {
    let mut state = impacted();
    let alerts = command(&mut state, ENCRYPTOR, 9100, "reboot", "reboot", 60);
    assert_eq!(t(&alerts, "T1529").len(), 1, "{alerts:?}");
}

#[test]
fn a_shutdown_after_a_t1490_finding_is_context_too() {
    let mut state = RuleState::new();
    command(
        &mut state,
        SHELL,
        9050,
        "vssadmin",
        "vssadmin delete shadows /all",
        0,
    );
    let alerts = command(&mut state, SHELL, 9100, "shutdown", "shutdown /r /t 0", 60);
    let found = t(&alerts, "T1529");
    assert_eq!(found.len(), 1, "{alerts:?}");
    assert!(found[0].message.contains("T1490"));
}

#[test]
fn a_reboot_with_no_finding_before_it_is_never_a_finding() {
    for cmdline in [
        "reboot",
        "shutdown -h now",
        "poweroff",
        "halt",
        "systemctl reboot",
        "init 6",
    ] {
        let mut state = RuleState::new();
        let comm = cmdline.split_whitespace().next().unwrap();
        let alerts = command(&mut state, SHELL, 9100, comm, cmdline, 60);
        assert!(t(&alerts, "T1529").is_empty(), "{cmdline}: {alerts:?}");
    }
}

#[test]
fn a_service_stop_burst_then_a_reboot_is_a_patch_window_not_context() {
    let mut state = RuleState::new();
    assert_eq!(t(&burst(&mut state, SHELL, 2000, 0), "T1489").len(), 1);
    let alerts = command(&mut state, SHELL, 9100, "reboot", "reboot", 60);
    assert!(t(&alerts, "T1529").is_empty(), "{alerts:?}");
}

#[test]
fn a_reboot_from_another_lineage_is_not_context_for_the_finding() {
    let mut state = impacted();
    // An admin session, a package manager or a cloud agent: another parent.
    for (shell, comm) in [(700, "reboot"), (701, "systemctl")] {
        let cmdline = if comm == "systemctl" {
            "systemctl reboot"
        } else {
            "reboot"
        };
        let alerts = command(&mut state, shell, 9100, comm, cmdline, 60);
        assert!(t(&alerts, "T1529").is_empty(), "{alerts:?}");
    }
}

#[test]
fn a_reboot_before_the_finding_or_long_after_it_is_not_context() {
    let mut state = RuleState::new();
    command(&mut state, SHELL, 9100, "reboot", "reboot", 0);
    let alerts = encrypt(
        &mut state,
        SHELL,
        ENCRYPTOR,
        RANSOMWARE_RENAME_THRESHOLD,
        10,
    );
    assert!(t(&alerts, "T1529").is_empty());

    let mut state = impacted();
    let late = IMPACT_TO_SHUTDOWN_WINDOW_NS / SEC + 60;
    let alerts = command(&mut state, SHELL, 9100, "reboot", "reboot", late);
    assert!(t(&alerts, "T1529").is_empty(), "{alerts:?}");
}

#[test]
fn one_finding_gets_one_note_however_many_reboots_follow() {
    let mut state = impacted();
    assert_eq!(
        t(
            &command(&mut state, SHELL, 9100, "reboot", "reboot", 60),
            "T1529"
        )
        .len(),
        1
    );
    assert!(
        t(
            &command(&mut state, SHELL, 9101, "reboot", "reboot", 61),
            "T1529"
        )
        .is_empty()
    );
}

#[test]
fn the_finding_memory_is_bounded_and_an_evicted_lineage_is_forgotten() {
    let mut state = RuleState::new();
    for i in 0..=(COUNTER_CAP as u32) {
        command(
            &mut state,
            10_000 + i,
            100_000 + i,
            "vssadmin",
            "vssadmin delete shadows /all",
            0,
        );
    }
    let evicted = command(&mut state, 10_000, 9100, "reboot", "reboot", 60);
    assert!(t(&evicted, "T1529").is_empty());
    let kept = command(
        &mut state,
        10_000 + COUNTER_CAP as u32,
        9101,
        "reboot",
        "reboot",
        60,
    );
    assert_eq!(t(&kept, "T1529").len(), 1);
}

#[test]
fn the_reboot_note_changes_nothing_the_manifest_or_the_reflex_read() {
    let mut state = impacted();
    let before = state.touched_files(ENCRYPTOR, None).len();
    command(&mut state, SHELL, 9100, "reboot", "reboot", 60);
    assert_eq!(state.touched_files(ENCRYPTOR, None).len(), before);
}

// --- what counts as a shutdown ---------------------------------------------------------------

#[test]
fn the_shutdown_commands_are_recognised() {
    for cmdline in [
        "shutdown -h now",
        "shutdown -r +5",
        "shutdown now",
        "shutdown",
        "reboot",
        "reboot -f",
        "halt",
        "poweroff",
        "systemctl reboot",
        "systemctl --force poweroff",
        "systemctl kexec",
        "init 0",
        "init 6",
        "telinit 6",
        "shutdown /r /t 0",
        "shutdown.exe /s /f",
    ] {
        assert!(shutdown_of(cmdline).is_some(), "{cmdline}");
    }
}

#[test]
fn a_command_that_visibly_does_nothing_is_not_a_shutdown() {
    for cmdline in [
        "shutdown -c",
        "shutdown -c cancelled",
        "shutdown -k now",
        "shutdown --cancel",
        "shutdown --help",
        "shutdown /a",
        "reboot -w",
        "halt -w",
        "reboot --help",
        "systemctl reboot --dry-run",
        "systemctl status reboot.target",
        "systemctl stop nginx",
        "systemctl",
        "init 3",
        "init q",
        "reboot-notifier",
        "cat shutdown",
    ] {
        assert!(shutdown_of(cmdline).is_none(), "{cmdline}");
    }
}

#[test]
fn an_empty_argv_still_counts_by_program_name_but_never_for_argument_commands() {
    // A short-lived process can reach the rules with no command line (ADR-0045, #1118).
    for comm in ["reboot", "poweroff", "halt", "shutdown"] {
        assert!(
            shutdown_command(&exec_event_full(5, 1, comm, "", 0)).is_some(),
            "{comm}"
        );
    }
    for comm in ["systemctl", "init"] {
        assert!(
            shutdown_command(&exec_event_full(5, 1, comm, "", 0)).is_none(),
            "{comm}"
        );
    }
}
