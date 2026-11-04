//! T1562.001 security-process signal rule (issue #362).

use schema::SignalEvent;

use super::*;
use crate::{check_security_process_signal, evaluate_signal};

fn signal_event(signal: u32) -> SignalEvent {
    SignalEvent {
        meta: EventMeta {
            pid: 4242,
            comm: "bash".into(),
            ..meta()
        },
        signal,
        target_pid: 400,
        target_image_path: Some("/usr/local/bin/synthaea-agent".into()),
        target_unit: None,
        sender_unreliable: false,
        signals_lost: 0,
    }
}

#[test]
fn sigkill_to_the_agent_alerts_with_the_sender() {
    let alert = check_security_process_signal(&signal_event(9)).expect("SIGKILL must alert");
    assert_eq!(alert.technique, "T1562.001");
    assert!(alert.message.contains("pid=4242 comm=bash uid=1000"));
    assert!(alert.message.contains("SIGKILL (9)"));
    assert!(
        alert
            .message
            .contains("pid=400 (/usr/local/bin/synthaea-agent)")
    );
}

#[test]
fn every_terminating_signal_alerts() {
    for signal in [1, 2, 3, 6, 9, 15] {
        assert!(
            check_security_process_signal(&signal_event(signal)).is_some(),
            "signal {signal} must alert"
        );
    }
}

/// `SIGSTOP`'s number on the host: 17 on macOS, where 19 is `SIGCONT`, 19 elsewhere.
const SIGSTOP: u32 = if cfg!(target_os = "macos") { 17 } else { 19 };

#[test]
fn sigstop_uses_the_host_numbering() {
    let alert = check_security_process_signal(&signal_event(SIGSTOP)).expect("SIGSTOP must alert");
    assert!(alert.message.contains("SIGSTOP"));
}

#[test]
fn probes_and_harmless_signals_stay_silent() {
    // 0 = existence probe, 10 = SIGUSR1, 17 = SIGCHLD on Linux (SIGSTOP on macOS,
    // hence Linux-only), 28 = SIGWINCH.
    let mut quiet = vec![0, 10, 28];
    if !cfg!(target_os = "macos") {
        quiet.push(17);
    }
    for signal in quiet {
        assert!(
            evaluate_signal(&signal_event(signal)).is_empty(),
            "signal {signal} must not alert"
        );
    }
}

#[test]
fn a_missing_target_image_is_still_reported() {
    let mut event = signal_event(9);
    event.target_image_path = None;
    let alert = check_security_process_signal(&event).expect("SIGKILL must alert");
    assert!(alert.message.contains("pid=400 (?)"));
}

fn signal_from(sender_pid: u32, comm: &str, signal: u32, target_pid: u32) -> SignalEvent {
    SignalEvent {
        meta: EventMeta {
            pid: sender_pid,
            comm: comm.into(),
            ..meta()
        },
        signal,
        target_pid,
        target_image_path: Some("/usr/local/bin/synthaea-agent".into()),
        target_unit: None,
        sender_unreliable: false,
        signals_lost: 0,
    }
}

#[test]
fn a_sender_that_is_not_the_service_manager_or_the_target_alerts_high() {
    for signal in [1, 2, 3, 6, 9, 15] {
        let alert = check_security_process_signal(&signal_from(4242, "bash", signal, 400))
            .expect("must alert");
        assert_eq!(alert.severity, crate::Severity::High, "signal {signal}");
        assert!(!alert.message.contains("service manager"));
    }
}

#[test]
fn the_service_manager_is_low_not_dropped_for_every_terminating_signal() {
    // `systemctl stop` (SIGTERM), the SIGKILL after a stop timeout, `systemctl kill` (whose
    // exec is read by `check_security_tool_stop`).
    for signal in [1, 2, 3, 6, 9, 15] {
        let alert = check_security_process_signal(&signal_from(1, "systemd", signal, 400))
            .expect("pid 1 stays visible");
        assert_eq!(alert.severity, crate::Severity::Low, "signal {signal}");
        assert!(
            alert.message.contains("service manager"),
            "{}",
            alert.message
        );
        assert!(alert.message.contains("pid=1 comm=systemd"));
    }
}

#[test]
fn pid_1_is_the_manager_whatever_its_comm_and_no_other_pid_is() {
    let launchd = check_security_process_signal(&signal_from(1, "launchd", 15, 400)).unwrap();
    assert_eq!(launchd.severity, crate::Severity::Low);
    // The comm is spoofable and pid 1 is not: a process named `systemd` is not the manager.
    for pid in [2, 10, 11, 100, 4242] {
        let alert = check_security_process_signal(&signal_from(pid, "systemd", 9, 400)).unwrap();
        assert_eq!(alert.severity, crate::Severity::High, "pid {pid}");
    }
}

#[test]
fn a_process_signalling_itself_does_not_alert() {
    for signal in [6, 9, 15] {
        assert!(
            check_security_process_signal(&signal_from(400, "synthaea-agent", signal, 400))
                .is_none(),
            "signal {signal}"
        );
    }
}

#[test]
fn a_different_pid_with_the_same_comm_is_not_a_self_signal() {
    let alert = check_security_process_signal(&signal_from(401, "synthaea-agent", 9, 400)).unwrap();
    assert_eq!(alert.severity, crate::Severity::High);
}

#[test]
fn a_sender_that_looks_like_the_agents_supervisor_is_not_exempt_for_lack_of_a_unit_in_the_event() {
    // Stated gap (#1103): the event carries no sender cgroup or unit, so the watchdog or
    // another process of the same unit cannot be told from an intruder. It alerts High.
    let mut event = signal_from(5000, "synthaea-watchdog", 15, 400);
    event.meta.ppid = 1;
    let alert = check_security_process_signal(&event).unwrap();
    assert_eq!(alert.severity, crate::Severity::High);
}

#[test]
fn a_signal_to_a_listed_unit_names_the_unit_and_a_signal_without_one_is_unchanged() {
    let mut event = signal_from(4242, "pkill", 9, 612);
    event.target_image_path = Some("/usr/sbin/auditd".into());
    event.target_unit = Some("auditd".into());
    let alert = check_security_process_signal(&event).expect("alerts");
    assert_eq!(alert.technique, "T1562.001");
    assert_eq!(alert.severity, crate::Severity::High);
    assert!(
        alert
            .message
            .contains("pid=612 (/usr/sbin/auditd) of unit auditd"),
        "{}",
        alert.message
    );
    event.target_unit = None;
    let alert = check_security_process_signal(&event).expect("alerts");
    assert!(!alert.message.contains("of unit"), "{}", alert.message);
}

/// A signal to a process of a listed security unit (Linux, #1103): the event names the unit.
fn signal_to_tool(sender_pid: u32, comm: &str, signal: u32) -> SignalEvent {
    let mut event = signal_from(sender_pid, comm, signal, 612);
    event.target_image_path = Some("/usr/sbin/auditd".into());
    event.target_unit = Some("auditd".into());
    event
}

/// A `SIGHUP` that reaches the rule is one the sensor did not drop as a reload (the tool catches
/// it, see `sensor-linux`'s `catches`): the tool has no handler and the signal ends it.
#[test]
fn a_sighup_to_a_tool_with_no_handler_alerts_medium_and_the_agent_stays_high() {
    for (pid, comm) in [(4242, "kill"), (3100, "logrotate")] {
        let alert = check_security_process_signal(&signal_to_tool(pid, comm, 1))
            .unwrap_or_else(|| panic!("{comm}"));
        assert_eq!(alert.severity, crate::Severity::Medium, "{comm}");
        assert!(alert.message.contains("SIGHUP"), "{}", alert.message);
    }
    // From the service manager: Low, like every terminating signal.
    let alert = check_security_process_signal(&signal_to_tool(1, "systemd", 1)).unwrap();
    assert_eq!(alert.severity, crate::Severity::Low);
    let alert = check_security_process_signal(&signal_from(4242, "bash", 1, 400)).unwrap();
    assert_eq!(alert.severity, crate::Severity::High);
}

#[test]
fn sigkill_and_sigstop_to_a_security_tool_are_high_and_name_the_unit() {
    for signal in [9, SIGSTOP] {
        let alert = check_security_process_signal(&signal_to_tool(4242, "pkill", signal))
            .expect("must alert");
        assert_eq!(alert.severity, crate::Severity::High, "signal {signal}");
        assert_eq!(alert.technique, "T1562.001");
        assert!(
            alert.message.contains("of unit auditd"),
            "{}",
            alert.message
        );
    }
}

/// An administrator's `kill <pid>` of auditd, and `service auditd stop` (its helper sends the
/// `SIGTERM` itself, not pid 1), look like an attacker's: Medium, like the exec rule's stop.
#[test]
fn the_catchable_terminating_signals_to_a_security_tool_are_medium() {
    for signal in [2, 3, 6, 15] {
        let alert = check_security_process_signal(&signal_to_tool(10138, "auditctl", signal))
            .expect("must alert");
        assert_eq!(alert.severity, crate::Severity::Medium, "signal {signal}");
    }
}

#[test]
fn the_service_manager_stays_low_for_a_security_tool_and_a_tool_signalling_itself_is_silent() {
    for signal in [2, 9, 15, SIGSTOP] {
        let alert = check_security_process_signal(&signal_to_tool(1, "systemd", signal)).unwrap();
        assert_eq!(alert.severity, crate::Severity::Low, "signal {signal}");
    }
    assert!(check_security_process_signal(&signal_to_tool(612, "auditd", 9)).is_none());
}

/// A signal whose default action ends a process, outside the seven named ones, still ends a
/// tool that does not handle it: it alerts Medium for an event with a unit, as `signal N`.
#[cfg(target_os = "linux")]
#[test]
fn a_default_terminating_signal_to_a_security_tool_alerts_medium() {
    // SIGUSR1, SIGSEGV, SIGPIPE, SIGALRM, a real-time signal.
    for signal in [10, 11, 13, 14, 34, 64] {
        let alert = check_security_process_signal(&signal_to_tool(4242, "kill", signal))
            .unwrap_or_else(|| panic!("signal {signal} must alert"));
        assert_eq!(alert.severity, crate::Severity::Medium, "signal {signal}");
        assert!(
            alert.message.contains(&format!("sent signal ({signal})")),
            "{}",
            alert.message
        );
    }
}

/// `SIGCHLD`, `SIGCONT`, `SIGURG`, `SIGWINCH` and `0` do not end a process; nor does a signal
/// number out of range. The agent's own pid keeps the old set (no unit, so no new signals).
#[cfg(target_os = "linux")]
#[test]
fn a_non_terminating_signal_to_a_security_tool_does_not_alert() {
    for signal in [0, 17, 18, 23, 28, 65] {
        assert!(
            check_security_process_signal(&signal_to_tool(4242, "kill", signal)).is_none(),
            "signal {signal}"
        );
    }
    assert!(check_security_process_signal(&signal_from(4242, "bash", 10, 400)).is_none());
}

/// A forged `si_code` must not hide a kill: the event is reported, High for `SIGKILL`, and the
/// message says the sender is not reliable (`rt_sigqueueinfo` lets a process pick `SI_TIMER`).
#[test]
fn a_kill_with_an_unreliable_sender_still_alerts_and_says_so() {
    let mut event = signal_to_tool(4242, "python3", 9);
    event.sender_unreliable = true;
    let alert = check_security_process_signal(&event).expect("a forged code must not hide a kill");
    assert_eq!(alert.severity, crate::Severity::High);
    assert!(
        alert.message.contains("sender is not reliable"),
        "{}",
        alert.message
    );
    event.sender_unreliable = false;
    let alert = check_security_process_signal(&event).unwrap();
    assert!(!alert.message.contains("not reliable"), "{}", alert.message);
}

#[test]
fn lost_signals_to_security_tools_are_a_high_finding() {
    let mut event = signal_event(0);
    event.target_pid = 0;
    event.target_image_path = None;
    event.signals_lost = 40;
    let alerts = evaluate_signal(&event);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].technique, "T1562.001");
    assert_eq!(alerts[0].severity, crate::Severity::High);
    // The exact text: a literal that lost its `\` continuations carried runs of spaces into every
    // loss alert, and `contains` checks did not see it (review of #1114).
    assert_eq!(
        alerts[0].message,
        "40 signals to security tools lost, signal ring buffer full: a flood of signals to a \
         security tool, or one too busy to read them, can hide a kill, and the lost signals may \
         include the SIGKILL, so this is High"
    );
    event.signals_lost = 0;
    assert!(evaluate_signal(&event).is_empty());
}

/// `O_TMPFILE | O_RDWR` is `0x0049_0002`: it contains `0x0040_0000`, the bit the first cut used to
/// carry the loss on a `FileOpenEvent`, and any process can open it (glibc `tmpfile()`, mariadbd).
/// The loss no longer travels on `FileOpenEvent::flags`, so such an open must not alert.
#[test]
fn an_o_tmpfile_open_does_not_raise_the_signal_loss_alert() {
    let event = file_open_event("/tmp", 0x0049_0002);
    assert!(
        crate::evaluate_file_open(&event)
            .iter()
            .all(|a| a.technique != "T1562.001")
    );
}

/// With an unreliable sender (`SI_TIMER`) `meta` is a bystander: pid 1 there does not make the
/// signal "sent by the service manager" (Low).
#[test]
fn a_bystander_pid_1_with_an_unreliable_sender_is_not_the_service_manager() {
    let mut event = signal_to_tool(1, "systemd", 9);
    let alert = check_security_process_signal(&event).unwrap();
    assert_eq!(alert.severity, crate::Severity::Low);
    event.sender_unreliable = true;
    let alert = check_security_process_signal(&event).unwrap();
    assert_eq!(alert.severity, crate::Severity::High);
    assert!(
        !alert.message.contains("service manager"),
        "{}",
        alert.message
    );
}
