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

#[test]
fn sigstop_uses_the_host_numbering() {
    let native = if cfg!(target_os = "macos") { 17 } else { 19 };
    let alert = check_security_process_signal(&signal_event(native)).expect("SIGSTOP must alert");
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
