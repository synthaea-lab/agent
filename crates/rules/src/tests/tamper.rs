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
