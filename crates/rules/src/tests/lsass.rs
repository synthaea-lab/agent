//! LSASS-ACCESS (T1003.001) and LSASS-REMOTE-THREAD (T1055), #960: over the driver-free
//! `ProcessAccessEvent` and `RemoteThreadEvent` of #720.

use schema::{ProcessAccessEvent, RemoteThreadEvent, detection::Severity};

use super::*;
use crate::{evaluate_remote_thread, lsass::LSASS_ACCESS_ALERT_WINDOW_NS};

const SECOND_NS: u64 = 1_000_000_000;
const LSASS_PID: u32 = 812;
const LSASS: &str = r"C:\Windows\System32\lsass.exe";
/// `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`: Mimikatz `sekurlsa`'s mask.
const SEKURLSA_MASK: u32 = 0x1010;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// An open of LSASS with Mimikatz's mask, granted unless `status` says otherwise.
fn open_of_lsass(pid: u32, comm: &str, status: u32, at_ns: u64) -> ProcessAccessEvent {
    let mut event = ProcessAccessEvent {
        meta: EventMeta {
            pid,
            comm: comm.to_string(),
            timestamp_ns: at_ns,
            ..meta()
        },
        target_pid: LSASS_PID,
        target_image_path: Some(LSASS.to_string()),
        desired_access: SEKURLSA_MASK,
        ..schema::fixtures::process_access()
    };
    event.status = status;
    event
}

/// A state in which `pid` was exec'd from `image` as `comm`.
fn state_with_exec(pid: u32, comm: &str, image: &str) -> RuleState {
    let mut state = RuleState::new();
    state.on_exec(&ExecEvent {
        image_path: image.to_string(),
        ..exec_event_win(pid, 4, comm, "", 0)
    });
    state
}

#[test]
fn a_granted_memory_read_of_lsass_alerts_high() {
    let mut state = RuleState::new();
    let alerts = state.on_process_access(&open_of_lsass(4242, "procdump64.exe", 0, 0));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1003.001");
    assert_eq!(alerts[0].severity, Severity::High);
    assert!(
        alerts[0].message.contains("PROCESS_VM_READ"),
        "{}",
        alerts[0].message
    );
    assert!(
        alerts[0].message.contains("granted"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn a_denied_open_of_a_protected_lsass_alerts_medium_with_its_status() {
    let mut state = RuleState::new();
    let alerts = state.on_process_access(&open_of_lsass(
        4242,
        "mimikatz.exe",
        STATUS_ACCESS_DENIED,
        0,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert!(
        alerts[0].message.contains("0xc0000022"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn an_expected_reader_at_its_system_path_is_silent() {
    let mut state = state_with_exec(700, "wininit.exe", r"C:\Windows\System32\wininit.exe");
    assert!(
        state
            .on_process_access(&open_of_lsass(700, "wininit.exe", 0, 0))
            .is_empty()
    );
}

#[test]
fn defender_from_its_platform_directory_is_silent() {
    let mut state = state_with_exec(
        900,
        "MsMpEng.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
    );
    assert!(
        state
            .on_process_access(&open_of_lsass(900, "MsMpEng.exe", 0, 0))
            .is_empty()
    );
}

#[test]
fn a_reader_name_run_from_a_user_directory_still_alerts() {
    let mut state = state_with_exec(901, "MsMpEng.exe", r"C:\Users\Public\MsMpEng.exe");
    let alerts = state.on_process_access(&open_of_lsass(901, "MsMpEng.exe", 0, 0));
    assert_eq!(alerts.len(), 1, "a renamed dumper is not Defender");
    assert!(alerts[0].message.contains(r"C:\Users\Public\MsMpEng.exe"));
}

#[test]
fn the_known_image_decides_not_the_comm() {
    // A dumper whose sensor-side name is a reader's, but whose exec the engine saw.
    let mut state = state_with_exec(902, "csrss.exe", r"C:\Windows\System32\rundll32.exe");
    assert_eq!(
        state
            .on_process_access(&open_of_lsass(902, "csrss.exe", 0, 0))
            .len(),
        1
    );
}

#[test]
fn a_reader_that_predates_the_agent_is_excluded_on_its_name() {
    // No exec seen: the sensor's name is the only evidence, and a sensor limitation is not
    // evidence of masquerade (policy::name_exclusion_applies).
    let mut state = RuleState::new();
    assert!(
        state
            .on_process_access(&open_of_lsass(640, "csrss.exe", 0, 0))
            .is_empty()
    );
}

#[test]
fn documented_dump_paths_are_never_excluded_readers() {
    for (comm, image) in [
        ("WerFault.exe", r"C:\Windows\System32\WerFault.exe"),
        ("Taskmgr.exe", r"C:\Windows\System32\Taskmgr.exe"),
        ("rundll32.exe", r"C:\Windows\System32\rundll32.exe"),
        ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
    ] {
        let mut state = state_with_exec(1000, comm, image);
        assert_eq!(
            state
                .on_process_access(&open_of_lsass(1000, comm, 0, 0))
                .len(),
            1,
            "{comm}"
        );
    }
}

#[test]
fn an_open_of_another_process_or_an_lsass_copy_raises_nothing() {
    let mut state = RuleState::new();
    let mut other = open_of_lsass(4242, "procdump64.exe", 0, 0);
    other.target_image_path = Some(r"C:\Users\Public\lsass.exe".to_string());
    assert!(state.on_process_access(&other).is_empty());
    other.target_image_path = None;
    assert!(state.on_process_access(&other).is_empty());
}

#[test]
fn one_alert_per_caller_and_outcome_per_window() {
    let mut state = RuleState::new();
    let first = open_of_lsass(4242, "dumper.exe", 0, 0);
    assert_eq!(state.on_process_access(&first).len(), 1);
    let retry = ProcessAccessEvent {
        desired_access: 0x1F_FFFF,
        ..open_of_lsass(4242, "dumper.exe", 0, SECOND_NS)
    };
    assert!(
        state.on_process_access(&retry).is_empty(),
        "another mask from the same caller is the same finding"
    );
    assert_eq!(
        state
            .on_process_access(&open_of_lsass(
                4242,
                "dumper.exe",
                STATUS_ACCESS_DENIED,
                SECOND_NS
            ))
            .len(),
        1,
        "a denied open is its own outcome"
    );
    assert_eq!(
        state
            .on_process_access(&open_of_lsass(4243, "dumper.exe", 0, SECOND_NS))
            .len(),
        1,
        "another caller is its own finding"
    );
    let later = open_of_lsass(
        4242,
        "dumper.exe",
        0,
        LSASS_ACCESS_ALERT_WINDOW_NS + SECOND_NS,
    );
    assert_eq!(
        state.on_process_access(&later).len(),
        1,
        "a new window alerts again"
    );
}

#[test]
fn a_thread_started_inside_lsass_alerts_high() {
    let event = RemoteThreadEvent {
        meta: EventMeta {
            pid: 4242,
            comm: "injector.exe".to_string(),
            ..meta()
        },
        target_pid: LSASS_PID,
        target_image_path: Some(LSASS.to_string()),
        start_address: 0x7ffd_0000_1000,
        ..schema::fixtures::remote_thread()
    };
    let alerts = evaluate_remote_thread(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1055");
    assert_eq!(alerts[0].severity, Severity::High);
    assert!(
        alerts[0].message.contains("0x7ffd00001000"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn a_thread_started_in_another_process_or_an_unknown_one_is_telemetry_only() {
    for target in [
        Some(r"C:\Windows\System32\notepad.exe".to_string()),
        Some(r"C:\Users\Public\lsass.exe".to_string()),
        None,
    ] {
        let event = RemoteThreadEvent {
            target_pid: 5000,
            target_image_path: target.clone(),
            ..schema::fixtures::remote_thread()
        };
        assert!(evaluate_remote_thread(&event).is_empty(), "{target:?}");
    }
}
