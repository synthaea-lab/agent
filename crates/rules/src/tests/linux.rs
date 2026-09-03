//! Stateless rules (base64, persistence writes) and the Linux stateful rules
//! (web-server→shell lineage, download-then-exec).

use super::*;

#[test]
fn base64_decode_matches() {
    let event = exec_event("bash -c $(echo ZWNobyBoZWxsbw== | base64 -d)");
    assert!(check_base64_decode(&event).is_some());
}

#[test]
fn base64_without_decode_flag_does_not_match() {
    let event = exec_event("base64 /etc/hosts");
    assert!(check_base64_decode(&event).is_none());
}

#[test]
fn benign_curl_does_not_match_base64() {
    let event = exec_event("curl -f http://backend:8000/api/health/");
    assert!(check_base64_decode(&event).is_none());
}

#[test]
fn write_to_bashrc_matches_persistence() {
    // O_WRONLY|O_CREAT|O_TRUNC, values observed in real conditions (touch(1)).
    let event = file_open_event("/home/app/.bashrc", 577);
    assert!(check_persistence_write(&event).is_some());
}

#[test]
fn readonly_bashrc_does_not_alert() {
    // Every interactive shell reads ~/.bashrc on startup: alerting here would be
    // constant noise, not a detection.
    let event = file_open_event("/home/app/.bashrc", O_RDONLY);
    assert!(check_persistence_write(&event).is_none());
}

#[test]
fn write_outside_persistence_paths_does_not_alert() {
    let event = file_open_event("/tmp/test.txt", 577);
    assert!(check_persistence_write(&event).is_none());
}

#[test]
fn write_to_systemd_unit_matches_persistence() {
    let event = file_open_event("/etc/systemd/system/evil.service", O_WRONLY | O_CREAT);
    assert!(check_persistence_write(&event).is_some());
}

#[test]
fn nginx_spawning_shell_matches_lineage() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "nginx", "nginx -g daemon off;", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
#[cfg(target_os = "linux")]
fn resolve_comm_falls_back_to_live_proc_when_not_cached() {
    let state = RuleState::new();
    let own_pid = std::process::id();
    let expected_comm = std::fs::read_to_string("/proc/self/comm")
        .unwrap()
        .trim_end()
        .to_string();
    assert_eq!(state.resolve_comm(own_pid), Some(expected_comm));
}

#[test]
#[cfg(target_os = "linux")]
fn seed_from_proc_finds_own_pid_comm() {
    let mut state = RuleState::new();
    state.seed_from_proc();
    let own_pid = std::process::id();
    let expected_comm = std::fs::read_to_string("/proc/self/comm")
        .unwrap()
        .trim_end()
        .to_string();
    assert_eq!(state.pid_comm.peek(&own_pid), Some(&expected_comm));
}

#[test]
fn shell_spawned_by_unrelated_parent_does_not_match_lineage() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "bash", "bash", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert!(alerts.is_empty());
}

#[test]
fn download_then_direct_exec_matches() {
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    // Direct execution (e.g. ELF binary): comm == argv[0] == basename of the path.
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        5_000_000_000, // 5s later, within the 60s window
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1105");
}

#[test]
fn download_then_shebang_script_exec_matches() {
    // Regression from 2026-08-13: script with `#!/bin/sh`, so argv = ["/bin/sh",
    // "/tmp/edr-payload"] — argv[0] is not the downloaded path, only `comm` (derived by
    // the kernel from the script name) allows correlation. Case observed in real
    // conditions.
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/edr-payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        12327,
        "edr-payload",
        "/bin/sh /tmp/edr-payload",
        5_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1105");
}

#[test]
fn exec_outside_correlation_window_does_not_match() {
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        120_000_000_000, // 120s later, outside the 60s window
    ));
    assert!(alerts.is_empty());
}

#[test]
fn readonly_download_by_curl_does_not_match() {
    // `curl` without `-o`/`-O`: no local write (e.g. plain GET), nothing to correlate.
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_RDONLY,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        1_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn chmod_on_downloaded_path_does_not_match_download() {
    // Regression from 2026-08-13: `chmod +x /tmp/payload` wrongly matched (the path
    // appears as an argument, but `chmod` is not the downloaded payload).
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "chmod",
        "chmod +x /tmp/payload",
        1_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn unrelated_exec_does_not_match_download() {
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(51, 1, "ls", "ls -la", 1_000_000_000));
    assert!(alerts.is_empty());
}
