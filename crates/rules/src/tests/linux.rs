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
fn containerized_process_opening_proc_pid_root_matches_escape() {
    let event = file_open_event_containerized("/proc/1/root/etc/shadow", "abc123");
    assert!(check_proc_root_escape(&event).is_some());
}

#[test]
fn containerized_process_opening_proc_pid_root_bare_matches_escape() {
    // No subpath past `root` itself — still the same escape shape.
    let event = file_open_event_containerized("/proc/42/root", "abc123");
    assert!(check_proc_root_escape(&event).is_some());
}

#[test]
fn bare_metal_process_opening_proc_pid_root_does_not_alert() {
    // Same path, no container attribution: host tooling (nsenter, procfs walkers,
    // debuggers) does this constantly and legitimately.
    let event = file_open_event("/proc/1/root/etc/shadow", O_RDONLY);
    assert!(check_proc_root_escape(&event).is_none());
}

#[test]
fn containerized_process_opening_unrelated_proc_path_does_not_alert() {
    let event = file_open_event_containerized("/proc/1/cgroup", "abc123");
    assert!(check_proc_root_escape(&event).is_none());
}

#[test]
fn containerized_process_opening_proc_root_without_pid_does_not_alert() {
    // `/proc/root` isn't a thing — must not false-positive on a coincidental
    // substring match.
    let event = file_open_event_containerized("/proc/root", "abc123");
    assert!(check_proc_root_escape(&event).is_none());
}

#[test]
fn containerized_process_opening_proc_self_root_does_not_alert() {
    // `/proc/self/root` is a process reading its OWN root (harmless, extremely
    // common) — `self` isn't numeric, so this must not match.
    let event = file_open_event_containerized("/proc/self/root", "abc123");
    assert!(check_proc_root_escape(&event).is_none());
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

// ── BEACON via conntrack polling (issue #92, NetworkFlowEvent) ──────────────────

#[test]
fn beacon_flow_three_distinct_ports_triggers_alert() {
    // 3 distinct short-lived connections (3 distinct local ports) to the same
    // (comm, daddr, dport) — the real beaconing shape `lab/scenarios/beacon.sh`
    // exercises, observed here via conntrack polling instead of a discrete
    // ConnectEvent trace.
    let mut state = RuleState::new();
    state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50000,
        [127, 0, 0, 1],
        4444,
        0,
    ));
    state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50001,
        [127, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50002,
        [127, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1071/T1041");
}

#[test]
fn beacon_flow_same_local_port_repolled_does_not_alert() {
    // One single long-lived flow (same local_port every time) polled 5x within
    // the window must NOT count as 5 connections — the false-positive risk this
    // wiring exists to avoid (an ordinary long-lived SSH session still open on
    // its 3rd poll is not beaconing).
    let mut state = RuleState::new();
    for i in 0..5u64 {
        let alerts = state.on_network_flow(&network_flow_event_full(
            300,
            "sshd",
            50000,
            [127, 0, 0, 1],
            22222, // non-standard port, so STANDARD_PORTS doesn't mask this case
            i * 1_000_000_000,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn beacon_flow_standard_port_does_not_alert() {
    let mut state = RuleState::new();
    for (i, port) in (50000..50003u16).enumerate() {
        let alerts = state.on_network_flow(&network_flow_event_full(
            300,
            "app",
            port,
            [10, 0, 0, 1],
            443,
            i as u64 * 1_000_000_000,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn beacon_flow_and_connect_share_the_same_window_state() {
    // check_beacon and check_beacon_flow share the same underlying counter keyed
    // by (comm, daddr, dport) — a mixed source (2 discrete connects + 1 polled
    // flow, e.g. eBPF and netlink both active) must still cross the threshold,
    // not reset it.
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(300, "nc", [127, 0, 0, 1], 4444, 0));
    state.on_connect(&connect_event_full(
        300,
        "nc",
        [127, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50002,
        [127, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1071/T1041");
}

// ── LISTENER-DRIFT via sock_diag polling (issue #92, ListenPortEvent) ───────────

#[test]
fn listen_port_not_in_baseline_alerts_once() {
    let mut state = RuleState::new();
    let alerts = state.on_listen_port(&listen_port_event_full(
        4242,
        "sshd-backdoor",
        [0, 0, 0, 0],
        31337,
        0,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1571");
}

#[test]
fn listen_port_seeded_at_startup_does_not_alert() {
    // The exact scenario seed_listen_ports exists for: a listener already up
    // before the agent attaches (sshd started by systemd at boot) must not look
    // like a freshly planted backdoor on the first poll.
    let mut state = RuleState::new();
    state.seed_listen_ports([(std::net::IpAddr::V4([0, 0, 0, 0].into()), 22)]);
    let alerts = state.on_listen_port(&listen_port_event_full(1, "sshd", [0, 0, 0, 0], 22, 0));
    assert!(alerts.is_empty());
}

#[test]
fn listen_port_repolled_does_not_realert() {
    // A poll-based source re-reports the same open listener every cycle — the
    // 2nd+ poll of the same (local_addr, local_port) is not a new finding.
    let mut state = RuleState::new();
    let first = state.on_listen_port(&listen_port_event_full(
        4242,
        "sshd-backdoor",
        [0, 0, 0, 0],
        31337,
        0,
    ));
    assert_eq!(first.len(), 1);
    let second = state.on_listen_port(&listen_port_event_full(
        4242,
        "sshd-backdoor",
        [0, 0, 0, 0],
        31337,
        10_000_000_000,
    ));
    assert!(second.is_empty());
}

#[test]
fn listen_port_two_distinct_new_ports_each_alert() {
    let mut state = RuleState::new();
    let first = state.on_listen_port(&listen_port_event_full(300, "nc", [0, 0, 0, 0], 4444, 0));
    let second = state.on_listen_port(&listen_port_event_full(
        301,
        "nc",
        [0, 0, 0, 0],
        4445,
        1_000_000_000,
    ));
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
}
