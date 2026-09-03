//! Rule engine tests — stateless first, then the stateful rules via `RuleState`.

use schema::{ConnectEvent, EventMeta, ExecEvent, FileOpenEvent, User};

use crate::{
    O_CREAT, O_WRONLY, RuleState, check_base64_decode, check_persistence_write,
    state::{BEACON_THRESHOLD, SELF_SPAWN_THRESHOLD},
};

const O_RDONLY: u32 = 0;

fn meta() -> EventMeta {
    EventMeta {
        pid: 1234,
        ppid: 1,
        user: User::Unix {
            uid: 1000,
            gid: 1000,
        },
        timestamp_ns: 0,
        comm: String::new(),
    }
}

fn exec_event(cmdline: &str) -> ExecEvent {
    ExecEvent {
        meta: meta(),
        image_path: String::new(),
        cmdline: cmdline.to_string(),
        argv: vec![],
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
    }
}

fn exec_event_full(pid: u32, ppid: u32, comm: &str, cmdline: &str, timestamp_ns: u64) -> ExecEvent {
    let mut event = exec_event(cmdline);
    event.meta.pid = pid;
    event.meta.ppid = ppid;
    event.meta.timestamp_ns = timestamp_ns;
    event.meta.comm = comm.to_string();
    event
}

fn file_open_event(path: &str, flags: u32) -> FileOpenEvent {
    FileOpenEvent {
        meta: meta(),
        path: path.to_string(),
        flags,
    }
}

fn file_open_event_full(
    pid: u32,
    comm: &str,
    path: &str,
    flags: u32,
    timestamp_ns: u64,
) -> FileOpenEvent {
    let mut event = file_open_event(path, flags);
    event.meta.pid = pid;
    event.meta.timestamp_ns = timestamp_ns;
    event.meta.comm = comm.to_string();
    event
}

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

// ── Windows rule tests (SELF-SPAWN, PARENT-SUSPECT, LOLBIN, BEACON) ─────────

fn connect_event_full(
    pid: u32,
    comm: &str,
    daddr_v4: [u8; 4],
    dport: u16,
    timestamp_ns: u64,
) -> ConnectEvent {
    let mut meta = meta();
    meta.pid = pid;
    meta.timestamp_ns = timestamp_ns;
    meta.comm = comm.to_string();
    ConnectEvent {
        meta,
        daddr: std::net::IpAddr::V4(daddr_v4.into()),
        dport,
    }
}

// ── SELF-SPAWN (T1059) ────────────────────────────────────────────────────

#[test]
fn self_spawn_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..SELF_SPAWN_THRESHOLD - 1 {
        let alerts = state.on_exec(&exec_event_full(200 + i, 1, "cmd.exe", "cmd.exe", i as u64));
        assert!(alerts.is_empty());
    }
}

#[test]
fn self_spawn_third_spawn_triggers_alert() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_full(
        201,
        1,
        "cmd.exe",
        "cmd.exe",
        1_000_000_000,
    ));
    let alerts = state.on_exec(&exec_event_full(
        202,
        1,
        "cmd.exe",
        "cmd.exe",
        2_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn self_spawn_does_not_realert_past_threshold() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_full(
        201,
        1,
        "cmd.exe",
        "cmd.exe",
        1_000_000_000,
    ));
    state.on_exec(&exec_event_full(
        202,
        1,
        "cmd.exe",
        "cmd.exe",
        2_000_000_000,
    )); // alerts here
    // 4th spawn, still within the window: already alerted (flag), no duplicate.
    let alerts = state.on_exec(&exec_event_full(
        203,
        1,
        "cmd.exe",
        "cmd.exe",
        3_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn self_spawn_excluded_process_does_not_alert() {
    // MpCmdRun.exe: false positive documented in lab (2026-08-24), explicitly excluded.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(200, 1, "MpCmdRun.exe", "MpCmdRun.exe", 0));
    state.on_exec(&exec_event_full(
        201,
        1,
        "MpCmdRun.exe",
        "MpCmdRun.exe",
        1_000_000_000,
    ));
    let alerts = state.on_exec(&exec_event_full(
        202,
        1,
        "MpCmdRun.exe",
        "MpCmdRun.exe",
        2_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn self_spawn_outside_window_resets_counter() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_full(
        201,
        1,
        "cmd.exe",
        "cmd.exe",
        1_000_000_000,
    ));
    // 40s later, outside the 30s window: the counter restarts at 1, no 3rd spawn
    // reached.
    let alerts = state.on_exec(&exec_event_full(
        202,
        1,
        "cmd.exe",
        "cmd.exe",
        40_000_000_000,
    ));
    assert!(alerts.is_empty());
}

// ── PARENT-SUSPECT (T1204/T1059) ──────────────────────────────────────────

#[test]
fn winword_spawning_powershell_matches_parent_suspect() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "winword.exe", "winword.exe", 0));
    let alerts = state.on_exec(&exec_event_full(
        101,
        100,
        "powershell.exe",
        "powershell.exe",
        1,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1204/T1059");
}

#[test]
fn winword_spawning_notepad_does_not_match_parent_suspect() {
    // notepad.exe is not in SUSPECT_CHILDREN_WIN.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "winword.exe", "winword.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "notepad.exe", "notepad.exe", 1));
    assert!(alerts.is_empty());
}

#[test]
fn explorer_spawning_powershell_does_not_match_parent_suspect() {
    // explorer.exe is not in SUSPECT_PARENTS_WIN — normal manual launch.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "explorer.exe", "explorer.exe", 0));
    let alerts = state.on_exec(&exec_event_full(
        101,
        100,
        "powershell.exe",
        "powershell.exe",
        1,
    ));
    assert!(alerts.is_empty());
}

// ── LOLBIN (T1218/T1127) ─────────────────────────────────────────────────

#[test]
fn cmd_spawning_msbuild_matches_lolbin() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "cmd.exe", "cmd.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "msbuild.exe", "msbuild.exe", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1218/T1127");
}

#[test]
fn devenv_spawning_msbuild_does_not_match_lolbin() {
    // devenv.exe: legitimate parent (dev environment), see LOLBIN_LEGIT_PARENTS.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "devenv.exe", "devenv.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "msbuild.exe", "msbuild.exe", 1));
    assert!(alerts.is_empty());
}

#[test]
fn cmd_spawning_notepad_does_not_match_lolbin() {
    // notepad.exe is not in LOLBINS.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "cmd.exe", "cmd.exe", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "notepad.exe", "notepad.exe", 1));
    assert!(alerts.is_empty());
}

// ── BEACON (T1071/T1041) ──────────────────────────────────────────────────

#[test]
fn beacon_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..BEACON_THRESHOLD - 1 {
        let alerts = state.on_connect(&connect_event_full(
            300,
            "malware.exe",
            [10, 0, 0, 1],
            4444,
            i as u64,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn beacon_third_connection_triggers_alert() {
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        0,
    ));
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1071/T1041");
}

#[test]
fn beacon_standard_port_does_not_alert() {
    // Port 443 is in STANDARD_PORTS: expected legitimate HTTPS traffic, not beaconing.
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(300, "app.exe", [10, 0, 0, 1], 443, 0));
    state.on_connect(&connect_event_full(
        300,
        "app.exe",
        [10, 0, 0, 1],
        443,
        1_000_000_000,
    ));
    let alerts = state.on_connect(&connect_event_full(
        300,
        "app.exe",
        [10, 0, 0, 1],
        443,
        2_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn beacon_browser_does_not_alert() {
    // chrome.exe is in BROWSERS: repeated outbound connections = normal behavior.
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(
        300,
        "chrome.exe",
        [10, 0, 0, 1],
        4444,
        0,
    ));
    state.on_connect(&connect_event_full(
        300,
        "chrome.exe",
        [10, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_connect(&connect_event_full(
        300,
        "chrome.exe",
        [10, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn beacon_outside_window_resets_counter() {
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        0,
    ));
    state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    // 90s later, outside the 60s window: the counter restarts at 1.
    let alerts = state.on_connect(&connect_event_full(
        300,
        "malware.exe",
        [10, 0, 0, 1],
        4444,
        90_000_000_000,
    ));
    assert!(alerts.is_empty());
}
