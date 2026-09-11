//! The Windows-calibrated stateful rules: SELF-SPAWN (T1059), PARENT-SUSPECT
//! (T1204/T1059), LOLBIN (T1218/T1127), BEACON (T1071/T1041).

use super::*;

// ── SELF-SPAWN (T1059) ────────────────────────────────────────────────────
// Windows-only (the rule is gated on `User::Windows` — #159), so these build
// events with `exec_event_win`.

#[test]
fn self_spawn_stays_quiet_on_a_unix_shell_loop() {
    // #159: `for i in 1..N; do sh -c …; done` spawns `sh` from the same ppid
    // repeatedly. The rule is Windows-calibrated and must not fire on Linux —
    // `exec_event_full` builds a `User::Unix` event.
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        alerts.extend(state.on_exec(&exec_event_full(
            200 + i,
            1,
            "sh",
            "sh -c true",
            u64::from(i) * sec,
        )));
    }
    assert!(
        alerts.iter().all(|a| a.technique != "T1059"),
        "SELF-SPAWN must not fire for a Unix shell loop (#159)"
    );
}

#[test]
fn self_spawn_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..SELF_SPAWN_THRESHOLD - 1 {
        let alerts = state.on_exec(&exec_event_win(200 + i, 1, "cmd.exe", "cmd.exe", i as u64));
        assert!(alerts.is_empty());
    }
}

#[test]
fn self_spawn_third_spawn_triggers_alert() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 1_000_000_000));
    let alerts = state.on_exec(&exec_event_win(202, 1, "cmd.exe", "cmd.exe", 2_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn excluded_name_from_untrusted_path_still_alerts() {
    // Name-based exclusion bypass: a payload renamed to an excluded name
    // (wermgr.exe) running from /tmp must NOT inherit the exclusion.
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let mut e = exec_event_win(300 + i, 1, "wermgr.exe", "wermgr.exe", u64::from(i) * sec);
        e.image_path = "/tmp/wermgr.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "masqueraded excluded name must still trigger self-spawn"
    );
}

#[test]
fn excluded_name_from_system_path_stays_excluded() {
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(300 + i, 1, "wermgr.exe", "wermgr.exe", u64::from(i) * sec);
        e.image_path = "C:\\Windows\\System32\\wermgr.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().all(|a| a.technique != "T1059"),
        "the real wermgr.exe must keep its exclusion"
    );
}

#[test]
fn self_spawn_window_slides_instead_of_resetting() {
    // Review finding: the reset-bucket scheme dropped in-window events at the
    // boundary — spawns at t=0s, 29s, 31s, 33s never alerted with a 30s window,
    // even though 29/31/33 are three spawns within 4 seconds.
    let mut state = RuleState::new();
    let sec = 1_000_000_000u64;
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 29 * sec));
    state.on_exec(&exec_event_win(202, 1, "cmd.exe", "cmd.exe", 31 * sec));
    let alerts = state.on_exec(&exec_event_win(203, 1, "cmd.exe", "cmd.exe", 33 * sec));
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "three spawns within 4s straddling the bucket boundary must alert"
    );
}

#[test]
fn self_spawn_does_not_realert_past_threshold() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 1_000_000_000));
    state.on_exec(&exec_event_win(202, 1, "cmd.exe", "cmd.exe", 2_000_000_000)); // alerts here
    // 4th spawn, still within the window: already alerted (flag), no duplicate.
    let alerts = state.on_exec(&exec_event_win(203, 1, "cmd.exe", "cmd.exe", 3_000_000_000));
    assert!(alerts.is_empty());
}

#[test]
fn self_spawn_excluded_process_does_not_alert() {
    // MpCmdRun.exe: false positive documented in lab (2026-08-24), explicitly excluded.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_win(200, 1, "MpCmdRun.exe", "MpCmdRun.exe", 0));
    state.on_exec(&exec_event_win(
        201,
        1,
        "MpCmdRun.exe",
        "MpCmdRun.exe",
        1_000_000_000,
    ));
    let alerts = state.on_exec(&exec_event_win(
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
    state.on_exec(&exec_event_win(200, 1, "cmd.exe", "cmd.exe", 0));
    state.on_exec(&exec_event_win(201, 1, "cmd.exe", "cmd.exe", 1_000_000_000));
    // 40s later, outside the 30s window: the counter restarts at 1, no 3rd spawn
    // reached.
    let alerts = state.on_exec(&exec_event_win(
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
