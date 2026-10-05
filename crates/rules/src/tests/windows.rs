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

// ── Agent's own children (issue #403) ─────────────────────────────────────

#[test]
fn agent_own_wevtutil_child_does_not_alert() {
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(
            6000 + i,
            1084,
            "wevtutil.exe",
            "wevtutil.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\System32\\wevtutil.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.is_empty(),
        "the agent's own wevtutil.exe poll children must not self-alert (#403)"
    );
}

#[test]
fn agent_own_logman_orphan_sweep_does_not_alert() {
    // #408's startup sweep: one `logman query -ets` + one `logman stop` per
    // orphan, all within milliseconds — two orphans already reach the threshold.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(7000 + i, 1084, "logman.exe", "logman.exe", u64::from(i));
        e.image_path = "C:\\Windows\\System32\\logman.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.is_empty(),
        "the agent's own logman.exe orphan-sweep children must not self-alert (#408)"
    );
}

#[test]
fn agent_own_auditpol_child_does_not_alert() {
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD + 2 {
        let mut e = exec_event_win(
            6100 + i,
            1084,
            "auditpol.exe",
            "auditpol.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\System32\\auditpol.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.is_empty(),
        "the agent's own auditpol.exe startup child must not self-alert (#403)"
    );
}

#[test]
fn spoofed_own_pid_with_non_allowlisted_image_still_alerts() {
    // Done-when criterion from #403: a process spawned with a spoofed parent (the
    // agent's own pid) and a non-allowlisted image must still trigger SELF-SPAWN —
    // ppid alone must never become a blanket exclusion.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let e = exec_event_win(6200 + i, 1084, "cmd.exe", "cmd.exe", u64::from(i) * sec);
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "spoofing the agent's pid as parent must not exempt an arbitrary child"
    );
}

#[test]
fn agent_child_name_from_untrusted_path_still_alerts() {
    // Same masquerade guard as SELF_SPAWN_EXCLUSIONS: a payload named wevtutil.exe
    // but not living at the real system path must not inherit the exclusion, even
    // with a matching (possibly spoofed) ppid.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let mut e = exec_event_win(
            6300 + i,
            1084,
            "wevtutil.exe",
            "wevtutil.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\Temp\\wevtutil.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "a masqueraded wevtutil.exe outside System32 must still trigger self-spawn"
    );
}

#[test]
fn wevtutil_child_of_a_different_parent_still_alerts() {
    // The exclusion is keyed on the *agent's own* pid, not on the name alone —
    // wevtutil.exe spawned by anything else is not the agent's poll loop.
    let mut state = RuleState::new();
    state.seed_own_pid(1084);
    let sec = 1_000_000_000u64;
    let mut alerts = Vec::new();
    for i in 0..SELF_SPAWN_THRESHOLD {
        let mut e = exec_event_win(
            6400 + i,
            9999,
            "wevtutil.exe",
            "wevtutil.exe",
            u64::from(i) * sec,
        );
        e.image_path = "C:\\Windows\\System32\\wevtutil.exe".to_string();
        alerts.extend(state.on_exec(&e));
    }
    assert!(
        alerts.iter().any(|a| a.technique == "T1059"),
        "wevtutil.exe spawned by a pid other than the agent's own must still alert"
    );
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

// ── SELF-SPAWN on system images (#432) ───────────────────────────────────

/// `n` spawns of `child` by pid 1, one second apart, with both image paths set.
fn spawn_burst(child_image: &str, parent_image: Option<&str>, n: u32) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let comm = child_image.rsplit('\\').next().unwrap_or(child_image);
    let mut alerts = Vec::new();
    for i in 0..n {
        let mut e = exec_event_win(500 + i, 1, comm, comm, u64::from(i) * 1_000_000_000);
        e.image_path = child_image.to_string();
        e.parent_image_path = parent_image.map(str::to_string);
        alerts.extend(state.on_exec(&e));
    }
    alerts
        .into_iter()
        .filter(|a| a.technique == "T1059")
        .collect()
}

const SYSTEM_POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

#[test]
fn three_system_children_of_a_system_parent_do_not_alert() {
    // #432: an operator running `schtasks` three times from PowerShell, and
    // svchost → taskhostw.exe, both read as self-spawn at the base threshold.
    assert!(
        spawn_burst(
            r"C:\Windows\System32\schtasks.exe",
            Some(SYSTEM_POWERSHELL),
            3
        )
        .is_empty()
    );
    assert!(
        spawn_burst(
            r"C:\Windows\System32\taskhostw.exe",
            Some(r"C:\Windows\System32\svchost.exe"),
            3
        )
        .is_empty()
    );
}

#[test]
fn an_installed_cli_run_from_a_shell_does_not_alert() {
    assert!(
        spawn_burst(
            r"C:\Program Files\Synthaea\cli.exe",
            Some(SYSTEM_POWERSHELL),
            3
        )
        .is_empty()
    );
}

#[test]
fn a_system_to_system_storm_still_alerts() {
    let taskhostw = r"C:\Windows\System32\taskhostw.exe";
    let svchost = Some(r"C:\Windows\System32\svchost.exe");
    assert!(spawn_burst(taskhostw, svchost, SELF_SPAWN_TRUSTED_THRESHOLD - 1).is_empty());
    assert_eq!(
        spawn_burst(taskhostw, svchost, SELF_SPAWN_TRUSTED_THRESHOLD).len(),
        1
    );
}

#[test]
fn a_system_shell_looping_a_script_host_alerts_at_the_base_threshold() {
    // #494 review: a malicious .ps1 respawning powershell.exe a few times
    // from a system shell, below SELF_SPAWN_TRUSTED_THRESHOLD.
    for child in [
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\wscript.exe",
    ] {
        let alerts = spawn_burst(child, Some(SYSTEM_POWERSHELL), SELF_SPAWN_THRESHOLD);
        assert_eq!(alerts.len(), 1, "{child}");
    }
}

#[test]
fn a_script_host_child_matches_case_insensitively() {
    let alerts = spawn_burst(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE",
        Some(r"C:\Windows\System32\svchost.exe"),
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
}

#[test]
fn a_dropped_parent_spawning_a_system_child_alerts_at_the_base_threshold() {
    // The 2026-09-07 malware3 capture: malware3.exe → powershell.exe, 20 in 30s.
    let alerts = spawn_burst(
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        Some(r"C:\Users\Public\malware3.exe"),
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
}

#[test]
fn a_dropped_child_of_a_system_shell_alerts_at_the_base_threshold() {
    let alerts = spawn_burst(
        r"C:\Users\victim\AppData\Local\Temp\payload.exe",
        Some(r"C:\Windows\System32\cmd.exe"),
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
}

#[test]
fn an_unknown_parent_image_keeps_the_base_threshold() {
    let alerts = spawn_burst(
        r"C:\Windows\System32\schtasks.exe",
        None,
        SELF_SPAWN_THRESHOLD,
    );
    assert_eq!(alerts.len(), 1);
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

// ── Download-then-exec (T1105) on Windows paths (#442) ──────────────────────

/// A Windows download by `downloader` of `path`, then an exec of `comm` 5s later.
fn windows_download_then_exec(downloader: &str, path: &str, comm: &str) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let _ = state.on_file_open(&file_open_event_full(
        50,
        downloader,
        path,
        O_WRONLY | O_CREAT,
        0,
    ));
    state.on_exec(&exec_event_win(51, 1, comm, path, 5_000_000_000))
}

#[test]
fn curl_exe_download_then_exec_matches_on_windows() {
    // Regression (#442): the downloader list said `curl` (the ETW comm is
    // `curl.exe`) and the leaf was cut on `/`, so the rule never fired on Windows.
    let alerts = windows_download_then_exec(
        "curl.exe",
        r"C:\Users\victim\AppData\Local\Temp\payload.exe",
        "payload.exe",
    );
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].technique, "T1105");
}

#[test]
fn certutil_download_then_exec_matches() {
    let alerts = windows_download_then_exec("certutil.exe", r"C:\ProgramData\p.exe", "p.exe");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn windows_leaf_match_ignores_case_like_ntfs() {
    let alerts = windows_download_then_exec("curl.exe", r"C:\Temp\PAYLOAD.EXE", "payload.exe");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn unc_path_download_then_exec_matches() {
    let alerts = windows_download_then_exec("curl.exe", r"\\share\drop\p.exe", "p.exe");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
}

#[test]
fn powershell_writes_do_not_feed_the_download_join() {
    // Deliberately not a downloader: powershell.exe writes far too many files.
    let alerts = windows_download_then_exec("powershell.exe", r"C:\Temp\p.exe", "p.exe");
    assert!(alerts.iter().all(|a| a.technique != "T1105"), "{alerts:?}");
}

#[test]
fn a_linux_leaf_match_stays_case_sensitive() {
    let mut state = RuleState::new();
    let _ = state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/Payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        5_000_000_000,
    ));
    assert!(alerts.iter().all(|a| a.technique != "T1105"), "{alerts:?}");
}
