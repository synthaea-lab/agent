//! Co-occurrence rule tests (R1 spawn+connect … R4 respawn+connect), including
//! the once-per-window and masquerade regression tests.

use super::*;

#[test]
fn spawn_then_connect_same_pid_alerts() {
    let mut engine = CorrelationEngine::new();
    let alerts = engine.on_event(exec_event(1234, 1_000_000_000));
    assert!(alerts.is_empty());

    let alerts = engine.on_event(connect_event(1234, 2_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059/T1071");
}

#[test]
fn connect_without_spawn_does_not_alert() {
    let mut engine = CorrelationEngine::new();
    let alerts = engine.on_event(connect_event(5678, 1_000_000_000));
    assert!(alerts.is_empty());
}

#[test]
fn different_pids_do_not_correlate() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(1111, 1_000_000_000));
    let alerts = engine.on_event(connect_event(2222, 2_000_000_000));
    assert!(alerts.is_empty());
}

// ── R2: connect + filewrite ───────────────────────────────────────────────

#[test]
fn connect_filewrite_same_pid_alerts() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(connect_event(42, 1_000_000_000));
    let alerts = engine.on_event(file_write_event(42, 2_000_000_000));
    assert!(alerts.iter().any(|a| a.technique == "T1105"));
}

#[test]
fn connect_fileread_does_not_alert_staging() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(connect_event(42, 1_000_000_000));
    let alerts = engine.on_event(file_read_event(42, 2_000_000_000));
    assert!(!alerts.iter().any(|a| a.technique == "T1105"));
}

// ── R3: spawn + connect + filewrite ──────────────────────────────────────

#[test]
fn complete_dropper_chain_alerts() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(99, 1_000_000_000));
    engine.on_event(connect_event(99, 2_000_000_000));
    let alerts = engine.on_event(file_write_event(99, 3_000_000_000));
    assert!(
        alerts.iter().any(|a| a.technique == "T1105/T1059/T1071"),
        "complete dropper chain not detected"
    );
}

#[test]
fn masqueraded_ignored_name_is_still_correlated() {
    // A payload renamed `svchost.exe` in /tmp must not inherit the IGNORED-list
    // exclusion (name-only exclusions are a trivial bypass).
    let mut engine = CorrelationEngine::new();
    let mut exec = exec_event(99, 1_000_000_000);
    exec_set_comm_and_path(&mut exec, "svchost.exe", "/tmp/svchost.exe");
    engine.on_event(exec);
    let mut connect = connect_event(99, 2_000_000_000);
    if let Event::Connect(c) = &mut connect {
        c.meta.comm = "svchost.exe".to_string();
    }
    let alerts = engine.on_event(connect);
    assert!(
        alerts.iter().any(|a| a.technique == "T1059/T1071"),
        "masqueraded svchost must still correlate: {alerts:?}"
    );
}

#[test]
fn real_system_svchost_stays_ignored() {
    let mut engine = CorrelationEngine::new();
    let mut exec = exec_event(99, 1_000_000_000);
    exec_set_comm_and_path(
        &mut exec,
        "svchost.exe",
        "C:\\Windows\\System32\\svchost.exe",
    );
    engine.on_event(exec);
    let mut connect = connect_event(99, 2_000_000_000);
    if let Event::Connect(c) = &mut connect {
        c.meta.comm = "svchost.exe".to_string();
    }
    let alerts = engine.on_event(connect);
    assert!(
        alerts.is_empty(),
        "real svchost must stay excluded: {alerts:?}"
    );
}

fn exec_set_comm_and_path(event: &mut Event, comm: &str, image_path: &str) {
    if let Event::Exec(e) = event {
        e.meta.comm = comm.to_string();
        e.image_path = image_path.to_string();
    }
}

#[test]
fn satisfied_pattern_alerts_once_per_window() {
    // Review finding: once exec+connect co-occurred, EVERY later event of the
    // pid re-emitted the identical alert — a flood from one pattern.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(99, 1_000_000_000));
    let first = engine.on_event(connect_event(99, 2_000_000_000));
    assert!(first.iter().any(|a| a.technique == "T1059/T1071"));
    let repeat = engine.on_event(connect_event(99, 3_000_000_000));
    assert!(
        repeat.iter().all(|a| a.technique != "T1059/T1071"),
        "same pattern re-alerted inside the window: {repeat:?}"
    );
    // A full window later, a fresh exec+connect pair is a new finding.
    engine.on_event(exec_event(99, 99_000_000_000));
    let later = engine.on_event(connect_event(99, 100_000_000_000));
    assert!(later.iter().any(|a| a.technique == "T1059/T1071"));
}

#[test]
fn complete_chain_masks_plain_spawn_connect() {
    // When the full chain is detected, spawn+connect alone must not
    // generate a duplicate.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(99, 1_000_000_000));
    engine.on_event(connect_event(99, 2_000_000_000));
    let alerts = engine.on_event(file_write_event(99, 3_000_000_000));
    let spawn_connect_count = alerts
        .iter()
        .filter(|a| a.technique == "T1059/T1071" && a.message.contains("spawn + network"))
        .count();
    assert_eq!(spawn_connect_count, 0, "unexpected spawn+connect duplicate");
}

// ── R4: respawn + connect ─────────────────────────────────────────────────

#[test]
fn respawn_connect_alerts() {
    let mut engine = CorrelationEngine::new();
    for i in 0..3u64 {
        engine.on_event(exec_event(77, i * 1_000_000_000));
    }
    let alerts = engine.on_event(connect_event(77, 4_000_000_000));
    assert!(
        alerts
            .iter()
            .any(|a| a.message.contains("automatic respawn"))
    );
}

/// Reproduces a real respawn (fork+exec): a new pid on each iteration, same
/// (ppid, comm) — unlike `respawn_connect_alerts` above, which artificially reuses
/// the same pid for the 3 execs. See lab/scenarios/respawn-beacon.sh, which
/// documented the hypothesis that a per-pid rule would never trigger in this case.
#[test]
fn respawn_connect_distinct_pids_alerts() {
    let mut engine = CorrelationEngine::new();
    for (i, pid) in (101..104u32).enumerate() {
        engine.on_event(exec_with_meta(
            meta_full(pid, 999, "listener", i as u64 * 1_000_000_000),
            "",
        ));
    }
    let alerts = engine.on_event(connect_to(
        meta_full(103, 999, "listener", 4_000_000_000),
        [1, 2, 3, 4],
        4444,
    ));
    assert!(
        alerts
            .iter()
            .any(|a| a.message.contains("automatic respawn")),
        "respawn with distinct pids (real fork+exec) should alert"
    );
}

#[test]
fn two_spawns_plus_connect_no_respawn_alert() {
    // Below the threshold (3) → no respawn alert
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(77, 1_000_000_000));
    engine.on_event(exec_event(77, 2_000_000_000));
    let alerts = engine.on_event(connect_event(77, 3_000_000_000));
    assert!(
        !alerts
            .iter()
            .any(|a| a.message.contains("automatic respawn"))
    );
}

#[test]
fn eviction_outside_window() {
    let window = Duration::from_secs(10);
    let mut engine = CorrelationEngine::with_window(window);

    // Exec at t=0s
    engine.on_event(exec_event(1234, 0));

    // Connect at t=11s — outside the window, the exec must have been evicted
    let alerts = engine.on_event(connect_event(1234, 11_000_000_000));
    assert!(
        alerts.is_empty(),
        "an exec outside the window must no longer correlate"
    );
}
