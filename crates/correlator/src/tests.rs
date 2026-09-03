//! Correlator tests — everything goes through the public API
//! ([`CorrelationEngine::on_event`]), except reading the Bayesian prior (internal
//! constant). Migrated from the old iteration with test names translated to English.

use std::time::Duration;

use schema::{ConnectEvent, Event, EventMeta, ExecEvent, FileOpenEvent, User};

use crate::{CorrelationEngine, bayes::PRIOR_LOG_ODDS};

fn meta(pid: u32, ts_ns: u64) -> EventMeta {
    meta_full(pid, 0, "", ts_ns)
}

fn meta_full(pid: u32, ppid: u32, comm: &str, ts_ns: u64) -> EventMeta {
    EventMeta {
        pid,
        ppid,
        user: User::Unknown,
        timestamp_ns: ts_ns,
        comm: comm.to_string(),
    }
}

fn exec_event(pid: u32, ts_ns: u64) -> Event {
    exec_with_meta(meta(pid, ts_ns), "")
}

fn exec_with_meta(meta: EventMeta, image_path: &str) -> Event {
    Event::Exec(ExecEvent {
        meta,
        image_path: image_path.to_string(),
        cmdline: String::new(),
        argv: vec![],
        parent_comm: None,
        parent_image_path: None,
    })
}

fn connect_event(pid: u32, ts_ns: u64) -> Event {
    connect_to(meta(pid, ts_ns), [1, 2, 3, 4], 4444)
}

fn connect_to(meta: EventMeta, daddr: [u8; 4], dport: u16) -> Event {
    Event::Connect(ConnectEvent {
        meta,
        daddr: std::net::IpAddr::V4(daddr.into()),
        dport,
    })
}

fn file_write_event(pid: u32, ts_ns: u64) -> Event {
    const O_WRONLY: u32 = 0o1;
    const O_CREAT: u32 = 0o100;
    // Path simulating a payload in a temp directory — needed to trigger
    // the is_payload_file() filter of the T1105 rules.
    Event::FileOpen(FileOpenEvent {
        meta: meta(pid, ts_ns),
        path: "C:\\Windows\\Temp\\payload.exe".to_string(),
        flags: O_WRONLY | O_CREAT,
    })
}

fn file_read_event(pid: u32, ts_ns: u64) -> Event {
    Event::FileOpen(FileOpenEvent {
        meta: meta(pid, ts_ns),
        path: String::new(),
        flags: 0o0, // O_RDONLY
    })
}

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

// ── BehaviorVector ─────────────────────────────────────────────────────────

#[test]
fn bv_unknown_pid_returns_none() {
    let engine = CorrelationEngine::new();
    assert!(engine.behavior_vector_for_pid(9999).is_none());
}

#[test]
fn bv_exec_only() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(11, 1_000_000_000));
    let bv = engine.behavior_vector_for_pid(11).unwrap();
    assert_eq!(bv.has_exec, 1.0);
    assert_eq!(bv.has_connect, 0.0);
    assert_eq!(bv.has_filewrite, 0.0);
    assert_eq!(bv.connect_count, 0.0);
    assert_eq!(bv.dest_is_external, 0.0);
}

#[test]
fn bv_exec_connect_delta_correct() {
    let mut engine = CorrelationEngine::new();
    // Exec at t=0, Connect at t=500ms
    engine.on_event(exec_event(22, 0));
    engine.on_event(connect_event(22, 500_000_000));
    let bv = engine.behavior_vector_for_pid(22).unwrap();
    assert_eq!(bv.has_exec, 1.0);
    assert_eq!(bv.has_connect, 1.0);
    assert!(
        (bv.time_exec_to_connect_ms - 500.0).abs() < 1.0,
        "expected delta 500 ms, got {}",
        bv.time_exec_to_connect_ms
    );
    assert_eq!(bv.connect_count, 1.0);
}

#[test]
fn bv_external_ip_detected() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(connect_to(meta(33, 1_000_000_000), [8, 8, 8, 8], 53));
    let bv = engine.behavior_vector_for_pid(33).unwrap();
    assert_eq!(bv.dest_is_external, 1.0);
}

#[test]
fn bv_private_ip_not_external() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(connect_to(meta(44, 1_000_000_000), [192, 168, 1, 1], 80));
    let bv = engine.behavior_vector_for_pid(44).unwrap();
    assert_eq!(bv.dest_is_external, 0.0);
}

#[test]
fn bv_unspecified_ip_not_external() {
    // Regression 2026-08-31: `0.0.0.0` (unspecified address) observed on a
    // `connect()` from `sshd` in a real session — must not be classified as external.
    let mut engine = CorrelationEngine::new();
    engine.on_event(connect_to(meta(55, 1_000_000_000), [0, 0, 0, 0], 22));
    let bv = engine.behavior_vector_for_pid(55).unwrap();
    assert_eq!(bv.dest_is_external, 0.0);
}

#[test]
fn bv_distinct_dports() {
    let mut engine = CorrelationEngine::new();
    // Two connections to different ports
    engine.on_event(connect_event(66, 1_000_000_000)); // port 4444
    engine.on_event(connect_to(meta(66, 2_000_000_000), [1, 2, 3, 4], 80));
    let bv = engine.behavior_vector_for_pid(66).unwrap();
    assert_eq!(bv.connect_count, 2.0);
    assert_eq!(bv.distinct_dports, 2.0);
}

#[test]
fn bv_filewrite_present() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(file_write_event(77, 1_000_000_000));
    let bv = engine.behavior_vector_for_pid(77).unwrap();
    assert_eq!(bv.has_filewrite, 1.0);
    assert_eq!(bv.has_exec, 0.0);
}

#[test]
fn bv_to_vec_has_9_features() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(88, 1_000_000_000));
    let bv = engine.behavior_vector_for_pid(88).unwrap();
    assert_eq!(bv.to_vec().len(), 9);
}

// ── Naive Bayes filter ─────────────────────────────────────────────────────

fn exec_event_with_ppid(pid: u32, ppid: u32, ts_ns: u64) -> Event {
    exec_with_meta(meta_full(pid, ppid, "", ts_ns), "")
}

fn exec_event_suspicious(pid: u32, ppid: u32, ts_ns: u64) -> Event {
    // Path in AppData → is_suspicious_path = 1.0
    exec_with_meta(
        meta_full(pid, ppid, "", ts_ns),
        "C:\\Users\\solka\\AppData\\Roaming\\malware.exe",
    )
}

fn connect_event_external(pid: u32, ts_ns: u64) -> Event {
    // Public IP → dest_is_external = 1.0
    connect_to(meta(pid, ts_ns), [185, 220, 101, 1], 4444)
}

#[test]
fn bayes_prior_at_1_percent() {
    let engine = CorrelationEngine::new();
    // No events → no belief
    assert!(engine.belief_for_pid(9999).is_none());
}

#[test]
fn bayes_rises_on_suspicious_path_and_external_ip() {
    let mut engine = CorrelationEngine::new();
    // ExecEvent from AppData
    engine.on_event(exec_event_suspicious(100, 50, 1_000_000_000));
    // ConnectEvent to a public IP
    engine.on_event(connect_event_external(100, 1_100_000_000));

    let belief = engine.belief_for_pid(100).expect("belief expected");
    // Suspicious path (+3.60) + external IP (+1.23) + connect (+1.19) + time (<2s,
    // +1.90) → log_odds >> prior. Must cross BAYES_THRESHOLD (2.0) on the very
    // first connection.
    assert!(
        belief.log_odds > PRIOR_LOG_ODDS,
        "log_odds must have risen above the prior, got {}",
        belief.log_odds
    );
    assert!(
        belief.probability() > 0.01,
        "probability must be > 1%, got {}",
        belief.probability()
    );
}

#[test]
fn bayes_alerts_on_threshold_crossing() {
    let mut engine = CorrelationEngine::new();
    // Suspicious path + external IP + many connections → must cross BAYES_THRESHOLD
    engine.on_event(exec_event_suspicious(200, 50, 0));
    // 20 ConnectEvents to an external IP → connect_count grows into the strong band
    for i in 0..20u64 {
        let alerts = engine.on_event(connect_event_external(200, (i + 1) * 100_000_000));
        // As soon as the threshold is crossed, a BAYES alert must appear
        if alerts.iter().any(|a| a.technique == "BAYES") {
            return; // test OK
        }
    }
    panic!("no BAYES alert generated despite a high score");
}

#[test]
fn bayes_alerts_only_once_per_crossing() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event_suspicious(300, 50, 0));
    let mut bayes_count = 0usize;
    for i in 0..30u64 {
        let alerts = engine.on_event(connect_event_external(300, (i + 1) * 100_000_000));
        bayes_count += alerts.iter().filter(|a| a.technique == "BAYES").count();
    }
    assert_eq!(
        bayes_count, 1,
        "the BAYES alert must fire only once per threshold crossing"
    );
}

#[test]
fn bayes_survives_respawn() {
    // Two different processes (pid 400 then 401) with the same (ppid=50, comm)
    // → the belief must accumulate across the two.
    let mut engine = CorrelationEngine::new();

    // First process pid=400, ppid=50
    engine.on_event(exec_event_with_ppid(400, 50, 0));
    engine.on_event(connect_event_external(400, 100_000_000));
    let log_odds_after_pid400 = engine
        .belief_for_pid(400)
        .expect("belief for pid 400 expected")
        .log_odds;

    // Respawn: pid=401, same ppid=50, same comm (empty in our tests)
    engine.on_event(exec_event_with_ppid(401, 50, 200_000_000));
    engine.on_event(connect_event_external(401, 300_000_000));

    // pid=401 must have the same entity key (ppid=50, comm="") as pid=400
    // → log_odds must keep rising, not restart from the prior
    let log_odds_after_pid401 = engine
        .belief_for_pid(401)
        .expect("belief for pid 401 expected")
        .log_odds;

    assert!(
        log_odds_after_pid401 > log_odds_after_pid400,
        "the belief must accumulate after a respawn: {} → {}",
        log_odds_after_pid400,
        log_odds_after_pid401
    );
}
