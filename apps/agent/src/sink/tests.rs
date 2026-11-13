use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    thread,
    time::Duration,
};

use schema::{ConnectEvent, Event, EventMeta, ExecEvent, User, sensor::EventSink as _};

use super::{
    DetectionSink, Load,
    canary::{CANARY_EXEC_HOLD_NS, MAX_HELD_CANARY_TOUCHES},
    correlation::{ScorerLoadError, correlator_case_id, locate_model_dir, try_load_scorer},
    entity_key, load_sigma_rules,
};

/// A content root with one Sigma rule per platform directory, each titled after it.
fn sigma_content_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for platform in ["linux", "windows", "macos"] {
        let dir = root.path().join("rules/sigma").join(platform);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rule.yml"),
            format!(
                "title: {platform}-rule\ndescription: d\ntags:\n  - attack.t1059\nlevel: low\n\
                 falsepositives:\n  - none\ndetection:\n  selection:\n    Image|endswith: '/x'\n  \
                 condition: selection\n"
            ),
        )
        .unwrap();
    }
    root
}

#[test]
fn the_agent_loads_only_the_sigma_rules_of_its_own_platform() {
    let root = sigma_content_root();
    let Load::Loaded(engine) = load_sigma_rules(root.path()) else {
        panic!("the content directory is present and readable");
    };
    // macOS also runs the Unix-family rules of `linux/` (#980); the others only their own.
    let mut titles = engine.rule_titles();
    titles.sort_unstable();
    let expected: &[&str] = if cfg!(target_os = "linux") {
        &["linux-rule"]
    } else if cfg!(target_os = "windows") {
        &["windows-rule"]
    } else {
        &["linux-rule", "macos-rule"]
    };
    assert_eq!(titles, expected);
}

#[test]
fn a_content_root_named_after_another_platform_does_not_change_which_rules_load() {
    // `<tmp>/windows/linux/...`: read from the full path, every rule would look like
    // every platform's.
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("windows").join("linux");
    std::fs::create_dir_all(&root).unwrap();
    let inner = sigma_content_root();
    let from = inner.path().join("rules");
    let to = root.join("rules");
    std::fs::create_dir_all(to.join("sigma")).unwrap();
    for platform in ["linux", "windows", "macos"] {
        std::fs::create_dir_all(to.join("sigma").join(platform)).unwrap();
        std::fs::copy(
            from.join("sigma").join(platform).join("rule.yml"),
            to.join("sigma").join(platform).join("rule.yml"),
        )
        .unwrap();
    }
    let Load::Loaded(engine) = load_sigma_rules(&root) else {
        panic!("the content directory is present and readable");
    };
    let expected = if cfg!(target_os = "macos") { 2 } else { 1 };
    assert_eq!(engine.rule_count(), expected, "{:?}", engine.rule_titles());
}

#[test]
fn the_verdict_entity_carries_the_parents_incarnation_when_stamped() {
    let mut meta = schema::fixtures::meta();
    meta.ppid = 50;
    meta.comm = "evil".into();
    assert_eq!(entity_key(&meta).parent_generation, None);
    meta.parent_process_generation = Some(7);
    let entity = entity_key(&meta);
    assert_eq!(entity.parent_generation, Some(7));
    assert_eq!((entity.ppid, entity.comm.as_str()), (50, "evil"));
}

#[test]
fn the_correlator_case_id_names_the_parent_incarnation_only_when_known() {
    let plain = verdict::EntityKey::new(50, "evil");
    assert_eq!(correlator_case_id(&plain), "50:evil");
    let stamped = plain.with_parent_generation(Some(7));
    assert_eq!(correlator_case_id(&stamped), "50:evil@7");
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sink-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sink_in(dir: &std::path::Path) -> Arc<DetectionSink> {
    Arc::new(
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap(),
    )
}

/// Asserts that the recording kill hook was called for exactly `pid`, once. On a mismatch it prints
/// `context` and the alert log: `maybe_kill` refuses before it calls the hook (the agent's own pid,
/// pid 1, a verdict shield), and that refusal is only in `RESPONSE-KILL` there. A bare `left: []`
/// (agent#247, seen once on macOS CI) names none of those.
#[track_caller]
fn assert_killed_exactly(killed: &Mutex<Vec<u32>>, dir: &std::path::Path, pid: u32, context: &str) {
    let got = killed.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![pid],
        "{context}; test process pid {}; alert log:\n{}",
        std::process::id(),
        alerts_in(dir)
    );
}

fn alerts_in(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("alerts.ndjson")).unwrap_or_default()
}

#[test]
fn ordinary_file_write_does_not_enter_the_timestomp_rule_route() {
    let dir = tmp("file-write-not-timestomp");
    let sink = sink_in(&dir);
    sink.on_event(Event::FileWrite(schema::FileWriteEvent {
        meta: schema::fixtures::meta(),
        fd: 12,
        bytes_requested: 4096,
    }));
    assert!(!alerts_in(&dir).contains("T1070.006"));
}

#[test]
fn set_time_event_reaches_the_timestomp_rule_through_the_real_sink() {
    let dir = tmp("file-set-time-route");
    let sink = sink_in(&dir);
    sink.on_event(Event::FileSetTime(schema::FileSetTimeEvent {
        meta: schema::fixtures::meta(),
        path: r"C:\Users\u\invoice.docx".into(),
        last_write_time: Some(132_537_600_000_000_000),
        ..schema::fixtures::file_set_time()
    }));
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1070.006"), "{alerts}");
    assert!(alerts.contains("invoice.docx"), "{alerts}");
}

/// `record_rule_alerts` re-locks `rule_state` for a ransomware alert's damage manifest. A guard
/// still held by the step that produced the alert would deadlock there (agent#144), so a step
/// returning a T1486 alert must finish. The channel timeout turns a deadlock into a failure.
#[test]
fn a_stateful_step_returning_a_ransomware_alert_does_not_deadlock_the_manifest_lookup() {
    let dir = tmp("rule-alerts-relock");
    let sink = sink_in(&dir);
    let event = Event::FileRename(schema::fixtures::file_rename());
    let (done, finished) = std::sync::mpsc::channel();
    let worker = Arc::clone(&sink);
    thread::spawn(move || {
        worker.rule_alerts(&event, |_| {
            vec![rules::Alert {
                technique: "T1486",
                severity: schema::detection::Severity::High,
                message: "mass rename".into(),
            }]
        });
        let _ = done.send(());
    });
    assert!(
        finished.recv_timeout(Duration::from_secs(10)).is_ok(),
        "rule_alerts held the rule-state lock while recording a ransomware alert"
    );
}

#[test]
fn a_panic_inside_rule_evaluation_does_not_stop_later_events_from_being_processed() {
    let dir = tmp("poisoned-rule-state");
    let sink = sink_in(&dir);
    // A rule that panics mid-evaluation leaves `rule_state` poisoned, exactly like this.
    thread::scope(|s| {
        let _ = s
            .spawn(|| {
                let _guard = sink.rule_state.lock().unwrap();
                panic!("a rule panicked while evaluating an event");
            })
            .join();
    });
    assert!(sink.rule_state.is_poisoned());

    sink.on_event(Event::FileSetTime(schema::FileSetTimeEvent {
        meta: schema::fixtures::meta(),
        path: r"C:\Users\u\invoice.docx".into(),
        last_write_time: Some(132_537_600_000_000_000),
        ..schema::fixtures::file_set_time()
    }));

    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1070.006"), "{alerts}");
    assert!(!sink.rule_state.is_poisoned());
}

#[test]
fn write_capable_volume_open_reaches_t1006_through_the_real_sink() {
    let dir = tmp("raw-volume-open-route");
    let sink = sink_in(&dir);
    sink.on_event(Event::RawVolumeOpen(schema::RawVolumeOpenEvent {
        meta: schema::fixtures::meta(),
        volume: r"\Device\HarddiskVolume3".into(),
        desired_access: 0x4000_0000,
    }));
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1006"), "{alerts}");
    assert!(alerts.contains("HarddiskVolume3"), "{alerts}");
}

#[test]
fn a_metadata_only_volume_open_does_not_enter_the_raw_volume_route() {
    // `alerts.ndjson` (`AlertRecord` in `apps/agent/src/alerts.rs`) carries only
    // timestamp/technique/message — no severity field — so this sink-level test
    // can only prove "produces no alert at all", not "produces Low rather than
    // Medium". That distinction is already proven directly against the rule:
    // `read_capability_and_maximum_allowed_are_low`
    // (`crates/rules/tests/raw_volume.rs`) asserts `Severity::Low` for the same
    // 0x8000_0000 (GENERIC_READ) mask this test used to send here. A bare,
    // metadata-only open (`desired_access = 0`) is the one shape the rule maps
    // to no alert (`evaluate_raw_volume_open`'s `None` branch), which is what
    // this sink-level test actually exercises.
    let dir = tmp("read-only-volume-open-route");
    let sink = sink_in(&dir);
    sink.on_event(Event::RawVolumeOpen(schema::RawVolumeOpenEvent {
        meta: schema::fixtures::meta(),
        volume: r"\Device\HarddiskVolume3".into(),
        desired_access: 0,
    }));
    let alerts = alerts_in(&dir);
    assert!(
        !alerts.contains("T1006"),
        "a metadata-only open must not alert: {alerts}"
    );
}

#[test]
fn sigma_sees_raw_exec_but_alert_and_event_outputs_are_redacted() {
    let dir = tmp("cmdline-redaction-e2e");
    // The engine only loads the running host's own platform directory (#980) -- write the
    // rule there, not a hardcoded "linux", so this test exercises the real load path on
    // whichever platform runs it instead of silently loading zero rules on Windows/macOS.
    let platform_dir = sigma::Platform::host()
        .expect("supported CI platform")
        .dir_name();
    let sigma_dir = dir.join("content/rules/sigma").join(platform_dir);
    std::fs::create_dir_all(&sigma_dir).unwrap();
    std::fs::write(
        sigma_dir.join("raw-secret.yml"),
        "title: Password flag on a command line\ndescription: test\ntags:\n  - attack.t1059\nlevel: high\nfalsepositives:\n  - none\ndetection:\n  selection:\n    CommandLine|contains: '--password='\n  condition: selection\n",
    )
    .unwrap();
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = Arc::new(
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap(),
    );
    for (pid, comm) in [(101, "it's"), (102, "a\"b")] {
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = pid;
        exec.meta.comm = comm.into();
        exec.image_path = "/usr/bin/curl".into();
        exec.cmdline = "curl -u a:S3cret h; base64 -d --password=S3cret".into();
        exec.argv = Vec::new();
        sink.on_event(Event::Exec(exec));
    }
    assert!(sink.enrich_queue.flush(std::time::Duration::from_secs(10)));

    let alerts = alerts_in(&dir);
    assert!(alerts.contains("REDACTED"), "{alerts}");
    assert!(!alerts.contains("S3cret"), "{alerts}");
    let recent = sink.alert_log.latest(crate::alerts::RECENT_ALERTS_CAPACITY);
    assert!(
        recent
            .iter()
            .any(|alert| alert.message.contains("base64 -d --password=REDACTED")),
        "{recent:?}"
    );
    assert!(
        recent.iter().all(|alert| !alert.message.contains("S3cret")),
        "{recent:?}"
    );
    let terminal_alert = crate::alerts::format_alert_line(&recent[0].technique, &recent[0].message);
    assert!(
        terminal_alert.contains("[ALERT]") && terminal_alert.contains("REDACTED"),
        "{terminal_alert}"
    );
    assert!(!terminal_alert.contains("S3cret"), "{terminal_alert}");
    let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
    assert!(events.contains("--password=REDACTED"), "{events}");
    assert!(!events.contains("S3cret"), "{events}");
    let detections: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    assert!(
        detections.len() >= 2,
        "Sigma and base64 rule should both detect: {detections:?}"
    );
    assert!(
        detections
            .iter()
            .any(|queued| queued.detection.title == "Password flag on a command line"),
        "{detections:?}"
    );
    assert!(
        detections.iter().any(|queued| queued
            .detection
            .title
            .contains("base64 -d --password=REDACTED")),
        "{detections:?}"
    );
    for queued in &detections {
        let serialized = serde_json::to_string(&queued.detection).unwrap();
        assert!(!serialized.contains("S3cret"), "{serialized}");
    }
}

/// #895: the AMSI rule reads the raw buffer and quotes an excerpt of it in its message;
/// the alert log, the detection spool and `events.jsonl` get the redacted excerpt.
#[test]
fn amsi_rules_see_the_raw_buffer_but_alert_and_event_outputs_are_redacted() {
    let dir = tmp("amsi-redaction-e2e");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = Arc::new(
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            Some(Arc::clone(&spool)),
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap(),
    );
    let amsi = schema::AmsiContentEvent {
        app_name: "PowerShell_C:\\Windows\\powershell.exe_10.0".into(),
        text: Some("New-LocalUser -Name svc -Password 'S3cret'".into()),
        // AMSI_RESULT_DETECTED: the provider-verdict rule fires whatever the text says.
        scan_result: 32768,
        ..schema::fixtures::amsi_content()
    };
    let raw_alerts = rules::evaluate_amsi_content(&amsi);
    assert!(
        raw_alerts.iter().any(|a| a.message.contains("S3cret")),
        "the rule quotes the raw buffer: {raw_alerts:?}"
    );
    sink.on_event(Event::AmsiContent(amsi));
    assert!(sink.enrich_queue.flush(std::time::Duration::from_secs(10)));

    let alerts = alerts_in(&dir);
    assert!(alerts.contains("-Password 'REDACTED'"), "{alerts}");
    assert!(!alerts.contains("S3cret"), "{alerts}");
    let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
    assert!(events.contains("-Password 'REDACTED'"), "{events}");
    assert!(!events.contains("S3cret"), "{events}");
    let detections: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    assert!(!detections.is_empty());
    for queued in &detections {
        let serialized = serde_json::to_string(&queued.detection).unwrap();
        assert!(!serialized.contains("S3cret"), "{serialized}");
    }
}

#[test]
fn redacted_detection_message_keeps_messages_with_an_empty_command_line_intact() {
    assert_eq!(
        super::recording::redact_detection_message("", "", "process comm=it's"),
        "process comm=it's"
    );
}

#[test]
fn advancing_the_correlator_clock_emits_a_silent_shell_alert() {
    let dir = tmp("correlator-tick");
    let sink = sink_in(&dir);
    let now = schema::time::now_ns();
    let mut meta = schema::fixtures::meta();
    meta.pid = 9_031;
    meta.ppid = 500;
    meta.comm = "sh".into();
    meta.timestamp_ns = now.saturating_sub(10_000_000_000);
    let shell = Event::Exec(ExecEvent {
        meta,
        image_path: "/usr/bin/sh".into(),
        parent_comm: Some("nginx".into()),
        ..schema::fixtures::exec()
    });

    sink.on_event(shell);
    assert!(!alerts_in(&dir).contains("T1505.003"));
    sink.advance_correlation_time(now);
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1505.003"), "{alerts}");
    assert!(alerts.contains("no matching"), "{alerts}");
}

#[test]
fn the_correlator_ticker_emits_without_a_following_event() {
    let dir = tmp("correlator-ticker-thread");
    let sink = sink_in(&dir);
    let now = schema::time::now_ns();
    let mut meta = schema::fixtures::meta();
    meta.pid = 9_032;
    meta.ppid = 500;
    meta.comm = "sh".into();
    meta.timestamp_ns = now.saturating_sub(10_000_000_000);
    let shell = Event::Exec(ExecEvent {
        meta,
        image_path: "/usr/bin/sh".into(),
        parent_comm: Some("nginx".into()),
        ..schema::fixtures::exec()
    });

    sink.on_event(shell);
    sink.start_correlator_ticker().unwrap();
    for _ in 0..30 {
        if alerts_in(&dir).contains("T1505.003") {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("the one-second ticker did not emit the idle shell alert");
}

/// Quarantine hooks + the alert log they audit into, over a real directory
/// holding one payload. `terminate` is never reached on this path.
fn quarantine_fixture(
    name: &str,
    quarantine_enabled: bool,
) -> (
    std::path::PathBuf,
    super::response::ResponseCell,
    crate::alerts::AlertLog,
    std::path::PathBuf,
) {
    let dir = tmp(name);
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"marker payload").unwrap();
    let hooks = super::response::ResponseHooks {
        policy: policy::ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled,
            isolate_enabled: false,
        },
        terminate: Box::new(|_| panic!("quarantine never terminates")),
        quarantine_dir: dir.join("quarantine"),
    };
    let log = crate::alerts::AlertLog::open(&dir.join("alerts.ndjson"), 8).unwrap();
    (
        dir,
        super::response::ResponseCell::from(hooks),
        log,
        payload,
    )
}

#[test]
fn a_yara_match_with_quarantine_disabled_leaves_the_payload_and_says_observe_only() {
    let (dir, hooks, log, payload) = quarantine_fixture("quarantine-off", false);
    super::quarantine_matched_payload(&hooks, &payload, &log);
    assert!(payload.exists(), "policy off must never move the file");
    assert!(
        !dir.join("quarantine").exists(),
        "policy off must not even create the quarantine directory"
    );
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("RESPONSE-QUARANTINE"), "{alerts}");
    assert!(alerts.contains("observe-only"), "{alerts}");
}

#[test]
fn a_yara_match_with_quarantine_enabled_moves_the_payload_and_audits_it() {
    let (dir, hooks, log, payload) = quarantine_fixture("quarantine-on", true);
    super::quarantine_matched_payload(&hooks, &payload, &log);
    assert!(!payload.exists(), "the payload must be moved out of place");
    let moved: Vec<_> = std::fs::read_dir(dir.join("quarantine"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        moved.iter().any(|n| n.ends_with(".origin")),
        "the restore sidecar must exist: {moved:?}"
    );
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("RESPONSE-QUARANTINE"), "{alerts}");
    assert!(alerts.contains("quarantined"), "{alerts}");
    // `alerts.ndjson` is JSON: a Windows path is written with doubled
    // backslashes, so compare the decoded message, not the raw text.
    let message = alerts
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|record| record["technique"] == "RESPONSE-QUARANTINE")
        .and_then(|record| record["message"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("no RESPONSE-QUARANTINE record: {alerts}"));
    assert!(
        message.contains(&payload.display().to_string()),
        "the audit line names the original path: {message}"
    );
}

/// The response chain through the real detection path, in-process: real
/// correlator, real YARA queue and rule set, real filesystem; only the
/// kernel-level `terminate` call is a recorder. The stream is the shape of the
/// lab's response scenario: an implant that connects out quickly and keeps
/// beaconing, while a payload carrying a YARA marker is written to disk.
const RESPONSE_MARKER_RULE: &str = r#"
rule response_marker {
    meta:
        technique = "T1105"
        severity = "low"
        falsepositives = "none, test-only rule"
    strings:
        $m = "RESPONSE-SCENARIO-MARKER"
    condition:
        $m
}
"#;

/// An implant execs and reaches an external address (TEST-NET-1, never
/// routed) within a second, then repeats: the beacon shape.
fn drive_linux_beacon(sink: &DetectionSink, pid: u32) {
    sink.on_event(exec(pid, "/tmp/implant", "/tmp/implant"));
    for i in 0..4u64 {
        sink.on_event(Event::Connect(ConnectEvent {
            meta: EventMeta {
                pid,
                timestamp_ns: (i + 1) * 500_000_000,
                ..schema::fixtures::meta()
            },
            daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            dport: 4444,
        }));
    }
}

/// Writes the marker payload, loads the YARA rule into the sink, enables
/// response with `policy`, then drives the beacon and reports the write
/// to the sensor path so YARA scans the payload. Returns the payload path
/// and the pids `terminate` was asked to kill.
fn run_response_scenario(
    dir: &std::path::Path,
    policy: policy::ResponsePolicy,
) -> (std::path::PathBuf, Arc<Mutex<Vec<u32>>>) {
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();

    let sink = sink_in(dir);
    assert_eq!(sink.reload_content().yara_rule_count, Some(1));
    let killed = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&killed);
    sink.enable_response(
        policy,
        move |pid| {
            recorder.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );

    sink.on_event(Event::FileOpen(schema::FileOpenEvent {
        path: payload.display().to_string(),
        flags: 0o101, // O_WRONLY | O_CREAT: write intent, what queues a scan
        meta: EventMeta {
            // Root: unrestricted, the payload is the test's own file.
            user: schema::User::Unix { uid: 0, gid: 0 },
            ..schema::fixtures::meta()
        },
    }));
    drive_linux_beacon(&sink, 6262);
    (payload, killed)
}

/// A sink watching the one canary a plant into `dir/canaries` produced.
fn sink_watching_canary(dir: &std::path::Path) -> (Arc<DetectionSink>, String) {
    let planted = dir.join("canaries");
    std::fs::create_dir_all(&planted).unwrap();
    let tripwires = crate::deception::start(
        &config::DeceptionConfig {
            canary_dirs: vec![planted.clone()],
            ..Default::default()
        },
        &dir.join("state"),
    )
    .unwrap();
    let canary = std::fs::read_dir(&planted)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .display()
        .to_string();
    let sink = sink_in(dir);
    sink.set_tripwires(tripwires);
    (sink, canary)
}

fn open_event(path: &str, pid: u32) -> Event {
    Event::FileOpen(schema::FileOpenEvent {
        path: path.to_string(),
        meta: EventMeta {
            pid,
            ..schema::fixtures::meta()
        },
        ..schema::fixtures::file_open()
    })
}

#[test]
fn another_process_opening_a_canary_raises_a_deception_detection() {
    let dir = tmp("canary-hit");
    let (sink, canary) = sink_watching_canary(&dir);
    sink.on_event(open_event(&canary, std::process::id() + 1));
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1083"), "{alerts}");
    assert!(alerts.contains("canary file touched"), "{alerts}");
}

fn open_event_at(path: &str, pid: u32, timestamp_ns: u64) -> Event {
    let Event::FileOpen(mut e) = open_event(path, pid) else {
        unreachable!()
    };
    e.meta.timestamp_ns = timestamp_ns;
    Event::FileOpen(e)
}

fn canary_alert_count(dir: &std::path::Path) -> usize {
    alerts_in(dir).matches("canary file touched").count()
}

#[test]
fn a_process_reopening_a_canary_raises_one_detection_per_cooldown() {
    let dir = tmp("canary-cooldown");
    let (sink, canary) = sink_watching_canary(&dir);
    let pid = std::process::id() + 1;
    let t0 = 1_000_000_000_000;
    for i in 0..5 {
        sink.on_event(open_event_at(&canary, pid, t0 + i * 1_000_000_000));
    }
    assert_eq!(canary_alert_count(&dir), 1);
    assert_eq!(sink.canary.hits_absorbed(), 4);
    sink.on_event(open_event_at(
        &canary,
        pid,
        t0 + super::canary::CANARY_COOLDOWN_NS + 1,
    ));
    assert_eq!(canary_alert_count(&dir), 2);
}

fn event_by(
    canary: &str,
    pid: u32,
    generation: Option<u64>,
    timestamp_ns: u64,
    kind: &str,
) -> Event {
    let meta = EventMeta {
        pid,
        process_generation: generation,
        timestamp_ns,
        ..schema::fixtures::meta()
    };
    match kind {
        "read" | "write" | "truncate" => {
            let mut e = schema::fixtures::file_open();
            e.path = canary.into();
            e.flags = match kind {
                "write" => 0o102,
                // O_RDONLY | O_TRUNC: no write access mode, yet the kernel empties the file (#233).
                "truncate" => schema::O_TRUNC,
                _ => 0,
            };
            e.meta = meta;
            Event::FileOpen(e)
        }
        "delete" => {
            let mut e = schema::fixtures::file_delete();
            e.path = canary.into();
            e.meta = meta;
            Event::FileDelete(e)
        }
        "rename" => Event::FileRename(schema::FileRenameEvent {
            old_path: canary.into(),
            new_path: format!("{canary}.locked"),
            meta,
            ..schema::fixtures::file_rename()
        }),
        other => panic!("unknown touch {other}"),
    }
}

#[test]
fn a_delete_rename_write_or_truncating_open_after_a_read_open_is_not_absorbed() {
    for destructive in ["delete", "rename", "write", "truncate"] {
        let dir = tmp(&format!("canary-destructive-{destructive}"));
        let (sink, canary) = sink_watching_canary(&dir);
        let pid = std::process::id() + 1;
        sink.on_event(event_by(&canary, pid, None, 5, "read"));
        sink.on_event(event_by(&canary, pid, None, 6, destructive));
        assert_eq!(
            canary_alert_count(&dir),
            2,
            "{destructive} must not hide behind the read open"
        );
        assert_eq!(sink.canary.hits_absorbed(), 0);
    }
}

#[test]
fn repeated_destructive_touches_each_raise_a_detection() {
    let dir = tmp("canary-repeat-delete");
    let (sink, canary) = sink_watching_canary(&dir);
    let pid = std::process::id() + 1;
    for t in 0..3 {
        sink.on_event(event_by(&canary, pid, None, 5 + t, "rename"));
    }
    assert_eq!(canary_alert_count(&dir), 3);
}

#[test]
fn a_process_that_reuses_the_pid_is_not_absorbed_as_its_predecessor() {
    let dir = tmp("canary-pid-reuse");
    let (sink, canary) = sink_watching_canary(&dir);
    let pid = std::process::id() + 1;
    sink.on_event(event_by(&canary, pid, Some(7), 5, "read"));
    sink.on_event(event_by(&canary, pid, Some(7), 6, "read"));
    assert_eq!(canary_alert_count(&dir), 1, "same incarnation: absorbed");
    sink.on_event(event_by(&canary, pid, Some(8), 7, "read"));
    assert_eq!(canary_alert_count(&dir), 2, "new incarnation: reported");
}

#[test]
fn a_second_process_touching_the_same_canary_is_not_absorbed() {
    let dir = tmp("canary-two-pids");
    let (sink, canary) = sink_watching_canary(&dir);
    let pid = std::process::id() + 1;
    sink.on_event(open_event_at(&canary, pid, 5));
    sink.on_event(open_event_at(&canary, pid + 1, 6));
    assert_eq!(canary_alert_count(&dir), 2);
}

#[test]
fn an_allowed_executable_touching_a_canary_is_not_a_detection() {
    let dir = tmp("canary-allowed");
    let (sink, canary) = sink_watching_canary(&dir);
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/updatedb",
        |_| Some("/usr/bin/updatedb".into()),
    ));
    sink.on_event(open_event(&canary, std::process::id() + 1));
    assert_eq!(canary_alert_count(&dir), 0);
}

#[test]
fn an_exec_is_recorded_only_when_an_executable_may_be_allowed() {
    let pid = std::process::id() + 1;
    let record = |sink: &DetectionSink| {
        let mut exec = schema::fixtures::exec();
        exec.meta.pid = pid;
        exec.meta.process_generation = Some(3);
        exec.image_path = "/usr/bin/updatedb".into();
        sink.on_event(Event::Exec(exec));
        sink.canary.exec_image_of(pid, Some(3))
    };
    let dir = tmp("exec-record-none");
    let (sink, _canary) = sink_watching_canary(&dir);
    assert!(record(&sink).is_none(), "no allow list: nothing recorded");
    let dir = tmp("exec-record-empty");
    let (sink, _canary) = sink_watching_canary(&dir);
    // What a host with `[deception]` but no `allow_exe` has: an allow list, empty.
    sink.set_canary_allow(crate::deception::CanaryAllow::new(
        &config::DeceptionConfig::default(),
    ));
    assert!(
        record(&sink).is_none(),
        "an empty allow list: nothing recorded"
    );
    let dir = tmp("exec-record-listed");
    let (sink, _canary) = sink_watching_canary(&dir);
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/updatedb",
        |_| None,
    ));
    assert!(record(&sink).is_some(), "an allow list: recorded");
}

#[test]
fn a_process_seen_to_exec_an_allowed_image_may_touch_a_canary_without_proc() {
    let dir = tmp("canary-exec-image");
    let (sink, canary) = sink_watching_canary(&dir);
    // The /proc fallback resolves nothing: only the Exec the sink saw can allow.
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/updatedb",
        |_| None,
    ));
    let pid = std::process::id() + 1;
    let mut exec = schema::fixtures::exec();
    exec.meta.pid = pid;
    exec.meta.process_generation = Some(3);
    exec.image_path = "/usr/bin/updatedb".into();
    sink.on_event(Event::Exec(exec));
    let mut open = schema::fixtures::file_open();
    open.path = canary.clone();
    open.meta.pid = pid;
    open.meta.process_generation = Some(3);
    sink.on_event(Event::FileOpen(open));
    assert_eq!(
        canary_alert_count(&dir),
        0,
        "an allowed image raises no hit"
    );

    // The same pid, another incarnation that never exec'd: not allowed.
    let mut other = schema::fixtures::file_open();
    other.path = canary;
    other.meta.pid = pid;
    other.meta.process_generation = Some(4);
    let other_ts = other.meta.timestamp_ns;
    sink.on_event(Event::FileOpen(other));
    // No Exec was seen for this incarnation: the touch is held, then raised.
    sink.on_event(tick_at(other_ts + CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 1, "a recycled pid raises the hit");
}

/// A canary open by `pid` (incarnation `generation`) at event time `ts`.
fn canary_touch(canary: &str, pid: u32, generation: u64, ts: u64) -> Event {
    let Event::FileOpen(mut e) = open_event_at(canary, pid, ts) else {
        unreachable!()
    };
    e.meta.process_generation = Some(generation);
    Event::FileOpen(e)
}

fn exec_of(image: &str, pid: u32, generation: u64, ts: u64) -> Event {
    let mut exec = schema::fixtures::exec();
    exec.meta.pid = pid;
    exec.meta.process_generation = Some(generation);
    exec.meta.timestamp_ns = ts;
    exec.image_path = image.into();
    Event::Exec(exec)
}

/// Any event that is not a canary touch, at event time `ts`: it moves the sink's clock.
fn tick_at(ts: u64) -> Event {
    open_event_at("/not/a/canary", 1, ts)
}

fn sink_allowing_tar(name: &str) -> (Arc<DetectionSink>, String, std::path::PathBuf) {
    let dir = tmp(name);
    let (sink, canary) = sink_watching_canary(&dir);
    // The `/proc` fallback resolves nothing, as for a process that already exited.
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/tar",
        |_| None,
    ));
    (sink, canary, dir)
}

#[test]
fn a_touch_that_arrives_before_the_exec_of_an_allowed_image_is_not_a_detection() {
    // The sensor stamps the exec before the open, but the merged stream can deliver the
    // open first (cron's `bash` then `tar`, #81): the decision waits for the exec.
    let (sink, canary, dir) = sink_allowing_tar("canary-before-exec-allowed");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    assert_eq!(canary_alert_count(&dir), 0, "held, not raised yet");
    sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
    assert_eq!(
        canary_alert_count(&dir),
        0,
        "the exec shows an allowed image"
    );
    sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
    assert_eq!(
        canary_alert_count(&dir),
        0,
        "and it is not raised later either"
    );
}

#[test]
fn a_touch_that_arrives_before_the_exec_of_another_image_is_raised_when_the_hold_ends() {
    let (sink, canary, dir) = sink_allowing_tar("canary-before-exec-other");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    sink.on_event(exec_of("/usr/bin/cat", pid, 3, 9_000));
    assert_eq!(
        canary_alert_count(&dir),
        0,
        "a later exec may still be the allowed one"
    );
    sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
    assert_eq!(
        canary_alert_count(&dir),
        1,
        "a listed name on another image is no excuse"
    );
}

#[test]
fn a_touch_before_a_two_step_exec_is_judged_by_the_last_image() {
    // `bash -c "tar ..."` is one pid that execs `bash`, then `tar`: the first image must
    // not settle the touch (the lab run of cron's job, #81).
    let (sink, canary, dir) = sink_allowing_tar("canary-before-two-step-exec");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    sink.on_event(exec_of("/usr/bin/bash", pid, 3, 8_000));
    sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
    sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 0);
}

#[test]
fn a_touch_between_the_two_execs_of_one_pid_is_judged_by_the_last_image() {
    // The first exec is recorded when the touch arrives, the second is still on its way.
    let (sink, canary, dir) = sink_allowing_tar("canary-between-two-execs");
    let pid = std::process::id() + 1;
    sink.on_event(exec_of("/usr/bin/bash", pid, 3, 8_000));
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    assert_eq!(
        canary_alert_count(&dir),
        0,
        "held, not raised on the first image"
    );
    sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
    sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 0);
}

#[test]
fn a_touch_whose_exec_never_comes_is_raised_once_the_hold_has_passed() {
    let (sink, canary, dir) = sink_allowing_tar("canary-hold-expires");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS - 1));
    assert_eq!(canary_alert_count(&dir), 0, "inside the hold");
    sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 1, "the hold is bounded");
    assert_eq!(
        sink.canary.hold_expired(),
        1,
        "a hold that ended with no exec is counted"
    );
    sink.on_event(tick_at(10_000 + 3 * CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 1, "raised once");
}

#[test]
fn an_exec_without_a_generation_does_not_resolve_a_held_touch() {
    // A sensor that does not stamp the generation: the touch and the exec both carry
    // `None`; `None == None` must not let the exec excuse the touch (a recycled pid).
    let (sink, canary, dir) = sink_allowing_tar("canary-hold-no-generation");
    let pid = std::process::id() + 1;
    let Event::FileOpen(mut open) = canary_touch(&canary, pid, 3, 10_000) else {
        unreachable!()
    };
    open.meta.process_generation = None;
    sink.on_event(Event::FileOpen(open));
    let Event::Exec(mut exec) = exec_of("/usr/bin/tar", pid, 3, 10_500) else {
        unreachable!()
    };
    exec.meta.process_generation = None;
    sink.on_event(Event::Exec(exec));
    sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
    assert_eq!(
        canary_alert_count(&dir),
        1,
        "no generation on the exec: the touch is judged when the hold ends"
    );
}

#[test]
fn an_allowed_exec_after_the_touch_does_not_excuse_it() {
    // `/tmp/evil` opens a canary, then execs an allowed `tar` that exits at once: the touch
    // was made by the first image, not by `tar` (#81 review).
    for prior in [None, Some("/usr/bin/cat")] {
        let (sink, canary, dir) = sink_allowing_tar("canary-exec-after-touch");
        let pid = std::process::id() + 1;
        if let Some(image) = prior {
            sink.on_event(exec_of(image, pid, 3, 8_000));
        }
        sink.on_event(canary_touch(&canary, pid, 3, 10_000));
        sink.on_event(exec_of("/usr/bin/tar", pid, 3, 11_000));
        sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
        assert_eq!(
            canary_alert_count(&dir),
            1,
            "an exec after the touch excuses nothing (prior exec: {prior:?})"
        );
    }
}

#[test]
fn an_allowed_exec_delivered_before_a_touch_it_follows_in_time_does_not_excuse_it() {
    // The merged stream can deliver the exec first, too: its time is what counts.
    let (sink, canary, dir) = sink_allowing_tar("canary-exec-after-touch-early");
    let pid = std::process::id() + 1;
    sink.on_event(exec_of("/usr/bin/tar", pid, 3, 11_000));
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 1);
}

#[test]
fn an_exec_at_the_time_of_the_touch_may_excuse_it() {
    let (sink, canary, dir) = sink_allowing_tar("canary-exec-same-time");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    sink.on_event(exec_of("/usr/bin/tar", pid, 3, 10_000));
    sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 0);
}

#[test]
fn a_held_touch_is_judged_on_the_last_exec_before_it_not_on_a_later_one() {
    // bash, then tar, both before the touch's time; a later `cat` is not what touched.
    let (sink, canary, dir) = sink_allowing_tar("canary-hold-latest-qualifying");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    sink.on_event(exec_of("/usr/bin/bash", pid, 3, 8_000));
    sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
    sink.on_event(exec_of("/usr/bin/cat", pid, 3, 11_000));
    sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 0);
}

#[test]
fn an_empty_allow_list_raises_a_touch_at_once() {
    let dir = tmp("canary-empty-allow");
    let (sink, canary) = sink_watching_canary(&dir);
    sink.set_canary_allow(crate::deception::CanaryAllow::new(
        &config::DeceptionConfig::default(),
    ));
    sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
    assert_eq!(canary_alert_count(&dir), 1, "nothing to wait for");
}

#[test]
fn a_process_in_another_mount_namespace_is_raised_at_once() {
    // `allows` refuses it whatever exec arrives, so holding it only delays the finding.
    let dir = tmp("canary-foreign-ns");
    let (sink, canary) = sink_watching_canary(&dir);
    sink.set_canary_allow(
        crate::deception::CanaryAllow::for_test("/usr/bin/tar", |_| None)
            .in_foreign_mount_ns_for_test(),
    );
    sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
    assert_eq!(canary_alert_count(&dir), 1, "not held");
}

#[test]
fn only_the_touch_stream_expires_the_hold() {
    // A poller on its own thread and clock must not end the hold before the exec can arrive.
    let (sink, canary, dir) = sink_allowing_tar("canary-hold-other-streams");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    let mut connect = schema::fixtures::connect();
    connect.meta.timestamp_ns = 10_000 + 2 * CANARY_EXEC_HOLD_NS;
    sink.on_event(Event::Connect(connect));
    assert_eq!(canary_alert_count(&dir), 0, "still held");
    sink.on_event(exec_of("/usr/bin/tar", pid, 3, 9_000));
    sink.on_event(tick_at(10_000 + 2 * CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 0, "the exec arrived in time");
}

#[test]
fn the_reflex_does_not_kill_from_a_touch_judged_after_the_hold() {
    // `/proc` was empty when the touch was held: by now the pid may be someone else's.
    let dir = tmp("reflex-held-touch");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/tar",
        |_| None,
    ));
    burst(&sink, 900);
    let touch_at = BURST_END_NS + 1_000_000;
    sink.on_event(canary_open_at(&canary, 900, touch_at));
    sink.on_event(tick_at(touch_at + CANARY_EXEC_HOLD_NS));
    assert!(
        alerts_in(&dir).contains("canary file touched"),
        "the touch is still a finding"
    );
    assert!(killed.lock().unwrap().is_empty(), "but nothing is killed");
}

#[test]
fn the_exec_of_another_incarnation_does_not_resolve_a_held_touch() {
    let (sink, canary, dir) = sink_allowing_tar("canary-hold-other-incarnation");
    let pid = std::process::id() + 1;
    sink.on_event(canary_touch(&canary, pid, 3, 10_000));
    // A recycled pid's later life exec'ing an allowed image says nothing about the toucher.
    sink.on_event(exec_of("/usr/bin/tar", pid, 4, 10_500));
    sink.on_event(tick_at(10_000 + CANARY_EXEC_HOLD_NS));
    assert_eq!(canary_alert_count(&dir), 1);
}

#[test]
fn a_full_hold_queue_raises_the_touch_instead_of_holding_it() {
    let (sink, canary, dir) = sink_allowing_tar("canary-hold-full");
    let first = std::process::id() + 1;
    for i in 0..MAX_HELD_CANARY_TOUCHES as u32 {
        sink.on_event(canary_touch(&canary, first + i, 3, 10_000));
    }
    assert_eq!(
        canary_alert_count(&dir),
        0,
        "every touch within the bound is held"
    );
    let overflow = first + MAX_HELD_CANARY_TOUCHES as u32;
    sink.on_event(canary_touch(&canary, overflow, 3, 10_000));
    assert_eq!(
        canary_alert_count(&dir),
        1,
        "beyond the bound it is raised at once"
    );
    assert_eq!(
        sink.canary.hold_overflow(),
        1,
        "and the overflow is counted"
    );
}

#[test]
fn a_process_that_proc_shows_running_another_image_is_raised_at_once() {
    // `/proc` is an answer, not a gap: nothing to wait for.
    let dir = tmp("canary-proc-other-image");
    let (sink, canary) = sink_watching_canary(&dir);
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/tar",
        |_| Some("/usr/bin/cat".into()),
    ));
    sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
    assert_eq!(canary_alert_count(&dir), 1);
}

#[test]
fn without_an_allow_list_a_touch_is_raised_at_once() {
    let dir = tmp("canary-no-allow-no-hold");
    let (sink, canary) = sink_watching_canary(&dir);
    sink.on_event(canary_touch(&canary, std::process::id() + 1, 3, 10_000));
    assert_eq!(canary_alert_count(&dir), 1);
}

#[test]
fn planting_canary_mtime_does_not_trip_the_agent_or_hide_a_real_touch() {
    let dir = tmp("canary-own-pid");
    let (sink, canary) = sink_watching_canary(&dir);
    let modified = std::fs::metadata(&canary).unwrap().modified().unwrap();
    assert!(modified < std::time::SystemTime::now());

    sink.on_event(open_event(&canary, std::process::id()));
    assert!(!alerts_in(&dir).contains("canary file touched"));

    sink.on_event(open_event(&canary, std::process::id() + 1));
    assert!(alerts_in(&dir).contains("canary file touched"));
}

#[test]
fn an_ordinary_path_is_not_a_canary_hit() {
    let dir = tmp("canary-miss");
    let (sink, _canary) = sink_watching_canary(&dir);
    sink.on_event(open_event("/etc/hostname", std::process::id() + 1));
    assert!(!alerts_in(&dir).contains("canary file touched"));
}

#[test]
fn without_tripwires_a_canary_looking_path_is_ordinary() {
    let dir = tmp("canary-off");
    let sink = sink_in(&dir);
    sink.on_event(open_event("/srv/passwords_00000000.txt", 1));
    assert!(!alerts_in(&dir).contains("canary file touched"));
}

/// The YARA scan runs on its own thread; wait for its response line.
fn wait_for_alert(dir: &std::path::Path, technique: &str) -> String {
    for _ in 0..200 {
        let alerts = alerts_in(dir);
        if alerts.contains(technique) {
            return alerts;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("no {technique} within 10s: {}", alerts_in(dir));
}

#[test]
fn a_beacon_with_a_dropped_payload_is_killed_and_quarantined_and_both_are_audited() {
    let dir = tmp("response-enforce");
    let (payload, killed) = run_response_scenario(
        &dir,
        policy::ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: true,
            isolate_enabled: false,
        },
    );
    let alerts = wait_for_alert(&dir, "RESPONSE-QUARANTINE");

    // Killed, audited.
    assert_killed_exactly(
        &killed,
        &dir,
        6262,
        "the injected terminate runs, exactly once",
    );
    assert!(alerts.contains("RESPONSE-KILL"), "{alerts}");
    assert!(alerts.contains("killed pid 6262"), "{alerts}");
    // Quarantined, audited.
    assert!(!payload.exists(), "the payload must have been moved");
    assert!(alerts.contains("quarantined"), "{alerts}");
    assert!(!alerts.contains("observe-only"), "policy is on: {alerts}");

    // And reversible from what the audit trail and the directory record.
    let listed = response::list_quarantined(&dir.join("quarantine")).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].original, payload);
    response::unquarantine(&dir.join("quarantine"), &listed[0].sha256_hex).unwrap();
    assert_eq!(
        std::fs::read(&payload).unwrap(),
        b"dropped payload RESPONSE-SCENARIO-MARKER"
    );
}

#[test]
fn the_same_beacon_and_payload_with_policy_off_kill_nothing_and_move_nothing() {
    let dir = tmp("response-observe");
    let (payload, killed) = run_response_scenario(&dir, policy::ResponsePolicy::default());
    let alerts = wait_for_alert(&dir, "RESPONSE-QUARANTINE");

    assert!(
        killed.lock().unwrap().is_empty(),
        "terminate must never run"
    );
    assert!(payload.exists(), "the payload must stay where it was");
    assert!(
        !dir.join("quarantine").exists(),
        "nothing may be quarantined"
    );
    // Both would-have-acted decisions are still audited, as observe-only.
    let observe_only: Vec<_> = alerts
        .lines()
        .filter(|l| l.contains("RESPONSE-") && l.contains("observe-only"))
        .collect();
    assert_eq!(observe_only.len(), 2, "one per action: {alerts}");
    assert!(alerts.contains("RESPONSE-KILL"), "{alerts}");
}

/// #594: a write whose user the sensor could not resolve is not scanned at all, not
/// read with the agent's own privileges. The control event after it proves the
/// queue and the rule work, so the single scan is the root one.
#[cfg(unix)]
#[test]
fn a_write_by_an_unresolved_user_is_not_scanned_on_unix() {
    let dir = tmp("yara-unknown-user");
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();
    let sink = sink_in(&dir);
    assert_eq!(sink.reload_content().yara_rule_count, Some(1));
    let write_as = |user: schema::User| {
        sink.on_event(Event::FileOpen(schema::FileOpenEvent {
            meta: EventMeta {
                user,
                ..schema::fixtures::meta()
            },
            path: payload.display().to_string(),
            flags: 0o101,
        }));
    };

    write_as(schema::User::Unknown);
    write_as(schema::User::Unix { uid: 0, gid: 0 });
    wait_for_alert(&dir, "YARA");
    std::thread::sleep(std::time::Duration::from_millis(600));
    let stats = sink.yara.lock().unwrap().as_ref().unwrap().0.stats();
    assert_eq!(
        stats.scanned, 1,
        "only the root write is scanned, the unresolved one never reaches the queue"
    );
}

#[test]
fn a_payload_already_in_quarantine_is_left_alone() {
    // The quarantine write is itself a file event the sensor sees; matching it
    // again must not quarantine the file into itself.
    let (dir, hooks, log, payload) = quarantine_fixture("quarantine-loop", true);
    super::quarantine_matched_payload(&hooks, &payload, &log);
    let before = std::fs::read_dir(dir.join("quarantine")).unwrap().count();
    let quarantined = std::fs::read_dir(dir.join("quarantine"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_none())
        .unwrap();
    super::quarantine_matched_payload(&hooks, &quarantined, &log);
    assert!(quarantined.exists());
    assert_eq!(
        std::fs::read_dir(dir.join("quarantine")).unwrap().count(),
        before
    );
}

fn exec(pid: u32, cmdline: &str, image_path: &str) -> Event {
    Event::Exec(ExecEvent {
        meta: EventMeta {
            pid,
            ppid: 1,
            user: User::Unix {
                uid: 1000,
                gid: 1000,
            },
            comm: "bash".into(),
            ..schema::fixtures::meta()
        },
        image_path: image_path.into(),
        cmdline: cmdline.into(),
        ..schema::fixtures::exec()
    })
}

/// The BAYES recipe from `correlator`'s own tests: a suspicious-path exec
/// plus repeated connects to a public address crosses the belief threshold.
fn drive_bayes_crossing(sink: &DetectionSink, pid: u32) {
    drive_bayes_crossing_from(sink, pid, "C:\\Users\\solka\\AppData\\Roaming\\malware.exe");
}

/// [`drive_bayes_crossing`] for an exec of `image_path`: the same connects to a
/// public address, so what differs between two runs is only where the binary lives.
fn drive_bayes_crossing_from(sink: &DetectionSink, pid: u32, image_path: &str) {
    sink.on_event(exec(pid, "malware.exe", image_path));
    drive_bayes_connects(sink, pid);
}

/// The connects of [`drive_bayes_crossing_from`], for a pid whose exec the test
/// sends itself.
fn drive_bayes_connects(sink: &DetectionSink, pid: u32) {
    for i in 0..25u64 {
        sink.on_event(Event::Connect(ConnectEvent {
            meta: EventMeta {
                pid,
                timestamp_ns: (i + 1) * 100_000_000,
                ..schema::fixtures::meta()
            },
            daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(185, 220, 101, 1)),
            dport: 4444,
        }));
    }
}

/// EGRESS-DOMAIN (#380) crosses two event kinds: the lookup is a `DnsQuery`, which the sink
/// must hand to the rule state (it did not before), and the volume is a `NetworkFlow`.
#[test]
fn a_dns_lookup_and_the_flow_that_follows_raise_egress_domain_in_the_alert_log() {
    let dir = tmp("egress-domain");
    let sink = sink_in(&dir);
    let pid = 4242;
    let meta_at = |ns: u64| EventMeta {
        pid,
        comm: "curl".to_string(),
        timestamp_ns: ns,
        ..schema::fixtures::meta()
    };
    sink.on_event(Event::DnsQuery(schema::DnsQueryEvent {
        meta: meta_at(0),
        query: "pastebin.com".to_string(),
        result: Some("203.0.113.9".to_string()),
        status: 0,
        ..schema::fixtures::dns_query()
    }));
    for (i, sent) in [0u64, 30 * 1024 * 1024].into_iter().enumerate() {
        sink.on_event(Event::NetworkFlow(schema::NetworkFlowEvent {
            meta: meta_at((i as u64 + 1) * 1_000_000_000),
            local_port: 50000,
            daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
            dport: 443,
            protocol: 6,
            bytes_sent: Some(sent),
            ..schema::fixtures::network_flow()
        }));
    }
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("T1567.003"),
        "the lookup must reach the rule state and join the flow, got: {alerts}"
    );
}

#[test]
fn exec_rule_alert_reaches_the_alert_log() {
    let dir = tmp("rule-alert");
    let sink = sink_in(&dir);
    sink.on_event(exec(
        42,
        "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
        "/bin/bash",
    ));
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("T1059.004"),
        "base64-decode rule must land in alerts.ndjson, got: {alerts}"
    );
}

/// Issue #131/PR #502 review point 3: verdict fusion's own dedup (bounded
/// evidence, one composed severity per entity — see `crates/verdict`'s own
/// tests, e.g. `the_same_technique_from_a_second_engine_within_the_window_is_one_finding`)
/// must never mean a finding disappears from `alerts.ndjson` — that file is
/// the audit trail, and every finding lands there regardless of whether
/// fusion also folded it into the entity's already-live verdict.
#[test]
fn repeated_identical_exec_alerts_each_still_reach_the_alert_log() {
    let dir = tmp("verdict-dedup");
    let sink = sink_in(&dir);
    let ev = exec(
        50,
        "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
        "/bin/bash",
    );
    sink.on_event(ev.clone());
    sink.on_event(ev);
    let alerts = alerts_in(&dir);
    assert_eq!(
        alerts.matches("T1059.004").count(),
        2,
        "verdict fusion dedups its own entity state, but alerts.ndjson is \
         the audit trail — every occurrence must still land there: {alerts}"
    );
}

/// The flip side of the dedup test: fusion is scoped per entity
/// (`(ppid, comm)`) — a different entity raising the identical technique
/// must still get its own finding, not be silently absorbed by the first
/// entity's state.
#[test]
fn the_same_technique_on_a_different_entity_still_alerts() {
    let dir = tmp("verdict-cross-entity");
    let sink = sink_in(&dir);
    sink.on_event(exec(
        60,
        "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
        "/bin/bash",
    ));
    let mut other = exec(
        61,
        "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
        "/bin/bash",
    );
    if let Event::Exec(e) = &mut other {
        e.meta.ppid = 2;
        e.meta.comm = "sh".into();
    }
    sink.on_event(other);
    let alerts = alerts_in(&dir);
    assert_eq!(
        alerts.matches("T1059.004").count(),
        2,
        "a distinct entity must get its own finding: {alerts}"
    );
}

#[test]
fn progress_advances_once_per_fully_processed_event() {
    let dir = tmp("progress");
    let sink = sink_in(&dir);
    let progress = sink.progress_handle();
    assert_eq!(progress.load(Ordering::Relaxed), 0);
    for i in 0..5 {
        sink.on_event(exec(100 + i, "ls", "/bin/ls"));
    }
    assert_eq!(
        progress.load(Ordering::Relaxed),
        5,
        "#102: real progress, one per event"
    );
}

#[test]
fn bayes_crossing_without_response_hooks_alerts_but_never_kills() {
    let dir = tmp("bayes-observe");
    let sink = sink_in(&dir);
    drive_bayes_crossing(&sink, 4242);
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("BAYES"),
        "belief crossing must alert: {alerts}"
    );
    assert!(
        !alerts.contains("RESPONSE-KILL"),
        "no enable_response call means response stays entirely silent"
    );
}

#[test]
fn bayes_crossing_with_kill_disabled_reports_observe_only() {
    let dir = tmp("bayes-disabled");
    let sink = sink_in(&dir);
    let killed = Arc::new(Mutex::new(Vec::new()));
    let killed_rec = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        move |pid| {
            killed_rec.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );
    drive_bayes_crossing(&sink, 4243);
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("RESPONSE-KILL"),
        "response path must report: {alerts}"
    );
    assert!(
        alerts.contains("observe-only"),
        "policy-off means observe-only: {alerts}"
    );
    assert!(
        killed.lock().unwrap().is_empty(),
        "terminate must never run with kill disabled"
    );
}

#[test]
fn bayes_crossing_with_kill_enabled_calls_terminate_on_the_verdict_pid() {
    let dir = tmp("bayes-kill");
    let sink = sink_in(&dir);
    let killed = Arc::new(Mutex::new(Vec::new()));
    let killed_rec = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        move |pid| {
            killed_rec.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );
    drive_bayes_crossing(&sink, 4244);
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("killed pid 4244"),
        "kill outcome must be recorded in alerts: {alerts}"
    );
    assert_killed_exactly(
        &killed,
        &dir,
        4244,
        "the injected terminate runs, exactly once",
    );
}

#[test]
fn enable_response_twice_keeps_the_first_policy() {
    let dir = tmp("bayes-enable-twice");
    let sink = sink_in(&dir);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        |_| panic!("kill is disabled by the first policy"),
        dir.join("quarantine"),
    );
    let killed = enable_recording_kill(&sink, &dir);
    drive_bayes_crossing(&sink, 4245);
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("pid 4245 would have been killed"),
        "the first (observe-only) policy stays in force: {alerts}"
    );
    assert!(
        killed.lock().unwrap().is_empty(),
        "the second call's terminate must never run"
    );
}

fn enable_recording_kill(sink: &DetectionSink, dir: &std::path::Path) -> Arc<Mutex<Vec<u32>>> {
    let killed = Arc::new(Mutex::new(Vec::new()));
    let killed_rec = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        move |pid| {
            killed_rec.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );
    killed
}

/// Issue #652: `NetworkManager` crossed `BAYES` on a stock Fedora host with no rule or
/// YARA hit and was killed. A package binary started by init is a system service's
/// main process: the crossing still raises its alert, but the kill is refused.
#[test]
fn a_system_service_crossing_bayes_is_refused_not_killed() {
    let dir = tmp("bayes-service");
    let sink = sink_in(&dir);
    let killed = enable_recording_kill(&sink, &dir);
    drive_bayes_crossing_from(&sink, 6001, "/usr/sbin/NetworkManager");
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("BAYES"),
        "the recipe must still cross the belief threshold: {alerts}"
    );
    assert!(
        alerts.contains("refused to kill pid 6001"),
        "the refusal must be audited: {alerts}"
    );
    assert!(
        killed.lock().unwrap().is_empty(),
        "a service's main process must never reach terminate on BAYES alone"
    );
}

/// The control for the test above: identical behaviour from a binary in `/tmp`
/// (the implant's provenance) is killed, as before.
#[test]
fn the_same_crossing_from_a_tmp_binary_is_still_killed() {
    let dir = tmp("bayes-tmp");
    let sink = sink_in(&dir);
    let killed = enable_recording_kill(&sink, &dir);
    drive_bayes_crossing_from(&sink, 6002, "/tmp/NetworkManager");
    assert_killed_exactly(
        &killed,
        &dir,
        6002,
        "the injected terminate runs, exactly once",
    );
}

/// Execs the `sshd-session` that holds one login under the `sshd` listener, as on
/// Alpine (<https://github.com/synthaea-lab/agent/issues/50>). The listener's own exec is not sent: it started at boot, before
/// the agent, so only its image (resolved by the sensor) is known.
fn exec_ssh_login(sink: &DetectionSink, listener: u32, session: u32) {
    exec_under_sshd_listener(
        sink,
        listener,
        session,
        "sshd-session",
        "/usr/lib/ssh/sshd-session",
    );
}

/// Execs the `sshd` the listener re-execs (`sshd -R`) for one login before
/// OpenSSH 9.8, as on Debian 12 (<https://github.com/synthaea-lab/agent/issues/50>, 2026-11-08 lab run).
fn exec_reexecd_sshd_login(sink: &DetectionSink, listener: u32, session: u32) {
    exec_under_sshd_listener(sink, listener, session, "sshd -R", "/usr/sbin/sshd");
}

/// Execs `image` as `pid` under the `sshd` listener, whose image the sensor resolved.
fn exec_under_sshd_listener(
    sink: &DetectionSink,
    listener: u32,
    pid: u32,
    cmdline: &str,
    image: &str,
) {
    let Event::Exec(mut e) = exec(pid, cmdline, image) else {
        unreachable!("exec() builds an Exec event");
    };
    e.meta.ppid = listener;
    e.parent_image_path = Some("/usr/sbin/sshd".into());
    sink.on_event(Event::Exec(e));
}

/// <https://github.com/synthaea-lab/agent/issues/50>: on a stock Alpine VM, BAYES named the `sshd-session` of an
/// interactive SSH login as a kill target; with kill enabled the agent would cut
/// the operator's session. It is refused like a service main, and audited as such.
#[test]
fn an_ssh_login_session_crossing_bayes_is_refused_not_killed() {
    let dir = tmp("bayes-sshd-session");
    let sink = sink_in(&dir);
    let killed = enable_recording_kill(&sink, &dir);
    exec_ssh_login(&sink, 6100, 6101);
    drive_bayes_connects(&sink, 6101);
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("BAYES"), "{alerts}");
    assert!(
        alerts.contains("refused to kill pid 6101") && alerts.contains("holds a login session"),
        "the refusal must be audited with its reason: {alerts}"
    );
    assert!(killed.lock().unwrap().is_empty());
}

/// <https://github.com/synthaea-lab/agent/issues/50>, lab run on Debian 12 (OpenSSH 9.2): no `sshd-session` there, the
/// listener re-execs `/usr/sbin/sshd`, and BAYES named that `comm=sshd` session.
#[test]
fn an_sshd_reexecd_for_a_login_crossing_bayes_is_refused_not_killed() {
    let dir = tmp("bayes-sshd-reexec");
    let sink = sink_in(&dir);
    let killed = enable_recording_kill(&sink, &dir);
    exec_reexecd_sshd_login(&sink, 6120, 6121);
    drive_bayes_connects(&sink, 6121);
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("BAYES"), "{alerts}");
    assert!(
        alerts.contains("refused to kill pid 6121") && alerts.contains("holds a login session"),
        "the refusal must be audited with its reason: {alerts}"
    );
    assert!(killed.lock().unwrap().is_empty());
}

/// The control for the pre-9.8 shape: a shell under the re-exec'd `sshd` is still
/// killed.
#[test]
fn a_shell_inside_a_reexecd_sshd_login_crossing_bayes_is_still_killed() {
    let dir = tmp("bayes-sshd-reexec-shell");
    let sink = sink_in(&dir);
    let killed = enable_recording_kill(&sink, &dir);
    exec_reexecd_sshd_login(&sink, 6130, 6131);
    let Event::Exec(mut shell) = exec(6132, "bash", "/bin/bash") else {
        unreachable!("exec() builds an Exec event");
    };
    shell.meta.ppid = 6131;
    shell.parent_image_path = Some("/usr/sbin/sshd".into());
    sink.on_event(Event::Exec(shell));
    drive_bayes_connects(&sink, 6132);
    assert_killed_exactly(
        &killed,
        &dir,
        6132,
        "the injected terminate runs, exactly once",
    );
}

/// The real `sshd` binary started from a user's shell is not a login session: it
/// crosses BAYES and is killed like anything else.
#[test]
fn an_sshd_started_from_a_shell_crossing_bayes_is_still_killed() {
    let dir = tmp("bayes-sshd-from-shell");
    let sink = sink_in(&dir);
    let killed = enable_recording_kill(&sink, &dir);
    let Event::Exec(mut e) = exec(6142, "sshd -R", "/usr/sbin/sshd") else {
        unreachable!("exec() builds an Exec event");
    };
    e.meta.ppid = 6141;
    e.parent_image_path = Some("/bin/bash".into());
    sink.on_event(Event::Exec(e));
    drive_bayes_connects(&sink, 6142);
    assert_killed_exactly(
        &killed,
        &dir,
        6142,
        "the injected terminate runs, exactly once",
    );
}

/// The control: a shell inside that login session crossing BAYES is still killed.
#[test]
fn a_shell_inside_an_ssh_login_crossing_bayes_is_still_killed() {
    let dir = tmp("bayes-ssh-shell");
    let sink = sink_in(&dir);
    let killed = enable_recording_kill(&sink, &dir);
    exec_ssh_login(&sink, 6110, 6111);
    let Event::Exec(mut shell) = exec(6112, "sh", "/bin/sh") else {
        unreachable!("exec() builds an Exec event");
    };
    shell.meta.ppid = 6111;
    sink.on_event(Event::Exec(shell));
    drive_bayes_connects(&sink, 6112);
    assert_killed_exactly(
        &killed,
        &dir,
        6112,
        "the injected terminate runs, exactly once",
    );
}

/// Observe-only mode says the truth too: a service is "refused", not "would have
/// been killed" (the line the issue's reporter saw on the Fedora VM).
#[test]
fn observe_mode_reports_a_service_as_refused_not_as_would_be_killed() {
    let dir = tmp("bayes-service-observe");
    let sink = sink_in(&dir);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        |_| panic!("terminate must not be called in observe mode"),
        dir.join("quarantine"),
    );
    drive_bayes_crossing_from(&sink, 6003, "/usr/sbin/NetworkManager");
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("refused to kill pid 6003"), "{alerts}");
    assert!(!alerts.contains("would have been killed"), "{alerts}");
}

/// PR #502 review: `maybe_kill`'s gate must read *this event's own*
/// evidence, not the entity's fused, sticky severity. `drive_bayes_crossing`'s
/// connect events all carry the fixture's neutral, unmodified
/// `(ppid, comm)` (`(0, "")`), so a second, unrelated pid's own connect
/// lands in the *same* verdict entity as the first pid's Bayes crossing —
/// exactly the "sibling process" collision the review found: a plain
/// `T1059/T1071` co-occurrence alert (`Medium`) on its own must never
/// trigger a kill just because that shared entity was earlier raised to
/// `Critical` by someone else's Bayes crossing.
#[test]
fn a_siblings_weak_alert_never_triggers_kill_from_anothers_bayes_crossing() {
    let dir = tmp("bayes-sibling");
    let sink = sink_in(&dir);
    let killed = Arc::new(Mutex::new(Vec::new()));
    let killed_rec = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        move |pid| {
            killed_rec.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );

    // pid 5001 crosses Bayes — raises the shared `(0, "")` verdict entity
    // to `Critical` and gets killed, exactly as before.
    drive_bayes_crossing(&sink, 5001);

    // pid 5002: one exec, one connect 40s later — outside
    // VERDICT_DEDUP_WINDOW_NS (30s), so this produces a genuine fresh
    // verdict for the shared entity, not a silently-absorbed duplicate.
    // Correlator's own window is 60s, so the co-occurrence rule still
    // fires: a plain, weak `T1059/T1071` finding, nothing Bayesian.
    sink.on_event(exec(5002, "bash -c true", "/bin/bash"));
    sink.on_event(Event::Connect(ConnectEvent {
        meta: EventMeta {
            pid: 5002,
            timestamp_ns: 40_000_000_000,
            ..schema::fixtures::meta()
        },
        daddr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
        dport: 443,
    }));

    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("T1059/T1071"),
        "the sibling's weak co-occurrence finding must still alert: {alerts}"
    );
    assert_killed_exactly(
        &killed,
        &dir,
        5001,
        "only the pid that actually crossed Bayes may be killed — the sibling's own weak \
         finding must not ride the shared entity's sticky severity to a kill",
    );
}

#[test]
fn events_and_spool_receive_the_raw_event_via_the_enrich_worker() {
    let dir = tmp("spool");
    let spool_dir = dir.join("spool");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&spool_dir, u64::MAX).unwrap(),
    ));
    let sink = Arc::new(
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            Some(Arc::clone(&spool)),
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap(),
    );
    sink.on_event(exec(7, "ls", "/bin/ls"));

    // The raw write and the spool append run on the enrich worker — wait.
    let mut spooled: Vec<Event> = Vec::new();
    for _ in 0..200 {
        spooled = spool.lock().unwrap().drain_oldest().unwrap();
        if !spooled.is_empty() {
            break;
        }
        // Segment may be in-flight from the empty drain — put it back.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(spooled.len(), 1, "the event must reach the transport spool");
    let events_log = std::fs::read_to_string(dir.join("events.jsonl")).unwrap_or_default();
    assert!(
        events_log.contains("/bin/ls"),
        "raw event log written off-thread"
    );
}

// --- tamper-class alerts are counted for the health beacon (#863) ---

fn sink_for_counting(dir: &std::path::Path) -> DetectionSink {
    DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        None,
        None,
        None,
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap()
}

#[test]
fn a_tamper_alert_is_recorded_like_any_alert_and_counted() {
    let dir = tmp("tamper-count");
    let sink = sink_for_counting(&dir);
    assert_eq!(sink.tamper_events(), 0);

    sink.emit_tamper("T1562", "sensor linux-journal went silent");
    sink.emit_tamper("T1601", "binary swapped");

    assert_eq!(sink.tamper_events(), 2);
    let alerts = std::fs::read_to_string(dir.join("alerts.ndjson")).unwrap();
    assert!(alerts.contains("T1562") && alerts.contains("sensor linux-journal went silent"));
    assert!(alerts.contains("T1601") && alerts.contains("binary swapped"));
}

#[test]
fn an_ordinary_alert_is_not_a_tamper_event() {
    let dir = tmp("tamper-not-counted");
    let sink = sink_for_counting(&dir);

    sink.emit("T1059", "command line contains a base64 decode");

    assert_eq!(sink.tamper_events(), 0);
}

#[test]
fn emitted_finding_reaches_the_durable_detection_spool() {
    let dir = tmp("detection-spool");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        Some(&dir.join("events.jsonl")),
        None,
        Some(Arc::clone(&spool)),
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap();
    let event = exec(7, "test", "/bin/test");
    sink.record(
        super::Finding {
            entity: &verdict::EntityKey::new(1, "test"),
            technique: "T1059",
            message: "test finding",
            source: schema::detection::DetectionSource::Rule {
                rule_id: "T1059".into(),
            },
            severity: schema::detection::Severity::Medium,
        },
        &event,
        Vec::new(),
    );
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );
    let records: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].detection.title, "test finding");
    assert_eq!(
        records[0].detection.events,
        vec![with_its_enrichment(&event, &records[0].detection.events)]
    );
    assert_eq!(records[0].key.len(), 36);
}

/// `event` as the spooled detection carries it: the enrichment worker adds the image's hash and
/// signature before the detection is stored (#62), so that the control plane can join hosts
/// on the hash. Everything else of the event must be as it was captured. The hash is asserted
/// present for an image that exists on this machine, and compared as given otherwise.
fn with_its_enrichment(event: &Event, spooled: &[Event]) -> Event {
    let (Event::Exec(captured), Some(Event::Exec(stored))) = (event, spooled.first()) else {
        return event.clone();
    };
    assert!(
        captured.sha256.is_some()
            || stored.sha256.is_some()
            || !std::path::Path::new(&captured.image_path).is_file(),
        "the detection's exec should carry the hash of {}",
        captured.image_path
    );
    let mut expected = captured.clone();
    expected.sha256.clone_from(&stored.sha256);
    expected.signature = stored.signature;
    Event::Exec(expected)
}

fn rename_of(pid: u32, i: u64, to: &str) -> Event {
    Event::FileRename(schema::FileRenameEvent {
        meta: EventMeta {
            pid,
            timestamp_ns: 1_000_000_000 + i * 50_000_000,
            comm: "encryptor".into(),
            ..schema::fixtures::meta()
        },
        old_path: format!("/home/u/doc{i}.txt"),
        new_path: format!("/home/u/doc{i}.txt{to}"),
        ..schema::fixtures::file_rename()
    })
}

fn canary_open_at(path: &str, pid: u32, timestamp_ns: u64) -> Event {
    Event::FileOpen(schema::FileOpenEvent {
        path: path.to_string(),
        meta: EventMeta {
            pid,
            timestamp_ns,
            comm: "encryptor".into(),
            ..schema::fixtures::meta()
        },
        ..schema::fixtures::file_open()
    })
}

/// A sink watching one canary, with kill wired to a recorder.
fn reflex_sink(
    dir: &std::path::Path,
    kill_enabled: bool,
) -> (Arc<DetectionSink>, String, Arc<Mutex<Vec<u32>>>) {
    let (sink, canary) = sink_watching_canary(dir);
    let killed = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        move |pid| {
            recorder.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );
    (sink, canary, killed)
}

fn burst(sink: &DetectionSink, pid: u32) {
    for i in 0..30 {
        sink.on_event(rename_of(pid, i, ".locked"));
    }
}

const BURST_END_NS: u64 = 1_000_000_000 + 30 * 50_000_000;

#[test]
fn a_burst_then_a_canary_touch_by_the_same_process_kills_it() {
    let dir = tmp("reflex-burst-first");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    burst(&sink, 900);
    assert!(
        killed.lock().unwrap().is_empty(),
        "a burst alone never kills"
    );
    sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
    assert_killed_exactly(
        &killed,
        &dir,
        900,
        "the injected terminate runs, exactly once",
    );
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("killed pid 900 on a corroborated ransomware signal"),
        "{alerts}"
    );
    assert!(
        alerts.find("canary file touched").unwrap() < alerts.find("RESPONSE-KILL").unwrap(),
        "the finding is recorded before the kill"
    );
}

#[test]
fn a_canary_touch_then_a_burst_by_the_same_process_kills_it_once() {
    let dir = tmp("reflex-canary-first");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    sink.on_event(canary_open_at(&canary, 900, 1_000_000_000));
    assert!(
        killed.lock().unwrap().is_empty(),
        "a canary touch alone never kills"
    );
    burst(&sink, 900);
    assert_killed_exactly(
        &killed,
        &dir,
        900,
        "the burst keeps raising alerts but the process is killed once",
    );
}

#[test]
fn a_burst_and_a_canary_touch_from_two_processes_kill_neither() {
    let dir = tmp("reflex-two-processes");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    burst(&sink, 900);
    sink.on_event(canary_open_at(&canary, 901, BURST_END_NS + 1_000_000));
    assert!(killed.lock().unwrap().is_empty());
}

#[test]
fn a_canary_touch_long_before_the_burst_does_not_corroborate() {
    let dir = tmp("reflex-stale");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    sink.on_event(canary_open_at(&canary, 900, 1_000_000_000));
    // The same process starts its burst two minutes later.
    for i in 0..30 {
        let Event::FileRename(mut e) = rename_of(900, i, ".locked") else {
            unreachable!()
        };
        e.meta.timestamp_ns += 120_000_000_000;
        sink.on_event(Event::FileRename(e));
    }
    assert!(killed.lock().unwrap().is_empty());
}

#[test]
fn an_allowed_executable_that_also_bursts_is_not_killed_by_the_reflex() {
    let dir = tmp("reflex-allowed");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    // A backup tool: it reads the canaries and rotates archives (a burst of renames).
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/backup-tool",
        |_| Some("/usr/bin/backup-tool".into()),
    ));
    burst(&sink, 900);
    sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
    assert!(
        killed.lock().unwrap().is_empty(),
        "an allowed process never notes a canary signal"
    );
    assert!(!alerts_in(&dir).contains("RESPONSE-KILL"));
}

/// #731 with #722: an allow-listed image recognised from the process's own `Exec` (no
/// `/proc` read) is not killed by the reflex either, even when it bursts and reads a canary.
#[test]
fn a_process_allowed_from_its_exec_that_also_bursts_is_not_killed_by_the_reflex() {
    let dir = tmp("reflex-allowed-by-exec");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/backup-tool",
        |_| None,
    ));
    let mut exec = schema::fixtures::exec();
    exec.meta.pid = 900;
    exec.meta.process_generation = Some(5);
    exec.image_path = "/usr/bin/backup-tool".into();
    sink.on_event(Event::Exec(exec));
    for i in 0..30 {
        let Event::FileRename(mut e) = rename_of(900, i, ".locked") else {
            unreachable!()
        };
        e.meta.process_generation = Some(5);
        sink.on_event(Event::FileRename(e));
    }
    let Event::FileOpen(mut open) = canary_open_at(&canary, 900, BURST_END_NS + 1_000_000) else {
        unreachable!()
    };
    open.meta.process_generation = Some(5);
    sink.on_event(Event::FileOpen(open));
    assert!(killed.lock().unwrap().is_empty());
    assert!(!alerts_in(&dir).contains("RESPONSE-KILL"));
}

#[test]
fn a_process_that_is_not_on_the_allow_list_is_still_killed_when_a_list_exists() {
    let dir = tmp("reflex-not-allowed");
    let (sink, canary, killed) = reflex_sink(&dir, true);
    sink.set_canary_allow(crate::deception::CanaryAllow::for_test(
        "/usr/bin/backup-tool",
        |_| Some("/tmp/encryptor".into()),
    ));
    burst(&sink, 900);
    sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
    assert_killed_exactly(
        &killed,
        &dir,
        900,
        "the injected terminate runs, exactly once",
    );
}

#[test]
fn with_kill_disabled_the_reflex_is_observe_only() {
    let dir = tmp("reflex-observe");
    let (sink, canary, killed) = reflex_sink(&dir, false);
    burst(&sink, 900);
    sink.on_event(canary_open_at(&canary, 900, BURST_END_NS + 1_000_000));
    assert!(killed.lock().unwrap().is_empty());
    let alerts = alerts_in(&dir);
    assert!(
        alerts.contains("pid 900 would have been killed on a corroborated ransomware signal"),
        "{alerts}"
    );
}

/// The ransomware detection (T1486, issue #82) carries the files the process touched
/// in the window, so the case records the scope of the damage.
#[test]
fn a_ransomware_detection_carries_the_files_the_process_renamed_as_a_damage_manifest() {
    let dir = tmp("damage-manifest");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        None,
        None,
        Some(Arc::clone(&spool)),
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap();

    // 30 renames to an encrypted extension by one process, then a different process's
    // rename that must not appear in the manifest.
    for i in 0..30 {
        sink.on_event(rename_of(900, i, ".locked"));
    }
    sink.on_event(rename_of(901, 99, ".bak"));

    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );
    let records: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    let ransomware: Vec<_> = records
        .iter()
        .filter(|r| r.detection.techniques.iter().any(|t| t == "T1486"))
        .collect();
    assert!(
        !ransomware.is_empty(),
        "the burst must raise a T1486 detection"
    );
    let detection = &ransomware[0].detection;

    // First the triggering event, then the earlier renames of the same process.
    assert!(detection.events.len() > 1, "the manifest is attached");
    for event in &detection.events {
        let Event::FileRename(rename) = event else {
            panic!("only renames expected, got {event:?}");
        };
        assert_eq!(
            rename.meta.pid, 900,
            "another process's files are not this one's damage"
        );
    }
    let triggering = detection.events[0].clone();
    assert!(
        !detection.events[1..].contains(&triggering),
        "the triggering event is not repeated in the manifest"
    );
    // Oldest first.
    let stamps: Vec<u64> = detection.events[1..]
        .iter()
        .map(|e| e.meta().timestamp_ns)
        .collect();
    assert!(stamps.windows(2).all(|w| w[0] <= w[1]));
    assert!(detection.events.len() <= 1 + super::DAMAGE_MANIFEST_MAX);
}

#[test]
fn a_detection_that_is_not_ransomware_carries_only_its_triggering_event() {
    let dir = tmp("no-manifest");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        None,
        None,
        Some(Arc::clone(&spool)),
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap();
    sink.on_event(rename_of(900, 0, ".bak"));
    let event = exec(7, "test", "/bin/test");
    sink.record(
        super::Finding {
            entity: &verdict::EntityKey::new(1, "test"),
            technique: "T1059",
            message: "test finding",
            source: schema::detection::DetectionSource::Rule {
                rule_id: "T1059".into(),
            },
            severity: schema::detection::Severity::Medium,
        },
        &event,
        Vec::new(),
    );
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );
    let records: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    assert_eq!(
        records[0].detection.events,
        vec![with_its_enrichment(&event, &records[0].detection.events)]
    );
}

#[test]
fn without_an_events_path_no_raw_event_log_is_written_but_the_spool_still_is() {
    let dir = tmp("no-events-log");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("spool"), u64::MAX).unwrap(),
    ));
    let sink = Arc::new(
        DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            None,
            Some(Arc::clone(&spool)),
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap(),
    );
    sink.on_event(exec(7, "ls", "/bin/ls"));

    // The enrich worker is what appends to the spool: once the event is there,
    // it has also gone past the (absent) raw-log step.
    let mut spooled: Vec<Event> = Vec::new();
    for _ in 0..200 {
        spooled = spool.lock().unwrap().drain_oldest().unwrap();
        if !spooled.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(spooled.len(), 1, "the event must still reach the spool");
    assert!(
        !dir.join("events.jsonl").exists(),
        "no events path means no raw event log, not a file at a default path"
    );
}

#[test]
fn the_model_is_found_under_the_state_directory_before_the_working_directory() {
    let state = tmp("model-root");
    let under_state = super::model_root(&state).join("fam").join("0.1.0");
    std::fs::create_dir_all(&under_state).unwrap();
    std::fs::write(under_state.join("model.onnx"), b"x").unwrap();
    let cwd_root = tmp("model-cwd");
    let under_cwd = cwd_root.join("fam").join("0.1.0");
    std::fs::create_dir_all(&under_cwd).unwrap();
    std::fs::write(under_cwd.join("model.onnx"), b"y").unwrap();

    let found = locate_model_dir(&[&super::model_root(&state), &cwd_root], "fam");
    assert_eq!(found, under_state);
}

#[test]
fn the_working_directory_registry_is_the_fallback_for_a_source_checkout() {
    let state = tmp("model-root-empty");
    let cwd_root = tmp("model-cwd-only");
    let under_cwd = cwd_root.join("fam").join("0.1.0");
    std::fs::create_dir_all(&under_cwd).unwrap();
    std::fs::write(under_cwd.join("model.onnx"), b"y").unwrap();

    let found = locate_model_dir(&[&super::model_root(&state), &cwd_root], "fam");
    assert_eq!(found, under_cwd);
}

#[test]
fn with_no_model_anywhere_the_state_directory_is_the_one_named() {
    let state = tmp("model-none");
    let cwd_root = tmp("model-none-cwd");
    let found = locate_model_dir(&[&super::model_root(&state), &cwd_root], "fam");
    assert_eq!(found, super::model_root(&state).join("fam").join("0.1.0"));
}

#[test]
fn a_model_directory_without_a_model_is_a_read_error() {
    let dir = tmp("scorer-missing");
    let error = try_load_scorer(&dir)
        .err()
        .expect("no model.onnx must not load");
    assert!(matches!(error, ScorerLoadError::ReadModel(_)), "{error:?}");
}

#[test]
fn a_model_the_scorer_cannot_parse_is_a_scorer_error() {
    let dir = tmp("scorer-garbage");
    std::fs::write(dir.join("model.onnx"), b"not an onnx model").unwrap();
    let error = try_load_scorer(&dir).err().expect("garbage must not load");
    assert!(matches!(error, ScorerLoadError::Scorer(_)), "{error:?}");
}

/// A counting sink for wiring tests elsewhere would go through `EventSink`;
/// this pins that `DetectionSink` is object-safe behind the same trait the
/// sensors use (compile-time check, the assertion is incidental).
#[test]
fn detection_sink_is_usable_as_a_trait_object() {
    let dir = tmp("dyn");
    let sink: Arc<dyn schema::sensor::EventSink> = sink_in(&dir);
    sink.on_event(exec(9, "true", "/bin/true"));
}

// ── reload_content (issue #30) ──────────────────────────────────────

/// A minimal, valid Sigma rule (issue #73's required metadata: `level`,
/// `falsepositives`, an ATT&CK tag, and a recognized platform directory
/// — the last one is why the test writes it under a `.../linux/` path,
/// not just any temp dir) matching on an image path no other rule in
/// this crate's tests, or `crates/rules`' deterministic checks, would
/// ever incidentally match.
/// The directory a test writes its Sigma rule to: the one the agent reads on the host it
/// runs on (`Platform::rule_dirs`, #980), not a fixed `linux/`: a Windows host loads only
/// `windows/`, so a rule written elsewhere is never loaded. The rule below matches the
/// image path of a synthetic exec event (`/opt/reload-content-marker`), so it fires on
/// any host once it is loaded.
fn host_sigma_dir(dir: &std::path::Path) -> std::path::PathBuf {
    let platform = sigma::Platform::host().expect("tests run on a platform with rules");
    dir.join("content")
        .join("rules")
        .join("sigma")
        .join(platform.rule_dirs()[0])
}

const RELOAD_TEST_SIGMA_RULE: &str = r#"
title: reload-content test marker rule
tags:
  - attack.t1059
level: low
falsepositives:
  - none, test-only rule
detection:
  selection:
    Image|endswith:
      - '/reload-content-marker'
  condition: selection
"#;

#[test]
fn reload_content_picks_up_a_sigma_rule_added_after_construction() {
    let dir = tmp("reload-sigma");
    let sink = sink_in(&dir);

    // Before reload: no Sigma engine loaded yet (content dir is empty),
    // so this exec produces no Sigma-sourced alert.
    sink.on_event(exec(900, "run", "/opt/reload-content-marker"));
    assert!(
        !alerts_in(&dir).contains("reload-content test marker rule"),
        "no sigma engine should be loaded before the first reload"
    );

    let sigma_dir = host_sigma_dir(&dir);
    std::fs::create_dir_all(&sigma_dir).unwrap();
    std::fs::write(sigma_dir.join("marker.yml"), RELOAD_TEST_SIGMA_RULE).unwrap();

    let report = sink.reload_content();
    assert_eq!(
        report.sigma_rule_count,
        Some(1),
        "the one rule just written must load"
    );
    assert_eq!(
        report.yara_rule_count, None,
        "no rules/yara directory exists in this test's content dir"
    );

    sink.on_event(exec(901, "run", "/opt/reload-content-marker"));
    assert!(
        alerts_in(&dir).contains("reload-content test marker rule"),
        "the reloaded rule must now fire: {}",
        alerts_in(&dir)
    );
}

/// A rule author's `level:` is data on the finding, not a kill decision
/// (#131): the rule below is `critical` and must still never terminate anything.
fn critical_sigma_sink(name: &str) -> (std::path::PathBuf, Arc<DetectionSink>) {
    let dir = tmp(name);
    let sigma_dir = host_sigma_dir(&dir);
    std::fs::create_dir_all(&sigma_dir).unwrap();
    std::fs::write(
        sigma_dir.join("critical.yml"),
        RELOAD_TEST_SIGMA_RULE.replace("level: low", "level: critical"),
    )
    .unwrap();
    let sink = sink_in(&dir);
    assert_eq!(sink.reload_content().sigma_rule_count, Some(1));
    (dir, sink)
}

#[test]
fn a_sigma_rules_severity_reaches_the_fused_verdict() {
    let (_dir, sink) = critical_sigma_sink("sigma-severity-verdict");
    sink.on_event(exec(910, "run", "/opt/reload-content-marker"));
    let verdict = sink
        .verdict
        .lock()
        .unwrap()
        .peek(&verdict::EntityKey::new(1, "bash"))
        .expect("the Sigma hit is folded into the entity's verdict");
    assert_eq!(verdict.severity, schema::detection::Severity::Critical);
}

fn yara_match(technique: &str, severity: schema::detection::Severity) -> yara::YaraMatch {
    yara::YaraMatch {
        identifier: "response_marker".into(),
        severity,
        technique: technique.into(),
    }
}

fn yara_context(meta: &EventMeta) -> yara::ScanContext {
    yara::ScanContext {
        ppid: meta.ppid,
        comm: meta.comm.clone(),
        parent_generation: meta.parent_process_generation,
        timestamp_ns: meta.timestamp_ns,
        requester: None,
    }
}

/// #614: a native rule and a YARA rule flagging the same technique on the same
/// entity are one finding, whichever engine reports first.
#[test]
fn a_yara_match_and_a_rule_alert_on_the_same_entity_and_technique_are_one_verdict() {
    let dir = tmp("yara-fusion-dedup");
    let sink = sink_in(&dir);
    let meta = schema::fixtures::meta();
    let entity = verdict::EntityKey::new(meta.ppid, meta.comm.clone());
    let event = Event::FileOpen(schema::FileOpenEvent {
        meta: meta.clone(),
        ..schema::fixtures::file_open()
    });
    sink.record(
        super::Finding {
            entity: &entity,
            technique: "T1105",
            message: "downloader wrote then ran a binary",
            source: schema::detection::DetectionSource::Rule {
                rule_id: "T1105".into(),
            },
            severity: schema::detection::Severity::Medium,
        },
        &event,
        Vec::new(),
    );

    let absorbed = super::fuse_yara_match(
        &sink.verdict,
        &yara_context(&meta),
        &yara_match("T1105", schema::detection::Severity::Low),
    );
    assert_eq!(absorbed, None, "same technique, same entity: a duplicate");

    let fused = sink.verdict.lock().unwrap().peek(&entity).unwrap();
    assert_eq!(fused.techniques, vec!["T1105"], "one finding, not two");
    assert_eq!(fused.sources.len(), 2, "both engines are on the evidence");
    assert_eq!(fused.severity, schema::detection::Severity::Medium);
}

#[test]
fn a_yara_match_on_a_different_entity_is_its_own_verdict() {
    let dir = tmp("yara-fusion-entity");
    let sink = sink_in(&dir);
    let meta = EventMeta {
        ppid: 900,
        comm: "dropper".into(),
        ..schema::fixtures::meta()
    };
    let fused = super::fuse_yara_match(
        &sink.verdict,
        &yara_context(&meta),
        &yara_match("T1105", schema::detection::Severity::High),
    )
    .expect("first sighting on this entity");
    assert_eq!(fused.entity, verdict::EntityKey::new(900, "dropper"));
    assert_eq!(fused.severity, schema::detection::Severity::High);
    assert_eq!(
        fused.sources,
        vec![schema::detection::DetectionSource::Yara {
            rule_name: "response_marker".into()
        }]
    );
}

/// End to end: the scan runs on its own thread after the settle delay, and the
/// match must still land on the process that wrote the file.
#[test]
fn a_scanned_payloads_match_reaches_the_verdict_of_the_process_that_wrote_it() {
    let dir = tmp("yara-fusion-e2e");
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();
    let sink = sink_in(&dir);
    assert_eq!(sink.reload_content().yara_rule_count, Some(1));

    let meta = EventMeta {
        // Root: unrestricted, the payload is the test's own file (#594).
        user: schema::User::Unix { uid: 0, gid: 0 },
        ppid: 777,
        comm: "dropper".into(),
        ..schema::fixtures::meta()
    };
    sink.on_event(Event::FileOpen(schema::FileOpenEvent {
        meta,
        path: payload.display().to_string(),
        flags: 0o101,
    }));
    wait_for_alert(&dir, "YARA");

    let fused = sink
        .verdict
        .lock()
        .unwrap()
        .peek(&verdict::EntityKey::new(777, "dropper"))
        .expect("the match is folded into the writer's verdict");
    assert_eq!(fused.techniques, vec!["T1105"]);
}

/// The YARA trigger is the shared write-intent predicate, so a truncating open
/// queues a scan even without a write access mode (#233). It used to test
/// `O_WRONLY | O_RDWR | O_CREAT` on its own and miss `O_TRUNC`.
#[test]
fn a_truncating_read_only_open_queues_a_yara_scan() {
    let dir = tmp("yara-trunc-trigger");
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();
    let sink = sink_in(&dir);
    assert_eq!(sink.reload_content().yara_rule_count, Some(1));

    sink.on_event(Event::FileOpen(schema::FileOpenEvent {
        meta: EventMeta {
            // Root: unrestricted, the payload is the test's own file (#594).
            user: schema::User::Unix { uid: 0, gid: 0 },
            ..schema::fixtures::meta()
        },
        path: payload.display().to_string(),
        flags: schema::O_TRUNC,
    }));
    wait_for_alert(&dir, "YARA");
}

#[test]
fn a_critical_fused_verdict_raises_an_escalation_alert_without_killing() {
    let (dir, sink) = critical_sigma_sink("sigma-critical-escalates");
    let killed = Arc::new(Mutex::new(Vec::new()));
    let killed_rec = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: true,
            isolate_enabled: false,
        },
        move |pid| {
            killed_rec.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );
    sink.on_event(exec(912, "run", "/opt/reload-content-marker"));
    assert!(
        alerts_in(&dir).contains("RESPONSE-ESCALATE"),
        "{}",
        alerts_in(&dir)
    );
    assert!(killed.lock().unwrap().is_empty());
}

#[test]
fn a_medium_fused_verdict_does_not_escalate() {
    let dir = tmp("medium-no-escalate");
    let sink = sink_in(&dir);
    sink.on_event(exec(
        913,
        "bash -c echo cGF5bG9hZAo= | base64 -d | sh",
        "/bin/bash",
    ));
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1059.004"), "{alerts}");
    assert!(!alerts.contains("RESPONSE-ESCALATE"), "{alerts}");
}

/// A built-in rule that fires on a plain exec: `T1490`, severity `High`.
const SHADOW_DELETE: &str = "vssadmin.exe Delete Shadows /All /Quiet";

/// #615: a built-in rule's own severity reaches the fused verdict, instead of
/// the flat placeholder every non-`BAYES` finding used to get.
#[test]
fn a_built_in_rules_own_severity_reaches_the_fused_verdict() {
    let dir = tmp("builtin-severity");
    let sink = sink_in(&dir);
    sink.on_event(exec(920, SHADOW_DELETE, "/usr/bin/vssadmin"));
    let fused = sink
        .verdict
        .lock()
        .unwrap()
        .peek(&verdict::EntityKey::new(1, "bash"))
        .expect("the built-in alert is folded into the entity's verdict");
    assert!(fused.techniques.contains(&"T1490".to_string()), "{fused:?}");
    assert_eq!(fused.severity, schema::detection::Severity::High);
}

/// #615: a high-severity built-in alert must never terminate a process by
/// severity alone: only the correlator's `BAYES` crossing gates kill.
#[test]
fn a_high_severity_built_in_alert_never_triggers_a_kill() {
    let dir = tmp("builtin-high-no-kill");
    let sink = sink_in(&dir);
    let killed = Arc::new(Mutex::new(Vec::new()));
    let killed_rec = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        move |pid| {
            killed_rec.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );
    sink.on_event(exec(921, SHADOW_DELETE, "/usr/bin/vssadmin"));
    assert!(alerts_in(&dir).contains("T1490"), "{}", alerts_in(&dir));
    assert!(
        killed.lock().unwrap().is_empty(),
        "severity alone must never gate a kill"
    );
    assert!(
        !alerts_in(&dir).contains("killed pid"),
        "{}",
        alerts_in(&dir)
    );
}

/// #613: a suppression drops the finding from the fused verdict, never from
/// the audit trail.
#[test]
fn a_suppressed_technique_leaves_the_verdict_but_stays_in_the_alert_log() {
    let dir = tmp("suppress-verdict");
    let sink = sink_in(&dir);
    let meta = EventMeta {
        comm: "dropper".into(),
        ..schema::fixtures::meta()
    };
    let entity = verdict::EntityKey::new(meta.ppid, meta.comm.clone());
    let event = Event::FileOpen(schema::FileOpenEvent {
        meta: meta.clone(),
        ..schema::fixtures::file_open()
    });
    let record = || {
        sink.record(
            super::Finding {
                entity: &entity,
                technique: "T1105",
                message: "downloader wrote then ran a binary",
                source: schema::detection::DetectionSource::Rule {
                    rule_id: "T1105".into(),
                },
                severity: schema::detection::Severity::Medium,
            },
            &event,
            Vec::new(),
        )
    };

    assert_eq!(
        sink.suppress_verdict(meta.ppid, &meta.comm, "T1105"),
        Ok(true)
    );
    assert_eq!(record(), None, "a suppressed finding yields no verdict");
    assert!(
        alerts_in(&dir).contains("T1105"),
        "the audit trail keeps it"
    );

    assert!(sink.unsuppress_verdict(meta.ppid, &meta.comm, "T1105"));
    assert!(record().is_some(), "lifting the mark restores fusion");
}

/// #592 applied to YARA: a match from a recycled parent pid is a new entity and
/// must not inherit the previous parent's evidence or severity.
#[test]
fn a_yara_match_from_a_recycled_parent_does_not_inherit_the_previous_parents_verdict() {
    let dir = tmp("yara-fusion-recycled-parent");
    let sink = sink_in(&dir);
    let first = EventMeta {
        ppid: 500,
        comm: "dropper".into(),
        parent_process_generation: Some(1),
        ..schema::fixtures::meta()
    };
    super::fuse_yara_match(
        &sink.verdict,
        &yara_context(&first),
        &yara_match("T1105", schema::detection::Severity::Critical),
    )
    .unwrap();

    let recycled = EventMeta {
        parent_process_generation: Some(2),
        ..first
    };
    let fused = super::fuse_yara_match(
        &sink.verdict,
        &yara_context(&recycled),
        &yara_match("T1071", schema::detection::Severity::Low),
    )
    .unwrap();
    assert_eq!(fused.severity, schema::detection::Severity::Low);
    assert_eq!(fused.techniques, vec!["T1071"]);
}

/// #614 + #612: a High-or-above YARA match escalates like any other engine's
/// finding; the low-severity marker rule used elsewhere does not.
#[test]
fn a_high_severity_yara_match_raises_an_escalation_alert() {
    let dir = tmp("yara-fusion-escalate");
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(
        yara_dir.join("marker.yar"),
        RESPONSE_MARKER_RULE.replace("severity = \"low\"", "severity = \"high\""),
    )
    .unwrap();
    let payload = dir.join("payload.bin");
    std::fs::write(&payload, b"dropped payload RESPONSE-SCENARIO-MARKER").unwrap();
    let sink = sink_in(&dir);
    assert_eq!(sink.reload_content().yara_rule_count, Some(1));

    let meta = EventMeta {
        // Root: unrestricted, the payload is the test's own file (#594).
        user: schema::User::Unix { uid: 0, gid: 0 },
        ppid: 778,
        comm: "dropper".into(),
        ..schema::fixtures::meta()
    };
    sink.on_event(Event::FileOpen(schema::FileOpenEvent {
        meta,
        path: payload.display().to_string(),
        flags: 0o101,
    }));
    let alerts = wait_for_alert(&dir, "RESPONSE-ESCALATE");
    assert!(alerts.contains("778:dropper"), "{alerts}");
}

/// Maps one page of anonymous read-write-execute memory holding `payload`: the shape
/// of shellcode or a reflectively loaded image. `None` when the host refuses RWX
/// mappings (`SELinux` `execmem` denial, a hardened kernel), so the test can skip.
#[cfg(target_os = "linux")]
fn plant_in_executable_memory(payload: &[u8]) -> Option<*mut libc::c_void> {
    assert!(payload.len() <= 4096);
    // SAFETY: a fresh private anonymous page, checked against MAP_FAILED before use,
    // and `payload` fits inside it (asserted above).
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            return None;
        }
        std::ptr::copy_nonoverlapping(payload.as_ptr(), page.cast::<u8>(), payload.len());
        Some(page)
    }
}

/// A fileless exec: the process image is a `/dev/fd/N` path and the comm says memfd,
/// which is what the T1620 rule keys on. `pid` is a real, readable process so the
/// memory scan it triggers is a real one.
#[cfg(target_os = "linux")]
fn memfd_exec_of(pid: u32) -> Event {
    Event::Exec(ExecEvent {
        meta: EventMeta {
            pid,
            ppid: 1,
            comm: "memfd:implant".into(),
            ..schema::fixtures::meta()
        },
        image_path: "/dev/fd/3".into(),
        argv: vec!["/dev/fd/3".into()],
        ..schema::fixtures::exec()
    })
}

/// Held by every test that scans this test process's own memory. The tests run in
/// parallel in one process, so a marker one of them plants in an executable page is
/// visible to a scan another one requests: the "clean" test then failed 17 times out
/// of 30 on a `YARA-MEM` it never planted.
#[cfg(target_os = "linux")]
static OWN_PROCESS_MEMORY: Mutex<()> = Mutex::new(());

/// Serializes the tests that scan `std::process::id()`. Poison-tolerant: one test's
/// failed assertion must not fail the others on a poisoned lock.
#[cfg(target_os = "linux")]
fn own_process_memory() -> std::sync::MutexGuard<'static, ()> {
    OWN_PROCESS_MEMORY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// #85 end to end, no mocks: a payload that exists only in executable anonymous
/// memory of a real process is found by the scan the memfd-exec alert triggers.
#[test]
#[cfg(target_os = "linux")]
fn a_payload_present_only_in_executable_memory_is_found_after_a_memfd_exec_alert() {
    let _own_memory = own_process_memory();
    let dir = tmp("memscan-e2e");
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(
        yara_dir.join("marker.yar"),
        RESPONSE_MARKER_RULE.replace("severity = \"low\"", "severity = \"high\""),
    )
    .unwrap();
    let sink = sink_in(&dir);
    assert_eq!(sink.reload_content().yara_rule_count, Some(1));

    let Some(page) = plant_in_executable_memory(b"..RESPONSE-SCENARIO-MARKER..") else {
        eprintln!("skipped: this host refuses RWX anonymous mappings");
        return;
    };
    sink.on_event(memfd_exec_of(std::process::id()));
    let alerts = wait_for_alert(&dir, "YARA-MEM");
    // SAFETY: `page` is the one-page mapping created above and is not used again.
    unsafe { libc::munmap(page, 4096) };

    assert!(alerts.contains("T1620"), "the trigger is audited: {alerts}");
    assert!(
        alerts.contains("matched in the memory of pid"),
        "the memory match is audited: {alerts}"
    );
    assert!(
        alerts.contains("RESPONSE-ESCALATE"),
        "a High memory match escalates like any other finding: {alerts}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn a_memfd_exec_of_a_clean_process_triggers_a_scan_that_finds_nothing() {
    let _own_memory = own_process_memory();
    let dir = tmp("memscan-clean");
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(yara_dir.join("marker.yar"), RESPONSE_MARKER_RULE).unwrap();
    let sink = sink_in(&dir);
    assert_eq!(sink.reload_content().yara_rule_count, Some(1));

    sink.on_event(memfd_exec_of(std::process::id()));
    let stats_done = || {
        sink.memscan
            .lock()
            .unwrap()
            .as_ref()
            .map(|q| q.wait_for_completed(1, std::time::Duration::from_secs(10)))
    };
    assert_eq!(stats_done(), Some(true), "the scan ran");
    assert!(
        !alerts_in(&dir).contains("YARA-MEM"),
        "no marker in executable memory: {}",
        alerts_in(&dir)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn without_yara_content_a_memfd_exec_requests_no_scan() {
    let dir = tmp("memscan-no-content");
    let sink = sink_in(&dir);
    sink.on_event(memfd_exec_of(std::process::id()));
    assert!(sink.memscan.lock().unwrap().is_none());
    assert!(
        alerts_in(&dir).contains("T1620"),
        "the rule itself still fires"
    );
}

#[test]
fn a_critical_sigma_hit_never_triggers_a_kill() {
    let (dir, sink) = critical_sigma_sink("sigma-critical-no-kill");
    let killed = Arc::new(Mutex::new(Vec::new()));
    let killed_rec = Arc::clone(&killed);
    sink.enable_response(
        policy::ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
            isolate_enabled: false,
        },
        move |pid| {
            killed_rec.lock().unwrap().push(pid);
            Ok(())
        },
        dir.join("quarantine"),
    );
    sink.on_event(exec(911, "run", "/opt/reload-content-marker"));
    assert!(
        alerts_in(&dir).contains("reload-content test marker rule"),
        "the critical rule must fire: {}",
        alerts_in(&dir)
    );
    assert!(
        killed.lock().unwrap().is_empty(),
        "only a correlator belief crossing its threshold may terminate a process"
    );
    assert!(
        !alerts_in(&dir).contains("killed pid"),
        "{}",
        alerts_in(&dir)
    );
}

#[test]
fn reload_content_with_no_content_dir_present_unloads_cleanly() {
    let dir = tmp("reload-empty");
    let sink = sink_in(&dir);
    let report = sink.reload_content();
    assert_eq!(report.sigma_rule_count, None);
    assert_eq!(report.yara_rule_count, None);
    // Still safe to process events after a no-op reload.
    sink.on_event(exec(902, "ls", "/bin/ls"));
}

const RELOAD_TEST_YARA_RULE: &str = r#"
rule reload_content_test_marker {
    meta:
        technique = "T1105"
        severity = "low"
        falsepositives = "none, test-only rule"
    strings:
        $m = "RELOAD-CONTENT-YARA-MARKER"
    condition:
        $m
}
"#;

#[test]
fn reload_content_keeps_the_previous_yara_rules_when_the_new_set_is_broken() {
    // YARA's `load_dir` is all-or-nothing (a rule that doesn't compile is a
    // hard error), which is the case a reload must survive: an applied,
    // signed-but-broken rule set must not switch scanning off.
    let dir = tmp("reload-broken-keeps-old");
    let sink = sink_in(&dir);
    let yara_dir = dir.join("content").join("rules").join("yara");
    std::fs::create_dir_all(&yara_dir).unwrap();
    std::fs::write(yara_dir.join("marker.yar"), RELOAD_TEST_YARA_RULE).unwrap();
    let report = sink.reload_content();
    assert_eq!(report.yara_rule_count, Some(1));
    assert!(!report.yara_reload_failed);

    std::fs::write(yara_dir.join("broken.yar"), "rule nope { condition: \n").unwrap();
    let report = sink.reload_content();
    assert!(report.yara_reload_failed, "a rule that fails to compile");
    assert_eq!(
        report.yara_rule_count,
        Some(1),
        "the previous scan queue must keep running"
    );

    // Fixing the content recovers on the next reload.
    std::fs::remove_file(yara_dir.join("broken.yar")).unwrap();
    let report = sink.reload_content();
    assert!(!report.yara_reload_failed);
    assert_eq!(report.yara_rule_count, Some(1));
}

#[test]
fn reload_content_drops_a_rule_whose_file_was_removed() {
    let dir = tmp("reload-remove");
    let sink = sink_in(&dir);
    let sigma_dir = host_sigma_dir(&dir);
    std::fs::create_dir_all(&sigma_dir).unwrap();
    std::fs::write(sigma_dir.join("marker.yml"), RELOAD_TEST_SIGMA_RULE).unwrap();
    assert_eq!(sink.reload_content().sigma_rule_count, Some(1));

    std::fs::remove_dir_all(dir.join("content")).unwrap();
    let report = sink.reload_content();
    assert_eq!(
        report.sigma_rule_count, None,
        "removing the content dir must unload the engine, not error"
    );

    sink.on_event(exec(903, "run", "/opt/reload-content-marker"));
    assert!(
        !alerts_in(&dir).contains("reload-content test marker rule"),
        "the removed rule must no longer fire"
    );
}

/// A download-provenance mark on `image`, then `image` run inside the
/// window, then the enrichment worker drained (#441).
fn mark_then_run(sink: &DetectionSink, image: &str) {
    // What the Windows sensor records at exec (#688): the file the image started from.
    mark_then_run_as(
        sink,
        image,
        enrich::path_identity(std::path::Path::new(image)),
    );
}

/// [`mark_then_run`] with the identity the sensor recorded given explicitly.
fn mark_then_run_as(sink: &DetectionSink, image: &str, ran: Option<String>) {
    sink.on_event(Event::FileQuarantine(schema::FileQuarantineEvent {
        path: image.into(),
        ..schema::fixtures::file_quarantine()
    }));
    sink.on_event(Event::Exec(schema::ExecEvent {
        image_path: image.into(),
        image_file_id: ran,
        ..schema::fixtures::exec()
    }));
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(30)),
        "the enrichment worker must drain"
    );
}

// ── the common-set snapshot (ADR-0020, issue #76) ───────────────────────

/// The shared common-set golden file in the `ml` sibling repo (the same bytes the
/// server's builder and the `ml` reader are tested against). Tests that need it read it
/// first with `siblings::require!` and skip without it.
const COMMON_SET_GOLDEN: &str = "tests/fixtures/common_set_snapshot_golden.json";

/// A reference snapshot from `golden` (the text of [`COMMON_SET_GOLDEN`]), with some
/// hashes it contains.
fn golden_common_set(golden: &str, case: &str) -> (Vec<u8>, Vec<String>, u32) {
    let doc: serde_json::Value = serde_json::from_str(golden).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == case)
        .unwrap();
    let hex = case["bytes_hex"].as_str().unwrap();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let members = case["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().to_owned())
        .collect();
    let hosts = u32::try_from(case["params"]["hosts_covered"].as_u64().unwrap()).unwrap();
    (bytes, members, hosts)
}

fn write_common_set(dir: &std::path::Path, bytes: &[u8]) {
    let snapshots = dir.join("content").join("snapshots");
    std::fs::create_dir_all(&snapshots).unwrap();
    std::fs::write(snapshots.join("common-set.bin"), bytes).unwrap();
}

#[test]
fn a_common_set_snapshot_in_the_content_dir_is_loaded_at_startup() {
    use ml::features::rarity::CommonSet as _;
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let dir = tmp("common-set-startup");
    let (bytes, members, hosts) = golden_common_set(&golden, "fifty_hashes_one_percent");
    write_common_set(&dir, &bytes);

    let sink = sink_in(&dir);

    let loaded = sink.common_set().expect("the snapshot must be loaded");
    assert_eq!(loaded.hosts_covered(), u64::from(hosts));
    assert!(members.iter().all(|m| loaded.contains(m)));
}

#[test]
fn no_snapshot_file_means_no_common_set_and_no_failure() {
    let dir = tmp("common-set-absent");
    let sink = sink_in(&dir);
    assert!(sink.common_set().is_none());
    sink.reload_content();
    assert!(sink.common_set().is_none());
}

#[test]
fn reload_content_picks_up_a_common_set_snapshot_added_after_construction() {
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let dir = tmp("common-set-reload");
    let sink = sink_in(&dir);
    assert!(sink.common_set().is_none());
    let (bytes, _, _) = golden_common_set(&golden, "one_hash");
    write_common_set(&dir, &bytes);

    sink.reload_content();

    assert!(sink.common_set().is_some());
}

#[test]
fn reload_content_unloads_the_common_set_when_its_file_is_removed() {
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    // Same posture as the rule directories: an absent file is "no content", not an error,
    // and the evidence that depends on it is withheld rather than judged on a stale set.
    let dir = tmp("common-set-removed");
    let (bytes, _, _) = golden_common_set(&golden, "one_hash");
    write_common_set(&dir, &bytes);
    let sink = sink_in(&dir);
    assert!(sink.common_set().is_some());
    std::fs::remove_file(dir.join("content/snapshots/common-set.bin")).unwrap();

    sink.reload_content();

    assert!(sink.common_set().is_none());
}

#[test]
fn reload_content_keeps_the_previous_common_set_when_the_new_file_is_corrupt() {
    use ml::features::rarity::CommonSet as _;
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let dir = tmp("common-set-corrupt");
    let (bytes, members, _) = golden_common_set(&golden, "fifty_hashes_one_percent");
    write_common_set(&dir, &bytes);
    let sink = sink_in(&dir);
    let mut broken = bytes.clone();
    broken.truncate(bytes.len() - 1);
    write_common_set(&dir, &broken);

    sink.reload_content();

    let kept = sink.common_set().expect("a broken file must not unload it");
    assert!(members.iter().all(|m| kept.contains(m)));
}

#[test]
fn a_corrupt_common_set_at_startup_leaves_it_unloaded_not_the_agent_down() {
    let dir = tmp("common-set-corrupt-startup");
    write_common_set(&dir, b"not a snapshot");
    let sink = sink_in(&dir);
    assert!(sink.common_set().is_none());
}

#[test]
fn a_common_set_file_over_the_size_cap_is_refused_unread() {
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let dir = tmp("common-set-cap");
    let (bytes, _, _) = golden_common_set(&golden, "two_hundred_hashes_one_in_a_thousand");
    write_common_set(&dir, &bytes);
    let root = dir.join("content");

    assert!(matches!(
        super::load_common_set_capped(&root, u64::try_from(bytes.len()).unwrap()),
        super::Load::Loaded(_)
    ));
    assert!(matches!(
        super::load_common_set_capped(&root, u64::try_from(bytes.len()).unwrap() - 1),
        super::Load::Failed
    ));
}

#[test]
fn a_directory_where_the_common_set_file_belongs_is_a_failure_not_a_crash() {
    let dir = tmp("common-set-dir");
    std::fs::create_dir_all(dir.join("content/snapshots/common-set.bin")).unwrap();
    let sink = sink_in(&dir);
    assert!(sink.common_set().is_none());
}

// ── rarity evidence (ADR-0020, issue #76) ───────────────────────────────

/// A hash the snapshot built in a golden case does not contain.
fn golden_non_member(golden: &str, case: &str) -> String {
    let doc: serde_json::Value = serde_json::from_str(golden).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == case)
        .unwrap();
    case["non_members"][0].as_str().unwrap().to_owned()
}

#[test]
fn rarity_evidence_follows_the_snapshot_the_hash_and_the_coverage() {
    use ml::features::common_set::CommonSetSnapshot;
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let load = |case: &str| CommonSetSnapshot::parse(&golden_common_set(&golden, case).0).unwrap();
    let wide = load("fifty_hashes_one_percent"); // 12 hosts covered
    let member = golden_common_set(&golden, "fifty_hashes_one_percent").1[0].clone();
    let absent = golden_non_member(&golden, "fifty_hashes_one_percent");

    assert_eq!(
        super::rarity_evidence(Some(&member), Some(&wide), 10),
        super::Rarity::InCommonSet
    );
    assert_eq!(
        super::rarity_evidence(Some(&absent), Some(&wide), 10),
        super::Rarity::NotInCommonSet
    );
    // Coverage exactly at the minimum counts, one below withholds.
    assert_eq!(
        super::rarity_evidence(Some(&absent), Some(&wide), 12),
        super::Rarity::NotInCommonSet
    );
    assert_eq!(
        super::rarity_evidence(Some(&absent), Some(&wide), 13),
        super::Rarity::Withheld
    );
    // A snapshot built from 4 hosts is too thin to call anything rare.
    let thin = load("one_hash");
    assert_eq!(
        super::rarity_evidence(Some(&absent), Some(&thin), 10),
        super::Rarity::Withheld
    );
    // No snapshot, no hash, or something that is not a hash: nothing to say.
    assert_eq!(
        super::rarity_evidence(Some(&absent), None, 10),
        super::Rarity::Withheld
    );
    assert_eq!(
        super::rarity_evidence(None, Some(&wide), 10),
        super::Rarity::Withheld
    );
    assert_eq!(
        super::rarity_evidence(Some("not-a-hash"), Some(&wide), 10),
        super::Rarity::Withheld
    );
}

/// An exec whose hash is `sha256`, for [`note_image_rarity`].
fn exec_hashed(pid: u32, sha256: Option<&str>) -> ExecEvent {
    ExecEvent {
        meta: EventMeta {
            pid,
            ..schema::fixtures::meta()
        },
        sha256: sha256.map(str::to_owned),
        ..schema::fixtures::exec()
    }
}

/// The counts after one exec, against an engine that has (or has not) correlated it.
fn rarity_counts_after(
    golden: &str,
    case: &str,
    sha256: Option<String>,
    correlated: bool,
) -> crate::health::RarityCounts {
    use ml::features::common_set::CommonSetSnapshot;

    use crate::health::RarityStatsSource as _;

    let snapshot = CommonSetSnapshot::parse(&golden_common_set(golden, case).0).unwrap();
    // "Now" is the instant the snapshot was built: its age is not what these cases are about.
    let now = snapshot.header().built_at;
    let exec = exec_hashed(7_001, sha256.as_deref());
    let mut engine = correlator::CorrelationEngine::new();
    if correlated {
        engine.on_event(Event::Exec(exec.clone()));
    }
    let stats = super::RarityStats::default();
    super::note_image_rarity(
        &Mutex::new(engine),
        &Mutex::new(Some(Arc::new(snapshot))),
        &stats,
        &exec,
        now,
    );
    stats.rarity_counts()
}

#[test]
fn rarity_counts_an_applied_evidence() {
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let absent = golden_non_member(&golden, "fifty_hashes_one_percent");
    let counts = rarity_counts_after(&golden, "fifty_hashes_one_percent", Some(absent), true);
    assert_eq!(
        (counts.applied, counts.withheld, counts.unapplied),
        (1, 0, 0)
    );
}

#[test]
fn rarity_counts_evidence_that_found_no_belief_to_land_on() {
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    // The correlator evicted (or never created) the process's belief: the loss is
    // counted, not silent.
    let absent = golden_non_member(&golden, "fifty_hashes_one_percent");
    let counts = rarity_counts_after(&golden, "fifty_hashes_one_percent", Some(absent), false);
    assert_eq!(
        (counts.applied, counts.withheld, counts.unapplied),
        (0, 0, 1)
    );
}

#[test]
fn rarity_counts_a_withheld_judgement_whatever_the_reason() {
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let absent = golden_non_member(&golden, "fifty_hashes_one_percent");
    // A snapshot too thin to judge by, then an exec with no hash.
    let thin = rarity_counts_after(&golden, "one_hash", Some(absent), true);
    let no_hash = rarity_counts_after(&golden, "fifty_hashes_one_percent", None, true);
    assert_eq!((thin.applied, thin.withheld, thin.unapplied), (0, 1, 0));
    assert_eq!(
        (no_hash.applied, no_hash.withheld, no_hash.unapplied),
        (0, 1, 0)
    );
}

#[test]
fn rarity_counts_nothing_for_an_image_the_fleet_knows() {
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let member = golden_common_set(&golden, "fifty_hashes_one_percent").1[0].clone();
    let counts = rarity_counts_after(&golden, "fifty_hashes_one_percent", Some(member), true);
    assert_eq!(
        (counts.applied, counts.withheld, counts.unapplied),
        (0, 0, 0)
    );
}

#[test]
fn rarity_counts_withheld_with_no_snapshot_at_all() {
    use crate::health::RarityStatsSource as _;
    let stats = super::RarityStats::default();
    super::note_image_rarity(
        &Mutex::new(correlator::CorrelationEngine::new()),
        &Mutex::new(None),
        &stats,
        &exec_hashed(7_002, Some(&"ab".repeat(32))),
        0,
    );
    assert_eq!(stats.rarity_counts().withheld, 1);
}

/// The same non-member judged at two instants: inside the maximum age it is evidence, past
/// it the snapshot counts as absent and the judgement is withheld (ADR-0033 decision 3).
#[test]
fn a_snapshot_past_its_maximum_age_withholds_the_evidence() {
    use crate::health::RarityStatsSource as _;
    let golden = siblings::require!("ml", COMMON_SET_GOLDEN);
    let case = "fifty_hashes_one_percent";
    let absent = golden_non_member(&golden, case);
    let built_at =
        ml::features::common_set::CommonSetSnapshot::parse(&golden_common_set(&golden, case).0)
            .unwrap()
            .header()
            .built_at;
    let counts_at = |now: u64| {
        let mut engine = correlator::CorrelationEngine::new();
        let exec = exec_hashed(7_003, Some(&absent));
        engine.on_event(Event::Exec(exec.clone()));
        let stats = super::RarityStats::default();
        super::note_image_rarity(
            &Mutex::new(engine),
            &Mutex::new(Some(Arc::new(
                ml::features::common_set::CommonSetSnapshot::parse(
                    &golden_common_set(&golden, case).0,
                )
                .unwrap(),
            ))),
            &stats,
            &exec,
            now,
        );
        stats.rarity_counts()
    };
    let max = super::MAX_SNAPSHOT_AGE_SECS;
    assert_eq!(
        counts_at(built_at + max).applied,
        1,
        "at the maximum age it is still in force"
    );
    let past = counts_at(built_at + max + 1);
    assert_eq!((past.applied, past.withheld), (0, 1));
}

/// A version-1 snapshot built here (the layout in
/// `docs/detection/common-set-snapshot-format.md`): a fixed 4096-bit, 7-hash filter holding
/// `hashes`, claiming `hosts_covered` hosts.
fn snapshot_holding(hashes: &[&str], hosts_covered: u32) -> Vec<u8> {
    const BITS: u32 = 4096;
    const HASHES: u16 = 7;
    let mut body = vec![0u8; (BITS / 8) as usize];
    for hash in hashes {
        let raw: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let h1 = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(raw[8..16].try_into().unwrap()) | 1;
        for i in 0..u64::from(HASHES) {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) % u64::from(BITS);
            body[(bit >> 3) as usize] |= 1 << (bit & 7);
        }
    }
    let mut out = b"SYCS".to_vec();
    out.extend(1u16.to_le_bytes());
    out.extend(HASHES.to_le_bytes());
    out.extend(3u32.to_le_bytes());
    out.extend(hosts_covered.to_le_bytes());
    out.extend(u32::try_from(hashes.len()).unwrap().to_le_bytes());
    out.extend(BITS.to_le_bytes());
    // Built just now: the worker judges against the real clock, and a snapshot past its
    // maximum age is withheld (ADR-0033).
    out.extend(super::unix_now_secs().to_le_bytes());
    out.extend(body);
    out
}

/// What the snapshot holds, for [`belief_after_exec`].
enum Snapshot {
    None,
    /// Holds the executed image's own hash.
    HoldingTheImage {
        hosts_covered: u32,
    },
    /// Holds only an unrelated hash.
    HoldingOthers {
        hosts_covered: u32,
    },
}

/// Runs one exec of a file through a sink, lets the enrichment worker finish, and returns
/// the belief the correlator holds for the process.
fn belief_after_exec(name: &str, snapshot: &Snapshot, image_exists: bool) -> f32 {
    let dir = tmp(name);
    let image = dir.join("image.bin");
    if image_exists {
        std::fs::write(&image, b"an executable nobody on the fleet has run").unwrap();
    }
    let image_hash = enrich::Enricher::new()
        .enrich(&image)
        .sha256
        .unwrap_or_else(|| "cd".repeat(32));
    let unrelated = "ab".repeat(32);
    match snapshot {
        Snapshot::None => {}
        Snapshot::HoldingTheImage { hosts_covered } => {
            write_common_set(&dir, &snapshot_holding(&[&image_hash], *hosts_covered));
        }
        Snapshot::HoldingOthers { hosts_covered } => {
            write_common_set(&dir, &snapshot_holding(&[&unrelated], *hosts_covered));
        }
    }
    let sink = sink_in(&dir);

    sink.on_event(exec(9_100, "run", image.to_str().unwrap()));
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );

    let engine = sink.correlator.lock().unwrap();
    engine
        .belief_for_pid(9_100)
        .expect("the exec created a belief")
        .log_odds
}

#[test]
fn an_image_the_fleet_has_not_seen_raises_the_belief_a_little() {
    let baseline = belief_after_exec("rarity-baseline", &Snapshot::None, true);

    let rare = belief_after_exec(
        "rarity-rare",
        &Snapshot::HoldingOthers { hosts_covered: 50 },
        true,
    );

    let gained = rare - baseline;
    assert!(gained > 0.0, "rarity evidence must apply, gained {gained}");
    assert!(
        gained <= 1.0,
        "and stay within its allowance, gained {gained}"
    );
}

#[test]
fn an_image_in_the_common_set_adds_nothing() {
    let baseline = belief_after_exec("rarity-common-baseline", &Snapshot::None, true);
    let common = belief_after_exec(
        "rarity-common",
        &Snapshot::HoldingTheImage { hosts_covered: 50 },
        true,
    );
    assert!((common - baseline).abs() < 1e-6);
}

#[test]
fn a_snapshot_covering_too_few_hosts_adds_nothing() {
    // A freshly enrolled fleet has a thin snapshot: without this every binary on it
    // would look rare.
    let baseline = belief_after_exec("rarity-thin-baseline", &Snapshot::None, true);
    let thin = belief_after_exec(
        "rarity-thin",
        &Snapshot::HoldingOthers { hosts_covered: 3 },
        true,
    );
    assert!((thin - baseline).abs() < 1e-6);
}

#[test]
fn an_exec_with_no_readable_image_adds_nothing() {
    let baseline = belief_after_exec("rarity-nohash-baseline", &Snapshot::None, false);
    let unreadable = belief_after_exec(
        "rarity-nohash",
        &Snapshot::HoldingOthers { hosts_covered: 50 },
        false,
    );
    assert!((unreadable - baseline).abs() < 1e-6);
}

#[test]
fn a_marked_unsigned_file_run_alerts_after_enrichment() {
    let dir = tmp("gate-unsigned");
    let image = dir.join("invoice.exe");
    // A real unsigned PE: this test binary. Bytes that are not a PE verify
    // as `Unsupported` on Windows, not `Unsigned`.
    std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
    let sink = sink_in(&dir);
    mark_then_run(&sink, &image.to_string_lossy());
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1204.002"), "{alerts}");
    #[cfg(windows)]
    assert!(alerts.contains("[unsigned]"), "{alerts}");
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

/// The issue's done-when: a signed installer run does not alert. notepad.exe
/// is catalog-signed, so it verifies `Valid` (the enrich crate's own test).
#[cfg(windows)]
#[test]
fn a_marked_signed_file_run_does_not_alert() {
    let image = r"C:\Windows\System32\notepad.exe";
    if !std::path::Path::new(image).exists() {
        eprintln!("skipping: {image} not present on this host");
        return;
    }
    let dir = tmp("gate-signed");
    let sink = sink_in(&dir);
    mark_then_run(&sink, image);
    let alerts = alerts_in(&dir);
    assert!(!alerts.contains("T1204.002"), "{alerts}");
}

/// #688: the identity the ETW sensor records and the one enrichment reads are the same
/// token for the same file; the gate compares them as strings, so a format drift between
/// the two crates (they share no code) would silently turn every gated alert on.
#[cfg(windows)]
#[test]
fn the_sensor_and_enrichment_agree_on_a_files_identity() {
    let exe = std::env::current_exe().unwrap();
    let sensor = sensor_windows::image_file_id(&exe);
    assert!(sensor.is_some(), "an ordinary file has an identity");
    assert_eq!(sensor, enrich::path_identity(&exe));
}

/// #688: the image that ran was moved aside and a signed file took its path before the
/// worker opened it. The verdict is `Valid`, for a file that is not the image that ran.
#[cfg(windows)]
#[test]
fn a_valid_signature_of_a_file_that_is_not_the_image_that_ran_still_alerts() {
    let image = r"C:\Windows\System32\notepad.exe";
    if !std::path::Path::new(image).exists() {
        eprintln!("skipping: {image} not present on this host");
        return;
    }
    let dir = tmp("gate-swapped");
    let decoy_run = dir.join("dropper.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &decoy_run).unwrap();
    let sink = sink_in(&dir);
    // The sensor saw the dropper start; the path now holds notepad.exe.
    let ran = enrich::path_identity(&decoy_run);
    assert!(ran.is_some());
    mark_then_run_as(&sink, image, ran);
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1204.002"), "{alerts}");
    assert!(
        alerts.contains("file differs from the image that ran"),
        "{alerts}"
    );
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

/// #655 review: a signed file runs once (its `Valid` verdict cached), then an
/// unsigned file of the same size takes its path with the mtime restored. The
/// Windows cache key has no file identity, so only an uncached verification
/// keeps the gate from reading the old file's verdict.
#[cfg(windows)]
#[test]
fn a_cached_valid_verdict_for_a_replaced_file_does_not_silence_t1204_002() {
    let signed = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
    let Ok(bytes) = std::fs::read(signed) else {
        eprintln!("skipping: {} not readable on this host", signed.display());
        return;
    };
    let dir = tmp("gate-replaced");
    let image = dir.join("setup.exe");
    std::fs::write(&image, &bytes).unwrap();
    // Catalog-signed: a copy verifies by its hash, so it is `Valid` too.
    if enrich::Enricher::new().enrich(&image).signature != schema::Signature::Valid {
        eprintln!("skipping: the notepad.exe copy does not verify on this host");
        return;
    }
    let sink = sink_in(&dir);
    let path = image.to_string_lossy().into_owned();
    sink.on_event(Event::Exec(schema::ExecEvent {
        image_path: path.clone(),
        ..schema::fixtures::exec()
    }));
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(30))
    );

    let mtime = std::fs::metadata(&image).unwrap().modified().unwrap();
    let mut tampered = bytes;
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    std::fs::write(&image, &tampered).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&image)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    mark_then_run(&sink, &path);
    let alerts = alerts_in(&dir);
    assert!(alerts.contains("T1204.002"), "{alerts}");
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

const IOC_HASH: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

fn write_ioc_feed(dir: &std::path::Path, text: &str) {
    let feeds = dir.join("content").join("ioc");
    std::fs::create_dir_all(&feeds).unwrap();
    std::fs::write(feeds.join("test-feed.txt"), text).unwrap();
    std::fs::write(feeds.join("VERSION"), "2026-10-26.1\n").unwrap();
}

fn connect_to(addr: &str, timestamp_ns: u64) -> Event {
    Event::Connect(schema::ConnectEvent {
        meta: EventMeta {
            timestamp_ns,
            ..schema::fixtures::meta()
        },
        daddr: addr.parse().unwrap(),
        dport: 443,
    })
}

#[test]
fn a_connect_to_a_listed_address_raises_one_ioc_finding_and_the_repeat_is_absorbed() {
    let dir = tmp("ioc-connect");
    write_ioc_feed(&dir, "ip:203.0.113.9\n");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        Some(&dir.join("events.jsonl")),
        None,
        Some(Arc::clone(&spool)),
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap();

    sink.on_event(connect_to("203.0.113.10", 1_000));
    assert!(
        !alerts_in(&dir).contains("IOC"),
        "an unlisted address is silent"
    );
    sink.on_event(connect_to("203.0.113.9", 2_000));
    sink.on_event(connect_to("203.0.113.9", 3_000));
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );

    let alerts = alerts_in(&dir);
    assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
    assert!(
        alerts.contains("test-feed") && alerts.contains("2026-10-26.1"),
        "{alerts}"
    );
    // The repeated connects may also move the correlator's belief; only IOC findings count.
    let drained: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    let records: Vec<_> = drained
        .into_iter()
        .filter(|r| {
            matches!(
                r.detection.source,
                schema::detection::DetectionSource::Ioc { .. }
            )
        })
        .collect();
    assert_eq!(records.len(), 1);
    let detection = &records[0].detection;
    assert_eq!(detection.severity, schema::detection::Severity::Medium);
    assert!(
        detection.techniques.is_empty(),
        "IOC is not an ATT&CK technique"
    );
    assert_eq!(
        detection.source,
        schema::detection::DetectionSource::Ioc {
            kind: schema::detection::IocKind::Ip,
            indicator: "203.0.113.9".into(),
            feed: "test-feed".into(),
            feed_version: "2026-10-26.1".into(),
            reference: None,
        }
    );
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_polled_flow_to_a_listed_address_raises_one_ioc_finding() {
    let dir = tmp("ioc-flow");
    write_ioc_feed(&dir, "ip:203.0.113.9\n");
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        Some(&dir.join("events.jsonl")),
        None,
        None,
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap();

    let flow = |addr: &str, timestamp_ns: u64| {
        Event::NetworkFlow(schema::NetworkFlowEvent {
            meta: EventMeta {
                timestamp_ns,
                ..schema::fixtures::meta()
            },
            daddr: addr.parse().unwrap(),
            ..schema::fixtures::network_flow()
        })
    };
    sink.on_event(flow("203.0.113.10", 1_000));
    assert!(
        !alerts_in(&dir).contains("IOC"),
        "an unlisted peer is silent"
    );
    for poll in 0..3 {
        sink.on_event(flow("203.0.113.9", 2_000 + poll));
    }
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );

    let alerts = alerts_in(&dir);
    assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

fn ioc_sink(dir: &std::path::Path, feed: &str) -> DetectionSink {
    write_ioc_feed(dir, feed);
    DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        Some(&dir.join("events.jsonl")),
        None,
        None,
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap()
}

fn connect_from(pid: u32, generation: Option<u64>, addr: &str, timestamp_ns: u64) -> Event {
    let mut event = connect_to(addr, timestamp_ns);
    if let Event::Connect(connect) = &mut event {
        connect.meta.pid = pid;
        connect.meta.process_generation = generation;
        #[cfg(unix)]
        {
            // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
            let uid = unsafe { libc::geteuid() };
            connect.meta.user = schema::User::Unix { uid, gid: 0 };
        }
    }
    event
}

fn ioc_alerts_after(sink: &DetectionSink, dir: &std::path::Path, event: Event) -> String {
    sink.on_event(event);
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );
    alerts_in(dir)
}

#[test]
fn the_agents_own_connection_to_its_control_plane_neither_alerts_nor_hides_the_next_one() {
    // https://github.com/synthaea-lab/agent/issues/47: the lab feed listed the control plane's address; the agent alerted on its own
    // fetch, and that finding started the cooldown a real process would then fall inside.
    let dir = tmp("ioc-own");
    let sink = ioc_sink(&dir, "ip:203.0.113.9\n");
    assert!(sink.set_control_plane("https://203.0.113.9/"));

    let own = connect_from(std::process::id(), None, "203.0.113.9", 1_000);
    assert!(
        !ioc_alerts_after(&sink, &dir, own).contains("IOC"),
        "the agent's own control-plane connection is silent"
    );
    let alerts = ioc_alerts_after(&sink, &dir, connect_to("203.0.113.9", 2_000));
    assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
    assert_eq!(sink.ioc_own_skips(), (1, 0));
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_agents_own_connection_to_a_listed_address_that_is_not_its_control_plane_raises() {
    // #1117 review: the skip is scoped to the destination, so code inside the agent reaching
    // a listed C2 is not hidden by being the agent.
    let dir = tmp("ioc-own-elsewhere");
    let sink = ioc_sink(&dir, "ip:203.0.113.9\n");
    assert!(sink.set_control_plane("https://198.51.100.1/"));
    let own = connect_from(std::process::id(), None, "203.0.113.9", 1_000);
    let alerts = ioc_alerts_after(&sink, &dir, own);
    assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
    assert_eq!(sink.ioc_own_skips(), (0, 0));
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn without_a_configured_control_plane_the_agents_own_connection_raises() {
    let dir = tmp("ioc-own-no-cp");
    let sink = ioc_sink(&dir, "ip:203.0.113.9\n");
    let own = connect_from(std::process::id(), None, "203.0.113.9", 1_000);
    assert!(ioc_alerts_after(&sink, &dir, own).contains("203.0.113.9"));
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_second_agent_process_reaching_a_listed_address_other_than_the_control_plane_raises() {
    // #1117 review: `agent apply-content-manifest --server https://<listed host>` runs the
    // agent's executable but talks to whatever host the caller names.
    let dir = tmp("ioc-sibling-elsewhere");
    let sink = ioc_sink(&dir, "ip:203.0.113.9\n");
    assert!(sink.set_control_plane("https://198.51.100.1/"));
    sink.on_event(Event::Exec(schema::ExecEvent {
        meta: EventMeta {
            pid: 4242,
            process_generation: Some(7),
            timestamp_ns: 500,
            ..schema::fixtures::meta()
        },
        image_path: std::env::current_exe().unwrap().display().to_string(),
        ..schema::fixtures::exec()
    }));
    let sibling = connect_from(4242, Some(7), "203.0.113.9", 1_000);
    let alerts = ioc_alerts_after(&sink, &dir, sibling);
    assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
    assert_eq!(sink.ioc_own_skips(), (0, 0));
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn a_second_agent_process_reaching_the_control_plane_is_skipped_for_its_incarnation_only() {
    let dir = tmp("ioc-sibling-cp");
    let sink = ioc_sink(&dir, "ip:203.0.113.9\n");
    assert!(sink.set_control_plane("https://203.0.113.9/"));
    sink.on_event(Event::Exec(schema::ExecEvent {
        meta: EventMeta {
            pid: 4242,
            process_generation: Some(7),
            timestamp_ns: 500,
            ..schema::fixtures::meta()
        },
        image_path: std::env::current_exe().unwrap().display().to_string(),
        ..schema::fixtures::exec()
    }));
    let sibling = connect_from(4242, Some(7), "203.0.113.9", 1_000);
    assert!(!ioc_alerts_after(&sink, &dir, sibling).contains("IOC"));
    assert_eq!(sink.ioc_own_skips(), (0, 1));

    // The pid recycled before the connection was judged: another incarnation raises.
    let recycled = connect_from(4242, Some(8), "203.0.113.9", 2_000);
    let alerts = ioc_alerts_after(&sink, &dir, recycled);
    assert_eq!(alerts.matches("203.0.113.9").count(), 1, "{alerts}");
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_agents_lookup_of_its_control_plane_host_is_skipped_and_of_a_subdomain_raises() {
    let dir = tmp("ioc-own-dns");
    let sink = ioc_sink(&dir, "domain:cp.example\n");
    // Set directly: `set_control_plane` would start resolving a name that does not exist.
    assert!(sink.own_traffic.set_control_plane("https://cp.example/"));
    let lookup = |query: &str, timestamp_ns: u64| {
        Event::DnsQuery(schema::DnsQueryEvent {
            meta: EventMeta {
                pid: std::process::id(),
                timestamp_ns,
                ..schema::fixtures::meta()
            },
            query: query.to_string(),
            ..schema::fixtures::dns_query()
        })
    };
    assert!(!ioc_alerts_after(&sink, &dir, lookup("cp.example.", 1_000)).contains("IOC"));
    let alerts = ioc_alerts_after(&sink, &dir, lookup("data.cp.example", 2_000));
    assert!(
        alerts.contains("cp.example"),
        "a subdomain is not the control plane, even from the agent: {alerts}"
    );
    assert_eq!(sink.ioc_own_skips(), (1, 0));
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_exec_whose_image_hash_is_listed_raises_a_high_ioc_finding_from_the_worker() {
    let dir = tmp("ioc-exec");
    write_ioc_feed(&dir, &format!("sha256:{IOC_HASH}\n"));
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        Some(&dir.join("events.jsonl")),
        None,
        Some(Arc::clone(&spool)),
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap();
    // The hash is set on the event, as enrichment leaves it: the worker looks it up.
    let listed = Event::Exec(ExecEvent {
        sha256: Some(IOC_HASH.to_uppercase()),
        image_path: String::new(),
        ..schema::fixtures::exec()
    });
    let other = Event::Exec(ExecEvent {
        sha256: Some("0".repeat(64)),
        image_path: String::new(),
        ..schema::fixtures::exec()
    });

    sink.on_event(other);
    sink.on_event(listed);
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );

    let alerts = alerts_in(&dir);
    assert!(alerts.contains(IOC_HASH), "{alerts}");
    let records: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    let [record] = records.as_slice() else {
        panic!("exactly one IOC detection expected, got {}", records.len());
    };
    assert_eq!(record.detection.severity, schema::detection::Severity::High);
    assert!(matches!(
        record.detection.source,
        schema::detection::DetectionSource::Ioc {
            kind: schema::detection::IocKind::Sha256,
            ..
        }
    ));
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reload_content_picks_up_a_feed_added_after_construction_and_unloads_a_removed_one() {
    let dir = tmp("ioc-reload");
    let sink = sink_in(&dir);
    sink.on_event(connect_to("203.0.113.9", 1_000));
    assert!(!alerts_in(&dir).contains("IOC"));

    write_ioc_feed(&dir, "ip:203.0.113.9\n");
    sink.reload_content();
    sink.on_event(connect_to("203.0.113.9", 2_000));
    assert!(alerts_in(&dir).contains("203.0.113.9"));

    std::fs::remove_dir_all(dir.join("content").join("ioc")).unwrap();
    sink.reload_content();
    let before = alerts_in(&dir).matches("203.0.113.9").count();
    sink.on_event(connect_to("203.0.113.9", 2 * 60 * 60 * 1_000_000_000));
    assert_eq!(alerts_in(&dir).matches("203.0.113.9").count(), before);
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}

fn dns_query_of(name: &str, timestamp_ns: u64) -> Event {
    Event::DnsQuery(schema::DnsQueryEvent {
        meta: EventMeta {
            timestamp_ns,
            ..schema::fixtures::meta()
        },
        query: name.into(),
        ..schema::fixtures::dns_query()
    })
}

#[test]
fn a_dns_query_under_a_listed_domain_names_the_listed_domain_not_the_subdomain() {
    let dir = tmp("ioc-dns");
    write_ioc_feed(&dir, "domain:evil.example\n");
    let spool = Arc::new(Mutex::new(
        store::EventSpool::open(&dir.join("detection-spool"), u64::MAX).unwrap(),
    ));
    let sink = DetectionSink::new(
        rules::RuleState::new(),
        &dir.join("alerts.ndjson"),
        Some(&dir.join("events.jsonl")),
        None,
        Some(Arc::clone(&spool)),
        &dir.join("content"),
        &dir.join("ml-registry"),
    )
    .unwrap();

    sink.on_event(dns_query_of("good.example", 1_000));
    sink.on_event(dns_query_of("notevil.example", 2_000));
    sink.on_event(dns_query_of("Cdn.Evil.Example.", 3_000));
    assert!(
        sink.enrich_queue()
            .flush(std::time::Duration::from_secs(10))
    );

    let drained: Vec<transport::QueuedDetection> = spool.lock().unwrap().drain_oldest().unwrap();
    let records: Vec<_> = drained
        .into_iter()
        .filter(|r| {
            matches!(
                r.detection.source,
                schema::detection::DetectionSource::Ioc { .. }
            )
        })
        .collect();
    let [record] = records.as_slice() else {
        panic!("exactly one IOC detection expected, got {}", records.len());
    };
    assert_eq!(
        record.detection.severity,
        schema::detection::Severity::Medium
    );
    assert_eq!(
        record.detection.source,
        schema::detection::DetectionSource::Ioc {
            kind: schema::detection::IocKind::Domain,
            indicator: "evil.example".into(),
            feed: "test-feed".into(),
            feed_version: "2026-10-26.1".into(),
            reference: None,
        }
    );
    drop(sink);
    std::fs::remove_dir_all(&dir).ok();
}
