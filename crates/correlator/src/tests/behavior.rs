//! `BehaviorVector` feature extraction and the naive-Bayes belief tests.

use super::*;

// ── BehaviorVector ─────────────────────────────────────────────────────────

#[test]
fn bv_unknown_pid_returns_none() {
    let engine = CorrelationEngine::new();
    assert!(engine.behavior_vector_for_pid(9999, None).is_none());
}

#[test]
fn bv_exec_only() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(11, 1_000_000_000));
    let bv = engine.behavior_vector_for_pid(11, None).unwrap();
    assert_eq!(bv.has_exec, 1.0);
    assert_eq!(bv.has_connect, 0.0);
    assert_eq!(bv.has_filewrite, 0.0);
    assert_eq!(bv.connect_count, 0.0);
    assert_eq!(bv.dest_is_external, 0.0);
}

#[test]
fn recycled_pid_does_not_update_the_old_entity_belief() {
    let mut engine = CorrelationEngine::new();
    let old_exec = stamped(
        exec_with_meta(meta_full(5000, 77, "old", 1_000_000_000), ""),
        1,
    );
    engine.on_event(old_exec);
    let old_odds = engine.belief_for_entity(77, "old").unwrap().log_odds;

    let new_connect = stamped(
        connect_to(meta_full(5000, 0, "new", 2_000_000_000), [8, 8, 8, 8], 80),
        2,
    );
    engine.on_event(new_connect);

    assert_eq!(
        engine.belief_for_entity(77, "old").unwrap().log_odds,
        old_odds
    );
    assert!(engine.belief_for_entity(5000, "new").is_some());
}

#[test]
fn bv_exec_connect_delta_correct() {
    let mut engine = CorrelationEngine::new();
    // Exec at t=0, Connect at t=500ms
    engine.on_event(exec_event(22, 0));
    engine.on_event(connect_event(22, 500_000_000));
    let bv = engine.behavior_vector_for_pid(22, None).unwrap();
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
    let bv = engine.behavior_vector_for_pid(33, None).unwrap();
    assert_eq!(bv.dest_is_external, 1.0);
}

#[test]
fn bv_private_ip_not_external() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(connect_to(meta(44, 1_000_000_000), [192, 168, 1, 1], 80));
    let bv = engine.behavior_vector_for_pid(44, None).unwrap();
    assert_eq!(bv.dest_is_external, 0.0);
}

#[test]
fn bv_unspecified_ip_not_external() {
    // Regression 2026-08-31: `0.0.0.0` (unspecified address) observed on a
    // `connect()` from `sshd` in a real session — must not be classified as external.
    let mut engine = CorrelationEngine::new();
    engine.on_event(connect_to(meta(55, 1_000_000_000), [0, 0, 0, 0], 22));
    let bv = engine.behavior_vector_for_pid(55, None).unwrap();
    assert_eq!(bv.dest_is_external, 0.0);
}

#[test]
fn bv_distinct_dports() {
    let mut engine = CorrelationEngine::new();
    // Two connections to different ports
    engine.on_event(connect_event(66, 1_000_000_000)); // port 4444
    engine.on_event(connect_to(meta(66, 2_000_000_000), [1, 2, 3, 4], 80));
    let bv = engine.behavior_vector_for_pid(66, None).unwrap();
    assert_eq!(bv.connect_count, 2.0);
    assert_eq!(bv.distinct_dports, 2.0);
}

#[test]
fn bv_filewrite_present() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(file_write_event(77, 1_000_000_000));
    let bv = engine.behavior_vector_for_pid(77, None).unwrap();
    assert_eq!(bv.has_filewrite, 1.0);
    assert_eq!(bv.has_exec, 0.0);
}

#[test]
fn bv_to_vec_has_9_features() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(88, 1_000_000_000));
    let bv = engine.behavior_vector_for_pid(88, None).unwrap();
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

// ── update_belief_with_ml (PR #345 review) ──────────────────────────────────

#[test]
fn update_belief_with_ml_adds_the_llr_exactly_once() {
    // Before the fix, `update_belief_with_ml` re-ran the full decay+feature-LLR
    // update `on_event` already did this cycle, so the hand-calibrated evidence
    // was summed twice and the ML term landed on top of that inflated total.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event_suspicious(600, 50, 0));
    engine.on_event(connect_event_external(600, 100_000_000));
    let before = engine
        .belief_for_pid(600)
        .expect("belief expected")
        .log_odds;

    engine
        .update_belief_with_ml(600, None, Some(0.75))
        .expect("belief state exists, must not error");
    let after = engine
        .belief_for_pid(600)
        .expect("belief expected")
        .log_odds;

    assert!(
        (after - (before + 0.75)).abs() < 1e-6,
        "expected exactly +0.75 (the ML term only), got {before} → {after}"
    );
}

#[test]
fn update_belief_with_ml_none_leaves_the_belief_untouched() {
    // A `None` LLR (gated / OOD / scorer error) must not re-apply decay or
    // re-sum the feature LLRs either — there is no new evidence at all.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event_suspicious(601, 50, 0));
    engine.on_event(connect_event_external(601, 100_000_000));
    let before = engine
        .belief_for_pid(601)
        .expect("belief expected")
        .log_odds;

    engine.update_belief_with_ml(601, None, None).unwrap();
    let after = engine
        .belief_for_pid(601)
        .expect("belief expected")
        .log_odds;

    assert_eq!(before, after, "a None LLR must be a complete no-op");
}

#[test]
fn update_belief_with_ml_before_any_belief_state_is_silent_err() {
    // No prior `on_event` for this pid → no belief state to add an ML term to.
    let mut engine = CorrelationEngine::new();
    assert!(engine.update_belief_with_ml(9999, None, Some(1.0)).is_err());
}

// ── Service main process provenance (issue #652) ───────────────────────────

#[test]
fn a_package_binary_started_by_init_is_a_service_main_process() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_with_meta(
        meta_full(800, 1, "NetworkManager", 0),
        "/usr/sbin/NetworkManager",
    ));
    assert!(engine.is_service_main_process(800, None));
}

#[test]
fn only_the_services_own_process_counts_not_what_it_spawns() {
    // A shell spawned by a compromised daemon runs a trusted binary too, but its
    // parent is the daemon, not init: it stays killable.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_with_meta(meta_full(801, 800, "sh", 0), "/usr/bin/sh"));
    assert!(!engine.is_service_main_process(801, None));
}

#[test]
fn an_untrusted_path_or_an_unknown_one_is_never_a_service_main_process() {
    let mut engine = CorrelationEngine::new();
    // A payload renamed after a service, started by init from /tmp.
    engine.on_event(exec_with_meta(
        meta_full(802, 1, "NetworkManager", 0),
        "/tmp/NetworkManager",
    ));
    // The sensor did not report an image path: not evidence of a service.
    engine.on_event(exec_with_meta(meta_full(803, 1, "chronyd", 0), ""));
    assert!(!engine.is_service_main_process(802, None));
    assert!(!engine.is_service_main_process(803, None));
    assert!(
        !engine.is_service_main_process(804, None),
        "a pid whose exec was never seen is not a service main process"
    );
}

#[test]
fn a_recycled_pid_does_not_inherit_the_service_provenance() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(stamped(
        exec_with_meta(meta_full(805, 1, "crond", 0), "/usr/sbin/crond"),
        1,
    ));
    assert!(engine.is_service_main_process(805, Some(1)));
    assert!(!engine.is_service_main_process(805, Some(2)));
}

#[test]
fn a_reexec_to_an_untrusted_image_clears_the_service_main_entry() {
    // Review of #755 (Sollykhan, 2026-10-19): `service_mains` was insert-only, so a
    // service main later compromised and `exec`'d into something else (same pid,
    // same generation — this is not a fork) kept the kill-gate refusal on its new
    // image forever. A pid stays a service main only as of its most recent exec.
    let mut engine = CorrelationEngine::new();
    engine.on_event(stamped(
        exec_with_meta(meta_full(806, 1, "crond", 0), "/usr/sbin/crond"),
        1,
    ));
    assert!(engine.is_service_main_process(806, Some(1)));

    engine.on_event(stamped(
        exec_with_meta(meta_full(806, 1, "crond", 1), "/tmp/payload"),
        1,
    ));
    assert!(
        !engine.is_service_main_process(806, Some(1)),
        "an exec to an untrusted image on the same pid/generation must drop the \
         service-main entry, not keep protecting the new image"
    );
}

#[test]
fn a_shell_or_interpreter_started_by_init_is_not_a_service_main_process() {
    // Review of #755 (Sollykhan, 2026-10-19): a systemd unit's `ExecStart` can be a
    // shell or interpreter (`ExecStart=/usr/bin/python3 /var/tmp/x.py`) just as
    // easily as a real daemon's own binary. The interpreter, not the script, is
    // what execs with ppid 1 — without this exclusion every payload run that way
    // would be permanently immune to the BAYES kill gate.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_with_meta(
        meta_full(807, 1, "python3", 0),
        "/usr/bin/python3",
    ));
    engine.on_event(exec_with_meta(
        meta_full(808, 1, "bash", 0),
        "/usr/bin/bash",
    ));
    assert!(!engine.is_service_main_process(807, None));
    assert!(!engine.is_service_main_process(808, None));
}

#[test]
fn opt_and_usr_local_are_not_service_main_paths() {
    // Review of #755 (Sollykhan, 2026-10-19): /opt/ and /usr/local/ host
    // third-party and admin-installed software as easily as a root attacker's own
    // unit — being under either is not evidence of being the kind of system-
    // installed service the broader name-exclusion check was designed to rule out a
    // masquerade for.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_with_meta(
        meta_full(809, 1, "kworkerd", 0),
        "/usr/local/bin/kworkerd",
    ));
    engine.on_event(exec_with_meta(meta_full(810, 1, "x", 0), "/opt/x/x"));
    assert!(!engine.is_service_main_process(809, None));
    assert!(!engine.is_service_main_process(810, None));
}

#[test]
fn a_daemon_that_shares_an_interpreter_family_prefix_still_qualifies() {
    // Review of #755 (old-dov, 2026-10-19): a bare `starts_with` on the family
    // list over-matches a real daemon that happens to share a prefix with an
    // interpreter name — php-fpm (the PHP-FPM master, #478's web host context)
    // is not a script runner, and losing its service-main status would make it
    // killable on a BAYES crossing again, the opposite of what this guard is
    // for. Only a bare family name or a version suffix (digits and `.`) counts
    // as the interpreter itself.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_with_meta(
        meta_full(811, 1, "php-fpm8.4", 0),
        "/usr/sbin/php-fpm8.4",
    ));
    engine.on_event(exec_with_meta(
        meta_full(812, 1, "nodm", 0),
        "/usr/bin/nodm",
    ));
    assert!(engine.is_service_main_process(811, None));
    assert!(engine.is_service_main_process(812, None));

    // The actual interpreter, with or without a version suffix, still does not.
    engine.on_event(exec_with_meta(
        meta_full(813, 1, "php8.4", 0),
        "/usr/bin/php8.4",
    ));
    assert!(!engine.is_service_main_process(813, None));
}

#[test]
fn interpreters_the_blocklist_used_to_miss_are_now_excluded() {
    // Review of #755 (old-dov and SherlockOmss, 2026-10-19): a handful of real
    // script runners had no version-suffix convention `FAMILIES` could already
    // tolerate (`nodejs`, the only Node.js binary name some Debian/Ubuntu
    // packages ship) or weren't in either list at all (`php-cgi`, which runs
    // scripts, unlike the `php-fpm` daemon the previous test pins as protected).
    // Each used to let a unit `ExecStart=`ing it through as a "service main",
    // making any payload run through it permanently immune to the BAYES kill
    // gate — the same class of hole #652 exists to close.
    let mut engine = CorrelationEngine::new();
    for (pid, name, path) in [
        (814, "nodejs", "/usr/bin/nodejs"),
        (815, "php-cgi8.4", "/usr/bin/php-cgi8.4"),
        (816, "lua5.4", "/usr/bin/lua5.4"),
        (817, "tclsh8.6", "/usr/bin/tclsh8.6"),
        (818, "pypy3", "/usr/bin/pypy3"),
    ] {
        engine.on_event(exec_with_meta(meta_full(pid, 1, name, 0), path));
        assert!(
            !engine.is_service_main_process(pid, None),
            "{name} must not be classed as a service main"
        );
    }

    // `php-fpm` (the daemon) does not share the `php-cgi` family prefix, so it
    // is unaffected by giving `php-cgi` its own entry.
    engine.on_event(exec_with_meta(
        meta_full(819, 1, "php-fpm8.4", 0),
        "/usr/sbin/php-fpm8.4",
    ));
    assert!(engine.is_service_main_process(819, None));

    // Documented, not fixed by this PR (ADR-0028 Consequences): a network tool
    // run directly by a unit is not a known shell/interpreter/daemon name, so
    // it still passes as a "service main". Pinning this is deliberate — it is
    // the unbounded-tail gap the ADR now names explicitly, not a regression to
    // catch, and a future narrowing of the blocklist should not close it by
    // accident without updating that documentation.
    engine.on_event(exec_with_meta(
        meta_full(820, 1, "socat", 0),
        "/usr/bin/socat",
    ));
    assert!(engine.is_service_main_process(820, None));
}

// ── BAYES_NAME_EXCLUSIONS (issue #212) ──────────────────────────────────────

#[test]
fn wget_from_a_trusted_path_never_alerts_bayes() {
    // Issue #212: a bare `wget -T 3 -O /dev/null http://1.1.1.1/` crossed
    // BAYES_THRESHOLD purely from "quick connect after spawn" + "external
    // destination" — features that don't distinguish beaconing malware from
    // any CLI network tool.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_with_meta(
        meta_full(500, 50, "wget", 0),
        "/usr/bin/wget",
    ));
    for i in 0..20u64 {
        let connect = connect_to(
            meta_full(500, 50, "wget", (i + 1) * 100_000_000),
            [1, 1, 1, 1],
            80,
        );
        let alerts = engine.on_event(connect);
        assert!(
            !alerts.iter().any(|a| a.technique == "BAYES"),
            "a trusted wget must never trigger the BAYES false positive"
        );
    }
}

#[test]
fn chronyd_without_an_observed_exec_never_alerts_bayes() {
    // Issue #212: chronyd is already running when the agent starts (no
    // ExecEvent is ever seen for it — see `prime_proc_lineage` in
    // sensor-linux) — its periodic NTP resync connects alone crossed
    // BAYES_THRESHOLD with zero user action.
    let mut engine = CorrelationEngine::new();
    for i in 0..20u64 {
        let connect = connect_to(
            meta_full(600, 0, "chronyd", i * 1_000_000_000),
            [162, 159, 200, 1],
            123,
        );
        let alerts = engine.on_event(connect);
        assert!(
            !alerts.iter().any(|a| a.technique == "BAYES"),
            "chronyd's periodic resync must never alert BAYES"
        );
    }
}

#[test]
fn masqueraded_wget_from_an_untrusted_path_still_alerts_bayes() {
    // A payload renamed "wget" in /tmp must not inherit the exclusion
    // (name-only exclusions are a trivial bypass) — same masquerade
    // regression as `masqueraded_ignored_name_is_still_correlated` in
    // tests/rules.rs.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_with_meta(meta_full(700, 50, "wget", 0), "/tmp/wget"));
    for i in 0..20u64 {
        let connect = connect_to(
            meta_full(700, 50, "wget", (i + 1) * 100_000_000),
            [1, 1, 1, 1],
            80,
        );
        let alerts = engine.on_event(connect);
        if alerts.iter().any(|a| a.technique == "BAYES") {
            return; // test OK
        }
    }
    panic!("a payload masquerading as wget from /tmp must still be able to alert BAYES");
}
