//! The "image is not in the fleet's common set" evidence (ADR-0020, issue #76): a weak,
//! capped term on an entity's belief. It can never be a verdict on its own.

use super::*;
use crate::bayes::{BAYES_THRESHOLD, RARITY_LLR, RARITY_MAX_TOTAL_LLR};

/// An engine that has seen one exec of `pid`, so its entity has a belief.
fn engine_with_exec(pid: u32) -> CorrelationEngine {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(pid, 1_000_000_000));
    engine
}

fn log_odds(engine: &CorrelationEngine, pid: u32) -> f32 {
    engine
        .belief_for_pid(pid)
        .expect("belief expected")
        .log_odds
}

// Whatever the rarity evidence does, it starts from the prior: even its full allowance cannot
// bring a belief at the prior near the threshold. Checked when the crate compiles.
const _: () = assert!(RARITY_LLR > 0.0 && RARITY_LLR <= RARITY_MAX_TOTAL_LLR);
const _: () = assert!(PRIOR_LOG_ODDS + RARITY_MAX_TOTAL_LLR < BAYES_THRESHOLD - 3.0);

#[test]
fn a_rare_image_raises_the_belief_by_the_stated_weight() {
    let mut engine = engine_with_exec(100);
    let before = log_odds(&engine, 100);

    assert!(engine.apply_rarity_evidence(100, None));

    assert!((log_odds(&engine, 100) - before - RARITY_LLR).abs() < 1e-6);
}

#[test]
fn rarity_alone_can_never_approach_the_alert_threshold() {
    // A build host runs thousands of binaries it has just compiled, every one of them "not in
    // the common set": the sum of those must stay bounded.
    let mut engine = engine_with_exec(100);
    let before = log_odds(&engine, 100);

    for _ in 0..10_000 {
        engine.apply_rarity_evidence(100, None);
    }

    let gained = log_odds(&engine, 100) - before;
    assert!(gained <= RARITY_MAX_TOTAL_LLR + 1e-4, "gained {gained}");
    assert!(log_odds(&engine, 100) < BAYES_THRESHOLD);
}

#[test]
fn the_allowance_comes_back_as_the_belief_decays() {
    let mut engine = engine_with_exec(100);
    for _ in 0..100 {
        engine.apply_rarity_evidence(100, None);
    }
    assert!(
        !engine_applies_more(&mut engine, 100),
        "the allowance is spent"
    );

    // An hour later the belief has decayed toward the prior (5 minute time constant), and the
    // allowance with it: a new rare image counts again.
    engine.on_event(exec_event(100, 3_700_000_000_000));

    assert!(engine_applies_more(&mut engine, 100));
}

/// Whether one more application still moves the belief.
fn engine_applies_more(engine: &mut CorrelationEngine, pid: u32) -> bool {
    let before = log_odds(engine, pid);
    engine.apply_rarity_evidence(pid, None);
    log_odds(engine, pid) - before > 1e-4
}

#[test]
fn rarity_is_one_more_term_on_top_of_evidence_the_belief_already_has() {
    // A process that already looks suspicious gets the same increment: the evidence combines,
    // it is not skipped once other evidence exists.
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(200, 1_000_000_000));
    engine.on_event(connect_event(200, 1_100_000_000));
    let before = log_odds(&engine, 200);
    assert!(
        before > PRIOR_LOG_ODDS,
        "the connect already moved the belief"
    );

    assert!(engine.apply_rarity_evidence(200, None));

    assert!((log_odds(&engine, 200) - before - RARITY_LLR).abs() < 1e-6);
}

#[test]
fn a_pid_the_correlator_has_not_seen_gets_no_evidence() {
    let mut engine = CorrelationEngine::new();
    assert!(!engine.apply_rarity_evidence(4242, None));
}

#[test]
fn a_different_incarnation_of_the_pid_gets_no_evidence() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(stamped(exec_event(300, 1_000_000_000), 5));
    let before = log_odds(&engine, 300);

    assert!(!engine.apply_rarity_evidence(300, Some(6)));

    assert!((log_odds(&engine, 300) - before).abs() < 1e-9);
}
