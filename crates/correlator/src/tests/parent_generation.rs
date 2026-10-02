//! The belief entity `(ppid, comm)` and the parent's incarnation (#592): a recycled
//! parent pid that spawns a child of the same `comm` must not inherit the previous
//! parent's belief, because that belief is what crosses `BAYES`, the kill trigger.

use super::*;
use crate::bayes::BAYES_THRESHOLD;

const SEC: u64 = 1_000_000_000;
const PARENT: u32 = 50;
const COMM: &str = "evil";

/// An exec of `COMM` by `PARENT`, whose incarnation is `parent_generation`.
fn child_exec(pid: u32, ts_ns: u64, parent_generation: Option<u64>, suspicious: bool) -> Event {
    let mut meta = meta_full(pid, PARENT, COMM, ts_ns);
    meta.parent_process_generation = parent_generation;
    let path = if suspicious {
        "C:\\Users\\x\\AppData\\Roaming\\malware.exe"
    } else {
        "C:\\Windows\\System32\\ordinary.exe"
    };
    exec_with_meta(meta, path)
}

fn external_connect(pid: u32, ts_ns: u64) -> Event {
    connect_to(meta(pid, ts_ns), [185, 220, 101, 1], 4444)
}

/// Drives a first child of `PARENT` to a belief well past the BAYES threshold.
fn compromised_first_child(engine: &mut CorrelationEngine, parent_generation: Option<u64>) -> f32 {
    engine.on_event(child_exec(100, 0, parent_generation, true));
    for i in 0..20u64 {
        engine.on_event(external_connect(100, (i + 1) * 100_000_000));
    }
    let odds = engine.belief_for_entity(PARENT, COMM).unwrap().log_odds;
    assert!(
        odds > BAYES_THRESHOLD,
        "setup: expected a high belief, got {odds}"
    );
    odds
}

fn second_child_belief(engine: &mut CorrelationEngine, parent_generation: Option<u64>) -> f32 {
    // The parent pid is reused later; its child has the same comm and does nothing odd.
    let alerts = engine.on_event(child_exec(101, 30 * SEC, parent_generation, false));
    assert!(
        !alerts.iter().any(|a| a.technique == "BAYES"),
        "an ordinary child must not be condemned by a stale belief: {alerts:?}"
    );
    engine.belief_for_entity(PARENT, COMM).unwrap().log_odds
}

#[test]
fn a_recycled_parent_does_not_inherit_the_previous_parents_belief() {
    let mut engine = CorrelationEngine::new();
    let first = compromised_first_child(&mut engine, Some(1));
    let second = second_child_belief(&mut engine, Some(2));
    assert!(
        second < BAYES_THRESHOLD && second < first,
        "second parent incarnation must start fresh: first={first}, second={second}"
    );
}

#[test]
fn without_stamps_the_belief_is_shared_exactly_as_before() {
    let mut engine = CorrelationEngine::new();
    compromised_first_child(&mut engine, None);
    let second = second_child_belief_unchecked(&mut engine, None);
    assert!(
        second > BAYES_THRESHOLD,
        "no stamp on either side: the entity is shared (old behaviour), got {second}"
    );
}

/// [`second_child_belief`] without the no-BAYES assertion: sharing the entity is the
/// behaviour under test here, and it may legitimately alert.
fn second_child_belief_unchecked(
    engine: &mut CorrelationEngine,
    parent_generation: Option<u64>,
) -> f32 {
    engine.on_event(child_exec(101, 30 * SEC, parent_generation, false));
    engine.belief_for_entity(PARENT, COMM).unwrap().log_odds
}

#[test]
fn a_missing_stamp_on_either_side_cannot_disprove_identity() {
    // Stamped first, unstamped second: shared.
    let mut engine = CorrelationEngine::new();
    compromised_first_child(&mut engine, Some(1));
    assert!(second_child_belief_unchecked(&mut engine, None) > BAYES_THRESHOLD);

    // Unstamped first, stamped second: shared too.
    let mut engine = CorrelationEngine::new();
    compromised_first_child(&mut engine, None);
    assert!(second_child_belief_unchecked(&mut engine, Some(2)) > BAYES_THRESHOLD);
}

#[test]
fn the_stamp_a_belief_adopts_makes_a_later_different_one_a_new_incarnation() {
    let mut engine = CorrelationEngine::new();
    compromised_first_child(&mut engine, None);
    // The first stamp seen is adopted by the shared belief...
    second_child_belief_unchecked(&mut engine, Some(2));
    // ...so a third, different incarnation starts fresh.
    let third = {
        engine.on_event(child_exec(102, 60 * SEC, Some(3), false));
        engine.belief_for_entity(PARENT, COMM).unwrap().log_odds
    };
    assert!(third < BAYES_THRESHOLD, "got {third}");
}

#[test]
fn the_same_parent_incarnation_keeps_its_belief_across_respawns() {
    let mut engine = CorrelationEngine::new();
    compromised_first_child(&mut engine, Some(1));
    let second = second_child_belief_unchecked(&mut engine, Some(1));
    assert!(
        second > BAYES_THRESHOLD,
        "respawns of one parent share the belief, got {second}"
    );
}
