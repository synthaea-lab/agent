# Phase 3 Integration Guide (Issue #46)

**Status:** Blocked by #13 (ML scorer integration), #14 (cmdline scorer), #47 (agent integration)

This document describes how to complete Phase 3 of issue #46 (correlator no-score handling) once the ML scorer is integrated into the agent.

## Current State

Phases 1-2 are complete:
- ✅ **Phase 1:** Conformal calibration (Python)
  - `ml/synthaea_ml/calibration/calibrate_conformal.py`
  - TrainingRecord schema v3 with `conformal_calibration` and `feature_bounds`
  - Training scripts updated (train_linux.py, train_windows.py, train_correlation.py)
  - `model_metadata.json` exported alongside `model.onnx`

- ✅ **Phase 2:** OOD guards (Rust)
  - `crates/ml/src/bounds.rs` with `FeatureBounds::validate`
  - `ScorerError::FeatureOutOfBounds` variant
  - `CmdlineScorer::from_onnx_bytes_with_metadata` loads bounds from metadata
  - `CorrelationScorer` has same OOD validation
  - Legacy models (no metadata) still work

## Phase 3: Correlator Integration

### Goal

Allow the correlator's `update_belief` to accept an optional ML LLR contribution, with clean semantics for "no score available" (gating, OOD rejection, errors).

### Changes Required

#### 1. Update `bayes::update_belief` Signature

**File:** `crates/correlator/src/bayes.rs:123`

Current:
```rust
pub(crate) fn update_belief(state: &mut BeliefState, v: &BehaviorVector, now_ns: u64)
```

Proposed:
```rust
pub(crate) fn update_belief(
    state: &mut BeliefState,
    v: &BehaviorVector,
    ml_llr: Option<f32>,  // NEW: ML contribution (None = no score)
    now_ns: u64,
)
```

Add before `state.last_update_ns = now_ns`:
```rust
// ML contribution: only if we have a score
if let Some(llr) = ml_llr {
    state.log_odds += llr;
}
// If ml_llr is None, skip this contribution entirely (no evidence)
```

**Key semantics:**
- `None` means "I don't know" (not "benign")
- OOD rejection → `None` → no ML evidence contribution
- T1 hand-calibrated LLRs still apply normally

#### 2. Update Call Sites in `engine.rs`

**File:** `crates/correlator/src/engine.rs`

Find all calls to `update_belief` and add the `ml_llr` parameter:

```rust
// OLD:
update_belief(&mut belief, bv, now_ns);

// NEW:
update_belief(&mut belief, bv, None, now_ns);  // Temporarily pass None until agent wiring
```

Once agent integration (#47) is complete, the agent sink will compute `ml_llr` and pass it through the correlator's public API.

#### 3. Agent Integration Point (Pending #47)

**File:** `agent/src/sink.rs` (future work)

Wiring pattern:

```rust
// After engine.on_event(event)
if let Some(bv) = engine.behavior_vector_for_pid(pid) {
    // Try to get ML score
    let ml_llr = match ml_scorer.score(&engine.bus, pid) {
        Ok(Some(score)) => Some(ml::correlation::score_to_llr(score)),
        Ok(None) => None,  // Gated (< MIN_EVENT_COUNT)
        Err(ScorerError::FeatureOutOfBounds { .. }) => {
            // Log OOD rejection for telemetry
            tracing::warn!("ML scorer rejected OOD vector for pid {pid}");
            None  // Treat OOD as no score
        }
        Err(e) => {
            tracing::error!("ML scorer error: {e}");
            None  // Fail open: skip ML contribution
        }
    };

    // Update belief with optional ML LLR
    engine.update_belief_with_ml(entity_key, bv, ml_llr)?;
}
```

**Error handling policy:**
- `FeatureOutOfBounds` → log warning, treat as `None`
- Other errors → log error, treat as `None` (fail open)
- Gating (`event_count < MIN_EVENT_COUNT`) → `None` (no evidence yet)

### Testing

#### Unit Tests

**File:** `crates/correlator/tests/bayes.rs` (add after Phase 3 changes)

```rust
#[test]
fn test_update_belief_with_ml_llr() {
    let mut state = BeliefState::new(0);
    let v = BehaviorVector::default();

    // With ML contribution
    update_belief(&mut state, &v, Some(1.5), 1_000_000_000);
    assert!(state.log_odds > PRIOR_LOG_ODDS);  // ML pushed belief up
}

#[test]
fn test_update_belief_ml_none_skipped() {
    let mut state = BeliefState::new(0);
    let v = BehaviorVector::default();

    // Without ML contribution
    update_belief(&mut state, &v, None, 1_000_000_000);
    // Only hand-calibrated LLRs applied
}
```

#### End-to-End Verification (After #47)

1. **Run agent with ML scorer on benign baseline**
   - Check telemetry: no OOD rejections on training-distribution data
   - Verify belief updates include ML LLR contributions

2. **Inject synthetic OOD vector**
   - Example: cmdline length = 1M chars (far outside training bounds)
   - Check telemetry: OOD rejection logged
   - Verify: no ML LLR contribution, hand-calibrated LLRs still apply

3. **Inject low-event-count process**
   - Example: process with only 1-2 events in correlator window
   - Check: `ml_llr = None` due to `MIN_EVENT_COUNT` gate
   - Verify: no ML contribution, no error

## Backward Compatibility

- Legacy models (no `model_metadata.json`) → `bounds = None` → no OOD validation
- Existing correlator code → pass `ml_llr = None` until agent wiring is complete
- Graceful degradation: system works without ML scorer, just missing that evidence term

## Migration Checklist

- [ ] Update `bayes::update_belief` signature (add `ml_llr` parameter)
- [ ] Update all `update_belief` call sites in `engine.rs` (pass `None` initially)
- [ ] Expose `update_belief_with_ml` or similar in correlator public API (for agent)
- [ ] Implement agent sink wiring (#47)
- [ ] Add unit tests for `ml_llr = Some(...)` and `ml_llr = None`
- [ ] End-to-end test: benign baseline (no OOD), OOD injection, low event count
- [ ] Update `docs/detection/ml.md` with Phase 3 semantics

## Timeline

Phase 3 can proceed once:
1. ML scorer is integrated into agent (#13, #14)
2. Agent has access to `CorrelationScorer` (#47)
3. Correlator exposes an API to pass `ml_llr` from agent sink

Estimated effort: 1-2 hours for correlator changes + agent wiring, 1-2 hours for tests.
