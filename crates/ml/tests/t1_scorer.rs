//! Inference parity seam for T1 (issue #617): `ml::BehaviorScorer` (Rust 23-feature vector
//! from an `EventBus`, then `ort`) must reproduce the score the training-side runtime
//! computes (Python vector through onnxruntime), pinned by
//! `crates/ml/tests/fixtures/t1_scorer_golden.jsonl` and its generator
//! `ml/tests/fixtures/gen_t1_scorer_fixture.py`. The vector itself is pinned by
//! `t1_golden.rs`; this pins what the shipped runtime does with it, and the gates around
//! the model: no exec, the conformal threshold, the out-of-distribution bounds.

use std::time::Duration;

use correlator::EventBus;
use ml::{
    BehaviorScorer, FeatureBounds, ScorerError,
    features::t1::{FEATURE_COUNT, FEATURE_NAMES},
};
use schema::Event;

const EVENTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ml/tests/fixtures/t1_events.jsonl"
));
const GOLDEN: &str = include_str!("fixtures/t1_scorer_golden.jsonl");
const MODEL: &[u8] = include_bytes!("fixtures/t1_scorer.onnx");

fn bus() -> EventBus {
    // One 60 s window: every fixture event fits, like `t1_golden.rs`.
    let mut bus = EventBus::new(Duration::from_secs(60));
    for line in EVENTS.lines().filter(|l| !l.trim().is_empty()) {
        bus.push(serde_json::from_str::<Event>(line).expect("t1_events.jsonl is schema::Event"));
    }
    bus
}

struct Case {
    pid: u32,
    generation: Option<u64>,
    score: Option<f32>,
}

fn cases() -> Vec<Case> {
    GOLDEN
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            Case {
                pid: u32::try_from(row["pid"].as_u64().unwrap()).unwrap(),
                generation: row["process_generation"].as_u64(),
                score: row["score"].as_f64().map(|s| s as f32),
            }
        })
        .collect()
}

fn metadata(threshold: f32, min: f32, max: f32) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "threshold": threshold,
        "feature_bounds": FeatureBounds {
            feature_names: FEATURE_NAMES.iter().map(|n| (*n).to_owned()).collect(),
            min_values: vec![min; FEATURE_COUNT],
            max_values: vec![max; FEATURE_COUNT],
        },
    }))
    .unwrap()
}

#[test]
fn scores_match_onnxruntime_reference() {
    let mut scorer = BehaviorScorer::from_onnx_bytes(MODEL).expect("fixture model loads");
    let bus = bus();
    let (mut scored, mut unscored) = (0, 0);
    for case in cases() {
        let got = scorer.score(&bus, case.pid, case.generation).unwrap();
        match case.score {
            None => {
                assert!(
                    got.is_none(),
                    "pid {}: expected no score, got {got:?}",
                    case.pid
                );
                unscored += 1;
            }
            Some(expected) => {
                let got = got.unwrap_or_else(|| panic!("pid {}: no score", case.pid));
                assert!(
                    (got - expected).abs() <= 1e-5,
                    "score drifted for pid {} gen {:?}: ort={got} reference={expected}",
                    case.pid,
                    case.generation,
                );
                scored += 1;
            }
        }
    }
    // Guardrail: a truncated or mis-pathed golden file must not pass silently.
    assert!(
        scored >= 6,
        "suspicious golden file: only {scored} scored cases"
    );
    assert!(unscored >= 1, "the no-exec case must be exercised");
}

#[test]
fn a_recycled_pid_is_scored_as_its_own_incarnation() {
    let mut scorer = BehaviorScorer::from_onnx_bytes(MODEL).unwrap();
    let bus = bus();
    let first = scorer.score(&bus, 100, Some(1)).unwrap().unwrap();
    let second = scorer.score(&bus, 100, Some(2)).unwrap().unwrap();
    assert!(
        first < 0.0 && second > 0.0,
        "the web-server child is anomalous and the quiet `ls` after it is not \
         (first={first}, second={second})"
    );
}

#[test]
fn the_conformal_threshold_keeps_only_anomalous_scores() {
    let meta = metadata(0.0, f32::MIN, f32::MAX);
    let mut scorer = BehaviorScorer::from_onnx_bytes_with_metadata(MODEL, Some(&meta)).unwrap();
    let bus = bus();
    assert!(
        scorer.score(&bus, 100, Some(1)).unwrap().is_some(),
        "anomalous: kept"
    );
    assert!(
        scorer.score(&bus, 100, Some(2)).unwrap().is_none(),
        "normal: dropped"
    );
    assert!(
        scorer
            .score_explained(&bus, 100, Some(2), 3)
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_out_of_bounds_vector_is_an_error_not_a_score() {
    let meta = metadata(0.0, -0.5, 0.5);
    let mut scorer = BehaviorScorer::from_onnx_bytes_with_metadata(MODEL, Some(&meta)).unwrap();
    let err = scorer.score(&bus(), 100, Some(1)).unwrap_err();
    assert!(
        matches!(err, ScorerError::FeatureOutOfBounds { .. }),
        "{err}"
    );
}

#[test]
fn score_explained_agrees_with_score_and_attributes_t1_features() {
    let mut scorer = BehaviorScorer::from_onnx_bytes(MODEL).unwrap();
    let bus = bus();
    for case in cases().into_iter().filter(|c| c.score.is_some()) {
        let bare = scorer
            .score(&bus, case.pid, case.generation)
            .unwrap()
            .unwrap();
        let explained = scorer
            .score_explained(&bus, case.pid, case.generation, 3)
            .unwrap()
            .unwrap();
        assert_eq!(bare, explained.value);
        assert!(explained.attributions.len() <= 3);
        for pair in explained.attributions.windows(2) {
            assert!(pair[0].contribution.abs() >= pair[1].contribution.abs());
        }
        for a in &explained.attributions {
            assert!(
                FEATURE_NAMES.contains(&a.feature.as_str()),
                "{:?}",
                a.feature
            );
        }
    }
}

#[test]
fn bounds_for_other_features_are_refused_at_load() {
    // A 9-feature (T0) bounds sidecar would otherwise skip the guard on 14 features.
    let meta = serde_json::to_vec(&serde_json::json!({
        "threshold": 0.0,
        "feature_bounds": FeatureBounds {
            feature_names: FEATURE_NAMES[..9].iter().map(|n| (*n).to_owned()).collect(),
            min_values: vec![0.0; 9],
            max_values: vec![1.0; 9],
        },
    }))
    .unwrap();
    assert!(BehaviorScorer::from_onnx_bytes_with_metadata(MODEL, Some(&meta)).is_err());
}

#[test]
fn a_model_of_another_width_is_refused_at_load() {
    // The T0 cmdline model is 9 features wide, the T2 correlation model 8.
    for fixture in ["cmdline_scorer.onnx", "correlation_scorer.onnx"] {
        let path = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
        let model = std::fs::read(path).unwrap();
        assert!(
            BehaviorScorer::from_onnx_bytes(&model).is_err(),
            "{fixture}"
        );
    }
}

#[test]
fn a_garbage_model_fails_closed() {
    assert!(BehaviorScorer::from_onnx_bytes(b"not a model").is_err());
}
