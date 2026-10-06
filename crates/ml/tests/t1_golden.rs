//! Python/Rust parity for the T1 behavior vector (issue #617).
//!
//! Consumes `ml/tests/fixtures/t1_events.jsonl` (the agent's wire format) and
//! `ml/tests/fixtures/t1_golden.jsonl` (`{pid, process_generation, features[23]}` per
//! incarnation), both written by `ml/tests/fixtures/gen_t1_parity.py`. The Python
//! counterpart is `ml/tests/test_t1_parity.py`.
//!
//! A break here means `ml::features::t1` (or one of the three blocks it assembles, or the
//! `EventBus` incarnation filter) has drifted from `synthaea_ml.features.t1`: a T1 model
//! would score vectors it never saw in training. Fix the divergence, or, if the change is
//! intentional, regenerate the fixtures AND retrain.

use std::time::Duration;

use correlator::EventBus;
use ml::features::t1::{FEATURE_COUNT, FEATURE_NAMES, extract_features};
use schema::Event;

const EVENTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ml/tests/fixtures/t1_events.jsonl"
));
const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ml/tests/fixtures/t1_golden.jsonl"
));

/// The golden file is f64 (Python); Rust computes in f32.
fn close(got: f32, expected: f64) -> bool {
    let expected32 = expected as f32;
    (got - expected32).abs() <= 1e-4 * expected32.abs().max(1.0)
}

#[test]
fn vectors_match_the_python_t1_features() {
    // One 60 s window: every fixture event fits, so no eviction and the per-incarnation
    // windows agree with the Python dataset builder's.
    let mut bus = EventBus::new(Duration::from_secs(60));
    for line in EVENTS.lines().filter(|l| !l.trim().is_empty()) {
        let event: Event =
            serde_json::from_str(line).expect("t1_events.jsonl line is a schema::Event");
        bus.push(event);
    }

    let mut checked = 0;
    for line in GOLDEN.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let pid = u32::try_from(row["pid"].as_u64().unwrap()).unwrap();
        let generation = row["process_generation"].as_u64();
        let expected: Vec<f64> = row["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .collect();
        assert_eq!(expected.len(), FEATURE_COUNT);

        let got = extract_features(&bus, pid, generation)
            .unwrap_or_else(|| panic!("pid {pid} gen {generation:?}: no exec in the window"));
        for (i, name) in FEATURE_NAMES.iter().enumerate() {
            assert!(
                close(got[i], expected[i]),
                "pid {pid} gen {generation:?} feature `{name}` drifted from t1.py: \
                 Rust={} Python={} — check ml/tests/fixtures/t1_golden.jsonl",
                got[i],
                expected[i],
            );
        }
        checked += 1;
    }
    // Guardrail: an empty or mis-pathed fixture must not pass silently.
    assert!(
        checked >= 6,
        "suspicious golden file: only {checked} incarnations"
    );
}
