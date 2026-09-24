//! Python/Rust golden parity test for the lineage features.
//!
//! Consumes `ml/tests/fixtures/lineage_golden.jsonl`, created manually with test cases
//! covering all lineage feature combinations. The Python counterpart is
//! `ml/tests/test_lineage_golden.py`.
//!
//! If this breaks, `ml::features::lineage::extract_features` has drifted from the
//! Python definition: the ONNX model would score vectors at inference time it never
//! saw during training. Fix the divergence — or, if the change is intentional,
//! regenerate the golden file AND retrain the models.

use ml::features::lineage::{FEATURE_NAMES, extract_features};
use schema::ExecEvent;
use schema::fixtures::meta;
use serde_json::Value;

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ml/tests/fixtures/lineage_golden.jsonl"
));

/// The golden file is f64 (Python); the Rust side computes in f32. Tolerance is loose
/// relative to f32 rounding (~1e-7) but strict relative to any real definition drift.
fn close(got: f32, expected: f64) -> bool {
    let expected32 = expected as f32;
    (got - expected32).abs() <= 1e-4 * expected32.abs().max(1.0)
}

/// Construct an `ExecEvent` from a JSON event dict (from golden fixture).
fn event_from_json(value: &Value) -> ExecEvent {
    let image_path = value["image_path"].as_str().unwrap_or("").to_string();
    let cmdline = value["cmdline"].as_str().unwrap_or("").to_string();
    let parent_comm = value
        .get("parent_comm")
        .and_then(|v| v.as_str())
        .map(String::from);
    let parent_image_path = value
        .get("parent_image_path")
        .and_then(|v| v.as_str())
        .map(String::from);

    ExecEvent {
        meta: meta(),
        image_path,
        cmdline,
        argv: vec![],
        parent_comm,
        parent_image_path,
        sha256: None,
        signature: None,
        env_security: vec![],
    }
}

#[test]
fn parity_with_lineage_py() {
    let mut cases = 0;
    for line in GOLDEN.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).expect("invalid golden line");
        let name = row["name"].as_str().expect("name field");
        let event_json = &row["event"];
        let expected: Vec<f64> = row["features"]
            .as_array()
            .expect("features field")
            .iter()
            .map(|v| v.as_f64().expect("non-numeric feature"))
            .collect();
        assert_eq!(expected.len(), FEATURE_NAMES.len());

        let event = event_from_json(event_json);
        let got = extract_features(&event);
        for (i, feature_name) in FEATURE_NAMES.iter().enumerate() {
            assert!(
                close(got[i], expected[i]),
                "feature `{feature_name}` drifted from lineage.py for test case '{name}': \
                 Rust={} Python={} — check ml/tests/fixtures/lineage_golden.jsonl",
                got[i],
                expected[i],
            );
        }
        cases += 1;
    }
    // Guardrail: an empty or mis-pathed golden file must not pass silently.
    assert!(cases >= 15, "suspicious golden file: only {cases} cases");
}
