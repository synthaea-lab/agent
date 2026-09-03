//! Inference parity seam: `CmdlineScorer` (Rust feature extraction through `ort`) must
//! reproduce the scores the training-side runtime produces (Python feature extraction
//! through onnxruntime), pinned by `ml/tests/fixtures/scorer_golden.json` and its
//! `gen_scorer_fixture.py` generator.
//!
//! This closes the loop the feature and attribution seams leave open: features_golden
//! pins the vector, attribution_golden pins the explanation, and this pins the score
//! the shipped runtime computes from that vector.

use ml::CmdlineScorer;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn golden() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(fixture_path("scorer_golden.json")).unwrap())
        .unwrap()
}

fn scorer() -> CmdlineScorer {
    let model = std::fs::read(fixture_path("cmdline_scorer.onnx")).unwrap();
    CmdlineScorer::from_onnx_bytes(&model).expect("fixture model must load")
}

#[test]
fn scores_match_onnxruntime_reference() {
    let mut scorer = scorer();
    // f32 inference vs the f32 golden: only rounding should differ.
    const TOL: f32 = 1e-5;
    for case in golden()["cases"].as_array().unwrap() {
        let cmdline = case["cmdline"].as_str().unwrap();
        let expected = case["score"].as_f64().unwrap() as f32;
        let got = scorer.score(cmdline).unwrap();
        assert!(
            (got - expected).abs() <= TOL,
            "score drifted for {cmdline:?}: ort={got} reference={expected}",
        );
    }
}

#[test]
fn score_explained_agrees_with_score_and_attributes() {
    let mut scorer = scorer();
    for case in golden()["cases"].as_array().unwrap() {
        let cmdline = case["cmdline"].as_str().unwrap();
        let bare = scorer.score(cmdline).unwrap();
        let explained = scorer.score_explained(cmdline, 3).unwrap();
        assert_eq!(
            bare, explained.value,
            "explained score must equal bare score"
        );
        assert!(explained.attributions.len() <= 3);
        // Attributions are ordered by |contribution| and name real features.
        for w in explained.attributions.windows(2) {
            assert!(w[0].contribution.abs() >= w[1].contribution.abs());
        }
        for a in &explained.attributions {
            assert!(
                ml::features::cmdline::FEATURE_NAMES.contains(&a.feature.as_str()),
                "unknown feature {:?}",
                a.feature
            );
        }
    }
}

#[test]
fn wrong_feature_arity_is_rejected() {
    // The attribution fixture from #47 is a 7-feature model — loading it as a cmdline
    // scorer (9 features) must fail at load, not mis-score silently.
    let model = std::fs::read(fixture_path("isoforest_small.onnx")).unwrap();
    assert!(CmdlineScorer::from_onnx_bytes(&model).is_err());
}

#[test]
fn garbage_model_fails_closed() {
    assert!(CmdlineScorer::from_onnx_bytes(b"not a model").is_err());
}
