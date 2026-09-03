//! Attribution parity seam, Rust side: the fixture under `tests/fixtures/` pins this
//! crate's forest parsing + attribution walk to the Python reference
//! (`ml/tests/attribution_reference.py`). Regenerate via
//! `ml/tests/fixtures/gen_attribution_fixture.py` only on a deliberate semantic
//! change — never to make a red test green.

use ml::{Forest, top_attributions};

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn load() -> (Forest, serde_json::Value) {
    let golden: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_path("attribution_golden.json")).unwrap(),
    )
    .unwrap();
    let model = std::fs::read(fixture_path(
        golden["model"].as_str().expect("model file name"),
    ))
    .unwrap();
    let forest = Forest::from_onnx_bytes(&model).expect("fixture model must parse");
    (forest, golden)
}

fn case_input(case: &serde_json::Value) -> Vec<f32> {
    case["x"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_f64().unwrap() as f32)
        .collect()
}

#[test]
fn forest_shape_matches_reference() {
    let (forest, golden) = load();
    assert_eq!(forest.n_trees() as u64, golden["n_trees"].as_u64().unwrap());
    assert_eq!(
        forest.n_features() as u64,
        golden["n_features"].as_u64().unwrap()
    );
}

#[test]
fn attributions_match_reference() {
    let (forest, golden) = load();
    const TOL: f64 = 1e-9;
    for (i, case) in golden["cases"].as_array().unwrap().iter().enumerate() {
        let attribution = forest.attribute(&case_input(case)).unwrap();
        let expected: Vec<f64> = case["contributions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .collect();
        assert_eq!(attribution.contributions.len(), expected.len(), "case {i}");
        for (f, (got, want)) in attribution.contributions.iter().zip(&expected).enumerate() {
            assert!(
                (got - want).abs() <= TOL,
                "case {i} feature {f}: got {got}, reference {want}"
            );
        }
        let depth = case["depth"].as_f64().unwrap();
        let expected_depth = case["expected_depth"].as_f64().unwrap();
        assert!((attribution.depth - depth).abs() <= TOL, "case {i} depth");
        assert!(
            (attribution.expected_depth - expected_depth).abs() <= TOL,
            "case {i} expected_depth"
        );
    }
}

#[test]
fn contributions_telescope() {
    // The decomposition is exact by construction: expected - actual == Σ contributions.
    let (forest, golden) = load();
    for (i, case) in golden["cases"].as_array().unwrap().iter().enumerate() {
        let attribution = forest.attribute(&case_input(case)).unwrap();
        let total: f64 = attribution.contributions.iter().sum();
        let gap = attribution.expected_depth - attribution.depth;
        assert!(
            (total - gap).abs() <= 1e-9,
            "case {i}: Σ contributions {total} vs expected-actual gap {gap}"
        );
    }
}

#[test]
fn top_attributions_are_schema_ready() {
    let (forest, golden) = load();
    let names = ["f0", "f1", "f2", "f3", "f4", "f5", "f6"];
    // The last fixture case is the everything-out outlier.
    let cases = golden["cases"].as_array().unwrap();
    let x = case_input(cases.last().unwrap());
    let attribution = forest.attribute(&x).unwrap();
    let top = top_attributions(&attribution, &x, &names, 3);
    assert_eq!(top.len(), 3);
    // Ordered by |contribution| descending, and carries the feature value seen.
    assert!(top[0].contribution.abs() >= top[1].contribution.abs());
    assert!(top[1].contribution.abs() >= top[2].contribution.abs());
    let idx = names.iter().position(|n| *n == top[0].feature).unwrap();
    assert_eq!(top[0].value, f64::from(x[idx]));
    // An across-the-board outlier's strongest signals push toward anomalous.
    assert!(top[0].contribution > 0.0);
}

#[test]
fn short_input_is_rejected() {
    let (forest, _) = load();
    assert!(forest.attribute(&[0.0]).is_err());
}

#[test]
fn garbage_fails_closed() {
    assert!(Forest::from_onnx_bytes(b"not a model").is_err());
    assert!(Forest::from_onnx_bytes(&[]).is_err());
    // Truncation anywhere must error, never panic or misparse.
    let model = std::fs::read(fixture_path("isoforest_small.onnx")).unwrap();
    for cut in [1, model.len() / 2, model.len() - 1] {
        assert!(Forest::from_onnx_bytes(&model[..cut]).is_err(), "cut {cut}");
    }
}
