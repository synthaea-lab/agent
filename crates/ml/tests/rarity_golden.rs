//! Python/Rust golden parity test for the rarity feature (ADR-0020, #640).
//!
//! Consumes `ml/tests/fixtures/rarity_golden.jsonl`, written by
//! `ml/tests/fixtures/gen_rarity_golden.py` from `rarity.py`. The Python counterpart is
//! `ml/tests/test_rarity_golden.py`.
//!
//! If this breaks, `ml::features::rarity::extract_features` has drifted from the Python
//! definition: a model trained on the rarity feature would score vectors at inference time it
//! never saw during training. Fix the divergence, or, if the change is intentional, regenerate
//! the golden file AND retrain.

use std::collections::HashSet;

use ml::features::rarity::{CommonSet, FEATURE_COUNT, FEATURE_NAMES, extract_features};
use serde_json::Value;

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ml/tests/fixtures/rarity_golden.jsonl"
));

/// A snapshot as a plain set: the extractor only needs a membership test and the coverage.
struct Snapshot {
    common: HashSet<String>,
    hosts_covered: u64,
}

impl CommonSet for Snapshot {
    fn contains(&self, sha256: &str) -> bool {
        self.common.contains(sha256)
    }

    fn hosts_covered(&self) -> u64 {
        self.hosts_covered
    }
}

fn snapshot_from_json(value: &Value) -> Option<Snapshot> {
    if value.is_null() {
        return None;
    }
    Some(Snapshot {
        common: value["common"]
            .as_array()
            .expect("common must be a list")
            .iter()
            .map(|h| h.as_str().expect("hash must be a string").to_string())
            .collect(),
        hosts_covered: value["hosts_covered"]
            .as_u64()
            .expect("hosts_covered must be an unsigned integer"),
    })
}

#[test]
fn parity_with_rarity_py() {
    let mut cases = 0;
    for line in GOLDEN.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).expect("invalid golden line");
        let name = row["name"].as_str().expect("name field");
        let sha256 = row["sha256"].as_str();
        let snapshot = snapshot_from_json(&row["snapshot"]);
        let min_hosts = row["min_hosts"].as_u64().expect("min_hosts field");
        let expected: Vec<f64> = row["features"]
            .as_array()
            .expect("features field")
            .iter()
            .map(|v| v.as_f64().expect("non-numeric feature"))
            .collect();
        assert_eq!(expected.len(), FEATURE_COUNT);

        let got = extract_features(
            sha256,
            snapshot.as_ref().map(|s| s as &dyn CommonSet),
            min_hosts,
        );
        for (i, feature_name) in FEATURE_NAMES.iter().enumerate() {
            assert_eq!(
                f64::from(got[i]),
                expected[i],
                "feature `{feature_name}` drifted from rarity.py for test case '{name}': \
                 Rust={} Python={} -- check ml/tests/fixtures/rarity_golden.jsonl",
                got[i],
                expected[i],
            );
        }
        cases += 1;
    }
    // Guardrail: an empty or mis-pathed golden file must not pass silently.
    assert!(cases >= 20, "suspicious golden file: only {cases} cases");
}
