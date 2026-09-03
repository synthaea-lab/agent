//! Content suite for rules/yara: every shipped rule file must compile (hard failure
//! naming the file — same stance as the sigma content suite), and every rule must
//! fire on a crafted matching sample.

use yara::RuleSet;

fn content_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara")
}

#[test]
fn every_shipped_rule_compiles() {
    let rules = RuleSet::load_dir(&content_dir()).expect("shipped YARA content must compile");
    assert!(rules.rule_file_count() >= 1, "no YARA rule files found");
}

#[test]
fn every_shipped_rule_fires_on_its_sample() {
    // One (rule identifier, matching bytes) pair per shipped rule.
    let samples: &[(&str, &[u8])] = &[(
        "synthaea_lab_payload",
        b"#!/bin/sh\n# SYNTHAEA-LAB-PAYLOAD\necho hi\n",
    )];
    let rules = RuleSet::load_dir(&content_dir()).unwrap();
    assert_eq!(
        samples.len(),
        rules.rule_file_count(),
        "one matching sample per shipped rule file — add the sample for the new rule"
    );
    for (ident, bytes) in samples {
        let p = std::env::temp_dir().join(format!("yara-content-{}-{ident}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        let hits = rules.scan_file(&p).unwrap();
        assert!(
            hits.iter().any(|h| h == ident),
            "rule `{ident}` did not fire (hits: {hits:?})"
        );
    }
}
