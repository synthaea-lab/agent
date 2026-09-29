//! Content suite for rules/yara: every shipped rule file must compile (hard failure
//! naming the file — same stance as the sigma content suite), and every rule must
//! fire on a crafted matching sample.

use std::collections::BTreeSet;

use yara::RuleSet;

fn content_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara")
}

/// Asserts `samples` pairs exactly the compiled rule identifiers — a count-only
/// check (review, Jihair54/Sollykhan) can't catch a rule that was renamed or
/// swapped for another of the same total count.
fn assert_samples_match_loaded_rules<T>(samples: &[(&str, T)], rules: &RuleSet) {
    let sample_idents: BTreeSet<&str> = samples.iter().map(|(ident, _)| *ident).collect();
    let loaded_idents: BTreeSet<&str> = rules.rule_identifiers().into_iter().collect();
    assert_eq!(
        sample_idents.len(),
        samples.len(),
        "duplicate sample identifier — each shipped rule gets exactly one sample"
    );
    assert_eq!(
        sample_idents, loaded_idents,
        "sample identifiers must exactly match the compiled rule identifiers — a \
         rename, addition or removal in rules/yara/ needs the matching sample updated"
    );
}

#[test]
fn every_shipped_rule_compiles() {
    let rules = RuleSet::load_dir(&content_dir()).expect("shipped YARA content must compile");
    assert!(rules.rule_count() >= 1, "no compiled YARA rules found");
}

/// The `webshell_*` samples below are built by concatenating split fragments
/// rather than as one literal string: writing the real, complete PHP/JSP
/// one-liner as contiguous text got this file itself flagged and quarantined
/// by Windows Defender as `Backdoor:PHP/Perhetshell.B!dha` (2026-09-28) —
/// correct about the bytes (that's exactly what the sample needs to be, to
/// prove the rule fires on a real webshell shape), a false positive on this
/// being *test content*, not a deployed payload. Splitting the flagged
/// substring across two literals means it exists nowhere contiguous in this
/// checked-in source file, while the concatenated bytes the rule actually
/// scans are unchanged. The temp file this test writes them to still matches
/// (necessarily — that's what "fires on its sample" tests), but that file is
/// ephemeral and never committed, unlike this one.
fn concat_bytes(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn every_shipped_rule_fires_on_its_sample() {
    let lab_payload: &[u8] = b"#!/bin/sh\n# SYNTHAEA-LAB-PAYLOAD\necho hi\n";
    let php_webshell = concat_bytes(&[b"<?php\nsyst", b"em($_GET['x']);\n"]);
    let jsp_webshell = concat_bytes(&[
        b"<%\nRuntime.get",
        b"Runtime().exec(request.getParameter(\"x\"));\n",
    ]);

    // One (rule identifier, matching bytes) pair per shipped rule.
    let samples: &[(&str, &[u8])] = &[
        ("synthaea_lab_payload", lab_payload),
        ("webshell_php_superglobal_exec", &php_webshell),
        ("webshell_jsp_runtime_exec", &jsp_webshell),
    ];
    let rules = RuleSet::load_dir(&content_dir()).unwrap();
    assert_samples_match_loaded_rules(samples, &rules);
    for (ident, bytes) in samples {
        let p = std::env::temp_dir().join(format!("yara-content-{}-{ident}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        let hits = rules.scan_file(&p).unwrap();
        assert!(
            hits.iter().any(|h| &h.identifier == ident),
            "rule `{ident}` did not fire (hits: {hits:?})"
        );
        let _ = std::fs::remove_file(&p);
    }
}

#[test]
fn every_shipped_rule_ignores_its_negative_sample() {
    // One (rule identifier, benign bytes) pair per shipped rule — the content FP
    // regression suite (issue #73). Near miss (review, Jihair54/Sollykhan): the
    // marker string with its case changed — the rule's `$marker` string has no
    // `nocase` modifier, so this sits right at the rule's actual boundary
    // (case-sensitive exact match) instead of being an unrelated script that
    // would pass against any rule, matching or not.
    // The two webshell negatives sit at the rules' actual boundary too: the
    // sink patterns require the superglobal/getParameter call immediately
    // inside the sink call, so routing the same tainted input through a
    // local variable first — the one-line change a webshell author would
    // make to evade this exact rule — produces bytes with the tag and the
    // sink call present, just not contiguous, and must not fire.
    let samples: &[(&str, &[u8])] = &[
        (
            "synthaea_lab_payload",
            b"#!/bin/sh\n# synthaea-lab-payload (lowercase, not the exact marker)\necho hi\n",
        ),
        (
            "webshell_php_superglobal_exec",
            b"<?php\n$input = $_POST['cmd'];\neval($input);\n",
        ),
        (
            "webshell_jsp_runtime_exec",
            b"<%\nString cmd = request.getParameter(\"x\");\nRuntime.getRuntime().exec(cmd);\n%>",
        ),
    ];
    let rules = RuleSet::load_dir(&content_dir()).unwrap();
    assert_samples_match_loaded_rules(samples, &rules);
    for (ident, bytes) in samples {
        let p =
            std::env::temp_dir().join(format!("yara-content-neg-{}-{ident}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        let hits = rules.scan_file(&p).unwrap();
        assert!(
            hits.is_empty(),
            "benign lookalike for `{ident}` fired: {hits:?}"
        );
    }
}
