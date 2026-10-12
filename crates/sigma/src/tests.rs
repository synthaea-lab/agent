//! Sigma engine tests — load-time validation and evaluation behavior, including
//! the regression tests for the review findings on the migration PRs.

use schema::{EventMeta, ExecEvent};

use crate::{
    engine::parse_rule_yaml,
    eval::{eval_rule_exec, glob_match},
    rule::SigmaRule,
    validate::validate,
};

fn exec(image: &str, cmdline: &str) -> ExecEvent {
    ExecEvent {
        meta: EventMeta {
            pid: 1,
            comm: "test".into(),
            ..schema::fixtures::meta()
        },
        image_path: image.to_string(),
        cmdline: cmdline.to_string(),
        ..schema::fixtures::exec()
    }
}

fn parse(yaml: &str) -> SigmaRule {
    let rule: SigmaRule = parse_rule_yaml(yaml).unwrap();
    // Under a platform segment so the metadata validator's directory check passes —
    // these fixtures test eval/selector behavior, not the platform check itself.
    validate(&rule, "<test>/linux/rule.yml").unwrap();
    rule
}

#[test]
fn glob_match_star_any() {
    assert!(glob_match("c:\\windows\\system32\\cmd.exe", "*\\cmd.exe"));
    assert!(glob_match(
        "c:\\windows\\system32\\cmd.exe",
        "c:\\windows\\*"
    ));
    assert!(glob_match("payload", "*payload*"));
    assert!(!glob_match("notepad.exe", "*\\cmd.exe"));
}

#[test]
fn eval_rule_endswith_image() {
    let rule = parse(
        r#"
title: Test cmd
description: test
tags:
  - attack.t1059
level: medium
falsepositives:
  - none known
detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection
"#,
    );
    let ev = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe");
    assert!(eval_rule_exec(&rule, &ev).is_some());
    let ev2 = exec("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
    assert!(eval_rule_exec(&rule, &ev2).is_none());
}

#[test]
fn eval_rule_commandline_contains() {
    let rule = parse(
        r#"
title: Base64 PowerShell
description: PS encoded
tags:
  - attack.t1059.001
level: high
falsepositives:
  - none known
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'encodedcommand'
  condition: selection
"#,
    );
    let ev = exec(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -EncodedCommand ZWNobyBoZWxsbw==",
    );
    assert!(eval_rule_exec(&rule, &ev).is_some());
    let ev2 = exec(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -NoProfile",
    );
    assert!(eval_rule_exec(&rule, &ev2).is_none());
}

/// Issue #74: `SigmaAlert.techniques` is the ATT&CK-tag subset of `tags`, normalized
/// to bare uppercase form, with non-technique tactic tags filtered out.
#[test]
fn eval_rule_extracts_techniques_from_tags() {
    let rule = parse(
        r#"
title: Base64 PowerShell
description: PS encoded
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
level: high
falsepositives:
  - none known
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
"#,
    );
    let ev = exec("C:\\Windows\\System32\\powershell.exe", "powershell.exe");
    let alert = eval_rule_exec(&rule, &ev).unwrap();
    assert_eq!(alert.techniques, vec!["T1059.001", "T1027"]);
}

#[test]
fn eval_rule_keywords() {
    let rule = parse(
        r#"
title: Suspicious keyword
description: test
tags:
  - attack.t1003
level: high
falsepositives:
  - none known
detection:
  selection:
    - mimikatz
    - sekurlsa
  condition: selection
"#,
    );
    let ev = exec("C:\\temp\\mimikatz.exe", "C:\\temp\\mimikatz.exe");
    assert!(eval_rule_exec(&rule, &ev).is_some());
    let ev2 = exec("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
    assert!(eval_rule_exec(&rule, &ev2).is_none());
}

#[test]
fn parent_image_matches_only_with_lineage() {
    let rule = parse(
        r#"
title: Office spawning shell
description: test
tags:
  - attack.t1059
level: high
falsepositives:
  - none known
detection:
  selection:
    ParentImage|endswith: '\winword.exe'
    Image|endswith: '\cmd.exe'
  condition: selection
"#,
    );
    let mut ev = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami");
    assert!(
        eval_rule_exec(&rule, &ev).is_none(),
        "no lineage — must not match"
    );
    ev.parent_image_path = Some("C:\\Program Files\\Office\\winword.exe".into());
    assert!(eval_rule_exec(&rule, &ev).is_some());
}

#[test]
fn empty_selection_is_rejected_not_match_everything() {
    // Review finding: `selection: {}` matched EVERY event (vacuous all()).
    let rule: SigmaRule =
        parse_rule_yaml("title: Empty\ndetection:\n  selection: {}\n  condition: selection\n")
            .unwrap();
    let err = validate(&rule, "<t>").unwrap_err();
    assert!(err.to_string().contains("empty selection"), "{err}");
}

#[test]
fn interior_wildcards_are_rejected_at_load() {
    // Review finding: `C:\*\cmd.exe` loaded fine and then never matched.
    let rule: SigmaRule = parse_rule_yaml(
        "title: Interior\ndetection:\n  selection:\n    Image: 'C:\\*\\cmd.exe'\n  condition: selection\n",
    )
    .unwrap();
    let err = validate(&rule, "<t>").unwrap_err();
    assert!(err.to_string().contains("interior wildcard"), "{err}");
}

#[test]
fn keyword_wildcards_match_like_field_globs() {
    let rule = parse(
        "title: KW\ntags:\n  - attack.t1003\nlevel: high\nfalsepositives:\n  - none known\ndetection:\n  selection:\n    - '*mimikatz*'\n  condition: selection\n",
    );
    let ev = exec("C:\\t\\x.exe", "run mimikatz please");
    assert!(eval_rule_exec(&rule, &ev).is_some());
}

#[test]
fn modifier_case_is_insensitive_at_eval() {
    let rule = parse(
        "title: Case\ntags:\n  - attack.t1059\nlevel: medium\nfalsepositives:\n  - none known\ndetection:\n  selection:\n    Image|EndsWith: '\\cmd.exe'\n  condition: selection\n",
    );
    let ev = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe");
    assert!(
        eval_rule_exec(&rule, &ev).is_some(),
        "EndsWith must behave as endswith"
    );
}

#[test]
fn unsupported_constructs_are_rejected_at_load() {
    let complex_condition: SigmaRule = parse_rule_yaml(
        r#"
title: Complex
detection:
  selection:
    Image: 'x'
  filter:
    Image: 'y'
  condition: selection and not filter
"#,
    )
    .unwrap();
    let err = validate(&complex_condition, "<t>").unwrap_err();
    assert!(err.to_string().contains("condition"), "{err}");

    let bad_field: SigmaRule = parse_rule_yaml(
        r#"
title: Bad field
detection:
  selection:
    TargetFilename|endswith: '.dll'
  condition: selection
"#,
    )
    .unwrap();
    let err = validate(&bad_field, "<t>").unwrap_err();
    assert!(err.to_string().contains("TargetFilename"), "{err}");

    let bad_modifier: SigmaRule = parse_rule_yaml(
        r#"
title: Bad modifier
detection:
  selection:
    CommandLine|re: '.*'
  condition: selection
"#,
    )
    .unwrap();
    let err = validate(&bad_modifier, "<t>").unwrap_err();
    assert!(err.to_string().contains("modifier `re`"), "{err}");
}

/// Robustness: patterns and haystacks are content-supplied (rules) and
/// event-supplied (an attacker names its own processes and command lines) —
/// the matcher must never panic, including on multibyte boundaries where a
/// byte-indexed slice would.
#[test]
fn glob_match_never_panics_on_hostile_inputs() {
    let hostile = [
        "",
        "*",
        "**",
        "*****************",
        "*café*",
        "état*",
        "\u{FFFD}\u{202E}evil",
        "a*b", // interior star: literal per the doc ("start/end only")
        "\0null\0",
        "𝕊𝕪𝕟𝕥𝕙𝕒𝕖𝕒",
    ];
    for pattern in hostile {
        for haystack in hostile {
            let _ = glob_match(haystack, pattern);
        }
    }
    // Long inputs: the minimal matcher is contains/prefix/suffix — linear, but
    // pin that a big haystack with a big pattern completes and doesn't panic.
    let long_h = "x".repeat(64 * 1024);
    let long_p = format!("*{}*", "y".repeat(1024));
    assert!(!glob_match(&long_h, &long_p));
}

/// Interior `*` is documented as literal (start/end only) — pinned so a future
/// "full glob" upgrade is a deliberate semantic change, not an accident.
#[test]
fn glob_match_interior_star_is_literal() {
    assert!(glob_match("a*b", "a*b"));
    assert!(!glob_match("axb", "a*b"));
}

// --- the YAML parser: serde-saphyr in place of serde_yaml (#790) -----------------------------

const RULE_HEAD: &str =
    "title: T\ndescription: d\ntags: [attack.t1059]\nlevel: medium\nfalsepositives: [x]\n";

fn rule_with_detection(body: &str) -> String {
    format!("{RULE_HEAD}detection:\n{body}")
}

#[test]
fn a_duplicate_selection_key_is_refused_not_resolved_in_favour_of_the_last() {
    // Under the parser this replaced, the second `selection:` silently won: a rule could be
    // weakened (or a filter dropped) by an edit that left no visible trace.
    let yaml = rule_with_detection(
        "  selection:\n    Image|endswith: '\\cmd.exe'\n  selection:\n    Image|endswith: '\\never.exe'\n  condition: selection\n",
    );
    let error = parse_rule_yaml(&yaml).expect_err("a duplicate key must not load");
    assert!(error.to_string().contains("duplicate"), "{error}");
}

#[test]
fn a_duplicate_field_in_a_selection_and_a_duplicate_title_are_refused() {
    let field =
        rule_with_detection("  selection:\n    Image: a\n    Image: b\n  condition: selection\n");
    assert!(parse_rule_yaml(&field).is_err());
    let title = rule_with_detection("  selection:\n    Image: a\n  condition: selection\n")
        .replacen("title: T\n", "title: T\ntitle: Other\n", 1);
    assert!(parse_rule_yaml(&title).is_err());
}

#[test]
fn only_true_and_false_are_booleans_so_an_unquoted_yes_or_no_stays_a_string() {
    // The old parser read these as strings; saphyr's default reads them as YAML 1.1
    // booleans and the rule would stop loading. `strict_booleans` keeps the behaviour.
    for word in ["yes", "no", "on", "off", "y", "n", "Yes", "NO"] {
        let yaml = rule_with_detection(&format!(
            "  selection:\n    CommandLine: {word}\n  condition: selection\n"
        ));
        let rule = parse(&yaml);
        let selection = rule.detection.selections.get("selection").unwrap();
        let crate::rule::Selection::FieldMap(fields) = selection else {
            panic!("expected a field map");
        };
        assert_eq!(fields["CommandLine"].as_slice(), [word], "{word}");
    }
    // A real boolean (or a number) is still not a string value: refused at load, as before.
    for scalar in ["true", "false", "4688", "1.5", "null"] {
        let yaml = rule_with_detection(&format!(
            "  selection:\n    CommandLine: {scalar}\n  condition: selection\n"
        ));
        assert!(
            parse_rule_yaml(&yaml).is_err(),
            "{scalar} must not load as a string"
        );
    }
}

#[test]
fn an_alias_bomb_is_refused_by_the_parser_budget() {
    let mut yaml = String::from(RULE_HEAD);
    yaml.push_str("lol: &a0 [x,x,x,x,x,x,x,x,x]\n");
    for i in 1..9 {
        let prev = format!("*a{}", i - 1);
        yaml.push_str(&format!(
            "l{i}: &a{i} [{p},{p},{p},{p},{p},{p},{p},{p},{p}]\n",
            p = prev
        ));
    }
    yaml.push_str("detection:\n  selection:\n    Image: a\n  condition: selection\n");
    let error = parse_rule_yaml(&yaml).expect_err("an alias bomb must not be expanded");
    assert!(error.to_string().contains("budget"), "{error}");
}

#[test]
fn deeply_nested_input_is_an_error_not_a_stack_overflow() {
    let yaml = rule_with_detection(&format!(
        "  selection:\n    Image: {}x{}\n  condition: selection\n",
        "[".repeat(5_000),
        "]".repeat(5_000)
    ));
    assert!(parse_rule_yaml(&yaml).is_err());
}

#[test]
fn malformed_and_empty_input_is_an_error_never_a_panic() {
    for text in [
        "",
        "just text\n",
        "- a\n- b\n",
        "title: [unclosed\n",
        "\u{0}\u{1}\u{2}",
        "a: &x\n",
    ] {
        assert!(parse_rule_yaml(text).is_err(), "{text:?}");
    }
}
