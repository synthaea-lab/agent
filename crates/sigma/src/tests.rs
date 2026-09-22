//! Sigma engine tests — load-time validation and evaluation behavior, including
//! the regression tests for the review findings on the migration PRs.

use schema::{EventMeta, ExecEvent};

use crate::{
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
    let rule: SigmaRule = serde_yaml::from_str(yaml).unwrap();
    validate(&rule, "<test>").unwrap();
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

#[test]
fn eval_rule_keywords() {
    let rule = parse(
        r#"
title: Suspicious keyword
description: test
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
        serde_yaml::from_str("title: Empty\ndetection:\n  selection: {}\n  condition: selection\n")
            .unwrap();
    let err = validate(&rule, "<t>").unwrap_err();
    assert!(err.to_string().contains("empty selection"), "{err}");
}

#[test]
fn interior_wildcards_are_rejected_at_load() {
    // Review finding: `C:\*\cmd.exe` loaded fine and then never matched.
    let rule: SigmaRule = serde_yaml::from_str(
        "title: Interior\ndetection:\n  selection:\n    Image: 'C:\\*\\cmd.exe'\n  condition: selection\n",
    )
    .unwrap();
    let err = validate(&rule, "<t>").unwrap_err();
    assert!(err.to_string().contains("interior wildcard"), "{err}");
}

#[test]
fn keyword_wildcards_match_like_field_globs() {
    let rule =
        parse("title: KW\ndetection:\n  selection:\n    - '*mimikatz*'\n  condition: selection\n");
    let ev = exec("C:\\t\\x.exe", "run mimikatz please");
    assert!(eval_rule_exec(&rule, &ev).is_some());
}

#[test]
fn modifier_case_is_insensitive_at_eval() {
    let rule = parse(
        "title: Case\ndetection:\n  selection:\n    Image|EndsWith: '\\cmd.exe'\n  condition: selection\n",
    );
    let ev = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe");
    assert!(
        eval_rule_exec(&rule, &ev).is_some(),
        "EndsWith must behave as endswith"
    );
}

#[test]
fn unsupported_constructs_are_rejected_at_load() {
    let complex_condition: SigmaRule = serde_yaml::from_str(
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

    let bad_field: SigmaRule = serde_yaml::from_str(
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

    let bad_modifier: SigmaRule = serde_yaml::from_str(
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
