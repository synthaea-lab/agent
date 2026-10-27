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

/// Issue #982: a selection written as a YAML list of maps is OR between the maps, with each
/// map keeping the usual implicit AND between its own fields.
#[test]
fn eval_rule_selection_as_list_of_maps_is_or_between_maps_and_between_them() {
    let rule = parse(
        r#"
title: cmd or encoded powershell
description: test
tags:
  - attack.t1059
level: high
falsepositives:
  - none known
detection:
  selection:
    - Image|endswith: '\cmd.exe'
    - Image|endswith: '\powershell.exe'
      CommandLine|contains: 'encodedcommand'
  condition: selection
"#,
    );
    // First map alone matches: plain cmd.exe, regardless of its command line.
    let via_first_map = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami");
    assert!(eval_rule_exec(&rule, &via_first_map).is_some());

    // Second map matches only when BOTH of its fields match (implicit AND survives inside a
    // list element) — powershell.exe alone, without the encoded command line, must not match.
    let powershell_plain = exec(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -NoProfile",
    );
    assert!(eval_rule_exec(&rule, &powershell_plain).is_none());

    // Second map matches when both of its fields do (OR across maps survives too).
    let powershell_encoded = exec(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -EncodedCommand ZWNobyBoZWxsbw==",
    );
    assert!(eval_rule_exec(&rule, &powershell_encoded).is_some());

    // Neither map matches: no alert.
    let neither = exec("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
    assert!(eval_rule_exec(&rule, &neither).is_none());
}

/// Issue #982: an empty list (`selection: []`) would OR over zero maps — vacuously false, i.e.
/// matches nothing — and a rule that can never fire is as much a load-time error as one that
/// matches everything.
#[test]
fn an_empty_list_of_maps_is_rejected_not_silently_never_matching() {
    let rule: SigmaRule =
        parse_rule_yaml("title: Empty list\ndetection:\n  selection: []\n  condition: selection\n")
            .unwrap();
    let err = validate(&rule, "<t>").unwrap_err();
    assert!(err.to_string().contains("empty"), "{err}");
}

/// Issue #982: an empty map *inside* the list is the same vacuous-AND footgun
/// `empty_selection_is_rejected_not_match_everything` covers for a lone map — a list-of-maps
/// selection must refuse it with the same message, not treat the list wrapper as a free pass.
#[test]
fn an_empty_map_inside_a_list_of_maps_is_rejected_not_match_everything() {
    let rule: SigmaRule = parse_rule_yaml(
        "title: Empty element\ndetection:\n  selection:\n    - {}\n  condition: selection\n",
    )
    .unwrap();
    let err = validate(&rule, "<t>").unwrap_err();
    assert!(err.to_string().contains("empty selection"), "{err}");
}

/// Issue #982: a list of maps is still checked field-by-field as strictly as a lone map — an
/// unsupported field inside one element of the list must be named, not waved through because
/// it's wrapped in a list.
#[test]
fn an_unsupported_field_inside_a_list_of_maps_is_rejected_by_name() {
    let rule: SigmaRule = parse_rule_yaml(
        "title: Bad field in list\ndetection:\n  selection:\n    - Image: a\n    - TargetFilename: b\n  condition: selection\n",
    )
    .unwrap();
    let err = validate(&rule, "<t>").unwrap_err();
    assert!(err.to_string().contains("TargetFilename"), "{err}");
}

/// Issue #982: the keyword-list form (a list of plain strings) must keep working once lists of
/// maps are also accepted — the two forms are distinguished by shape, not confused.
#[test]
fn a_plain_keyword_list_still_works_once_lists_of_maps_are_accepted() {
    let rule = parse(
        "title: KW\ntags:\n  - attack.t1003\nlevel: high\nfalsepositives:\n  - none known\ndetection:\n  selection:\n    - mimikatz\n    - sekurlsa\n  condition: selection\n",
    );
    let ev = exec("C:\\temp\\mimikatz.exe", "C:\\temp\\mimikatz.exe");
    assert!(eval_rule_exec(&rule, &ev).is_some());
}

/// Issue #982 explicitly calls for this to be a load error: a list mixing a map and a plain
/// string matches neither the "list of maps" nor the "list of keywords" shape, so it must be
/// refused — not have the string silently dropped or misread as a one-field map.
#[test]
fn a_selection_list_mixing_a_map_and_a_keyword_is_refused_not_guessed_at() {
    assert!(
        parse_rule_yaml(&rule_with_detection(
            "  selection:\n    - mimikatz\n    - Image: a\n  condition: selection\n"
        ))
        .is_err(),
        "a list mixing a keyword and a map must not load"
    );
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
  condition: selection | count() > 5
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
//
// Rule files ship as signed content to every agent, so what the parser accepts is part of what a
// rule means: every option that could change it is set explicitly (`parse_rule_yaml`), and each
// is pinned by a test that fails without it (the review of #792).

const RULE_HEAD: &str =
    "title: T\ndescription: d\ntags: [attack.t1059]\nlevel: medium\nfalsepositives: [x]\n";

fn rule_with_detection(body: &str) -> String {
    format!("{RULE_HEAD}detection:\n{body}")
}

fn refused_with(yaml: &str, needle: &str) {
    let error = parse_rule_yaml(yaml).expect_err("this must not load");
    let text = error.to_string().to_lowercase();
    assert!(text.contains(needle), "expected {needle:?} in: {error}");
}

#[test]
fn a_duplicate_selection_key_is_refused_not_resolved_in_favour_of_the_last() {
    // Under the parser this replaced, the second `selection:` silently won: a rule could be
    // weakened (or a filter dropped) by an edit that left no visible trace.
    refused_with(
        &rule_with_detection(
            "  selection:\n    Image|endswith: '\\cmd.exe'\n  selection:\n    Image|endswith: '\\never.exe'\n  condition: selection\n",
        ),
        "duplicate",
    );
}

#[test]
fn a_duplicate_is_refused_in_a_selection_other_than_selection_and_in_flow_style() {
    refused_with(
        &rule_with_detection(
            "  selection:\n    Image: a\n  filter:\n    Image: b\n  filter:\n    Image: c\n  condition: selection\n",
        ),
        "duplicate",
    );
    refused_with(
        &rule_with_detection("  selection:\n    Image: a\n    Image: b\n  condition: selection\n"),
        "duplicate",
    );
    refused_with(
        &format!(
            "{RULE_HEAD}detection: {{selection: {{Image: a, Image: b}}, condition: selection}}\n"
        ),
        "duplicate",
    );
}

#[test]
fn a_custom_tag_on_a_key_does_not_hide_a_duplicate_selection() {
    // Without `reject_unsupported_tags` the tag is part of the key's identity for the
    // duplicate check, and the flatten into a map then drops it: the last `selection` won.
    refused_with(
        &rule_with_detection(
            "  selection:\n    Image: a\n  !x selection:\n    Image: b\n  condition: selection\n",
        ),
        "tag",
    );
}

#[test]
fn merge_keys_are_refused_so_a_merged_field_cannot_silently_override_or_vanish() {
    // `<<` merged the anchor's fields, and `<<` plus an explicit key dropped the merged one
    // without an error; the parser this replaced refused `<<`.
    for body in [
        "  base: &b\n    Image: a\n  selection:\n    <<: *b\n  condition: selection\n",
        "  base: &b\n    Image: a\n  selection:\n    <<: *b\n    Image: b\n  condition: selection\n",
        "  base: &d\n    selection:\n      Image: a\n  <<: *d\n  selection:\n    Image: b\n  condition: selection\n",
    ] {
        refused_with(&rule_with_detection(body), "merge");
    }
}

#[test]
fn a_binary_tagged_value_stays_the_text_it_shows_not_decoded_into_a_value_a_reviewer_cannot_read() {
    // `!!binary aGVsbG8=` would match `hello` while the file shows base64; under the parser
    // this replaced it stayed the literal.
    let rule = parse(&rule_with_detection(
        "  selection:\n    CommandLine: !!binary aGVsbG8=\n  condition: selection\n",
    ));
    let crate::rule::Selection::FieldMap(fields) = &rule.detection.selections["selection"] else {
        panic!("expected a field map");
    };
    assert_eq!(fields["CommandLine"].as_slice(), ["aGVsbG8="]);
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
}

#[test]
fn numbers_that_were_strings_before_are_refused_at_load_not_misread() {
    // Under serde_yaml `017`, `08` and `1_000` were strings; they are integers now, and an
    // integer is not a Sigma value: the rule is refused loudly (quote the value).
    for scalar in ["017", "08", "1_000", "4688", "1.5", "true", "null"] {
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
    refused_with(&yaml, "budget");
}

#[test]
fn a_rule_file_is_bounded_in_nodes_not_only_in_alias_replays() {
    // The defaults allow 250,000 nodes; a rule is a few dozen. An unknown key is ignored by
    // the deserializer, so only the budget can stop it.
    let big = format!("[{}]", vec!["1"; 30_000].join(","));
    refused_with(
        &format!(
            "{RULE_HEAD}ignored: {big}\ndetection:\n  selection:\n    Image: a\n  condition: selection\n"
        ),
        "budget",
    );
}

#[test]
fn nesting_inside_an_ignored_key_hits_the_depth_limit_not_the_stack() {
    // In an ignored key nothing else can reject it: only the depth limit does.
    let deep = format!("{}x{}", "[".repeat(300), "]".repeat(300));
    let yaml = format!(
        "{RULE_HEAD}ignored: {deep}\ndetection:\n  selection:\n    Image: a\n  condition: selection\n"
    );
    assert!(parse_rule_yaml(&yaml).is_err());
}

#[test]
fn nesting_deeper_than_a_rule_needs_is_refused_by_the_depth_budget() {
    // 30 levels of block mappings in an ignored key: far above what a rule uses (about 5) and
    // below the parser's own default depth limit (64), so only our budget refuses it.
    let mut nested = String::new();
    for level in 0..30 {
        nested.push_str(&format!("{}k{level}:\n", "  ".repeat(level + 1)));
    }
    nested.push_str(&format!("{}leaf: x\n", "  ".repeat(31)));
    let yaml = format!(
        "{RULE_HEAD}ignored:\n{nested}detection:\n  selection:\n    Image: a\n  condition: selection\n"
    );
    refused_with(&yaml, "depth");
}

#[test]
fn a_yaml_error_is_one_line_with_no_snippet_and_no_hint_to_weaken_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("linux").join("dup.yml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        rule_with_detection("  selection:\n    Image: a\n    Image: b\n  condition: selection\n"),
    )
    .unwrap();
    let text = crate::SigmaEngine::load_rule(&path)
        .unwrap_err()
        .to_string();
    assert!(!text.contains('\n'), "{text}");
    assert!(text.to_lowercase().contains("duplicate"), "{text}");
    assert!(
        !text.contains("DuplicateKeyPolicy") && !text.contains("if acceptable"),
        "{text}"
    );
    assert!(text.contains("line 9"), "the location is kept: {text}");
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

#[test]
fn field_names_and_modifiers_that_differ_only_by_case_are_refused() {
    // Two parsers agree they are different keys and evaluation ANDs them, so a selection
    // could be made never to fire (or a field silently doubled).
    for body in [
        "  selection:\n    Image: a\n    image: b\n  condition: selection\n",
        "  selection:\n    Image|endswith: a\n    Image|EndsWith: b\n  condition: selection\n",
    ] {
        let rule = parse_rule_yaml(&rule_with_detection(body)).expect("two different keys parse");
        let error = validate(&rule, "<test>/linux/rule.yml").expect_err("must be refused");
        assert!(error.to_string().to_lowercase().contains("case"), "{error}");
        for spec in body
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("Image") || line.starts_with("image"))
        {
            let spec = spec.split(':').next().unwrap();
            assert!(
                error.to_string().contains(spec),
                "{error} should name `{spec}`"
            );
        }
    }
}

fn field_rule(field: &str, values_yaml: &str) -> SigmaRule {
    let yaml = format!(
        "title: Modifier test\ntags: [attack.t1059]\nlevel: medium\nfalsepositives: [none]\ndetection:\n  selection:\n    {field}: {values_yaml}\n  condition: selection\n"
    );
    let rule: SigmaRule = parse_rule_yaml(&yaml).unwrap();
    validate(&rule, "<test>/linux/rule.yml").unwrap();
    rule
}

#[test]
fn all_requires_every_value_for_each_matching_modifier_case_insensitively() {
    let cases = [
        ("contains", "WIN CMD", "win", "cmd"),
        ("startswith", "C:\\Windows\\cmd.exe", "c:", "C:\\Windows"),
        ("endswith", "C:\\Windows\\cmd.exe", "CMD.EXE", ".exe"),
    ];
    for (modifier, haystack, first, second) in cases {
        let rule = field_rule(
            &format!("CommandLine|{modifier}|ALL"),
            &format!("['{first}', '{second}']"),
        );
        assert!(
            eval_rule_exec(&rule, &exec("x.exe", haystack)).is_some(),
            "{modifier}"
        );
        let missing = field_rule(
            &format!("CommandLine|{modifier}|all"),
            &format!("['{first}', 'not-present']"),
        );
        assert!(
            eval_rule_exec(&missing, &exec("x.exe", haystack)).is_none(),
            "{modifier}"
        );
    }
}

#[test]
fn value_lists_keep_or_semantics_without_all() {
    let rule = field_rule("CommandLine|contains", "[missing, cmd]");
    assert!(eval_rule_exec(&rule, &exec("x.exe", "cmd.exe")).is_some());
}

#[test]
fn plain_field_values_keep_their_exact_match_behavior() {
    let rule = field_rule("CommandLine", "cmd.exe");
    assert!(eval_rule_exec(&rule, &exec("x.exe", "cmd.exe")).is_some());
    assert!(eval_rule_exec(&rule, &exec("x.exe", "other.exe")).is_none());
}

#[test]
fn evaluator_defensively_rejects_multiple_match_modifiers() {
    let rule: SigmaRule = parse_rule_yaml(
        "title: Invalid modifier\ndetection:\n  selection:\n    CommandLine|contains|startswith: a\n  condition: selection\n",
    )
    .unwrap();
    assert!(eval_rule_exec(&rule, &exec("x.exe", "a")).is_none());
}

#[test]
fn all_must_be_last_and_only_one_matching_modifier_is_allowed() {
    for spec in [
        "CommandLine|contains|all|startswith",
        "CommandLine|contains|startswith|all",
        "CommandLine|all",
    ] {
        let yaml = format!(
            "title: Bad\ndetection:\n  selection:\n    {spec}: [a, b]\n  condition: selection\n"
        );
        let rule: SigmaRule = parse_rule_yaml(&yaml).unwrap();
        assert!(validate(&rule, "<test>/linux/test.yml").is_err(), "{spec}");
    }
}

#[test]
fn empty_all_value_list_is_refused() {
    for spec in ["CommandLine|contains|all", "CommandLine|contains"] {
        let yaml = format!(
            "title: Empty\ndetection:\n  selection:\n    {spec}: []\n  condition: selection\n"
        );
        let rule: SigmaRule = parse_rule_yaml(&yaml).unwrap();
        let error = validate(&rule, "<test>/linux/test.yml").unwrap_err();
        assert!(error.to_string().contains("empty value list"), "{error}");
    }
}

proptest::proptest! {
    #[test]
    fn all_equals_conjunction_of_single_value_rules(
        values in proptest::collection::vec("[a-z]{1,8}", 1..8),
        present in proptest::collection::vec(proptest::bool::ANY, 8),
    ) {
        // Only the values flagged `present` are in the haystack: with every value in it the
        // property holds trivially, so a missing value is what reaches the false branch.
        let haystack = values
            .iter()
            .zip(&present)
            .filter(|(_, keep)| **keep)
            .map(|(value, _)| value.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let yaml_values = format!("[{}]", values.iter()
            .map(|value| format!("'{value}'"))
            .collect::<Vec<_>>().join(", "));
        let all_rule = field_rule("CommandLine|contains|all", &yaml_values);
        let conjunction = values.iter().all(|value| {
            let single = field_rule("CommandLine|contains", &format!("'{value}'"));
            eval_rule_exec(&single, &exec("x.exe", &haystack)).is_some()
        });
        proptest::prop_assert_eq!(
            eval_rule_exec(&all_rule, &exec("x.exe", &haystack)).is_some(),
            conjunction
        );
    }
}

#[test]
fn all_is_false_when_one_value_is_absent_and_true_when_every_value_is_present() {
    // The cases the property above samples, pinned: it cannot pass if `|all` behaves as `any`.
    let rule = field_rule("CommandLine|contains|all", "['alpha', 'beta', 'gamma']");
    assert!(eval_rule_exec(&rule, &exec("x.exe", "alpha beta gamma")).is_some());
    assert!(eval_rule_exec(&rule, &exec("x.exe", "alpha beta")).is_none());
    assert!(eval_rule_exec(&rule, &exec("x.exe", "gamma")).is_none());
    assert!(eval_rule_exec(&rule, &exec("x.exe", "")).is_none());
}

#[test]
fn the_validator_and_the_evaluator_agree_on_modifier_shapes() {
    for (spec, accepted) in [
        ("CommandLine", true),
        ("CommandLine|contains", true),
        ("CommandLine|contains|all", true),
        ("CommandLine|CONTAINS|ALL", true),
        ("CommandLine|all", false),
        ("CommandLine|contains|startswith", false),
        ("CommandLine|contains|all|startswith", false),
        ("CommandLine|contains|startswith|all", false),
        ("CommandLine|contains|all|all", false),
    ] {
        // A complete rule: without `level` and an ATT&CK tag the validator refuses it for its
        // metadata, whatever the modifiers, and the comparison would test nothing.
        let yaml = rule_with_detection(&format!(
            "  selection:\n    {spec}: [a, b]\n  condition: selection\n"
        ));
        let rule: SigmaRule = parse_rule_yaml(&yaml).unwrap();
        let validated = validate(&rule, "<test>/linux/test.yml").is_ok();
        let evaluated = crate::eval::parse_modifiers(spec.split('|').skip(1)).is_some();
        assert_eq!(validated, accepted, "validator: {spec}");
        assert_eq!(evaluated, accepted, "evaluator: {spec}");
    }
}

#[test]
fn a_rule_file_over_the_size_cap_is_refused_before_it_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("linux").join("big.yml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let padding = "# padding\n".repeat(200_000); // about 2 MB
    std::fs::write(
        &path,
        rule_with_detection("  selection:\n    Image: a\n  condition: selection\n") + &padding,
    )
    .unwrap();
    let error = crate::SigmaEngine::load_rule(&path).expect_err("too large");
    assert!(
        error.to_string().to_lowercase().contains("larger"),
        "{error}"
    );
}
