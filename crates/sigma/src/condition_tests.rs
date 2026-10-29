//! The condition grammar (#978): every operator, the precedence, the quantifiers, every refusal
//! and every bound at its exact edge, and properties against an evaluator written independently
//! of the one under test.

use proptest::prelude::*;
use schema::{EventMeta, ExecEvent};

use crate::{
    condition::{MAX_BLOCKS, MAX_CONDITION_BYTES, MAX_DEPTH, MAX_TOKENS, compile},
    engine::parse_rule_yaml,
    eval::eval_rule_exec,
    rule::SigmaRule,
    validate::validate,
};

const HEAD: &str = "title: T\ntags: [attack.t1059]\nlevel: medium\nfalsepositives: [none]\n";

/// A rule whose blocks each match when the command line holds that block's marker
/// (`CommandLine|contains: mark_<name>`).
fn rule_text(blocks: &[&str], condition: &str) -> String {
    let mut yaml = format!("{HEAD}detection:\n");
    for block in blocks {
        yaml.push_str(&format!(
            "  {block}:\n    CommandLine|contains: mark_{block}\n"
        ));
    }
    // JSON string syntax is valid YAML: any text, including quotes and an empty one.
    let quoted = serde_json::to_string(condition).unwrap();
    yaml.push_str(&format!("  condition: {quoted}\n"));
    yaml
}

fn load(yaml: &str) -> Result<SigmaRule, String> {
    let rule = parse_rule_yaml(yaml).map_err(|e| e.to_string())?;
    validate(&rule, "<test>/linux/rule.yml").map_err(|e| e.to_string())?;
    Ok(rule)
}

fn rule(blocks: &[&str], condition: &str) -> SigmaRule {
    load(&rule_text(blocks, condition)).unwrap_or_else(|e| panic!("`{condition}` must load: {e}"))
}

fn refused(blocks: &[&str], condition: &str, what: &str) {
    let error = load(&rule_text(blocks, condition))
        .err()
        .unwrap_or_else(|| panic!("`{condition}` must be refused"));
    assert!(error.contains(what), "`{condition}`: {error}");
    assert!(
        error.contains("condition"),
        "the message names the condition: {error}"
    );
}

/// An event whose command line holds the markers of exactly the blocks in `present`.
fn event(present: &[&str]) -> ExecEvent {
    let cmdline = present
        .iter()
        .map(|b| format!("mark_{b}"))
        .collect::<Vec<_>>()
        .join(" ");
    ExecEvent {
        meta: EventMeta {
            pid: 1,
            comm: "t".into(),
            ..schema::fixtures::meta()
        },
        image_path: "/bin/x".into(),
        cmdline: format!("x {cmdline}"),
        ..schema::fixtures::exec()
    }
}

fn fires(rule: &SigmaRule, present: &[&str]) -> bool {
    eval_rule_exec(rule, &event(present)).is_some()
}

/// Every subset of `names`, as the list of the names present.
fn subsets<'a>(names: &[&'a str]) -> Vec<Vec<&'a str>> {
    (0..1u32 << names.len())
        .map(|mask| {
            names
                .iter()
                .enumerate()
                .filter(|(i, _)| mask >> i & 1 == 1)
                .map(|(_, n)| *n)
                .collect()
        })
        .collect()
}

/// `condition` against `reference` on every subset of the blocks `a`, `b`, `c`.
fn truth_table(condition: &str, reference: impl Fn(bool, bool, bool) -> bool) {
    let r = rule(&["a", "b", "c"], condition);
    for present in subsets(&["a", "b", "c"]) {
        let (a, b, c) = (
            present.contains(&"a"),
            present.contains(&"b"),
            present.contains(&"c"),
        );
        assert_eq!(
            fires(&r, &present),
            reference(a, b, c),
            "`{condition}` with {present:?}"
        );
    }
}

#[test]
fn a_single_block_named_anything_is_a_condition_and_selection_is_not_special() {
    for name in ["selection", "main", "sel_1", "a-b", "Sel.x"] {
        let r = rule(&[name], name);
        assert!(fires(&r, &[name]), "{name}");
        assert!(!fires(&r, &[]), "{name}");
    }
}

#[test]
fn and_or_not_each_do_what_they_say() {
    truth_table("a and b", |a, b, _| a && b);
    truth_table("a or b", |a, b, _| a || b);
    truth_table("not a", |a, _, _| !a);
    truth_table("a and b and c", |a, b, c| a && b && c);
    truth_table("a or b or c", |a, b, c| a || b || c);
    truth_table("not not a", |a, _, _| a);
}

#[test]
fn not_binds_tighter_than_and_which_binds_tighter_than_or() {
    truth_table("not a and b", |a, b, _| !a && b);
    truth_table("not a or b", |a, b, _| !a || b);
    truth_table("a and b or c", |a, b, c| (a && b) || c);
    truth_table("a or b and c", |a, b, c| a || (b && c));
    truth_table("a or not b and c", |a, b, c| a || (!b && c));
    truth_table("not a and not b or c", |a, b, c| (!a && !b) || c);
}

#[test]
fn parentheses_override_the_precedence() {
    truth_table("(a or b) and c", |a, b, c| (a || b) && c);
    truth_table("a and (b or c)", |a, b, c| a && (b || c));
    truth_table("not (a and b)", |a, b, _| !(a && b));
    truth_table("not (a or b)", |a, b, _| !(a || b));
    truth_table("((a)) and (((b)))", |a, b, _| a && b);
    truth_table("not (not (a or b) or c)", |a, b, c| !(!(a || b) || c));
}

#[test]
fn keywords_are_case_insensitive_and_names_are_not() {
    truth_table("a AND NOT b", |a, b, _| a && !b);
    // A block `A` is not the block `a`: the reference is what is case-sensitive.
    let r = rule(&["A", "b"], "A or b");
    assert!(fires(&r, &["A"]));
    refused(&["A", "b"], "a or b", "unknown block `a`");
}

#[test]
fn one_of_and_all_of_a_pattern_or_them() {
    // `my_sel_z` contains `sel_` without starting with it: a pattern is a prefix, not a substring.
    let blocks = [
        "sel_a", "sel_b", "sel_c", "filter_x", "filter_y", "my_sel_z",
    ];
    let all_present = [
        "sel_a", "sel_b", "sel_c", "filter_x", "filter_y", "my_sel_z",
    ];
    for (condition, reference) in [
        (
            "1 of sel_*",
            Box::new(|p: &[&str]| p.iter().any(|n| n.starts_with("sel_")))
                as Box<dyn Fn(&[&str]) -> bool>,
        ),
        (
            "all of sel_*",
            Box::new(|p| ["sel_a", "sel_b", "sel_c"].iter().all(|n| p.contains(n))),
        ),
        ("1 of them", Box::new(|p| !p.is_empty())),
        (
            "all of them",
            Box::new(|p| all_present.iter().all(|n| p.contains(n))),
        ),
        ("1 of sel_a", Box::new(|p| p.contains(&"sel_a"))),
        ("all of sel_a", Box::new(|p| p.contains(&"sel_a"))),
        (
            "1 of filter*",
            Box::new(|p| p.iter().any(|n| n.starts_with("filter"))),
        ),
        ("1 of *", Box::new(|p| !p.is_empty())),
        (
            "all of sel_* and not 1 of filter_*",
            Box::new(|p| {
                ["sel_a", "sel_b", "sel_c"].iter().all(|n| p.contains(n))
                    && !p.iter().any(|n| n.starts_with("filter_"))
            }),
        ),
        (
            "1 of sel_* and not (filter_x or filter_y)",
            Box::new(|p| {
                p.iter().any(|n| n.starts_with("sel_"))
                    && !(p.contains(&"filter_x") || p.contains(&"filter_y"))
            }),
        ),
    ] {
        let r = rule(&blocks, condition);
        for present in subsets(&blocks) {
            assert_eq!(
                fires(&r, &present),
                reference(&present),
                "`{condition}` with {present:?}"
            );
        }
    }
}

#[test]
fn quantifier_keywords_are_case_insensitive() {
    let r = rule(&["sel_a", "sel_b"], "ALL OF sel_* and 1 Of Them");
    assert!(fires(&r, &["sel_a", "sel_b"]));
    assert!(!fires(&r, &["sel_a"]));
}

#[test]
fn them_counts_every_block_filters_included() {
    // Sigma's own definition: `them` is every block of the detection.
    let r = rule(&["selection", "filter"], "all of them");
    assert!(fires(&r, &["selection", "filter"]));
    assert!(!fires(&r, &["selection"]));
}

#[test]
fn an_empty_pattern_is_a_load_error_never_a_vacuous_match() {
    for condition in [
        "1 of nothing_*",
        "all of nothing_*",
        "selection and 1 of nothing_*",
        "not 1 of nothing_*",
        "1 of nothing",
        "all of nothing",
    ] {
        refused(&["selection", "other"], condition, "matches no block");
    }
}

#[test]
fn a_reference_to_a_block_that_does_not_exist_is_a_load_error() {
    refused(
        &["selection"],
        "selection and missing",
        "unknown block `missing`",
    );
    refused(&["selection"], "missing", "unknown block `missing`");
    refused(&["main"], "selection", "unknown block `selection`");
    refused(
        &["selection"],
        "not (selection or ghost)",
        "unknown block `ghost`",
    );
}

#[test]
fn aggregations_pipes_and_timeframes_are_refused_by_name() {
    refused(&["selection"], "selection | count() > 5", "pipe");
    refused(
        &["selection"],
        "selection | count(CommandLine) by Image > 5",
        "pipe",
    );
    refused(&["selection"], "count(selection) > 5", "aggregations");
    refused(&["selection"], "selection and count > 1", "aggregations");
    refused(&["selection"], "selection near filter", "aggregations");
    refused(&["selection"], "sum(selection)", "aggregations");
    refused(&["selection"], "min (selection)", "aggregations");
    let with_timeframe = format!(
        "{HEAD}detection:\n  selection:\n    CommandLine|contains: x\n  timeframe: 15m\n  condition: selection\n"
    );
    let error = load(&with_timeframe).expect_err("timeframe is refused");
    assert!(error.contains("timeframe: 15m"), "{error}");
}

#[test]
fn a_block_may_be_named_like_an_aggregation_function_when_it_is_not_called() {
    let r = rule(&["min", "sum"], "min or sum");
    assert!(fires(&r, &["min"]));
}

#[test]
fn other_quantifiers_and_pattern_shapes_are_refused() {
    let blocks = ["sel_a", "sel_b"];
    refused(&blocks, "2 of sel_*", "`2 of` is not supported");
    refused(&blocks, "3 of them", "`3 of` is not supported");
    refused(&blocks, "any of sel_*", "`any of` is not supported");
    refused(&blocks, "1 of *_a", "one `*`, at its end");
    refused(&blocks, "1 of s*l_*", "one `*`, at its end");
    refused(&blocks, "1 of **", "one `*`, at its end");
    refused(&blocks, "sel_*", "only valid after `1 of` or `all of`");
    refused(
        &blocks,
        "sel_a and *",
        "only valid after `1 of` or `all of`",
    );
    refused(&blocks, "1 of", "nothing after it");
    refused(&blocks, "all of and", "not a block name or pattern");
    refused(&blocks, "1 of (sel_a)", "not a block name or pattern");
}

#[test]
fn malformed_expressions_are_refused_with_what_is_wrong() {
    let blocks = ["a", "b"];
    refused(&blocks, "", "empty");
    refused(&blocks, "   ", "empty");
    refused(&blocks, "a and", "ends where an operand is expected");
    refused(&blocks, "or b", "where a block name is expected");
    refused(&blocks, "a and and b", "where a block name is expected");
    refused(&blocks, "not", "ends where an operand is expected");
    refused(&blocks, "a b", "unexpected `b`");
    refused(&blocks, "a (b)", "unexpected `(`");
    refused(&blocks, "(a and b", "never closed");
    refused(&blocks, "a and b)", "unexpected `)`");
    refused(&blocks, ")", "closes nothing");
    refused(&blocks, "()", "closes nothing");
    refused(&blocks, "(a or b))", "unexpected `)`");
    refused(&blocks, "a == b", "only block names");
    refused(&blocks, "a and 'b'", "only block names");
    refused(&blocks, "a, b", "only block names");
    refused(&blocks, "a and b # comment", "only block names");
    refused(&blocks, "a and them", "where a block name is expected");
    refused(&blocks, "of", "where a block name is expected");
}

#[test]
fn every_referenced_block_is_validated_as_strictly_as_selection_always_was() {
    let yaml = format!(
        "{HEAD}detection:\n  selection:\n    Image|endswith: cmd.exe\n  filter_bad:\n    TargetFilename: x\n  condition: selection and not filter_bad\n"
    );
    let error = load(&yaml).expect_err("an unsupported field in a filter");
    assert!(error.contains("TargetFilename"), "{error}");
    assert!(error.contains("(in block `filter_bad`)"), "{error}");

    // The block every rule used to have keeps its message byte for byte.
    let yaml =
        format!("{HEAD}detection:\n  selection:\n    TargetFilename: x\n  condition: selection\n");
    let error = load(&yaml).expect_err("an unsupported field");
    assert!(!error.contains("(in block"), "{error}");

    // Empty blocks never become a vacuous match, in any position.
    let yaml = format!(
        "{HEAD}detection:\n  selection:\n    Image: a\n  filter_empty: {{}}\n  condition: selection and not filter_empty\n"
    );
    let error = load(&yaml).expect_err("an empty filter");
    assert!(error.contains("empty selection"), "{error}");
}

#[test]
fn a_block_the_condition_never_refers_to_is_neither_evaluated_nor_validated_as_before() {
    // Today's engine ignores every block but `selection`; this keeps that, so a shipped rule
    // with a spare block means what it meant.
    let yaml = format!(
        "{HEAD}detection:\n  selection:\n    CommandLine|contains: mark_selection\n  spare:\n    TargetFilename: x\n  condition: selection\n"
    );
    let r = load(&yaml).expect("an unreferenced block is not checked");
    assert!(fires(&r, &["selection"]));
}

#[test]
fn each_block_is_evaluated_at_most_once_per_event() {
    let yaml = rule_text(
        &["a", "b"],
        "a and (a or b) or (not a and b) or 1 of them or all of them",
    );
    let rule = parse_rule_yaml(&yaml).unwrap();
    let compiled = compile(&rule.detection.condition, &rule.detection.selections).unwrap();
    let mut calls = vec![0usize; compiled.blocks.len()];
    compiled.eval(|index| {
        calls[index] += 1;
        false
    });
    assert!(calls.iter().all(|&n| n <= 1), "{calls:?}");
    assert!(
        calls.iter().all(|&n| n == 1),
        "all were needed here: {calls:?}"
    );
}

#[test]
fn evaluation_short_circuits() {
    let rule = parse_rule_yaml(&rule_text(&["a", "b", "c"], "a or b or c")).unwrap();
    let compiled = compile(&rule.detection.condition, &rule.detection.selections).unwrap();
    let mut calls = 0;
    assert!(compiled.eval(|_| {
        calls += 1;
        true
    }));
    assert_eq!(calls, 1, "`or` stops at the first true block");

    let rule = parse_rule_yaml(&rule_text(&["a", "b", "c"], "a and b and c")).unwrap();
    let compiled = compile(&rule.detection.condition, &rule.detection.selections).unwrap();
    let mut calls = 0;
    assert!(!compiled.eval(|_| {
        calls += 1;
        false
    }));
    assert_eq!(calls, 1, "`and` stops at the first false block");
}

// --- bounds, each at its exact edge -------------------------------------------------------

fn names(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("b{i}")).collect()
}

fn with_blocks(count: usize, condition: &str) -> Result<SigmaRule, String> {
    let owned = names(count);
    let blocks: Vec<&str> = owned.iter().map(String::as_str).collect();
    load(&rule_text(&blocks, condition))
}

#[test]
fn nesting_of_parentheses_and_not_is_bounded() {
    let nested = |depth: usize| format!("{}b0{}", "(".repeat(depth), ")".repeat(depth));
    assert!(with_blocks(1, &nested(MAX_DEPTH)).is_ok());
    let error = with_blocks(1, &nested(MAX_DEPTH + 1)).err().unwrap();
    assert!(error.contains("nest more than"), "{error}");

    let nots = |depth: usize| format!("{}b0", "not ".repeat(depth));
    assert!(with_blocks(1, &nots(MAX_DEPTH)).is_ok());
    let error = with_blocks(1, &nots(MAX_DEPTH + 1)).err().unwrap();
    assert!(error.contains("nest more than"), "{error}");

    // Mixed: the two count together.
    let mixed = format!("{}not b0{}", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
    assert!(with_blocks(1, &mixed).is_err());
}

#[test]
fn a_hostile_nesting_is_refused_without_overflowing_the_stack() {
    let deep = format!("{}b0{}", "(".repeat(50_000), ")".repeat(50_000));
    assert!(compile_text(&deep).is_err());
    let nots = "not ".repeat(50_000) + "b0";
    assert!(compile_text(&nots).is_err());
}

fn compile_text(condition: &str) -> Result<(), String> {
    let rule = parse_rule_yaml(&rule_text(&["b0"], "b0")).unwrap();
    compile(condition, &rule.detection.selections).map(|_| ())
}

#[test]
fn the_token_count_is_bounded() {
    // `b0 or b0 or ...` has 2n - 1 tokens; a leading `not` makes the count even.
    let odd = |blocks: usize| vec!["b0"; blocks].join(" or ");
    let even = |blocks: usize| format!("not {}", odd(blocks));
    assert!(compile_text(&odd(MAX_TOKENS / 2)).is_ok(), "127 tokens");
    assert!(
        compile_text(&even(MAX_TOKENS / 2)).is_ok(),
        "128 tokens, the limit"
    );
    let error = compile_text(&odd(MAX_TOKENS / 2 + 1)).err().unwrap();
    assert!(error.contains("more than"), "129 tokens: {error}");
    assert!(
        compile_text(&even(MAX_TOKENS / 2 + 1)).is_err(),
        "130 tokens"
    );
}

#[test]
fn the_text_length_is_bounded() {
    // Whitespace counts toward the byte limit.
    let at_limit = format!("b0 or {}b0", " ".repeat(MAX_CONDITION_BYTES - 8));
    assert_eq!(at_limit.len(), MAX_CONDITION_BYTES);
    assert!(compile_text(&at_limit).is_ok());
    let over = format!("b0 or {}b0", " ".repeat(MAX_CONDITION_BYTES - 7));
    let error = compile_text(&over).err().unwrap();
    assert!(error.contains("longer than"), "{error}");
}

#[test]
fn the_number_of_referenced_blocks_is_bounded() {
    assert!(with_blocks(MAX_BLOCKS, "1 of them").is_ok());
    let error = with_blocks(MAX_BLOCKS + 1, "1 of them").err().unwrap();
    assert!(error.contains("refers to"), "{error}");
    // Referring to a few of many is fine: the bound is on what the condition uses.
    assert!(with_blocks(MAX_BLOCKS + 40, "b0 and b1").is_ok());
    assert!(with_blocks(MAX_BLOCKS + 40, "1 of b1*").is_ok());
}

#[test]
fn a_rule_at_every_bound_evaluates() {
    // 64 blocks, a 1 of them, 8 levels of nesting: one pass over the event.
    let owned = names(MAX_BLOCKS);
    let blocks: Vec<&str> = owned.iter().map(String::as_str).collect();
    let condition = format!(
        "{}1 of them and not all of b1*{}",
        "(".repeat(MAX_DEPTH - 1),
        ")".repeat(MAX_DEPTH - 1)
    );
    let r = load(&rule_text(&blocks, &condition)).unwrap();
    assert!(fires(&r, &["b0"]));
    assert!(!fires(&r, &[]));
}

// --- properties -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Tree {
    Leaf(usize),
    Not(Box<Tree>),
    And(Box<Tree>, Box<Tree>),
    Or(Box<Tree>, Box<Tree>),
}

const NAMES: [&str; 4] = ["a", "b", "c", "d"];

fn tree() -> impl Strategy<Value = Tree> {
    let leaf = (0..NAMES.len()).prop_map(Tree::Leaf);
    leaf.prop_recursive(4, 24, 2, |inner| {
        prop_oneof![
            inner.clone().prop_map(|t| Tree::Not(Box::new(t))),
            (inner.clone(), inner.clone()).prop_map(|(l, r)| Tree::And(Box::new(l), Box::new(r))),
            (inner.clone(), inner).prop_map(|(l, r)| Tree::Or(Box::new(l), Box::new(r))),
        ]
    })
}

/// The reference: evaluated straight off the tree, sharing nothing with the parser.
fn reference(tree: &Tree, present: &[bool; 4]) -> bool {
    match tree {
        Tree::Leaf(i) => present[*i],
        Tree::Not(t) => !reference(t, present),
        Tree::And(l, r) => reference(l, present) && reference(r, present),
        Tree::Or(l, r) => reference(l, present) || reference(r, present),
    }
}

/// Fully parenthesised: no reliance on precedence.
fn full(tree: &Tree) -> String {
    match tree {
        Tree::Leaf(i) => NAMES[*i].to_string(),
        Tree::Not(t) => format!("(not {})", full(t)),
        Tree::And(l, r) => format!("({} and {})", full(l), full(r)),
        Tree::Or(l, r) => format!("({} or {})", full(l), full(r)),
    }
}

/// Minimal parentheses by the precedence `not` > `and` > `or`: relies on the parser getting it
/// right. `parent` is the binding strength of the context (0 or, 1 and, 2 not).
fn minimal(tree: &Tree, parent: u8) -> String {
    let (text, strength) = match tree {
        Tree::Leaf(i) => (NAMES[*i].to_string(), 3),
        Tree::Not(t) => (format!("not {}", minimal(t, 2)), 2),
        Tree::And(l, r) => (format!("{} and {}", minimal(l, 1), minimal(r, 2)), 1),
        Tree::Or(l, r) => (format!("{} or {}", minimal(l, 0), minimal(r, 1)), 0),
    };
    if strength < parent {
        format!("({text})")
    } else {
        text
    }
}

proptest! {
    #[test]
    fn any_expression_means_what_a_reference_evaluator_says(tree in tree()) {
        for text in [full(&tree), minimal(&tree, 0)] {
            // Skip what the nesting bound legitimately refuses.
            let Ok(r) = load(&rule_text(&NAMES, &text)) else { continue };
            for mask in 0..16u32 {
                let present: [bool; 4] = std::array::from_fn(|i| mask >> i & 1 == 1);
                let present_names: Vec<&str> = NAMES
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| present[*i])
                    .map(|(_, n)| *n)
                    .collect();
                prop_assert_eq!(fires(&r, &present_names), reference(&tree, &present), "{}", text);
            }
        }
    }

    #[test]
    fn no_text_makes_the_parser_panic_or_loop(text in ".{0,300}") {
        let _ = compile_text(&text);
    }

    #[test]
    fn grammar_shaped_noise_never_panics(
        parts in prop::collection::vec(
            prop::sample::select(vec![
                "a", "b", "(", ")", "and", "or", "not", "1", "all", "of", "them", "a*", "*",
                "|", "count", "x*", " ", "2",
            ]),
            0..200,
        ),
    ) {
        let _ = compile_text(&parts.join(" "));
    }
}

#[test]
fn the_engine_loads_multi_block_rules_from_a_directory_and_alerts_on_them() {
    // The path the agent takes: `load_dir`, then `eval_exec`.
    let dir = tempfile::tempdir().unwrap();
    let linux = dir.path().join("linux");
    std::fs::create_dir_all(&linux).unwrap();
    std::fs::write(
        linux.join("two_blocks.yml"),
        rule_text(
            &["selection", "filter_known"],
            "selection and not filter_known",
        ),
    )
    .unwrap();
    std::fs::write(
        linux.join("aggregation.yml"),
        rule_text(&["selection"], "selection | count() > 3"),
    )
    .unwrap();
    std::fs::write(
        linux.join("no_match.yml"),
        rule_text(&["selection"], "1 of nothing_*"),
    )
    .unwrap();

    let engine = crate::SigmaEngine::load_dir(dir.path()).unwrap();
    assert_eq!(
        engine.rule_count(),
        1,
        "the two refused rules are not loaded"
    );
    assert_eq!(engine.eval_exec(&event(&["selection"])).len(), 1);
    assert!(
        engine
            .eval_exec(&event(&["selection", "filter_known"]))
            .is_empty()
    );
    assert!(engine.eval_exec(&event(&[])).is_empty());
}
