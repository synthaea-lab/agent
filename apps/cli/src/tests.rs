use super::*;

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(std::iter::once("cli").chain(args.iter().copied())).unwrap()
}

fn target() -> SuppressionTarget {
    SuppressionTarget {
        ppid: 4242,
        comm: "bash".into(),
        technique: "T1059.004".into(),
    }
}

#[test]
fn suppress_reads_the_entity_and_the_technique_in_order() {
    let cli = parse(&["suppress", "4242", "bash", "T1059.004"]);

    assert!(matches!(cli.command, Command::Suppress(t) if t == target()));
}

#[test]
fn unsuppress_reads_the_same_target_as_suppress() {
    let cli = parse(&["unsuppress", "4242", "bash", "T1059.004"]);

    assert!(matches!(cli.command, Command::Unsuppress(t) if t == target()));
}

#[test]
fn a_ppid_that_is_not_a_number_is_refused() {
    let parsed = Cli::try_parse_from(["cli", "suppress", "bash", "4242", "T1059.004"]);

    assert!(parsed.is_err());
}

#[test]
fn the_global_flags_apply_to_suppress() {
    let cli = parse(&["suppress", "4242", "bash", "T1059.004", "--json"]);

    assert!(cli.json);
}

#[test]
fn a_new_suppression_says_what_it_silenced() {
    assert_eq!(
        SuppressionChange::Suppress.outcome_line(&target(), true),
        "suppressed T1059.004 on 4242:bash"
    );
}

#[test]
fn a_repeated_suppression_says_nothing_changed() {
    assert_eq!(
        SuppressionChange::Suppress.outcome_line(&target(), false),
        "T1059.004 on 4242:bash already suppressed; nothing changed"
    );
}

#[test]
fn a_lifted_suppression_says_what_it_restored() {
    assert_eq!(
        SuppressionChange::Lift.outcome_line(&target(), true),
        "lifted suppression of T1059.004 on 4242:bash"
    );
}

#[test]
fn lifting_a_suppression_that_was_not_there_says_nothing_changed() {
    assert_eq!(
        SuppressionChange::Lift.outcome_line(&target(), false),
        "T1059.004 on 4242:bash was not suppressed; nothing changed"
    );
}
