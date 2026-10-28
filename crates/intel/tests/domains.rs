//! Domain matching through the public API: suffix on a label boundary, normalisation, bounds,
//! budget, provenance.

use intel::{
    BuildError, DEFAULT_MEMORY_BUDGET_BYTES, FeedId, IndicatorKind, IndicatorSet, Intel,
    MAX_DOMAIN_BYTES, MAX_INDICATOR_LABELS, ParseError, SetBuilder, estimated_bytes_with_domains,
    normalize_domain,
};

const BIG: usize = DEFAULT_MEMORY_BUDGET_BYTES;

fn set_of(names: &[&str]) -> IndicatorSet {
    let mut builder = SetBuilder::new(BIG);
    for name in names {
        assert_eq!(builder.add_domain(name, FeedId(1)), Ok(true), "{name}");
    }
    builder.build().unwrap()
}

#[test]
fn a_listed_domain_matches_itself_and_every_name_beneath_it() {
    let set = set_of(&["evil.example"]);
    for name in [
        "evil.example",
        "www.evil.example",
        "a.b.c.evil.example",
        "xn--80ak6aa92e.evil.example",
    ] {
        let found = set.lookup_domain(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(found.kind, IndicatorKind::Domain);
        assert_eq!(found.feed, FeedId(1));
    }
}

#[test]
fn a_suffix_must_start_on_a_label_boundary_never_inside_a_label() {
    let set = set_of(&["evil.example"]);
    for name in [
        "notevil.example",
        "xevil.example",
        "evil.example.org",
        "evil-example",
        "evilxexample",
        "example",
        "evil.examples",
        "my.evil.example.net",
    ] {
        assert!(set.lookup_domain(name).is_none(), "{name}");
    }
}

#[test]
fn a_listed_subdomain_does_not_cover_its_parent() {
    let set = set_of(&["c2.evil.example"]);
    assert!(set.lookup_domain("c2.evil.example").is_some());
    assert!(set.lookup_domain("x.c2.evil.example").is_some());
    assert!(set.lookup_domain("evil.example").is_none());
    assert!(set.lookup_domain("www.evil.example").is_none());
}

#[test]
fn case_and_the_trailing_root_dot_do_not_change_the_answer() {
    let set = set_of(&["Evil.Example."]);
    for name in ["EVIL.example", "evil.example.", "Www.Evil.EXAMPLE."] {
        assert!(set.lookup_domain(name).is_some(), "{name}");
    }
    // One root dot only: a second one is an empty label.
    assert!(set.lookup_domain("evil.example..").is_none());
}

#[test]
fn a_name_that_is_not_valid_dns_matches_nothing() {
    let set = set_of(&["evil.example"]);
    let too_long_label = format!("{}.evil.example", "a".repeat(64));
    for name in [
        "",
        ".",
        ".evil.example",
        "a..evil.example",
        "bad name.evil.example",
        "-a.evil.example",
        "a-.evil.example",
        "é.evil.example",
        "evil.example\0",
        &too_long_label,
    ] {
        assert!(set.lookup_domain(name).is_none(), "{name:?}");
    }
}

#[test]
fn a_label_of_63_bytes_and_a_name_of_253_are_the_limits() {
    let longest_label = "a".repeat(63);
    assert!(normalize_domain(&format!("{longest_label}.example")).is_ok());
    assert!(normalize_domain(&format!("{}.example", "a".repeat(64))).is_err());

    // 3 labels of 63 + 1 of 61, joined by dots: 63*3 + 61 + 3 = 253.
    let longest = format!("{l}.{l}.{l}.{}", "a".repeat(61), l = longest_label);
    assert_eq!(longest.len(), MAX_DOMAIN_BYTES);
    assert!(normalize_domain(&longest).is_ok());
    assert_eq!(
        normalize_domain(&format!("{longest}a")),
        Err(ParseError::BadDomain)
    );
}

#[test]
fn a_lookup_costs_the_same_bounded_work_for_a_name_of_any_depth() {
    let set = set_of(&["evil.example"]);
    // 118 labels under the listed domain (248 bytes): still found through the last two.
    let deep = format!("{}.evil.example", ["x"; 118].join("."));
    assert!(deep.len() <= MAX_DOMAIN_BYTES);
    assert!(set.lookup_domain(&deep).is_some());
    // An indicator deeper than a lookup probes is refused at load, not silently unmatchable.
    let too_deep = ["a"; MAX_INDICATOR_LABELS + 1].join(".");
    let mut builder = SetBuilder::new(BIG);
    assert_eq!(
        builder.add_domain(&too_deep, FeedId(1)),
        Err(ParseError::DomainTooDeep)
    );
    let deepest = ["a"; MAX_INDICATOR_LABELS].join(".");
    assert_eq!(builder.add_domain(&deepest, FeedId(1)), Ok(true));
    let set = builder.build().unwrap();
    assert!(set.lookup_domain(&format!("q.{deepest}")).is_some());
}

#[test]
fn a_single_label_and_an_address_literal_are_not_indicators() {
    let mut builder = SetBuilder::new(BIG);
    for (text, error) in [
        ("com", ParseError::DomainTooBroad),
        ("localhost.", ParseError::DomainTooBroad),
        ("203.0.113.7", ParseError::BadDomain),
        ("evil.123", ParseError::BadDomain),
        ("évil.example", ParseError::NonAsciiDomain),
        ("*.evil.example", ParseError::BadDomain),
        ("evil.example/path", ParseError::BadDomain),
        ("http://evil.example", ParseError::BadDomain),
        ("evil.example:8080", ParseError::BadDomain),
    ] {
        assert_eq!(builder.add_domain(text, FeedId(1)), Err(error), "{text}");
    }
    let report = builder.add_lines(
        FeedId(1),
        "domain:com\ndomain:\ndomain:203.0.113.7\ndomain:ok.example",
    );
    assert_eq!((report.added, report.rejected), (1, 3));
}

#[test]
fn a_single_label_name_never_matches_even_when_its_tld_is_listed_as_a_suffix_of_nothing() {
    let set = set_of(&["evil.example"]);
    assert!(set.lookup_domain("example").is_none());
    assert!(set.lookup_domain("com").is_none());
}

#[test]
fn punycode_is_compared_as_written_and_unicode_is_rejected() {
    let set = set_of(&["xn--80ak6aa92e.example"]);
    assert!(set.lookup_domain("XN--80AK6AA92E.example").is_some());
    assert!(set.lookup_domain("www.xn--80ak6aa92e.example").is_some());
    assert!(set.lookup_domain("пример.example").is_none());
}

#[test]
fn when_feeds_list_nested_domains_the_lowest_feed_is_reported() {
    let mut builder = SetBuilder::new(BIG);
    assert_eq!(builder.add_domain("evil.example", FeedId(7)), Ok(true));
    assert_eq!(builder.add_domain("c2.evil.example", FeedId(3)), Ok(true));
    assert_eq!(builder.add_domain("evil.example", FeedId(9)), Ok(true));
    let set = builder.build().unwrap();
    assert_eq!(set.len(), 3 - 1, "the same name twice collapses");
    assert_eq!(set.lookup_domain("evil.example").unwrap().feed, FeedId(7));
    assert_eq!(
        set.lookup_domain("x.c2.evil.example").unwrap().feed,
        FeedId(3)
    );
    assert_eq!(
        set.lookup_domain("www.evil.example").unwrap().feed,
        FeedId(7)
    );

    // The lowest feed wins whichever of the nested names carries it.
    let mut builder = SetBuilder::new(BIG);
    assert_eq!(builder.add_domain("evil.example", FeedId(3)), Ok(true));
    assert_eq!(builder.add_domain("c2.evil.example", FeedId(7)), Ok(true));
    let set = builder.build().unwrap();
    assert_eq!(
        set.lookup_domain("x.c2.evil.example").unwrap().feed,
        FeedId(3)
    );
}

#[test]
fn the_filter_never_decides_and_unlisted_names_are_rarely_probed_exactly() {
    let listed: Vec<String> = (0..5_000).map(|i| format!("bad{i}.example")).collect();
    let mut builder = SetBuilder::new(BIG);
    for name in &listed {
        assert_eq!(builder.add_domain(name, FeedId(1)), Ok(true));
    }
    let set = builder.build().unwrap();
    for name in &listed {
        assert!(set.lookup_domain(name).is_some());
    }
    for i in 0..50_000 {
        assert!(set.lookup_domain(&format!("good{i}.example")).is_none());
    }
    let stats = set.stats();
    assert_eq!(stats.hits, 5_000);
    assert_eq!(
        stats.lookups,
        stats.hits + stats.filter_negatives + stats.filter_false_positives
    );
    // Each unlisted name is probed once (its two-label suffix), ~1% by construction.
    assert!(
        stats.filter_false_positives < 1_500,
        "filter false positives: {}",
        stats.filter_false_positives
    );
}

#[test]
fn domains_count_in_len_and_in_memory_and_stay_within_the_estimate() {
    let names = [
        "evil.example",
        "c2.bad.example",
        "a.very.long.indicator.example",
    ];
    let bytes: usize = names.iter().map(|n| n.len()).sum();
    let set = set_of(&names);
    assert_eq!(set.len(), 3);
    assert_eq!(
        set.memory_bytes(),
        estimated_bytes_with_domains(0, 0, 3, bytes),
        "no duplicates, so the estimate is exact"
    );
}

#[test]
fn a_set_over_the_budget_is_refused_whole_and_names_count_by_their_length() {
    let names: Vec<String> = (0..100).map(|i| format!("name{i:03}.example")).collect();
    let bytes: usize = names.iter().map(String::len).sum();
    let budget = estimated_bytes_with_domains(0, 0, 100, bytes);
    let mut builder = SetBuilder::new(budget);
    for name in &names {
        assert_eq!(builder.add_domain(name, FeedId(1)), Ok(true));
    }
    // One more, longer than any of them, does not fit.
    assert_eq!(builder.add_domain("one.more.example", FeedId(1)), Ok(false));
    assert_eq!(
        builder.build().unwrap_err(),
        BuildError::BudgetExceeded { budget, refused: 1 }
    );
}

#[test]
fn a_reload_swaps_domains_with_the_rest_of_the_set() {
    let engine = Intel::new();
    assert!(engine.lookup_domain("evil.example").is_none());
    engine.load(set_of(&["evil.example"]));
    assert!(engine.lookup_domain("www.evil.example").is_some());
    engine.load(set_of(&["other.example"]));
    assert!(engine.lookup_domain("www.evil.example").is_none());
    assert!(engine.lookup_domain("other.example").is_some());
}

#[test]
fn an_empty_set_matches_no_domain() {
    assert!(
        IndicatorSet::empty()
            .lookup_domain("evil.example")
            .is_none()
    );
}
