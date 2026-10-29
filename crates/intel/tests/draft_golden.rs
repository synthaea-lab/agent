//! The draft IOC set the server's hunt graduation writes (#934) loads in this engine whole: every
//! line is an indicator, none is rejected, and each one matches. The fixture is the file
//! `server/tests/unit/hunt-ioc-draft.test.ts` compares the exporter's output to, so a change to
//! either side that the other cannot read fails here or there.

use intel::{DEFAULT_MEMORY_BUDGET_BYTES, FeedId, IndicatorKind, SetBuilder};

const DRAFT: &str = include_str!("../../../server/tests/fixtures/ioc-draft-golden.txt");

#[test]
fn a_graduated_draft_loads_whole_and_every_line_matches() {
    let mut builder = SetBuilder::new(DEFAULT_MEMORY_BUDGET_BYTES);
    let report = builder.add_lines(FeedId(1), DRAFT);
    assert_eq!(
        report.rejected, 0,
        "a line of the draft is not an indicator"
    );
    assert_eq!(report.over_budget, 0);
    let indicators = DRAFT
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count() as u64;
    assert_eq!(report.added, indicators);
    assert_eq!(indicators, 6);

    let set = builder.build().expect("the draft fits the budget");
    for hash in [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        &"a".repeat(64),
    ] {
        let found = set
            .lookup_sha256_hex(hash)
            .unwrap_or_else(|| panic!("{hash}"));
        assert_eq!(found.kind, IndicatorKind::Sha256);
        assert_eq!(found.feed, FeedId(1));
    }
    for address in ["2001:db8::1", "203.0.113.9"] {
        let ip = address.parse().unwrap();
        let found = set.lookup_ip(ip).unwrap_or_else(|| panic!("{address}"));
        assert_eq!(found.kind, IndicatorKind::Ip);
    }
    for name in ["a.evil.example", "c2.evil.example", "www.a.evil.example"] {
        let found = set.lookup_domain(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(found.kind, IndicatorKind::Domain);
        assert_eq!(found.feed, FeedId(1));
    }
}
