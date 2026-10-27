//! No input panics, and a parsed hash round-trips.

use intel::{FeedId, MAX_DOMAIN_BYTES, SetBuilder, normalize_domain, parse_sha256};
use proptest::prelude::*;

proptest! {
    #[test]
    fn a_feed_of_arbitrary_text_never_panics_and_counts_every_line(text in "\\PC{0,400}") {
        let mut builder = SetBuilder::new(1 << 20);
        let report = builder.add_lines(FeedId(1), &text);
        let lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .count() as u64;
        prop_assert_eq!(report.added + report.rejected + report.over_budget, lines);
        prop_assert!(builder.build().is_ok());
    }

    #[test]
    fn arbitrary_bytes_as_a_hash_never_panic(text in "\\PC{0,100}") {
        let _ = parse_sha256(&text);
    }

    #[test]
    fn a_hash_round_trips_through_hex(digest in prop::array::uniform32(any::<u8>())) {
        let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
        prop_assert_eq!(parse_sha256(&hex), Ok(digest));
    }

    #[test]
    fn arbitrary_text_as_a_domain_never_panics_in_either_direction(name in "\\PC{0,300}") {
        let mut builder = SetBuilder::new(1 << 20);
        let _ = builder.add_domain(&name, FeedId(1));
        let set = builder.build().unwrap();
        let _ = set.lookup_domain(&name);
    }

    #[test]
    fn domain_normalisation_is_idempotent_and_lowercase_ascii(name in "[a-zA-Z0-9_.-]{0,300}") {
        if let Ok(once) = normalize_domain(&name) {
            prop_assert_eq!(normalize_domain(&once), Ok(once.clone()));
            prop_assert!(once.len() <= MAX_DOMAIN_BYTES);
            prop_assert!(once.is_ascii());
            prop_assert!(once.bytes().all(|b| !b.is_ascii_uppercase()));
            prop_assert!(!once.ends_with('.'));
        }
    }

    #[test]
    fn a_listed_domain_matches_every_name_beneath_it_in_any_case(
        parent in "[a-z][a-z0-9]{0,10}\\.[a-z]{2,6}",
        below in prop::collection::vec("[a-z0-9]{1,12}", 0..6),
        upper in any::<bool>(),
    ) {
        let mut builder = SetBuilder::new(1 << 20);
        prop_assert_eq!(builder.add_domain(&parent, FeedId(4)), Ok(true));
        let set = builder.build().unwrap();
        let mut name = below.join(".");
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&parent);
        if upper {
            name = name.to_uppercase();
        }
        prop_assert_eq!(set.lookup_domain(&name).map(|m| m.feed), Some(FeedId(4)));
    }

    #[test]
    fn a_name_not_ending_in_the_listed_domain_on_a_label_boundary_never_matches(
        prefix in "[a-z0-9]{1,12}",
    ) {
        let mut builder = SetBuilder::new(1 << 20);
        prop_assert_eq!(builder.add_domain("evil.example", FeedId(1)), Ok(true));
        let set = builder.build().unwrap();
        // Joined without a dot, `evil.example` is the tail of one label, not a parent.
        let glued = format!("{prefix}evil.example");
        prop_assert!(set.lookup_domain(&glued).is_none());
        let other_tld = format!("{prefix}.evil.example.test");
        prop_assert!(set.lookup_domain(&other_tld).is_none());
    }
}
