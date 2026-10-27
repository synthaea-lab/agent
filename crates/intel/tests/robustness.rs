//! No input panics, and a parsed hash round-trips.

use intel::{FeedId, SetBuilder, parse_sha256};
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
}
