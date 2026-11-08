//! The file the server's feed builder writes (`server/lib/ioc-feed.ts`) loads here unchanged.
//!
//! `server/tests/fixtures/ioc-feed-golden.txt` is checked on both sides: the server test asserts
//! its builder produces it from `ioc-feed-input.txt`, this test asserts the engine takes every line
//! of it. A rule changed on one side only breaks one of the two.

use intel::{DEFAULT_MEMORY_BUDGET_BYTES, FeedId, SetBuilder};

/// In the `server` sibling repo; read at run time, the test skips without it.
const GOLDEN_PATH: &str = "tests/fixtures/ioc-feed-golden.txt";

#[test]
fn every_line_of_the_servers_golden_feed_loads_with_no_rejection() {
    let golden = siblings::require!("server", GOLDEN_PATH);
    let lines = golden.lines().count() as u64;
    let mut builder = SetBuilder::new(DEFAULT_MEMORY_BUDGET_BYTES);
    let report = builder.add_lines(FeedId(1), &golden);
    assert_eq!(
        (report.added, report.rejected, report.over_budget),
        (lines, 0, 0)
    );
    let set = builder.build().unwrap();
    assert_eq!(set.len() as u64, lines, "no duplicate in the golden file");
}

#[test]
fn the_golden_feed_is_found_by_its_normal_forms() {
    let golden = siblings::require!("server", GOLDEN_PATH);
    let mut builder = SetBuilder::new(DEFAULT_MEMORY_BUDGET_BYTES);
    builder.add_lines(FeedId(1), &golden);
    let set = builder.build().unwrap();
    assert!(set.lookup_domain("www.evil.example.org").is_some());
    assert!(set.lookup_ip("203.0.113.10".parse().unwrap()).is_some());
    assert!(set.lookup_ip("2001:db8:0:1::1".parse().unwrap()).is_some());
    assert!(
        set.lookup_sha256_hex("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .is_some()
    );
}
