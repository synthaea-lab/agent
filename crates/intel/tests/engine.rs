//! The engine through its public API: exactness, provenance, budget, reload.

use std::{net::IpAddr, sync::Arc, thread};

use intel::{
    BuildError, DEFAULT_MEMORY_BUDGET_BYTES, FeedId, IndicatorKind, IndicatorSet, Intel,
    ParseError, SetBuilder, estimated_bytes, parse_sha256,
};

const BIG: usize = DEFAULT_MEMORY_BUDGET_BYTES;

/// A deterministic stream of well-spread digests (`SplitMix64`, four words per digest).
fn digests(seed: u64, count: usize) -> Vec<[u8; 32]> {
    let mut state = seed;
    let mut next = move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    (0..count)
        .map(|_| {
            let mut digest = [0u8; 32];
            for chunk in digest.as_chunks_mut::<8>().0.iter_mut() {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            digest
        })
        .collect()
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn set_of(hashes: &[[u8; 32]], feed: FeedId) -> IndicatorSet {
    let mut builder = SetBuilder::new(BIG);
    for digest in hashes {
        assert!(builder.add_sha256(*digest, feed));
    }
    builder.build().unwrap()
}

#[test]
fn every_listed_hash_is_found_and_the_feed_is_reported() {
    let listed = digests(1, 20_000);
    let set = set_of(&listed, FeedId(7));
    for digest in &listed {
        let found = set.lookup_sha256(digest).expect("a listed hash must match");
        assert_eq!(found.kind, IndicatorKind::Sha256);
        assert_eq!(found.feed, FeedId(7));
    }
    assert_eq!(set.stats().hits, 20_000);
}

#[test]
fn an_unlisted_hash_never_matches_and_the_filter_rarely_costs_a_lookup() {
    let set = set_of(&digests(1, 20_000), FeedId(1));
    let absent = digests(2, 100_000);
    for digest in &absent {
        assert!(set.lookup_sha256(digest).is_none());
    }
    let stats = set.stats();
    assert_eq!(stats.hits, 0, "the exact tier is the verdict");
    assert_eq!(
        stats.filter_negatives + stats.filter_false_positives,
        100_000
    );
    // ~1% by construction; 3% leaves room for variance without hiding a broken filter.
    assert!(
        stats.filter_false_positives < 3_000,
        "filter false positives: {}",
        stats.filter_false_positives
    );
}

#[test]
fn hex_is_accepted_in_either_case_and_malformed_hex_matches_nothing() {
    let digest = digests(3, 1)[0];
    let set = set_of(&[digest], FeedId(1));
    let lower = hex(&digest);
    assert!(set.lookup_sha256_hex(&lower).is_some());
    assert!(set.lookup_sha256_hex(&lower.to_uppercase()).is_some());
    assert!(set.lookup_sha256_hex(&lower[..63]).is_none());
    assert!(set.lookup_sha256_hex(&format!("{lower}0")).is_none());
    assert!(
        set.lookup_sha256_hex(&format!("g{}", &lower[1..]))
            .is_none()
    );
    assert_eq!(parse_sha256(&lower[..10]), Err(ParseError::BadHashLength));
    assert_eq!(
        parse_sha256(&format!("g{}", &lower[1..])),
        Err(ParseError::BadHashDigit)
    );
}

#[test]
fn an_ipv4_mapped_ipv6_address_is_the_ipv4_address() {
    let mut builder = SetBuilder::new(BIG);
    assert_eq!(builder.add_ip(ip("203.0.113.9"), FeedId(1)), Ok(true));
    assert_eq!(builder.add_ip(ip("2001:db8::5"), FeedId(1)), Ok(true));
    let set = builder.build().unwrap();
    assert!(set.lookup_ip(ip("203.0.113.9")).is_some());
    assert!(set.lookup_ip(ip("::ffff:203.0.113.9")).is_some());
    assert!(set.lookup_ip(ip("2001:db8::5")).is_some());
    assert!(set.lookup_ip(ip("203.0.113.10")).is_none());
    assert!(set.lookup_ip(ip("2001:db8::6")).is_none());
}

#[test]
fn loopback_and_unspecified_addresses_are_not_indicators() {
    let mut builder = SetBuilder::new(BIG);
    for text in ["127.0.0.1", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1"] {
        assert_eq!(
            builder.add_ip(ip(text), FeedId(1)),
            Err(ParseError::UnusableAddress),
            "{text}"
        );
    }
    let report = builder.add_lines(FeedId(1), "ip:127.0.0.1\nip:::1\nip:0.0.0.0");
    assert_eq!((report.added, report.rejected), (0, 3));
    assert!(builder.build().unwrap().is_empty());
}

#[test]
fn when_feeds_overlap_the_lowest_feed_is_reported() {
    let digest = digests(4, 1)[0];
    let mut builder = SetBuilder::new(BIG);
    assert!(builder.add_sha256(digest, FeedId(9)));
    assert!(builder.add_sha256(digest, FeedId(2)));
    assert!(builder.add_sha256(digest, FeedId(5)));
    assert_eq!(builder.add_ip(ip("198.51.100.1"), FeedId(8)), Ok(true));
    assert_eq!(builder.add_ip(ip("198.51.100.1"), FeedId(3)), Ok(true));
    let set = builder.build().unwrap();
    assert_eq!(set.len(), 2, "duplicates collapse");
    assert_eq!(set.lookup_sha256(&digest).unwrap().feed, FeedId(2));
    assert_eq!(set.lookup_ip(ip("198.51.100.1")).unwrap().feed, FeedId(3));
}

#[test]
fn add_lines_counts_bad_lines_and_keeps_the_good_ones() {
    let digest = digests(5, 1)[0];
    let text = format!(
        "# a feed\n\nsha256:{}\n  ip: 192.0.2.7  \nsha256:xyz\nmd5:abc\nip:not-an-address\nip:10.0.0.0/8\n",
        hex(&digest)
    );
    let mut builder = SetBuilder::new(BIG);
    let report = builder.add_lines(FeedId(1), &text);
    assert_eq!(
        (report.added, report.rejected, report.over_budget),
        (2, 4, 0)
    );
    let set = builder.build().unwrap();
    assert!(set.lookup_sha256(&digest).is_some());
    assert!(set.lookup_ip(ip("192.0.2.7")).is_some());
}

#[test]
fn a_set_over_the_budget_is_refused_whole_not_truncated() {
    let budget = estimated_bytes(100, 0);
    let mut builder = SetBuilder::new(budget);
    let mut refused = 0;
    for digest in digests(6, 150) {
        if !builder.add_sha256(digest, FeedId(1)) {
            refused += 1;
        }
    }
    assert_eq!(refused, 50);
    assert_eq!(
        builder.build().unwrap_err(),
        BuildError::BudgetExceeded {
            budget,
            refused: 50
        }
    );
}

#[test]
fn a_built_set_stays_within_the_estimate_and_the_budget() {
    let hashes = digests(7, 5_000);
    let mut builder = SetBuilder::new(estimated_bytes(5_000, 3));
    for digest in &hashes {
        assert!(builder.add_sha256(*digest, FeedId(1)));
    }
    for text in ["192.0.2.1", "192.0.2.2", "2001:db8::1"] {
        assert_eq!(builder.add_ip(ip(text), FeedId(1)), Ok(true));
    }
    let set = builder.build().unwrap();
    assert!(set.memory_bytes() <= estimated_bytes(5_000, 3));
}

#[test]
fn an_empty_set_and_a_fresh_engine_match_nothing() {
    let set = IndicatorSet::empty();
    assert!(set.is_empty());
    assert!(set.lookup_sha256(&[0; 32]).is_none());
    assert!(set.lookup_ip(ip("192.0.2.1")).is_none());
    let engine = Intel::new();
    assert!(engine.lookup_ip(ip("192.0.2.1")).is_none());
    assert!(engine.lookup_sha256_hex(&"0".repeat(64)).is_none());
}

#[test]
fn a_reload_replaces_the_set_and_a_held_snapshot_keeps_the_old_one() {
    let old = digests(8, 1)[0];
    let new = digests(9, 1)[0];
    let engine = Intel::new();
    engine.load(set_of(&[old], FeedId(1)));
    let held = engine.snapshot();
    assert!(engine.lookup_sha256_hex(&hex(&old)).is_some());

    let replaced = engine.load(set_of(&[new], FeedId(2)));
    assert_eq!(replaced.len(), 1);
    assert!(engine.lookup_sha256_hex(&hex(&old)).is_none());
    assert_eq!(
        engine.lookup_sha256_hex(&hex(&new)).unwrap().feed,
        FeedId(2)
    );
    // A lookup begun before the reload ends on the set it began with.
    assert!(held.lookup_sha256(&old).is_some());
    assert!(held.lookup_sha256(&new).is_none());
}

#[test]
fn lookups_during_reloads_always_see_one_whole_set() {
    let a = digests(10, 2_000);
    let b = digests(11, 2_000);
    let engine = Arc::new(Intel::new());
    engine.load(set_of(&a, FeedId(1)));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let engine = Arc::clone(&engine);
            let (a, b) = (a.clone(), b.clone());
            thread::spawn(move || {
                for _ in 0..200 {
                    let view = engine.snapshot();
                    // Every digest of one list is in the view, or none is: never a mix.
                    let in_a = a.iter().filter(|d| view.lookup_sha256(d).is_some()).count();
                    let in_b = b.iter().filter(|d| view.lookup_sha256(d).is_some()).count();
                    assert!(
                        (in_a == a.len() && in_b == 0) || (in_a == 0 && in_b == b.len()),
                        "torn view: {in_a} of a, {in_b} of b"
                    );
                }
            })
        })
        .collect();
    for round in 0..50 {
        let (list, feed) = if round % 2 == 0 { (&b, 2) } else { (&a, 1) };
        engine.load(set_of(list, FeedId(feed)));
    }
    for reader in readers {
        reader.join().unwrap();
    }
}
