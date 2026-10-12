//! The rarity feature: is the executed image on this fleet's common set? The Rust mirror of
//! `ml/synthaea_ml/features/rarity.py` (issue #640, ADR-0020).
//!
//! ADR-0020: the server publishes, per tenant, a **common-set snapshot** (the image hashes seen
//! on at least K hosts) and the device checks an executed image against it locally. The model
//! input is a small ordinal derived from that snapshot, never a host count (a count is not
//! something the device can compute). Two numbers, because "rare" must be distinguishable from
//! "no basis to say":
//!
//! - `rarity_known`: 1.0 when a snapshot exists, covers at least `min_hosts` hosts and the event
//!   carries a usable image hash; otherwise 0.0. A freshly enrolled fleet has an empty
//!   snapshot, and without this every binary on it would look rare.
//! - `image_in_common_set`: 1.0 when known and the hash is in the common set, else 0.0. Only
//!   meaningful when `rarity_known` is 1.0.
//!
//! This is a parity seam like the others: a model trained on the Python vectors only scores
//! consistently here if both sides produce the identical vector. It is locked by
//! `ml/tests/fixtures/rarity_golden.jsonl`, checked from Rust (`tests/rarity_golden.rs`) and
//! Python (`ml/tests/test_rarity_golden.py`).
//!
//! The snapshot's wire format (a set, a Bloom or a cuckoo filter) is not decided here: the
//! extractor takes a [`CommonSet`], a membership test plus the number of hosts the snapshot
//! covered, so it does not depend on how the server ships it. K, the minimum coverage, the
//! cadence and the filter's false-positive rate are left to calibration on lab data
//! (ADR-0020). Nothing in the agent builds a [`CommonSet`] yet: this module only defines the
//! feature, so that a model trained on it can later be loaded.

/// Feature names, in vector order. See `rarity.py::FEATURE_NAMES` -- keep in sync.
pub const FEATURE_NAMES: [&str; 2] = ["rarity_known", "image_in_common_set"];

/// Length of the vector [`extract_features`] returns.
pub const FEATURE_COUNT: usize = FEATURE_NAMES.len();

/// What the agent knows about the fleet's common set: a membership test and how many hosts the
/// snapshot was built from.
pub trait CommonSet {
    /// Whether the normalized image hash (see [`normalize_sha256`]) is in the common set. A
    /// probabilistic filter may answer `true` for a hash that is not in it, never `false` for
    /// one that is.
    fn contains(&self, sha256: &str) -> bool;

    /// How many hosts had reported when the snapshot was taken; compared with the `min_hosts`
    /// the extractor is given.
    fn hosts_covered(&self) -> u64;
}

/// The key the server's counters use: 64 lowercase hex characters after trimming surrounding
/// whitespace and lowercasing, else `None`.
///
/// Mirrors `rarity.py::normalize_sha256`, including what Python's `str.strip()` treats as
/// whitespace: the Unicode `White_Space` property plus the four ASCII separators U+001C..U+001F.
#[must_use]
pub fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed =
        value.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c));
    let lowered = trimmed.to_lowercase();
    let is_hash = lowered.len() == 64
        && lowered
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    is_hash.then_some(lowered)
}

/// The two rarity features for one executed image against the snapshot in force.
///
/// `[0.0, 0.0]` when the event has no usable hash, there is no snapshot, or the snapshot covers
/// fewer than `min_hosts` hosts: "no basis to say", which the model must not read as "rare".
#[must_use]
pub fn extract_features(
    sha256: Option<&str>,
    snapshot: Option<&dyn CommonSet>,
    min_hosts: u64,
) -> [f32; FEATURE_COUNT] {
    let Some(key) = sha256.and_then(normalize_sha256) else {
        return [0.0, 0.0];
    };
    let Some(snapshot) = snapshot else {
        return [0.0, 0.0];
    };
    if snapshot.hosts_covered() < min_hosts {
        return [0.0, 0.0];
    }
    [1.0, if snapshot.contains(&key) { 1.0 } else { 0.0 }]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    struct Set {
        common: HashSet<String>,
        hosts: u64,
    }

    impl CommonSet for Set {
        fn contains(&self, sha256: &str) -> bool {
            self.common.contains(sha256)
        }
        fn hosts_covered(&self) -> u64 {
            self.hosts
        }
    }

    fn set_of(hashes: &[&str], hosts: u64) -> Set {
        Set {
            common: hashes.iter().map(|h| (*h).to_string()).collect(),
            hosts,
        }
    }

    const H1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const H2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn rare_is_distinguished_from_no_basis_to_say() {
        let covered = set_of(&[H1], 10);
        let thin = set_of(&[H1], 2);
        assert_eq!(extract_features(Some(H1), Some(&covered), 5), [1.0, 1.0]);
        assert_eq!(extract_features(Some(H2), Some(&covered), 5), [1.0, 0.0]);
        assert_eq!(extract_features(Some(H1), Some(&thin), 5), [0.0, 0.0]);
        assert_eq!(extract_features(Some(H1), None, 5), [0.0, 0.0]);
        assert_eq!(extract_features(None, Some(&covered), 5), [0.0, 0.0]);
    }

    #[test]
    fn coverage_is_inclusive_at_the_minimum() {
        assert_eq!(
            extract_features(Some(H1), Some(&set_of(&[H1], 5)), 5),
            [1.0, 1.0]
        );
        assert_eq!(
            extract_features(Some(H1), Some(&set_of(&[H1], 4)), 5),
            [0.0, 0.0]
        );
    }

    #[test]
    fn a_hash_is_normalized_like_the_python_side() {
        assert_eq!(normalize_sha256(&H1.to_uppercase()).as_deref(), Some(H1));
        assert_eq!(normalize_sha256(&format!("  {H1}\n")).as_deref(), Some(H1));
        assert_eq!(
            normalize_sha256(&format!("\u{1c}{H1}\u{a0}")).as_deref(),
            Some(H1)
        );
        assert_eq!(normalize_sha256(&H1[..63]), None);
        assert_eq!(normalize_sha256(&format!("{H1}a")), None);
        assert_eq!(normalize_sha256(&format!("g{}", &H1[1..])), None);
        assert_eq!(normalize_sha256(""), None);
    }
}
