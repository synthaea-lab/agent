//! The pre-filter: a plain Bloom filter over a 128-bit key, kept in memory only.
//!
//! It answers "certainly not in the set" cheaply so that most lookups never touch the exact
//! tier's sorted array. It is never the verdict: a "maybe" is always confirmed by the exact
//! tier, so a false positive costs one binary search and never produces a detection.
//!
//! Not persisted and not shared with the server, so there is no byte layout to keep stable
//! (unlike the common-set snapshot, `crates/ml/src/features/common_set.rs`, which is a
//! server-written format read as weak evidence). The two do not share code on purpose: that
//! reader sits in `ml`, which a detection leaf like this one should not pull in.

/// Bit positions per key. With [`BITS_PER_ENTRY`] this gives a false-positive rate near 1%.
const HASHES: u64 = 7;
/// Filter bits per indicator.
const BITS_PER_ENTRY: u64 = 10;

/// Bytes the filter for `entries` keys occupies; exposed so the memory budget is computed
/// before anything is allocated.
pub(crate) fn bytes_for(entries: usize) -> usize {
    words_for(entries) * 8
}

fn words_for(entries: usize) -> usize {
    let bits = (entries as u64).saturating_mul(BITS_PER_ENTRY);
    // At least one word so `% bits` is defined, even for an empty set.
    usize::try_from(bits.div_ceil(64).max(1)).unwrap_or(usize::MAX)
}

#[derive(Debug)]
pub(crate) struct Bloom {
    words: Vec<u64>,
}

impl Bloom {
    pub(crate) fn with_capacity(entries: usize) -> Self {
        Self {
            words: vec![0; words_for(entries)],
        }
    }

    fn bit_count(&self) -> u64 {
        self.words.len() as u64 * 64
    }

    /// Double hashing: position `i` is `h1 + i * h2`; `h2` is forced odd so the positions of
    /// one key do not collapse onto each other when the bit count is a multiple of 64.
    fn positions(&self, (h1, h2): (u64, u64)) -> impl Iterator<Item = u64> {
        let bits = self.bit_count();
        let step = h2 | 1;
        (0..HASHES).map(move |i| h1.wrapping_add(i.wrapping_mul(step)) % bits)
    }

    pub(crate) fn insert(&mut self, key: (u64, u64)) {
        let positions: Vec<u64> = self.positions(key).collect();
        for bit in positions {
            self.words[(bit / 64) as usize] |= 1 << (bit % 64);
        }
    }

    pub(crate) fn may_contain(&self, key: (u64, u64)) -> bool {
        self.positions(key)
            .all(|bit| self.words[(bit / 64) as usize] & (1 << (bit % 64)) != 0)
    }

    pub(crate) fn bytes(&self) -> usize {
        self.words.len() * 8
    }
}

/// `SplitMix64`'s finaliser: a bijective mixer, so distinct inputs stay distinct.
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Filter key of a SHA-256 digest: it is already uniform, so two of its words are used as they
/// are.
pub(crate) fn digest_key(digest: &[u8; 32]) -> (u64, u64) {
    let word = |at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[at..at + 8]);
        u64::from_le_bytes(bytes)
    };
    (word(0), word(8))
}

/// Filter key of a canonical IPv6-mapped address.
pub(crate) fn address_key(address: u128) -> (u64, u64) {
    let lo = address as u64;
    let hi = (address >> 64) as u64;
    (mix(lo ^ mix(hi)), mix(hi ^ 0x9e37_79b9_7f4a_7c15))
}
