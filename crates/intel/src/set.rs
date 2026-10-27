//! An immutable indicator set: an exact tier (sorted arrays, binary search) behind a Bloom
//! pre-filter, built within a memory budget.

use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use thiserror::Error;

use crate::filter::{self, Bloom};

/// Memory a built set may occupy unless the caller says otherwise. **Provisional**: sized for a
/// few million hashes, not measured on a fleet.
pub const DEFAULT_MEMORY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Bytes per hash indicator in the exact tier: the digest and its feed.
const SHA256_ENTRY_BYTES: usize = 32 + 2;
/// Bytes per address indicator in the exact tier: the 128-bit address and its feed.
const IP_ENTRY_BYTES: usize = 16 + 2;

/// Which feed an indicator came from; the provenance a detection carries. Assigned by whoever
/// loads the set, an index into its own feed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeedId(pub u16);

/// What kind of indicator matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorKind {
    /// A file's SHA-256.
    Sha256,
    /// An IP address, either family.
    Ip,
}

/// A confirmed match against the exact tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// What matched.
    pub kind: IndicatorKind,
    /// The feed that listed it. When several feeds list one indicator, the lowest id.
    pub feed: FeedId,
}

/// Why a line or value is not an indicator.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// A SHA-256 is 64 hex digits.
    #[error("a sha256 is 64 hex digits")]
    BadHashLength,
    /// A character outside `0-9a-fA-F` in a hash.
    #[error("not a hex digit in a sha256")]
    BadHashDigit,
    /// Not an IPv4 or IPv6 literal (a CIDR range is not supported).
    #[error("not an IP address")]
    BadAddress,
    /// Loopback and unspecified addresses never identify an attacker, and listing one would
    /// alert on every local connection.
    #[error("an address that can never be an indicator")]
    UnusableAddress,
    /// A line that is neither `sha256:<hex>` nor `ip:<address>`.
    #[error("unknown indicator kind")]
    UnknownKind,
}

/// Why a set could not be built.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BuildError {
    /// The set would not fit the memory budget. It is refused whole, never truncated: a
    /// partial feed is partial coverage nobody asked for.
    #[error("{refused} indicators did not fit the {budget}-byte memory budget")]
    BudgetExceeded {
        /// The budget, in bytes.
        budget: usize,
        /// Indicators the builder refused.
        refused: u64,
    },
}

/// What [`SetBuilder::add_lines`] did, counted so that a bad feed is visible.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LoadReport {
    /// Indicators accepted (before de-duplication).
    pub added: u64,
    /// Lines that were not an indicator.
    pub rejected: u64,
    /// Indicators refused because the budget was reached.
    pub over_budget: u64,
}

/// Bytes a built set of this many indicators occupies.
#[must_use]
pub fn estimated_bytes(sha256_count: usize, ip_count: usize) -> usize {
    sha256_count
        .saturating_mul(SHA256_ENTRY_BYTES)
        .saturating_add(filter::bytes_for(sha256_count))
        .saturating_add(ip_count.saturating_mul(IP_ENTRY_BYTES))
        .saturating_add(filter::bytes_for(ip_count))
}

/// Parses a SHA-256 as 64 hex digits, either case.
///
/// # Errors
/// [`ParseError::BadHashLength`] or [`ParseError::BadHashDigit`].
pub fn parse_sha256(hex: &str) -> Result<[u8; 32], ParseError> {
    let hex = hex.as_bytes();
    if hex.len() != 64 {
        return Err(ParseError::BadHashLength);
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseError::BadHashDigit),
    };
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(digest)
}

/// An address as one 128-bit key: IPv4 and IPv4-mapped IPv6 are the same address.
fn address_bits(address: IpAddr) -> u128 {
    match address.to_canonical() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().to_bits(),
        IpAddr::V6(v6) => v6.to_bits(),
    }
}

/// Judged on the canonical form: `::ffff:127.0.0.1` is loopback although `Ipv6Addr` says it
/// is not.
fn is_unusable(address: IpAddr) -> bool {
    let address = address.to_canonical();
    address.is_loopback() || address.is_unspecified()
}

fn parse_address(text: &str) -> Result<u128, ParseError> {
    let address: IpAddr = text.parse().map_err(|_| ParseError::BadAddress)?;
    if is_unusable(address) {
        return Err(ParseError::UnusableAddress);
    }
    Ok(address_bits(address))
}

/// Collects indicators, then builds an [`IndicatorSet`].
///
/// Bounded: once the set it would build no longer fits the budget, further indicators are
/// refused and counted, and [`Self::build`] then fails. While building, the builder holds up to
/// the same entries again as the finished set.
#[derive(Debug)]
pub struct SetBuilder {
    budget: usize,
    sha256: Vec<([u8; 32], FeedId)>,
    addresses: Vec<(u128, FeedId)>,
    refused: u64,
}

impl SetBuilder {
    /// A builder whose set may occupy at most `budget` bytes.
    #[must_use]
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            sha256: Vec::new(),
            addresses: Vec::new(),
            refused: 0,
        }
    }

    fn has_room_for(&self, sha256: usize, addresses: usize) -> bool {
        estimated_bytes(self.sha256.len() + sha256, self.addresses.len() + addresses) <= self.budget
    }

    /// Adds a file hash. Returns `false` when the budget refused it.
    pub fn add_sha256(&mut self, digest: [u8; 32], feed: FeedId) -> bool {
        if !self.has_room_for(1, 0) {
            self.refused += 1;
            return false;
        }
        self.sha256.push((digest, feed));
        true
    }

    /// Adds an address; `Ok(false)` when the budget refused it.
    ///
    /// # Errors
    /// [`ParseError::UnusableAddress`] for a loopback or unspecified address.
    pub fn add_ip(&mut self, address: IpAddr, feed: FeedId) -> Result<bool, ParseError> {
        if is_unusable(address) {
            return Err(ParseError::UnusableAddress);
        }
        Ok(self.push_address(address_bits(address), feed))
    }

    fn push_address(&mut self, bits: u128, feed: FeedId) -> bool {
        if !self.has_room_for(0, 1) {
            self.refused += 1;
            return false;
        }
        self.addresses.push((bits, feed));
        true
    }

    /// Adds every indicator in `text`: one per line, `sha256:<hex>` or `ip:<address>`, blank
    /// lines and `#` comments ignored. A bad line is counted and skipped, never fatal, so one
    /// malformed line does not discard a feed.
    pub fn add_lines(&mut self, feed: FeedId, text: &str) -> LoadReport {
        let mut report = LoadReport::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match self.add_line(feed, line) {
                Ok(true) => report.added += 1,
                Ok(false) => report.over_budget += 1,
                Err(_) => report.rejected += 1,
            }
        }
        report
    }

    fn add_line(&mut self, feed: FeedId, line: &str) -> Result<bool, ParseError> {
        if let Some(hex) = line.strip_prefix("sha256:") {
            Ok(self.add_sha256(parse_sha256(hex.trim())?, feed))
        } else if let Some(address) = line.strip_prefix("ip:") {
            Ok(self.push_address(parse_address(address.trim())?, feed))
        } else {
            Err(ParseError::UnknownKind)
        }
    }

    /// Sorts, de-duplicates (the lowest feed wins) and builds the set.
    ///
    /// # Errors
    /// [`BuildError::BudgetExceeded`] if any indicator was refused for lack of room.
    pub fn build(mut self) -> Result<IndicatorSet, BuildError> {
        if self.refused > 0 {
            return Err(BuildError::BudgetExceeded {
                budget: self.budget,
                refused: self.refused,
            });
        }
        self.sha256.sort_unstable();
        self.sha256.dedup_by_key(|(digest, _)| *digest);
        self.addresses.sort_unstable();
        self.addresses.dedup_by_key(|(address, _)| *address);

        let mut sha256_filter = Bloom::with_capacity(self.sha256.len());
        let mut address_filter = Bloom::with_capacity(self.addresses.len());
        for (digest, _) in &self.sha256 {
            sha256_filter.insert(filter::digest_key(digest));
        }
        for (address, _) in &self.addresses {
            address_filter.insert(filter::address_key(*address));
        }
        Ok(IndicatorSet {
            sha256: self.sha256,
            addresses: self.addresses,
            sha256_filter,
            address_filter,
            counters: Counters::default(),
        })
    }
}

#[derive(Debug, Default)]
struct Counters {
    lookups: AtomicU64,
    filter_negatives: AtomicU64,
    filter_false_positives: AtomicU64,
    hits: AtomicU64,
}

/// Lookup counters of one set; a reload starts a new set and so new counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetStats {
    /// Lookups answered.
    pub lookups: u64,
    /// Lookups the filter rejected without touching the exact tier.
    pub filter_negatives: u64,
    /// Lookups the filter passed and the exact tier then refused: what the filter costs.
    pub filter_false_positives: u64,
    /// Confirmed matches.
    pub hits: u64,
}

/// An immutable set of indicators. Cheap to query from several threads.
#[derive(Debug)]
pub struct IndicatorSet {
    sha256: Vec<([u8; 32], FeedId)>,
    addresses: Vec<(u128, FeedId)>,
    sha256_filter: Bloom,
    address_filter: Bloom,
    counters: Counters,
}

impl IndicatorSet {
    /// A set that matches nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sha256: Vec::new(),
            addresses: Vec::new(),
            sha256_filter: Bloom::with_capacity(0),
            address_filter: Bloom::with_capacity(0),
            counters: Counters::default(),
        }
    }

    /// Distinct indicators, both kinds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sha256.len() + self.addresses.len()
    }

    /// Whether the set holds no indicator.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Memory the set occupies, for the budget and for health reporting.
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        self.sha256.len() * SHA256_ENTRY_BYTES
            + self.addresses.len() * IP_ENTRY_BYTES
            + self.sha256_filter.bytes()
            + self.address_filter.bytes()
    }

    /// Matches a file hash.
    #[must_use]
    pub fn lookup_sha256(&self, digest: &[u8; 32]) -> Option<Match> {
        self.counters.lookups.fetch_add(1, Ordering::Relaxed);
        if !self.sha256_filter.may_contain(filter::digest_key(digest)) {
            self.counters
                .filter_negatives
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let found = self
            .sha256
            .binary_search_by_key(digest, |(candidate, _)| *candidate)
            .ok()
            .map(|at| self.sha256[at].1);
        self.confirm(IndicatorKind::Sha256, found)
    }

    /// Matches a hash written as hex, as `enrich` reports it; anything that is not 64 hex
    /// digits matches nothing.
    #[must_use]
    pub fn lookup_sha256_hex(&self, hex: &str) -> Option<Match> {
        self.lookup_sha256(&parse_sha256(hex).ok()?)
    }

    /// Matches an address; an IPv4-mapped IPv6 address is the IPv4 address.
    #[must_use]
    pub fn lookup_ip(&self, address: IpAddr) -> Option<Match> {
        self.counters.lookups.fetch_add(1, Ordering::Relaxed);
        let bits = address_bits(address);
        if !self.address_filter.may_contain(filter::address_key(bits)) {
            self.counters
                .filter_negatives
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let found = self
            .addresses
            .binary_search_by_key(&bits, |(candidate, _)| *candidate)
            .ok()
            .map(|at| self.addresses[at].1);
        self.confirm(IndicatorKind::Ip, found)
    }

    fn confirm(&self, kind: IndicatorKind, found: Option<FeedId>) -> Option<Match> {
        if let Some(feed) = found {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            Some(Match { kind, feed })
        } else {
            self.counters
                .filter_false_positives
                .fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// The lookup counters so far.
    #[must_use]
    pub fn stats(&self) -> SetStats {
        SetStats {
            lookups: self.counters.lookups.load(Ordering::Relaxed),
            filter_negatives: self.counters.filter_negatives.load(Ordering::Relaxed),
            filter_false_positives: self.counters.filter_false_positives.load(Ordering::Relaxed),
            hits: self.counters.hits.load(Ordering::Relaxed),
        }
    }
}
