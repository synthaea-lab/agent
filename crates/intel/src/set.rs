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
/// Bytes per domain indicator in the exact tier, besides the name itself: the boxed-string
/// header with the feed, and the allocator's bookkeeping for the name (assumed, not measured).
const DOMAIN_ENTRY_BYTES: usize = std::mem::size_of::<(Box<str>, FeedId)>() + 16;

/// The longest DNS name in presentation form, without the root dot (RFC 1035).
pub const MAX_DOMAIN_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;
/// Fewest labels of a listed domain. `com` is a single label and would cover a whole TLD;
/// `example.com` is the shortest indicator. Two labels is a floor, not a guarantee: `co.uk` has
/// two and is still a public suffix, which only a public-suffix list can tell (ADR-0038).
pub const MIN_INDICATOR_LABELS: usize = 2;
/// Most labels of a listed domain, which bounds a lookup: a name is probed against its
/// suffixes of 2 to this many labels, at most [`MAX_DOMAIN_PROBES`] searches, whatever its
/// length. Real indicators are far shallower.
pub const MAX_INDICATOR_LABELS: usize = 8;
/// Most exact-tier searches one domain lookup costs.
pub const MAX_DOMAIN_PROBES: usize = MAX_INDICATOR_LABELS - MIN_INDICATOR_LABELS + 1;

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
    /// A DNS name: the listed domain itself or a name beneath it.
    Domain,
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
    /// Not a DNS name: an empty label, a label over 63 bytes, a name over 253, a character outside
    /// letters, digits, `-` and `_`, a hyphen at the edge of a label, or an all-numeric last
    /// label (which is how an IPv4 literal looks).
    #[error("not a valid DNS name")]
    BadDomain,
    /// A non-ASCII name. DNS carries internationalised names as punycode (`xn--`) and the engine
    /// does not convert; the feed must list the ASCII form.
    #[error("a domain must be ASCII (punycode for an internationalised name)")]
    NonAsciiDomain,
    /// A single label: `com` as an indicator would flag every name under a TLD.
    #[error("a domain indicator needs at least two labels")]
    DomainTooBroad,
    /// More labels than a lookup probes, so it could never match.
    #[error("a domain indicator has too many labels")]
    DomainTooDeep,
    /// A line that is not `sha256:<hex>`, `ip:<address>` or `domain:<name>`.
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

/// Bytes a built set of this many hashes and addresses occupies.
#[must_use]
pub fn estimated_bytes(sha256_count: usize, ip_count: usize) -> usize {
    estimated_bytes_with_domains(sha256_count, ip_count, 0, 0)
}

/// Bytes a built set occupies when it also lists `domain_count` domains whose names total
/// `domain_name_bytes`.
#[must_use]
pub fn estimated_bytes_with_domains(
    sha256_count: usize,
    ip_count: usize,
    domain_count: usize,
    domain_name_bytes: usize,
) -> usize {
    sha256_count
        .saturating_mul(SHA256_ENTRY_BYTES)
        .saturating_add(filter::bytes_for(sha256_count))
        .saturating_add(ip_count.saturating_mul(IP_ENTRY_BYTES))
        .saturating_add(filter::bytes_for(ip_count))
        .saturating_add(domain_count.saturating_mul(DOMAIN_ENTRY_BYTES))
        .saturating_add(domain_name_bytes)
        .saturating_add(filter::bytes_for(domain_count))
}

/// Validates and lowercases a DNS name into `out`, returning its length. One trailing dot (the
/// root) is dropped. No allocation, so the lookup path can use it per query.
fn normalize_into(name: &str, out: &mut [u8; MAX_DOMAIN_BYTES]) -> Result<usize, ParseError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_DOMAIN_BYTES {
        return Err(ParseError::BadDomain);
    }
    if !name.is_ascii() {
        return Err(ParseError::NonAsciiDomain);
    }
    let mut label_len = 0usize;
    let mut previous = b'.';
    for (slot, &byte) in out.iter_mut().zip(bytes) {
        let byte = byte.to_ascii_lowercase();
        match byte {
            b'.' => {
                if label_len == 0 || previous == b'-' {
                    return Err(ParseError::BadDomain);
                }
                label_len = 0;
            }
            b'-' if label_len == 0 => return Err(ParseError::BadDomain),
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => label_len += 1,
            _ => return Err(ParseError::BadDomain),
        }
        if label_len > MAX_LABEL_BYTES {
            return Err(ParseError::BadDomain);
        }
        *slot = byte;
        previous = byte;
    }
    if label_len == 0 || previous == b'-' {
        return Err(ParseError::BadDomain);
    }
    let last_label = bytes.rsplit(|&b| b == b'.').next().unwrap_or_default();
    if last_label.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::BadDomain);
    }
    Ok(bytes.len())
}

/// Normalises a DNS name as the engine compares it: ASCII lowercase, one trailing dot dropped.
/// Idempotent. It checks the syntax of a name, not whether it may be an indicator (that also
/// needs [`MIN_INDICATOR_LABELS`] to [`MAX_INDICATOR_LABELS`] labels).
///
/// # Errors
/// [`ParseError::BadDomain`] or [`ParseError::NonAsciiDomain`].
pub fn normalize_domain(name: &str) -> Result<String, ParseError> {
    let mut buffer = [0u8; MAX_DOMAIN_BYTES];
    let len = normalize_into(name, &mut buffer)?;
    std::str::from_utf8(&buffer[..len])
        .map(str::to_owned)
        .map_err(|_| ParseError::BadDomain)
}

fn parse_indicator_domain(name: &str) -> Result<String, ParseError> {
    let name = normalize_domain(name)?;
    match name.split('.').count() {
        labels if labels < MIN_INDICATOR_LABELS => Err(ParseError::DomainTooBroad),
        labels if labels > MAX_INDICATOR_LABELS => Err(ParseError::DomainTooDeep),
        _ => Ok(name),
    }
}

/// The names a lookup probes: the suffixes of `name` on a label boundary of
/// [`MIN_INDICATOR_LABELS`] to [`MAX_INDICATOR_LABELS`] labels, `name` itself included when it is
/// that short. Never a substring that starts inside a label, and at most [`MAX_DOMAIN_PROBES`].
fn candidate_suffixes(name: &str) -> impl Iterator<Item = &str> {
    let labels = name.bytes().filter(|&b| b == b'.').count() + 1;
    let whole = (MIN_INDICATOR_LABELS..=MAX_INDICATOR_LABELS)
        .contains(&labels)
        .then_some(name);
    name.rmatch_indices('.')
        .map(|(at, _)| &name[at + 1..])
        .take(MAX_INDICATOR_LABELS)
        .skip(MIN_INDICATOR_LABELS - 1)
        .chain(whole)
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
    for (byte, pair) in digest.iter_mut().zip(hex.as_chunks::<2>().0.iter()) {
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
    domains: Vec<(Box<str>, FeedId)>,
    domain_name_bytes: usize,
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
            domains: Vec::new(),
            domain_name_bytes: 0,
            refused: 0,
        }
    }

    fn has_room_for(&self, sha256: usize, addresses: usize, domain_name: Option<usize>) -> bool {
        estimated_bytes_with_domains(
            self.sha256.len() + sha256,
            self.addresses.len() + addresses,
            self.domains.len() + usize::from(domain_name.is_some()),
            self.domain_name_bytes + domain_name.unwrap_or(0),
        ) <= self.budget
    }

    /// Adds a file hash. Returns `false` when the budget refused it.
    pub fn add_sha256(&mut self, digest: [u8; 32], feed: FeedId) -> bool {
        if !self.has_room_for(1, 0, None) {
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
        if !self.has_room_for(0, 1, None) {
            self.refused += 1;
            return false;
        }
        self.addresses.push((bits, feed));
        true
    }

    /// Adds a domain: it matches itself and every name beneath it. The name is normalised
    /// (lowercase, one trailing dot dropped); `Ok(false)` when the budget refused it.
    ///
    /// # Errors
    /// [`ParseError::BadDomain`], [`ParseError::NonAsciiDomain`], [`ParseError::DomainTooBroad`]
    /// (a single label) or [`ParseError::DomainTooDeep`].
    pub fn add_domain(&mut self, name: &str, feed: FeedId) -> Result<bool, ParseError> {
        Ok(self.push_domain(parse_indicator_domain(name)?, feed))
    }

    fn push_domain(&mut self, name: String, feed: FeedId) -> bool {
        if !self.has_room_for(0, 0, Some(name.len())) {
            self.refused += 1;
            return false;
        }
        self.domain_name_bytes += name.len();
        self.domains.push((name.into_boxed_str(), feed));
        true
    }

    /// Adds every indicator in `text`: one per line, `sha256:<hex>`, `ip:<address>` or
    /// `domain:<name>`, blank lines and `#` comments ignored. A bad line is counted and skipped, never fatal, so one
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
        } else if let Some(name) = line.strip_prefix("domain:") {
            Ok(self.push_domain(parse_indicator_domain(name.trim())?, feed))
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
        self.domains.sort_unstable();
        self.domains.dedup_by(|later, kept| later.0 == kept.0);

        let mut sha256_filter = Bloom::with_capacity(self.sha256.len());
        let mut address_filter = Bloom::with_capacity(self.addresses.len());
        for (digest, _) in &self.sha256 {
            sha256_filter.insert(filter::digest_key(digest));
        }
        for (address, _) in &self.addresses {
            address_filter.insert(filter::address_key(*address));
        }
        let mut domain_filter = Bloom::with_capacity(self.domains.len());
        for (name, _) in &self.domains {
            domain_filter.insert(filter::domain_key(name));
        }
        Ok(IndicatorSet {
            sha256: self.sha256,
            addresses: self.addresses,
            domains: self.domains,
            sha256_filter,
            address_filter,
            domain_filter,
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
    domains: Vec<(Box<str>, FeedId)>,
    sha256_filter: Bloom,
    address_filter: Bloom,
    domain_filter: Bloom,
    counters: Counters,
}

impl IndicatorSet {
    /// A set that matches nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sha256: Vec::new(),
            addresses: Vec::new(),
            domains: Vec::new(),
            sha256_filter: Bloom::with_capacity(0),
            address_filter: Bloom::with_capacity(0),
            domain_filter: Bloom::with_capacity(0),
            counters: Counters::default(),
        }
    }

    /// Distinct indicators, all kinds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sha256.len() + self.addresses.len() + self.domains.len()
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
            + self
                .domains
                .iter()
                .map(|(name, _)| name.len() + DOMAIN_ENTRY_BYTES)
                .sum::<usize>()
            + self.sha256_filter.bytes()
            + self.address_filter.bytes()
            + self.domain_filter.bytes()
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

    /// Matches a DNS name against the listed domains: the name itself or any suffix of it on a
    /// label boundary (`a.b.evil.com` matches `evil.com`; `notevil.com` does not). The name is
    /// normalised first (case, trailing dot); a name that is not valid DNS matches nothing. At
    /// most [`MAX_DOMAIN_PROBES`] filter checks and exact searches, whatever the name's length,
    /// and no allocation. When several listed suffixes match, the lowest feed id is reported.
    ///
    /// The counters count the lookup once: a filter negative when no probe passed the filter (an
    /// invalid name included), a false positive when some probe did and none was confirmed.
    #[must_use]
    pub fn lookup_domain(&self, name: &str) -> Option<Match> {
        self.counters.lookups.fetch_add(1, Ordering::Relaxed);
        let mut buffer = [0u8; MAX_DOMAIN_BYTES];
        let normalized = normalize_into(name, &mut buffer)
            .ok()
            .and_then(|len| std::str::from_utf8(&buffer[..len]).ok());
        let mut passed_filter = false;
        let mut found: Option<FeedId> = None;
        for candidate in normalized.into_iter().flat_map(candidate_suffixes) {
            if !self
                .domain_filter
                .may_contain(filter::domain_key(candidate))
            {
                continue;
            }
            passed_filter = true;
            if let Ok(at) = self
                .domains
                .binary_search_by(|(listed, _)| (**listed).cmp(candidate))
            {
                let feed = self.domains[at].1;
                found = Some(found.map_or(feed, |lowest| lowest.min(feed)));
            }
        }
        if passed_filter {
            self.confirm(IndicatorKind::Domain, found)
        } else {
            self.counters
                .filter_negatives
                .fetch_add(1, Ordering::Relaxed);
            None
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lookup_probes_label_suffixes_only_and_at_most_the_bound() {
        let probes: Vec<_> = candidate_suffixes("a.b.evil.com").collect();
        assert_eq!(probes, ["evil.com", "b.evil.com", "a.b.evil.com"]);
        assert_eq!(
            candidate_suffixes("evil.com").collect::<Vec<_>>(),
            ["evil.com"]
        );
        assert_eq!(candidate_suffixes("com").count(), 0);
        let deep = vec!["x"; 127].join(".");
        let probes: Vec<_> = candidate_suffixes(&deep).collect();
        assert_eq!(probes.len(), MAX_DOMAIN_PROBES);
        assert!(probes.iter().all(|p| deep.ends_with(p)));
        assert!(
            probes
                .iter()
                .all(|p| p.split('.').count() >= MIN_INDICATOR_LABELS)
        );
    }
}
