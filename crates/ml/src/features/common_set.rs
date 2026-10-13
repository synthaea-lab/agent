//! The common-set snapshot as the agent reads it (ADR-0020, issue #76): a Bloom filter of the
//! image hashes seen on at least K hosts of this tenant, implementing [`CommonSet`] for the
//! rarity feature.
//!
//! The byte layout, the hashing and the sizing rules are specified in
//! `docs/detection/common-set-snapshot-format.md`. The server writes it
//! (`server/lib/common-set-snapshot.ts`); a stdlib-only Python reference generates
//! `ml/tests/fixtures/common_set_snapshot_golden.json`, which both sides test against so the
//! reader cannot drift from the writer.
//!
//! Parsing is strict (an unknown magic or version, an out-of-range size, or a length that is not
//! exactly header plus body is an error, never a guess) and total: no input panics, and no
//! allocation is sized by an untrusted header field.

use thiserror::Error;

use super::rarity::{CommonSet, normalize_sha256};

const MAGIC: &[u8; 4] = b"SYCS";
const FORMAT_VERSION: u16 = 1;
const HEADER_BYTES: usize = 32;
const MIN_BITS: u32 = 64;
const MAX_HASH_COUNT: u16 = 16;

/// Why a byte string is not a snapshot this reader understands.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotError {
    /// Shorter than the 32-byte header.
    #[error("shorter than the snapshot header")]
    TooShort,
    /// The first four bytes are not `SYCS`.
    #[error("bad magic")]
    BadMagic,
    /// A format version this reader does not know.
    #[error("unknown snapshot format version {0}")]
    UnknownVersion(u16),
    /// `hash_count` outside 1..=16.
    #[error("hash count {0} out of range")]
    HashCountOutOfRange(u16),
    /// `bit_count` below 64 or not a multiple of 8.
    #[error("bit count {0} out of range")]
    BitCountOutOfRange(u32),
    /// The length is not exactly the header plus `bit_count / 8`.
    #[error("length does not match the header")]
    LengthMismatch,
}

/// The fixed-size header, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotHeader {
    /// Format version (1).
    pub format_version: u16,
    /// Bit positions per hash.
    pub hash_count: u16,
    /// K: hosts a hash was seen on to be a member.
    pub min_hosts: u32,
    /// Distinct agents that had reported when the snapshot was built.
    pub hosts_covered: u32,
    /// Distinct hashes inserted.
    pub entry_count: u32,
    /// Filter size in bits.
    pub bit_count: u32,
    /// Unix seconds when the snapshot was built.
    pub built_at: u64,
}

/// A parsed common-set snapshot. Owns its filter bytes; membership is a few array reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonSetSnapshot {
    header: SnapshotHeader,
    body: Vec<u8>,
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

impl CommonSetSnapshot {
    /// Reads a snapshot, copying only the filter body (whose length the input has already
    /// proved).
    ///
    /// # Errors
    /// [`SnapshotError`] when the bytes are not exactly one version-1 snapshot.
    pub fn parse(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() < HEADER_BYTES {
            return Err(SnapshotError::TooShort);
        }
        if &bytes[..4] != MAGIC {
            return Err(SnapshotError::BadMagic);
        }
        let format_version = le_u16(bytes, 4);
        if format_version != FORMAT_VERSION {
            return Err(SnapshotError::UnknownVersion(format_version));
        }
        let header = SnapshotHeader {
            format_version,
            hash_count: le_u16(bytes, 6),
            min_hosts: le_u32(bytes, 8),
            hosts_covered: le_u32(bytes, 12),
            entry_count: le_u32(bytes, 16),
            bit_count: le_u32(bytes, 20),
            built_at: le_u64(bytes, 24),
        };
        if header.hash_count == 0 || header.hash_count > MAX_HASH_COUNT {
            return Err(SnapshotError::HashCountOutOfRange(header.hash_count));
        }
        if header.bit_count < MIN_BITS || !header.bit_count.is_multiple_of(8) {
            return Err(SnapshotError::BitCountOutOfRange(header.bit_count));
        }
        // The body length is checked against the input before anything is allocated.
        if (bytes.len() - HEADER_BYTES) as u64 != u64::from(header.bit_count / 8) {
            return Err(SnapshotError::LengthMismatch);
        }
        Ok(Self {
            header,
            body: bytes[HEADER_BYTES..].to_vec(),
        })
    }

    /// The header as written by the server.
    #[must_use]
    pub fn header(&self) -> &SnapshotHeader {
        &self.header
    }

    fn bit_is_set(&self, position: u64) -> bool {
        // `position < bit_count` and `body.len() == bit_count / 8`, so the index is in range;
        // `get` keeps a future change from turning that into a panic.
        usize::try_from(position >> 3)
            .ok()
            .and_then(|byte| self.body.get(byte))
            .is_some_and(|b| b >> (position & 7) & 1 == 1)
    }
}

impl CommonSet for CommonSetSnapshot {
    /// Double hashing over the digest, which is already uniform: `h1` and `h2` are its first two
    /// little-endian u64 words (`h2` forced odd), position `i` is
    /// `((h1 + i * h2) mod 2^64) mod bit_count`. Anything that is not a normalized SHA-256 is not
    /// a member.
    fn contains(&self, sha256: &str) -> bool {
        if normalize_sha256(sha256).as_deref() != Some(sha256) {
            return false;
        }
        let mut digest = [0u8; 16];
        for (i, byte) in digest.iter_mut().enumerate() {
            let pair = &sha256[i * 2..i * 2 + 2];
            match u8::from_str_radix(pair, 16) {
                Ok(b) => *byte = b,
                Err(_) => return false,
            }
        }
        let h1 = le_u64(&digest, 0);
        let h2 = le_u64(&digest, 8) | 1;
        let bits = u64::from(self.header.bit_count);
        (0..u64::from(self.header.hash_count))
            .all(|i| self.bit_is_set(h1.wrapping_add(i.wrapping_mul(h2)) % bits))
    }

    fn hosts_covered(&self) -> u64 {
        u64::from(self.header.hosts_covered)
    }
}
