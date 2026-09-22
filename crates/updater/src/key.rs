//! The updater's embedded Ed25519 public key (ADR-0015 Decision 4).
//!
//! This slice ships test-only: [`UPDATER_PUBLIC_KEY`] is the public half of a
//! fixed, checked-in seed, not a production key. [`SYNTHAEA_UPDATER_TEST_KEY`]
//! flags that distinction so a caller — and a future production build — can tell
//! them apart, mirroring ADR-0010's `SYNTHAEA_STRICT_PROVENANCE`-style dev/prod
//! split. Production key generation, storage, and rotation-away-from-compromise
//! are deferred (ADR-0015 Deferred section); there is no production key to embed
//! yet, so every build today verifies against the test key.

use std::sync::LazyLock;

use ring::signature::{Ed25519KeyPair, KeyPair};

/// `true` for every build today. Flips only once a real production key replaces
/// [`TEST_KEY_SEED`] and the derivation below is replaced with a hand-copied
/// production public key constant.
pub const SYNTHAEA_UPDATER_TEST_KEY: bool = true;

/// Deterministic 32-byte seed for the bundled test keypair. Deliberately trivial
/// — this seed is public, checked into source control, and signs nothing beyond
/// local dev builds and this crate's own tests.
const TEST_KEY_SEED: [u8; 32] = [0x42; 32];

/// The test keypair, for signing manifests in tests and local dev builds
/// (ADR-0015 Decision 4: real production signing happens out of band, once a
/// production key exists).
///
/// # Panics
///
/// Never — [`TEST_KEY_SEED`] is a fixed, valid 32-byte Ed25519 seed.
#[must_use]
pub fn test_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&TEST_KEY_SEED)
        .expect("TEST_KEY_SEED is a fixed, valid 32-byte Ed25519 seed")
}

/// The public key manifests are verified against. Derived from [`TEST_KEY_SEED`]
/// at startup rather than hand-copied, so the seed stays the single source of
/// truth and the embedded key cannot silently drift from it — see
/// [`tests::updater_public_key_matches_test_key_pair`] for the regression test
/// that would catch a mismatch if this derivation were ever hand-inlined instead.
pub static UPDATER_PUBLIC_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    test_key_pair()
        .public_key()
        .as_ref()
        .try_into()
        .expect("Ed25519 public key is always 32 bytes")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_public_key_matches_test_key_pair() {
        let derived: [u8; 32] = test_key_pair().public_key().as_ref().try_into().unwrap();
        assert_eq!(*UPDATER_PUBLIC_KEY, derived);
    }
}
