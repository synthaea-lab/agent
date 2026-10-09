//! The updater's embedded trust set: three Ed25519 public keys, each with one job
//! (ADR-0027). `release` verifies binary release manifests, `content` verifies content
//! manifests, `recovery` is held offline and reserved for a key-rotation release (its
//! manifest shape is a later slice, so nothing verifies against it yet).
//!
//! A production build embeds the keys in `crates/updater/keys/*.pub` (hex). Until the real
//! keys are committed there those files say `unprovisioned`, the statics below are `None`,
//! and nothing verifies: the build fails closed instead of trusting a public seed.
//!
//! The public test set (a seed checked into the repository) exists only under the
//! `test-key` cargo feature or `cfg(test)`, so a build without either cannot ship it by
//! omission. In that set `release` and `content` are one key (ADR-0016's development
//! shortcut) and `recovery` is a second one.

use std::sync::LazyLock;

#[cfg(any(test, feature = "test-key"))]
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::hash::hex_decode;

/// `true` when the embedded trust set is the public test set, never a hand-flipped constant:
/// it follows the feature that compiles the test seed in.
pub const SYNTHAEA_UPDATER_TEST_KEY: bool = cfg!(any(test, feature = "test-key"));

/// Present in a binary only if it carries the test set: `tools/check-no-test-key.sh` looks for
/// it in the packaged build (and in a test-set build, to prove the check can see it).
#[cfg(feature = "test-key")]
const TEST_KEY_MARKER: &[u8] = b"SYNTHAEA-PUBLIC-TEST-KEY-SET-V1";

/// Seed of the bundled test `release`/`content` key. Deliberately trivial: public, checked in,
/// and signing nothing beyond local dev builds and tests.
#[cfg(any(test, feature = "test-key"))]
const TEST_KEY_SEED: [u8; 32] = [0x42; 32];

/// Seed of the bundled test `recovery` key.
#[cfg(any(test, feature = "test-key"))]
const TEST_RECOVERY_SEED: [u8; 32] = [0x43; 32];

/// The test keypair that signs releases and content in tests and lab builds.
///
/// # Panics
///
/// Never: [`TEST_KEY_SEED`] is a fixed, valid 32-byte Ed25519 seed.
#[cfg(any(test, feature = "test-key"))]
#[must_use]
pub fn test_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&TEST_KEY_SEED)
        .expect("TEST_KEY_SEED is a fixed, valid 32-byte Ed25519 seed")
}

#[cfg(any(test, feature = "test-key"))]
fn public_of(seed: &[u8; 32]) -> Option<[u8; 32]> {
    Ed25519KeyPair::from_seed_unchecked(seed)
        .ok()?
        .public_key()
        .as_ref()
        .try_into()
        .ok()
}

/// A key file's public key: the first line that is not blank or a `#` comment, 64 hex
/// characters. Anything else (`unprovisioned`, a typo, a truncated key) is `None`.
#[cfg_attr(any(test, feature = "test-key"), allow(dead_code))]
fn parse_key_file(text: &str) -> Option<[u8; 32]> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))?;
    hex_decode(line)?.try_into().ok()
}

/// Which key of the trust set.
#[derive(Clone, Copy)]
enum Role {
    Release,
    Content,
    Recovery,
}

/// The test set, when this build has one: derived from the seeds, not copied.
#[cfg(any(test, feature = "test-key"))]
fn embedded(role: Role, _file: &str) -> Option<[u8; 32]> {
    // Reached whenever a key is read, so the linker keeps the marker in the final binary.
    #[cfg(feature = "test-key")]
    std::hint::black_box(TEST_KEY_MARKER);
    public_of(match role {
        Role::Release | Role::Content => &TEST_KEY_SEED,
        Role::Recovery => &TEST_RECOVERY_SEED,
    })
}

/// The committed key file; no seed exists in this build.
#[cfg(not(any(test, feature = "test-key")))]
fn embedded(_role: Role, file: &str) -> Option<[u8; 32]> {
    parse_key_file(file)
}

/// Verifies binary release manifests. `None` when no key is provisioned.
pub static RELEASE_PUBLIC_KEY: LazyLock<Option<[u8; 32]>> =
    LazyLock::new(|| embedded(Role::Release, include_str!("../keys/release.pub")));

/// Verifies content manifests. `None` when no key is provisioned. Equal to
/// [`RELEASE_PUBLIC_KEY`] in the test set only.
pub static CONTENT_PUBLIC_KEY: LazyLock<Option<[u8; 32]>> =
    LazyLock::new(|| embedded(Role::Content, include_str!("../keys/content.pub")));

/// The offline key that will sign key rotations (ADR-0027). Nothing verifies against it yet.
pub static RECOVERY_PUBLIC_KEY: LazyLock<Option<[u8; 32]>> =
    LazyLock::new(|| embedded(Role::Recovery, include_str!("../keys/recovery.pub")));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_set_release_key_matches_the_test_key_pair() {
        let derived: [u8; 32] = test_key_pair().public_key().as_ref().try_into().unwrap();
        assert_eq!(*RELEASE_PUBLIC_KEY, Some(derived));
        assert_eq!(*CONTENT_PUBLIC_KEY, Some(derived));
    }

    #[test]
    fn the_test_recovery_key_is_not_the_release_key() {
        assert!(RECOVERY_PUBLIC_KEY.is_some());
        assert_ne!(*RECOVERY_PUBLIC_KEY, *RELEASE_PUBLIC_KEY);
    }

    #[test]
    fn an_unprovisioned_key_file_embeds_no_key() {
        for file in ["release", "content", "recovery"] {
            let text =
                std::fs::read_to_string(format!("{}/keys/{file}.pub", env!("CARGO_MANIFEST_DIR")))
                    .unwrap();
            assert_eq!(parse_key_file(&text), None, "{file}.pub");
        }
    }

    #[test]
    fn a_key_file_holds_one_hex_key_after_its_comments() {
        let hex = "ab".repeat(32);
        assert_eq!(
            parse_key_file(&format!("# the key\n\n  {hex}  \n")),
            Some([0xab; 32])
        );
        assert_eq!(parse_key_file(&hex[..62]), None, "a truncated key");
        assert_eq!(
            parse_key_file(&format!("{hex}00")),
            None,
            "a key that is too long"
        );
        assert_eq!(parse_key_file("# only a comment\n"), None);
    }

    #[test]
    fn the_marker_follows_the_feature_that_compiles_the_test_seed_in() {
        const { assert!(SYNTHAEA_UPDATER_TEST_KEY) };
    }
}
