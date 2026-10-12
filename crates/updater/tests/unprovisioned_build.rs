//! The production variant of the trust set (ADR-0027, #753), which no unit test can reach:
//! those compile under `cfg(test)`, where the public test seed is always present. An
//! integration test links the library without `cfg(test)`, so with `--no-default-features`
//! it sees exactly what a packaged build embeds. CI runs it as
//! `cargo test -p updater --no-default-features` (and `tools/gauntlet.sh` does too).
#![cfg(not(feature = "test-key"))]

use std::collections::BTreeMap;

use ring::signature::Ed25519KeyPair;
use updater::{
    ContentManifest, ReleaseManifest, UpdaterError,
    content::CONTENT_MANIFEST_SCHEMA_VERSION,
    key::{CONTENT_PUBLIC_KEY, RECOVERY_PUBLIC_KEY, RELEASE_PUBLIC_KEY, SYNTHAEA_UPDATER_TEST_KEY},
};

/// Any keypair will do: the point is that a build with no key refuses to look at the
/// signature at all, so even a manifest signed by a well-formed key is not "invalid", the
/// build just has nothing to verify against.
fn some_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).unwrap()
}

#[test]
fn a_build_without_the_test_key_feature_does_not_claim_the_test_set() {
    // `black_box`: clippy rejects asserting a constant, and the constant is the thing under test.
    assert!(!std::hint::black_box(SYNTHAEA_UPDATER_TEST_KEY));
}

#[test]
fn a_build_without_the_test_key_feature_embeds_no_key_while_the_key_files_are_unprovisioned() {
    // Fails the day the real keys are committed under `crates/updater/keys/`: that is the
    // moment to replace this with a check that the embedded keys are the committed ones and
    // that the three roles differ.
    assert_eq!(*RELEASE_PUBLIC_KEY, None);
    assert_eq!(*CONTENT_PUBLIC_KEY, None);
    assert_eq!(*RECOVERY_PUBLIC_KEY, None);
}

#[test]
fn a_release_manifest_is_refused_as_unprovisioned_when_no_key_is_embedded() {
    let mut manifest = ReleaseManifest::new(2, BTreeMap::new());
    manifest.sign(&some_key_pair());
    assert!(matches!(
        manifest.verify_signature(),
        Err(UpdaterError::SigningKeyUnprovisioned)
    ));
}

#[test]
fn a_content_manifest_is_refused_as_unprovisioned_when_no_key_is_embedded() {
    let mut manifest = ContentManifest {
        entries: Vec::new(),
        release_version: 2,
        released_at: "2026-10-12T00:00:00Z".into(),
        ring: "prod".into(),
        schema_version: CONTENT_MANIFEST_SCHEMA_VERSION,
        signature: String::new(),
    };
    manifest.sign(&some_key_pair());
    assert!(matches!(
        manifest.verify_signature(),
        Err(UpdaterError::SigningKeyUnprovisioned)
    ));
}
