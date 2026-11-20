//! The production variant of the trust set (ADR-0027, <https://github.com/synthaea-lab/agent/issues/43>), which no unit test can reach:
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

/// The public test seed, which anyone can read in `crates/updater/src/key.rs`. The committed keys
/// are not derived from it, so a packaged build must refuse what it signs (the fail-closed
/// `SigningKeyUnprovisioned` path, for a key file that says `unprovisioned`, is covered by the
/// tests below that pass `None` to `verify_signature_with`, and by the snapshot and rotation unit tests).
fn some_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).unwrap()
}

#[test]
fn a_build_without_the_test_key_feature_does_not_claim_the_test_set() {
    // `black_box`: clippy rejects asserting a constant, and the constant is the thing under test.
    assert!(!std::hint::black_box(SYNTHAEA_UPDATER_TEST_KEY));
}

/// The first non-comment line of a committed key file, as `parse_key_file` reads it.
fn committed(file: &str) -> String {
    let text =
        std::fs::read_to_string(format!("{}/keys/{file}.pub", env!("CARGO_MANIFEST_DIR"))).unwrap();
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap()
        .to_owned()
}

fn hex(key: &Option<[u8; 32]>) -> Option<String> {
    key.map(|k| k.iter().map(|b| format!("{b:02x}")).collect())
}

#[test]
fn a_build_without_the_test_key_feature_embeds_exactly_the_committed_keys() {
    // A file that says `unprovisioned` embeds no key; a file that holds a key embeds that key
    // and nothing else. The three roles must differ (ADR-0027: a content signer must not be
    // able to sign releases).
    for (file, embedded) in [
        ("release", &*RELEASE_PUBLIC_KEY),
        ("content", &*CONTENT_PUBLIC_KEY),
        ("recovery", &*RECOVERY_PUBLIC_KEY),
    ] {
        let line = committed(file);
        let expected = (line != "unprovisioned").then_some(line);
        assert_eq!(hex(embedded), expected, "{file}");
    }
    let keys = [
        *RELEASE_PUBLIC_KEY,
        *CONTENT_PUBLIC_KEY,
        *RECOVERY_PUBLIC_KEY,
    ];
    for (i, a) in keys.iter().enumerate() {
        for b in &keys[i + 1..] {
            assert!(a.is_none() || a != b, "two roles share one key");
        }
    }
}

#[test]
fn a_release_manifest_signed_by_the_public_test_seed_is_refused() {
    let mut manifest = ReleaseManifest::new(2, BTreeMap::new());
    manifest.sign(&some_key_pair());
    assert!(matches!(
        manifest.verify_signature(),
        Err(UpdaterError::SignatureInvalid)
    ));
}

#[test]
fn a_content_manifest_signed_by_the_public_test_seed_is_refused() {
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
        Err(UpdaterError::SignatureInvalid)
    ));
}

#[test]
fn a_key_rotation_signed_by_a_test_recovery_seed_is_refused() {
    use updater::{KeyRotationManifest, rotation::ROTATION_SCHEMA_VERSION};

    let mut rotation = KeyRotationManifest {
        expires_at: 1_760_000_000 + 3600,
        issued_at: 1_760_000_000,
        new_content_key: None,
        new_release_key: Some("aa".repeat(32)),
        reason: "scheduled".into(),
        release_version: 9,
        retired_content_key: None,
        retired_release_key: Some("bb".repeat(32)),
        schema_version: ROTATION_SCHEMA_VERSION,
        signature: String::new(),
    };
    let key = some_key_pair();
    rotation
        .sign_with(|message| Ok::<_, ()>(key.sign(message).as_ref().to_vec()))
        .unwrap();
    assert!(matches!(
        rotation.verify_signature(),
        Err(UpdaterError::SignatureInvalid)
    ));
}

#[test]
fn a_release_or_content_manifest_is_refused_as_unprovisioned_when_its_key_file_says_so() {
    // What `release.pub` / `content.pub` containing `unprovisioned` makes of the static: `None`.
    let mut release = ReleaseManifest::new(2, BTreeMap::new());
    release.sign(&some_key_pair());
    assert!(matches!(
        release.verify_signature_with(None),
        Err(UpdaterError::SigningKeyUnprovisioned)
    ));

    let mut content = ContentManifest {
        entries: Vec::new(),
        release_version: 2,
        released_at: "2026-10-12T00:00:00Z".into(),
        ring: "prod".into(),
        schema_version: CONTENT_MANIFEST_SCHEMA_VERSION,
        signature: String::new(),
    };
    content.sign(&some_key_pair());
    assert!(matches!(
        content.verify_signature_with(None),
        Err(UpdaterError::SigningKeyUnprovisioned)
    ));
}
