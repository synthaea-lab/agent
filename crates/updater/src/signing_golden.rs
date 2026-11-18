//! Pins the signed bytes and the verification order of the four signed documents
//! (`ReleaseManifest`, `ContentManifest`, `SnapshotManifest`, `KeyRotationManifest`) on fixed
//! fixtures (#149). Ed25519 is deterministic: the same canonical bytes under the same test key give
//! the same signature, so a change to the canonical form of any document, or to what is signed,
//! fails here. The signatures below were produced by the code as it was before the signing logic
//! was shared, so a refactor of that logic is neutral if these still hold.

use std::collections::BTreeMap;

use ring::signature::KeyPair;

use crate::{
    content::{CONTENT_MANIFEST_SCHEMA_VERSION, ContentEntry, ContentManifest},
    error::UpdaterError,
    key::{test_key_pair, test_recovery_key_pair, test_snapshot_key_pair},
    manifest::{MANIFEST_SCHEMA_VERSION, ReleaseManifest},
    rotation::{KeyRotationManifest, ROTATION_SCHEMA_VERSION},
    snapshot::{KIND_COMMON_SET, SNAPSHOT_MANIFEST_SCHEMA_VERSION, SnapshotManifest},
};

fn release() -> ReleaseManifest {
    let mut entries = BTreeMap::new();
    entries.insert("bin/agent".into(), "aa".repeat(32));
    entries.insert("lib/ml.so".into(), "bb".repeat(32));
    ReleaseManifest::new(42, entries)
}

fn content() -> ContentManifest {
    ContentManifest {
        entries: vec![ContentEntry {
            metadata: None,
            path: "rules/beacon.sigma".into(),
            sha256: "cc".repeat(32),
            size: 1234,
            content_type: "rule".into(),
        }],
        release_version: 7,
        released_at: "2026-09-23T16:00:00Z".into(),
        ring: "canary_0".into(),
        schema_version: CONTENT_MANIFEST_SCHEMA_VERSION,
        signature: String::new(),
    }
}

fn snapshot() -> SnapshotManifest {
    SnapshotManifest {
        built_at: 1_790_000_000,
        entry_count: 10,
        hosts_covered: 5,
        kind: KIND_COMMON_SET.into(),
        min_hosts: 3,
        schema_version: SNAPSHOT_MANIFEST_SCHEMA_VERSION,
        sha256: "dd".repeat(32),
        signature: String::new(),
        size: 4096,
    }
}

fn rotation() -> KeyRotationManifest {
    KeyRotationManifest {
        expires_at: 1_790_086_400,
        issued_at: 1_790_000_000,
        new_content_key: Some("11".repeat(32)),
        new_release_key: None,
        reason: "scheduled".into(),
        release_version: 9,
        retired_content_key: Some("22".repeat(32)),
        retired_release_key: None,
        schema_version: ROTATION_SCHEMA_VERSION,
        signature: String::new(),
    }
}

/// Signatures produced by the code before #149, over the fixtures above.
const RELEASE_SIGNATURE: &str = "3ecfe9fdc3eca7996b8146a986bf62708df07cc5e4c2860da22168fa9f76096e30fcedc8590f439392aeb87bb89ff9963c5206347a61a9c1a77d2d9584d05e04";
const CONTENT_SIGNATURE: &str = "5010cc3d4c28f53da93308eb2f77df9d26e388fd474200c316e941152e5463853313a514439fff0b7bf6cdba00111cfab87ca009166641d8bc7f352737aa7806";
const SNAPSHOT_SIGNATURE: &str = "0aaff22f02b0bb207a8c8d8972f0c3cf455da787200942766ad39a3b0a01727a347e1310f76819e4d97eb0659d63907741a451b92339f69fcfeec191186e0701";
const ROTATION_SIGNATURE: &str = "c9712f724ea6b903691282b6171aef1772f3115317d9c02093177ad5463f8e232457ed74565b21d08840cc8b2ffefcefb9bd7e33b8f330412f7ec4b0977d1309";

fn public(pair: &ring::signature::Ed25519KeyPair) -> [u8; 32] {
    pair.public_key().as_ref().try_into().unwrap()
}

/// A malformed signature (not hex) and no key to verify against: the document-specific order of
/// the two refusals is part of the behaviour.
const NOT_HEX: &str = "zz";

#[test]
fn each_document_signs_to_its_golden_signature_and_verifies_against_it() {
    let mut r = release();
    r.sign(&test_key_pair());
    assert_eq!(r.signature, RELEASE_SIGNATURE);
    r.verify_signature_with(Some(&public(&test_key_pair())))
        .unwrap();

    let mut c = content();
    c.sign(&test_key_pair());
    assert_eq!(c.signature, CONTENT_SIGNATURE);
    c.verify_signature_with(Some(&public(&test_key_pair())))
        .unwrap();

    let mut s = snapshot();
    s.sign(&test_snapshot_key_pair());
    assert_eq!(s.signature, SNAPSHOT_SIGNATURE);
    s.verify_signature_with(Some(&public(&test_snapshot_key_pair())))
        .unwrap();

    let mut k = rotation();
    k.sign(&test_recovery_key_pair());
    assert_eq!(k.signature, ROTATION_SIGNATURE);
    k.verify_signature_with(Some(&public(&test_recovery_key_pair())))
        .unwrap();
}

#[test]
fn signing_through_a_closure_gives_the_same_signature_and_a_failed_closure_leaves_none() {
    let pair = test_key_pair();
    let sign = |msg: &[u8]| Ok::<_, ()>(pair.sign(msg).as_ref().to_vec());

    let mut r = release();
    r.sign_with(sign).unwrap();
    assert_eq!(r.signature, RELEASE_SIGNATURE);
    let mut c = content();
    c.sign_with(sign).unwrap();
    assert_eq!(c.signature, CONTENT_SIGNATURE);

    let recovery = test_recovery_key_pair();
    let mut k = rotation();
    k.sign_with(|msg| Ok::<_, ()>(recovery.sign(msg).as_ref().to_vec()))
        .unwrap();
    assert_eq!(k.signature, ROTATION_SIGNATURE);

    // A failing signer leaves the field empty, even when it held a signature before.
    let mut r = release();
    r.signature = "stale".into();
    assert_eq!(
        r.sign_with(|_| Err::<Vec<u8>, _>("token gone")),
        Err("token gone")
    );
    assert!(r.signature.is_empty());
    let mut c = content();
    c.signature = "stale".into();
    assert_eq!(
        c.sign_with(|_| Err::<Vec<u8>, _>("token gone")),
        Err("token gone")
    );
    assert!(c.signature.is_empty());
    let mut k = rotation();
    k.signature = "stale".into();
    assert_eq!(
        k.sign_with(|_| Err::<Vec<u8>, _>("token gone")),
        Err("token gone")
    );
    assert!(k.signature.is_empty());
}

#[test]
fn a_signature_over_a_changed_document_or_under_another_key_does_not_verify() {
    let mut r = release();
    r.sign(&test_key_pair());
    let mut changed = r.clone();
    changed.release_version += 1;
    assert!(matches!(
        changed.verify_signature_with(Some(&public(&test_key_pair()))),
        Err(UpdaterError::SignatureInvalid)
    ));
    assert!(matches!(
        r.verify_signature_with(Some(&public(&test_snapshot_key_pair()))),
        Err(UpdaterError::SignatureInvalid)
    ));
    let mut s = snapshot();
    s.sign(&test_snapshot_key_pair());
    s.size += 1;
    assert!(matches!(
        s.verify_signature_with(Some(&public(&test_snapshot_key_pair()))),
        Err(UpdaterError::SignatureInvalid)
    ));
}

#[test]
fn the_schema_version_is_refused_before_the_signature_is_looked_at() {
    let wrong = |result: Result<(), UpdaterError>, want: u32| {
        assert!(
            matches!(result, Err(UpdaterError::SchemaVersionUnsupported { found: 99, expected }) if expected == want),
            "{result:?}"
        );
    };
    let mut r = release();
    r.schema_version = 99;
    r.signature = NOT_HEX.into();
    wrong(r.verify_signature_with(None), MANIFEST_SCHEMA_VERSION);
    let mut c = content();
    c.schema_version = 99;
    c.signature = NOT_HEX.into();
    wrong(
        c.verify_signature_with(None),
        CONTENT_MANIFEST_SCHEMA_VERSION,
    );
    let mut s = snapshot();
    s.schema_version = 99;
    s.signature = NOT_HEX.into();
    wrong(
        s.verify_signature_with(None),
        SNAPSHOT_MANIFEST_SCHEMA_VERSION,
    );
    let mut k = rotation();
    k.schema_version = 99;
    k.signature = NOT_HEX.into();
    wrong(k.verify_signature_with(None), ROTATION_SCHEMA_VERSION);
}

#[test]
fn a_malformed_signature_with_no_key_gives_the_refusal_each_document_gave_before() {
    // Release and content decode the signature first, snapshot and rotation look for the key first.
    let mut r = release();
    r.signature = NOT_HEX.into();
    assert!(matches!(
        r.verify_signature_with(None),
        Err(UpdaterError::SignatureInvalid)
    ));
    let mut c = content();
    c.signature = NOT_HEX.into();
    assert!(matches!(
        c.verify_signature_with(None),
        Err(UpdaterError::SignatureInvalid)
    ));
    let mut s = snapshot();
    s.signature = NOT_HEX.into();
    assert!(matches!(
        s.verify_signature_with(None),
        Err(UpdaterError::SigningKeyUnprovisioned)
    ));
    let mut k = rotation();
    k.signature = NOT_HEX.into();
    assert!(matches!(
        k.verify_signature_with(None),
        Err(UpdaterError::SigningKeyUnprovisioned)
    ));
    // A well-formed signature and no key: unprovisioned everywhere.
    let mut r = release();
    r.sign(&test_key_pair());
    assert!(matches!(
        r.verify_signature_with(None),
        Err(UpdaterError::SigningKeyUnprovisioned)
    ));
}
