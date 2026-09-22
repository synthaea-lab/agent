//! The signed release manifest (ADR-0015 Decision 2): the payload the updater
//! verifies before staging or promoting a release. Wraps the same `(path,
//! sha256)` shape `tamper::integrity::Manifest` consumes at runtime, plus the
//! version counter and signature that make it trustworthy in the first place.

use std::{collections::BTreeMap, path::PathBuf};

use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    error::UpdaterError,
    hash::{hex_decode, hex_encode},
    key::UPDATER_PUBLIC_KEY,
};

/// The only `schema_version` this build accepts (ADR-0015 Decision 2: readers
/// reject an unknown value outright rather than parsing leniently).
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// A signed release manifest.
///
/// Field order is alphabetical and fixed by declaration — canonicalization
/// (ADR-0015 Decision 2: "canonical JSON serialization ... sorted keys") relies on
/// it, so do not reorder these fields without checking [`Self::canonical_bytes`].
/// `entries`' `BTreeMap` iterates in sorted path order on its own regardless of
/// field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// Path (relative to the release's version directory) → expected lowercase-hex
    /// SHA-256. Forward-slash strings — the scope is Linux-only, so paths are
    /// POSIX-native already.
    pub entries: BTreeMap<PathBuf, String>,
    /// Monotone, strictly increasing. A manifest whose `release_version` is not
    /// greater than the currently installed one is rejected (anti-rollback-attack;
    /// see [`Self::check_release_version`]).
    pub release_version: u64,
    /// Must equal [`MANIFEST_SCHEMA_VERSION`] or the manifest is rejected before
    /// any other check runs.
    pub schema_version: u32,
    /// Lowercase-hex Ed25519 signature over [`Self::canonical_bytes`] computed
    /// with this field forced to `""`. Empty until [`Self::sign`] fills it in.
    pub signature: String,
}

impl ReleaseManifest {
    /// Builds an unsigned manifest at the current [`MANIFEST_SCHEMA_VERSION`].
    /// Call [`Self::sign`] before distributing it.
    #[must_use]
    pub fn new(release_version: u64, entries: BTreeMap<PathBuf, String>) -> Self {
        Self {
            entries,
            release_version,
            schema_version: MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        }
    }

    /// The canonical bytes this manifest signs and verifies over: 2-space-indented
    /// JSON with `signature` forced to `""`, fields in the alphabetical order they
    /// are declared in the struct, and `entries` in its `BTreeMap`'s natural sorted
    /// key order (ADR-0015 Decision 2).
    fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = Self {
            signature: String::new(),
            ..self.clone()
        };
        serde_json::to_vec_pretty(&unsigned)
            .expect("ReleaseManifest has no non-serializable content")
    }

    /// Signs this manifest in place with `key_pair`, replacing whatever
    /// `signature` currently holds. Production signing happens out of band
    /// (ADR-0015 Deferred: production key generation and custody) — this is used
    /// by the test/dev release tooling and this crate's own tests, always against
    /// [`crate::key::test_key_pair`] today.
    pub fn sign(&mut self, key_pair: &Ed25519KeyPair) {
        self.signature.clear();
        let msg = self.canonical_bytes();
        let sig = key_pair.sign(&msg);
        self.signature = hex_encode(sig.as_ref());
    }

    /// Verifies this manifest's `schema_version` and Ed25519 signature against
    /// [`UPDATER_PUBLIC_KEY`]. Does not check `release_version` monotonicity or
    /// per-file hashes — see [`Self::check_release_version`] and
    /// `crate::layout::Layout::verify_staged`.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SchemaVersionUnsupported`] if `schema_version` does not
    /// match [`MANIFEST_SCHEMA_VERSION`]; [`UpdaterError::SignatureInvalid`] if
    /// the signature is malformed or does not verify.
    pub fn verify_signature(&self) -> Result<(), UpdaterError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(UpdaterError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: MANIFEST_SCHEMA_VERSION,
            });
        }
        let sig_bytes = hex_decode(&self.signature).ok_or(UpdaterError::SignatureInvalid)?;
        let msg = self.canonical_bytes();
        let public_key = UnparsedPublicKey::new(&signature::ED25519, UPDATER_PUBLIC_KEY.as_slice());
        public_key
            .verify(&msg, &sig_bytes)
            .map_err(|_| UpdaterError::SignatureInvalid)
    }

    /// Anti-rollback-attack check (ADR-0015 Decision 2): rejects a manifest whose
    /// `release_version` is not strictly greater than `current` — `None` means no
    /// release is installed yet (day 0, still on `bootstrap`; ADR-0015 Decision 7),
    /// which always accepts.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::ReleaseNotNewer`] if `release_version <= current`.
    pub fn check_release_version(&self, current: Option<u64>) -> Result<(), UpdaterError> {
        match current {
            Some(current) if self.release_version <= current => {
                Err(UpdaterError::ReleaseNotNewer {
                    offered: self.release_version,
                    current,
                })
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_key_pair;

    fn signed_manifest(release_version: u64) -> ReleaseManifest {
        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("agent"), "a".repeat(64));
        let mut m = ReleaseManifest::new(release_version, entries);
        m.sign(&test_key_pair());
        m
    }

    #[test]
    fn a_freshly_signed_manifest_verifies() {
        assert!(signed_manifest(2).verify_signature().is_ok());
    }

    #[test]
    fn tampering_with_entries_after_signing_breaks_verification() {
        let mut m = signed_manifest(2);
        m.entries.insert(PathBuf::from("watchdog"), "b".repeat(64));
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampering_with_release_version_after_signing_breaks_verification() {
        let mut m = signed_manifest(2);
        m.release_version = 99;
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn an_unsigned_manifest_fails_verification() {
        let entries = BTreeMap::new();
        let m = ReleaseManifest::new(1, entries);
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn unsupported_schema_version_is_rejected_before_checking_the_signature() {
        let mut m = signed_manifest(2);
        m.schema_version = MANIFEST_SCHEMA_VERSION + 1;
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SchemaVersionUnsupported { found, expected })
                if found == MANIFEST_SCHEMA_VERSION + 1 && expected == MANIFEST_SCHEMA_VERSION
        ));
    }

    #[test]
    fn release_version_must_exceed_the_installed_one() {
        let m = signed_manifest(5);
        assert!(m.check_release_version(Some(4)).is_ok());
        assert!(matches!(
            m.check_release_version(Some(5)),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 5,
                current: 5
            })
        ));
        assert!(matches!(
            m.check_release_version(Some(6)),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 5,
                current: 6
            })
        ));
    }

    #[test]
    fn no_installed_release_always_accepts_bootstrap_day_zero() {
        let m = signed_manifest(1);
        assert!(m.check_release_version(None).is_ok());
    }

    #[test]
    fn canonical_bytes_are_stable_regardless_of_the_signature_field() {
        let mut a = signed_manifest(3);
        let mut b = a.clone();
        b.signature = "not-the-real-signature".into();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        a.signature.clear();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_use_two_space_indent() {
        let m = signed_manifest(1);
        let bytes = m.canonical_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\n  \"entries\""));
    }
}
