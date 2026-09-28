//! The signed content manifest (ADR-0016): detection rules, ML models, and
//! policy distributed via canary rings, independent of a binary release. Same
//! Ed25519 signing/verification discipline as [`crate::manifest::ReleaseManifest`]
//! — a distinct type, not a variant of it, because the two manifests carry
//! genuinely different shapes: content entries need a `ring`, a `type`, and
//! optional `metadata` that a binary release's flat `(path, sha256)` map has no
//! use for.
//!
//! This module covers verification only — fetching the manifest over the
//! network (`crates/transport`) and reloading rules/models into a running agent
//! are composed by the binary that uses this crate (`updater` stays a LEAF crate
//! per `tools/check-deps.py`; see [`crate`]'s module doc for why).

use std::collections::BTreeMap;

use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{error::UpdaterError, hash::hex_decode, key::UPDATER_PUBLIC_KEY};

/// The only `schema_version` this build accepts — same anti-drift stance as
/// [`crate::manifest::MANIFEST_SCHEMA_VERSION`], a separate constant because the
/// two manifest kinds version independently.
pub const CONTENT_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// One artifact in a content manifest (ADR-0016 §1).
///
/// Field order is alphabetical and fixed by declaration, same reasoning as
/// [`ContentManifest`] — canonicalization depends on it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentEntry {
    /// Free-form key/value metadata (e.g. `{"technique": "T1071.001"}`) —
    /// carried through, never interpreted by this crate. Absent rather than
    /// `null` when empty, matching the server's `.optional()` Zod field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
    /// Path relative to the content root (e.g. `rules/beacon.sigma`). Forward-slash
    /// strings regardless of host OS — content paths are a server-defined
    /// namespace, not a filesystem path on either side.
    pub path: String,
    /// Lowercase-hex SHA-256 of the artifact's bytes.
    pub sha256: String,
    /// Size in bytes — lets a caller budget a download before fetching it.
    pub size: u64,
    /// `rule` | `model` | `policy` (ADR-0016 §1). Kept as a plain string, not a
    /// Rust enum: this crate only ever forwards the value to a caller that
    /// decides what to do with each type, and a string can't fail to
    /// deserialize just because the server added a fourth type this build
    /// doesn't know the name of yet.
    #[serde(rename = "type")]
    pub content_type: String,
}

/// A signed content manifest for one ring (ADR-0016 §1).
///
/// Field order is alphabetical and fixed by declaration — canonicalization
/// relies on it, exactly like [`crate::manifest::ReleaseManifest`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentManifest {
    pub entries: Vec<ContentEntry>,
    /// Monotone, strictly increasing per `ring`. See [`Self::check_release_version`].
    pub release_version: u64,
    /// ISO 8601 UTC timestamp, e.g. `2026-09-23T16:00:00Z`. Kept as the raw
    /// string the server sent — this crate never computes with it, only a
    /// caller displaying "last updated" would parse it.
    pub released_at: String,
    /// Target ring (`canary_0`/`canary_1`/`canary_2`/`prod`). A plain string for
    /// the same reason as [`ContentEntry::content_type`] — this crate compares
    /// it, never branches on an exhaustive match.
    pub ring: String,
    /// Must equal [`CONTENT_MANIFEST_SCHEMA_VERSION`] or the manifest is
    /// rejected before any other check runs.
    pub schema_version: u32,
    /// Lowercase-hex Ed25519 signature over [`Self::canonical_bytes`] computed
    /// with this field forced to `""`.
    pub signature: String,
}

impl ContentManifest {
    /// The canonical bytes this manifest signs and verifies over: 2-space-indented
    /// JSON with `signature` forced to `""`, fields in the alphabetical order
    /// they are declared in the struct. Same scheme as
    /// [`crate::manifest::ReleaseManifest::canonical_bytes`] (ADR-0015 Decision 2,
    /// reused by ADR-0016 for consistency) — kept as a private, independent
    /// implementation rather than shared code, since the two manifest shapes
    /// differ and a shared helper would need to take the signature-bearing
    /// struct by trait object for no real savings.
    fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = Self {
            signature: String::new(),
            ..self.clone()
        };
        serde_json::to_vec_pretty(&unsigned)
            .expect("ContentManifest has no non-serializable content")
    }

    /// Verifies this manifest's `schema_version` and Ed25519 signature against
    /// [`UPDATER_PUBLIC_KEY`] — the same embedded key that verifies binary
    /// release manifests. Does not check `release_version` monotonicity,
    /// `ring` assignment, or per-entry hashes — see [`Self::check_release_version`]
    /// and the caller's own per-artifact hash check after download.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SchemaVersionUnsupported`] if `schema_version` does not
    /// match [`CONTENT_MANIFEST_SCHEMA_VERSION`]; [`UpdaterError::SignatureInvalid`]
    /// if the signature is malformed or does not verify.
    pub fn verify_signature(&self) -> Result<(), UpdaterError> {
        if self.schema_version != CONTENT_MANIFEST_SCHEMA_VERSION {
            return Err(UpdaterError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: CONTENT_MANIFEST_SCHEMA_VERSION,
            });
        }
        let sig_bytes = hex_decode(&self.signature).ok_or(UpdaterError::SignatureInvalid)?;
        let msg = self.canonical_bytes();
        let public_key = UnparsedPublicKey::new(&signature::ED25519, UPDATER_PUBLIC_KEY.as_slice());
        public_key
            .verify(&msg, &sig_bytes)
            .map_err(|_| UpdaterError::SignatureInvalid)
    }

    /// Rejects a manifest whose `ring` does not match `requested` — a valid
    /// signature only proves the server signed this manifest, not that it is
    /// the manifest for the ring the caller actually asked for. Without this,
    /// a validly-signed manifest for a different ring (e.g. a less-vetted
    /// canary release replayed against a prod agent) would still verify.
    /// Callers must check this before, or alongside,
    /// [`Self::check_release_version`] — see `agent::content::plan`.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::RingMismatch`] if `self.ring != requested`.
    pub fn check_ring(&self, requested: &str) -> Result<(), UpdaterError> {
        if self.ring != requested {
            return Err(UpdaterError::RingMismatch {
                requested: requested.to_string(),
                found: self.ring.clone(),
            });
        }
        Ok(())
    }

    /// Anti-rollback-attack check, same shape as
    /// [`crate::manifest::ReleaseManifest::check_release_version`]: rejects a
    /// manifest whose `release_version` is not strictly greater than `current`.
    /// `current` is per-`ring` — a caller tracks the last-applied version for
    /// each ring it has ever fetched, not one counter shared across rings.
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

    /// Entries this manifest carries that are missing from, or whose hash
    /// disagrees with, `have` (the caller's map of already-applied
    /// `path -> sha256`). Empty means the caller is already fully up to date
    /// with this manifest's content — a legitimate outcome (e.g. re-fetching
    /// the same ring's manifest after a restart with no new release).
    #[must_use]
    pub fn entries_to_fetch<'a>(
        &'a self,
        have: &BTreeMap<String, String>,
    ) -> Vec<&'a ContentEntry> {
        self.entries
            .iter()
            .filter(|e| have.get(&e.path) != Some(&e.sha256))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_key_pair;

    fn entry(path: &str, sha256: &str) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: sha256.to_string(),
            size: 1234,
            content_type: "rule".to_string(),
        }
    }

    fn signed_manifest(release_version: u64) -> ContentManifest {
        let mut m = ContentManifest {
            entries: vec![entry("rules/beacon.sigma", &"a".repeat(64))],
            released_at: "2026-09-23T16:00:00Z".to_string(),
            release_version,
            ring: "canary_0".to_string(),
            schema_version: CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        };
        let msg = m.canonical_bytes();
        let sig = test_key_pair().sign(&msg);
        m.signature = crate::hash::hex_encode(sig.as_ref());
        m
    }

    #[test]
    fn a_freshly_signed_manifest_verifies() {
        assert!(signed_manifest(1).verify_signature().is_ok());
    }

    #[test]
    fn tampering_with_entries_after_signing_breaks_verification() {
        let mut m = signed_manifest(1);
        m.entries.push(entry("rules/other.sigma", &"b".repeat(64)));
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampering_with_ring_after_signing_breaks_verification() {
        // A signed canary_0 manifest replayed as a prod manifest must not verify
        // — the ring is part of what's signed, not a side channel the server
        // could swap after the fact.
        let mut m = signed_manifest(1);
        m.ring = "prod".to_string();
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn an_unsigned_manifest_fails_verification() {
        let m = ContentManifest {
            entries: vec![],
            released_at: "2026-09-23T16:00:00Z".to_string(),
            release_version: 1,
            ring: "canary_0".to_string(),
            schema_version: CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        };
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn unsupported_schema_version_is_rejected_before_checking_the_signature() {
        let mut m = signed_manifest(1);
        m.schema_version = CONTENT_MANIFEST_SCHEMA_VERSION + 1;
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SchemaVersionUnsupported { found, expected })
                if found == CONTENT_MANIFEST_SCHEMA_VERSION + 1
                    && expected == CONTENT_MANIFEST_SCHEMA_VERSION
        ));
    }

    #[test]
    fn check_ring_accepts_a_matching_ring() {
        let m = signed_manifest(1);
        assert!(m.check_ring("canary_0").is_ok());
    }

    #[test]
    fn check_ring_rejects_a_correctly_signed_manifest_for_another_ring() {
        // A validly-signed canary_0 manifest must not pass as a prod manifest
        // just because the signature verifies — the signature proves who
        // signed it, not that it's the manifest for the ring asked for.
        let m = signed_manifest(1);
        assert!(matches!(
            m.check_ring("prod"),
            Err(UpdaterError::RingMismatch { requested, found })
                if requested == "prod" && found == "canary_0"
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
    }

    #[test]
    fn no_installed_release_always_accepts_day_zero() {
        let m = signed_manifest(1);
        assert!(m.check_release_version(None).is_ok());
    }

    #[test]
    fn entries_to_fetch_skips_files_already_at_the_right_hash() {
        let mut m = signed_manifest(1);
        m.entries.push(entry("rules/other.sigma", &"b".repeat(64)));

        let mut have = BTreeMap::new();
        have.insert("rules/beacon.sigma".to_string(), "a".repeat(64));
        // Stale hash for this one — must still be reported.
        have.insert("rules/other.sigma".to_string(), "c".repeat(64));

        let missing = m.entries_to_fetch(&have);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].path, "rules/other.sigma");
    }

    #[test]
    fn entries_to_fetch_is_empty_when_fully_up_to_date() {
        let m = signed_manifest(1);
        let mut have = BTreeMap::new();
        have.insert("rules/beacon.sigma".to_string(), "a".repeat(64));
        assert!(m.entries_to_fetch(&have).is_empty());
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
}

/// Parity-seam golden fixture (CLAUDE.md): one real, signed manifest checked
/// in once at `server/tests/fixtures/content-manifest-golden.json` and
/// verified by both this crate's tests and the server's TS unit tests
/// (`server/tests/unit/content-manifest-golden.test.ts`), so a canonicalization
/// mismatch between the two sides (PR #509 review) can't silently reappear.
#[cfg(test)]
mod golden_fixture {
    use super::*;

    const GOLDEN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../server/tests/fixtures/content-manifest-golden.json"
    ));

    #[test]
    fn golden_fixture_verifies_against_the_embedded_key() {
        let manifest: ContentManifest = serde_json::from_str(GOLDEN_FIXTURE).unwrap();
        manifest.verify_signature().unwrap();
    }

    #[test]
    fn golden_fixture_bytes_are_the_canonical_form() {
        // The fixture file itself is `serde_json::to_string_pretty` of the
        // signed manifest — asserts the checked-in bytes haven't drifted from
        // what this crate would itself produce, so a hand-edit of the fixture
        // can't silently break the cross-language comparison it exists for.
        // `.gitattributes` pins this file to `eol=lf`, but normalize `\r\n` on
        // both sides anyway rather than depend on that alone — a Windows
        // checkout that reintroduces CRLF here should fail on real content
        // drift, not on line endings (this crate's own CI caught exactly that
        // once, before this normalization existed).
        let manifest: ContentManifest = serde_json::from_str(GOLDEN_FIXTURE).unwrap();
        let regenerated = serde_json::to_string_pretty(&manifest).unwrap();
        assert_eq!(
            GOLDEN_FIXTURE.trim_end().replace("\r\n", "\n"),
            regenerated.trim_end().replace("\r\n", "\n")
        );
    }
}
