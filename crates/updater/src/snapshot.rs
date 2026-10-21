//! The signed manifest of the fleet common-set snapshot (ADR-0033, issue #76 box 2): the document
//! that tells an agent which snapshot artifact to fetch and proves the control plane's own
//! signing key made it. A manifest of its own, verified against the `snapshot` key alone: a
//! content or release manifest signed by another key does not verify here, and this one does not
//! verify as either of those.
//!
//! Verification only, like [`crate::content`]: fetching, writing the file and reloading the
//! sink are the agent binary's job (`updater` is a LEAF crate, see [`crate`]). Freshness is
//! checked here, as pure functions over times the caller passes, so the rules are tested without
//! a clock: a snapshot not newer than the one in force is refused, one dated beyond a small
//! clock-skew tolerance is refused, and one older than the maximum age counts as absent.

use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    error::UpdaterError,
    hash::{hash_bytes, hex_decode, hex_encode},
    key::SNAPSHOT_PUBLIC_KEY,
};

/// The only `schema_version` this build accepts, versioned independently of the other manifests.
pub const SNAPSHOT_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The only manifest `kind` today.
pub const KIND_COMMON_SET: &str = "common-set";

/// How far past "now" a manifest's `built_at` may be before it is refused: a server clock a few
/// minutes ahead is normal, a manifest dated days ahead would outlive its maximum age.
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 15 * 60;

/// A snapshot older than this is treated as absent, so a server that stops publishing, or a
/// blocked network, cannot keep a stale set in force (ADR-0033 decision 3). **Provisional**:
/// three daily cadences, calibrated in slice 6 of
/// `docs/detection/fleet-prevalence-snapshot-plan.md`.
pub const DEFAULT_MAX_AGE_SECS: u64 = 3 * 24 * 60 * 60;

/// A signed snapshot manifest. Field order is alphabetical and fixed by declaration:
/// canonicalization depends on it, exactly like [`crate::content::ContentManifest`], and
/// `server/lib/snapshot-manifest.ts` writes the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    /// Unix seconds when the snapshot was built; equals the artifact header's `built_at`.
    pub built_at: u64,
    /// Distinct hashes in the artifact.
    pub entry_count: u64,
    /// Distinct reporting agents when the snapshot was built.
    pub hosts_covered: u64,
    /// Must be [`KIND_COMMON_SET`].
    pub kind: String,
    /// K: hosts a hash was seen on to be a member.
    pub min_hosts: u64,
    /// Must equal [`SNAPSHOT_MANIFEST_SCHEMA_VERSION`], checked before anything else.
    pub schema_version: u32,
    /// Lowercase-hex SHA-256 of the artifact.
    pub sha256: String,
    /// Lowercase-hex Ed25519 signature over [`Self::canonical_bytes`], computed with this field
    /// forced to `""`.
    pub signature: String,
    /// The artifact's size in bytes, so a caller can budget the download.
    pub size: u64,
}

impl SnapshotManifest {
    /// The bytes signed and verified: 2-space-indented JSON, `signature` forced to `""`, fields
    /// in the alphabetical order of the struct.
    fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = Self {
            signature: String::new(),
            ..self.clone()
        };
        serde_json::to_vec_pretty(&unsigned)
            .expect("SnapshotManifest has no non-serializable content")
    }

    /// Signs in place with `key_pair`, over the bytes [`Self::verify_signature`] checks. The
    /// production signer is a key service the control plane asks (ADR-0033); this is what tests
    /// and the public test key use.
    pub fn sign(&mut self, key_pair: &ring::signature::Ed25519KeyPair) {
        self.signature.clear();
        let sig = key_pair.sign(&self.canonical_bytes());
        self.signature = hex_encode(sig.as_ref());
    }

    /// Checks `schema_version`, `kind` and the Ed25519 signature against
    /// [`SNAPSHOT_PUBLIC_KEY`], the `snapshot` key of the trust set.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SchemaVersionUnsupported`], [`UpdaterError::SnapshotKindUnsupported`],
    /// [`UpdaterError::SigningKeyUnprovisioned`] when this build embeds no `snapshot` key, or
    /// [`UpdaterError::SignatureInvalid`].
    pub fn verify_signature(&self) -> Result<(), UpdaterError> {
        self.verify_signature_with(SNAPSHOT_PUBLIC_KEY.as_ref())
    }

    fn verify_signature_with(&self, key: Option<&[u8; 32]>) -> Result<(), UpdaterError> {
        if self.schema_version != SNAPSHOT_MANIFEST_SCHEMA_VERSION {
            return Err(UpdaterError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: SNAPSHOT_MANIFEST_SCHEMA_VERSION,
            });
        }
        if self.kind != KIND_COMMON_SET {
            return Err(UpdaterError::SnapshotKindUnsupported {
                found: self.kind.clone(),
            });
        }
        let key = key.ok_or(UpdaterError::SigningKeyUnprovisioned)?;
        let signature = hex_decode(&self.signature).ok_or(UpdaterError::SignatureInvalid)?;
        UnparsedPublicKey::new(&signature::ED25519, key)
            .verify(&self.canonical_bytes(), &signature)
            .map_err(|_| UpdaterError::SignatureInvalid)
    }

    /// Whether this manifest may replace the snapshot in force and is not from the future.
    /// `in_force` is the `built_at` of the snapshot the agent holds, `None` when it holds none;
    /// `now` is Unix seconds. An offer equal to the one in force is [`UpdaterError::SnapshotNotNewer`]
    /// too: the caller treats that as "nothing to do", the same posture as an up-to-date content
    /// release.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SnapshotNotNewer`] or [`UpdaterError::SnapshotFromFuture`].
    pub fn check_freshness(&self, in_force: Option<u64>, now: u64) -> Result<(), UpdaterError> {
        if let Some(current) = in_force
            && self.built_at <= current
        {
            return Err(UpdaterError::SnapshotNotNewer {
                offered: self.built_at,
                current,
            });
        }
        if self.built_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(UpdaterError::SnapshotFromFuture {
                built_at: self.built_at,
                now,
            });
        }
        Ok(())
    }

    /// Whether `bytes` are the artifact this manifest signs: the declared size and SHA-256.
    /// The artifact's own header is checked by the caller with the reader that parses it.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SnapshotArtifactMismatch`].
    pub fn verify_artifact(&self, bytes: &[u8]) -> Result<(), UpdaterError> {
        if bytes.len() as u64 != self.size {
            return Err(UpdaterError::SnapshotArtifactMismatch(format!(
                "size {} bytes, the manifest says {}",
                bytes.len(),
                self.size
            )));
        }
        let actual = hash_bytes(bytes);
        if actual != self.sha256 {
            return Err(UpdaterError::SnapshotArtifactMismatch(format!(
                "sha256 {actual}, the manifest says {}",
                self.sha256
            )));
        }
        Ok(())
    }
}

/// Whether a snapshot built at `built_at` is past `max_age_secs` at `now`: it then counts as
/// absent and its evidence is withheld. A snapshot dated in the future (inside the tolerance) is
/// not expired.
#[must_use]
pub fn is_expired(built_at: u64, now: u64, max_age_secs: u64) -> bool {
    now.saturating_sub(built_at) > max_age_secs
}

#[cfg(test)]
mod tests {
    use ring::signature::KeyPair;

    use super::*;
    use crate::key::test_snapshot_key_pair;

    const NOW: u64 = 1_760_000_000;

    fn manifest(built_at: u64) -> SnapshotManifest {
        let mut m = SnapshotManifest {
            built_at,
            entry_count: 4096,
            hosts_covered: 12,
            kind: KIND_COMMON_SET.into(),
            min_hosts: 3,
            schema_version: SNAPSHOT_MANIFEST_SCHEMA_VERSION,
            sha256: hash_bytes(b"artifact"),
            signature: String::new(),
            size: 8,
        };
        m.sign(&test_snapshot_key_pair());
        m
    }

    /// The file the TypeScript signer's tests read too (`server/lib/snapshot-manifest.ts`).
    fn golden() -> (String, SnapshotManifest) {
        #[derive(Deserialize)]
        struct Golden {
            public_key: String,
            manifest: SnapshotManifest,
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../server/tests/fixtures/snapshot-manifest-golden.json"
        );
        let g: Golden = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        (g.public_key, g.manifest)
    }

    #[test]
    fn a_manifest_signed_with_the_test_key_verifies() {
        manifest(NOW).verify_signature().unwrap();
    }

    #[test]
    fn the_golden_fixture_from_the_server_verifies_against_the_key_derived_from_the_seed() {
        let (public_key, golden) = golden();
        let derived = hex_encode(test_snapshot_key_pair().public_key().as_ref());
        assert_eq!(
            public_key, derived,
            "the two sides derive one test key from one seed"
        );
        golden.verify_signature().unwrap();
    }

    #[test]
    fn signing_the_golden_manifest_here_gives_the_servers_signature() {
        // Ed25519 is deterministic: the same canonical bytes under the same key give the same
        // signature, so any drift in the canonical form fails here and in the TypeScript test.
        let (_, golden) = golden();
        let mut resigned = golden.clone();
        resigned.sign(&test_snapshot_key_pair());
        assert_eq!(resigned.signature, golden.signature);
    }

    #[test]
    fn a_field_changed_after_signing_does_not_verify() {
        let good = manifest(NOW);
        type Change = fn(&mut SnapshotManifest);
        let changes: [Change; 6] = [
            |m| m.built_at += 1,
            |m| m.entry_count += 1,
            |m| m.hosts_covered += 1,
            |m| m.min_hosts += 1,
            |m| m.sha256 = "ab".repeat(32),
            |m| m.size += 1,
        ];
        for change in changes {
            let mut m = good.clone();
            change(&mut m);
            assert!(matches!(
                m.verify_signature(),
                Err(UpdaterError::SignatureInvalid)
            ));
        }
    }

    #[test]
    fn another_key_or_a_malformed_signature_does_not_verify() {
        let m = manifest(NOW);
        assert!(matches!(
            m.verify_signature_with(Some(&[7; 32])),
            Err(UpdaterError::SignatureInvalid)
        ));
        for bad in ["", "zz", &"ab".repeat(63)] {
            let mut tampered = m.clone();
            tampered.signature = bad.into();
            assert!(matches!(
                tampered.verify_signature(),
                Err(UpdaterError::SignatureInvalid)
            ));
        }
    }

    #[test]
    fn a_manifest_signed_by_the_content_or_release_key_is_not_a_snapshot_manifest() {
        // In the test set `release` and `content` are one key, the snapshot key another: role
        // separation (ADR-0027, ADR-0033).
        let mut m = manifest(NOW);
        m.sign(&crate::key::test_key_pair());
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_build_with_no_snapshot_key_verifies_nothing() {
        assert!(matches!(
            manifest(NOW).verify_signature_with(None),
            Err(UpdaterError::SigningKeyUnprovisioned)
        ));
    }

    #[test]
    fn an_unknown_schema_version_or_kind_is_refused_before_the_signature_is_looked_at() {
        let mut m = manifest(NOW);
        m.schema_version = 2;
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SchemaVersionUnsupported {
                found: 2,
                expected: 1
            })
        ));
        let mut m = manifest(NOW);
        m.kind = "policy".into();
        assert!(matches!(
            m.verify_signature(),
            Err(UpdaterError::SnapshotKindUnsupported { .. })
        ));
    }

    #[test]
    fn json_with_an_unknown_field_is_not_a_manifest() {
        let mut value = serde_json::to_value(manifest(NOW)).unwrap();
        value["tenant_id"] = "t".into();
        assert!(serde_json::from_value::<SnapshotManifest>(value).is_err());
    }

    #[test]
    fn a_snapshot_must_be_strictly_newer_than_the_one_in_force() {
        let m = manifest(NOW);
        m.check_freshness(None, NOW).unwrap();
        m.check_freshness(Some(NOW - 1), NOW).unwrap();
        for in_force in [NOW, NOW + 1] {
            assert!(matches!(
                m.check_freshness(Some(in_force), NOW),
                Err(UpdaterError::SnapshotNotNewer { offered, current })
                    if offered == NOW && current == in_force
            ));
        }
    }

    #[test]
    fn a_snapshot_from_the_future_is_refused_beyond_the_clock_skew_tolerance() {
        manifest(NOW + CLOCK_SKEW_TOLERANCE_SECS)
            .check_freshness(None, NOW)
            .unwrap();
        assert!(matches!(
            manifest(NOW + CLOCK_SKEW_TOLERANCE_SECS + 1).check_freshness(None, NOW),
            Err(UpdaterError::SnapshotFromFuture { .. })
        ));
    }

    #[test]
    fn the_artifact_must_be_the_declared_size_and_hash() {
        let mut m = manifest(NOW);
        m.sha256 = hash_bytes(b"artifact");
        m.size = 8;
        m.verify_artifact(b"artifact").unwrap();
        assert!(matches!(
            m.verify_artifact(b"artifac"),
            Err(UpdaterError::SnapshotArtifactMismatch(_))
        ));
        assert!(matches!(
            m.verify_artifact(b"artifacT"),
            Err(UpdaterError::SnapshotArtifactMismatch(_))
        ));
    }

    #[test]
    fn a_snapshot_expires_after_the_maximum_age_and_not_before() {
        let max = DEFAULT_MAX_AGE_SECS;
        assert!(!is_expired(NOW, NOW, max));
        assert!(
            !is_expired(NOW - max, NOW, max),
            "exactly the maximum age is still in force"
        );
        assert!(is_expired(NOW - max - 1, NOW, max));
        assert!(
            !is_expired(NOW + 60, NOW, max),
            "a snapshot inside the skew tolerance is not expired"
        );
    }
}
