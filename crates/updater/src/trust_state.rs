//! The keys an install trusts now: the embedded set, then every key rotation it applied, in
//! order (ADR-0027). The embedded keys are compile-time statics, so a rotation cannot change
//! them; what an install records is **the signed rotation manifests themselves**, not the keys
//! they produced. Every load replays the record from the embedded keys and re-verifies each
//! manifest under the embedded `recovery` key, so the record cannot introduce a key that
//! `recovery` did not sign, and a record that was edited, truncated in the middle or built for
//! other keys is refused instead of trusted.
//!
//! Pure over the embedded keys and the clock the caller passes, like [`crate::rotation`]; the
//! agent binary decides where the file lives and when to load it.
//!
//! **The order, and what never goes backward.** Effective keys = embedded keys, then each recorded
//! rotation. For each role a rotation changes:
//!
//! - the key in force is the one it retires: apply it;
//! - the key in force is already the one it installs, or a key a later rotation installs (a newer
//!   build embeds keys the record is behind): skip, the embedded key is ahead of the record;
//! - anything else: the record does not lead from these keys, refused.
//!
//! So an older record than the embedded keys is harmless (the embedded keys win and the record's
//! version still counts), and a record can only ever move a role forward along keys `recovery`
//! signed. A **missing** file is a fresh install: the embedded keys. A file that exists and is
//! not trustworthy is an error, never a fallback. The residual risk is deletion: removing the file
//! on an install that rotated puts the embedded (retired) keys back in force, which needs write
//! access to the state directory, which is root's; this is the same trust boundary as the ban
//! list and the content state.

use std::{io, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    error::UpdaterError,
    fsutil::write_atomically,
    key::RECOVERY_PUBLIC_KEY,
    rotation::{KeyRotationManifest, TrustedKeys},
};

/// The file, directly under the install's state directory.
pub const TRUST_STATE_FILE: &str = "key-rotations.json";

/// The only `schema_version` this build reads.
pub const TRUST_STATE_SCHEMA_VERSION: u32 = 1;

/// The most rotations an install records: the file is read on every integrity pass and every
/// replay re-verifies each signature, so it stays small. Hitting it means a reinstall, which is
/// also the answer to a fleet that has needed that many rotations.
pub const MAX_ROTATIONS: usize = 64;

/// The applied rotations, in order. What is persisted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    schema_version: u32,
    rotations: Vec<KeyRotationManifest>,
}

/// What a verified record gives the verifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The keys to verify releases and content against now.
    pub keys: TrustedKeys,
    /// The highest `release_version` among the recorded rotations: a rotation takes a number from
    /// the release counter, so the next release or rotation must go above it.
    pub applied_release_version: Option<u64>,
    /// Every `release` key this install has trusted: the embedded one and each one a recorded
    /// rotation installed. For re-checking the manifest of a release already promoted (signed by
    /// the key in force when it was promoted), never for applying anything new.
    pub release_lineage: Vec<[u8; 32]>,
    /// Whether the `release` key in force is not the embedded one.
    pub release_rotated: bool,
    /// Whether the `content` key in force is not the embedded one.
    pub content_rotated: bool,
}

#[derive(Clone, Copy)]
enum Role {
    Release,
    Content,
}

impl Role {
    fn get(self, keys: &TrustedKeys) -> [u8; 32] {
        match self {
            Self::Release => keys.release,
            Self::Content => keys.content,
        }
    }

    fn set(self, keys: &mut TrustedKeys, key: [u8; 32]) {
        match self {
            Self::Release => keys.release = key,
            Self::Content => keys.content = key,
        }
    }

    /// `(retired, new)` of this role in `rotation`, if it changes it. The manifest was validated
    /// before this is reached.
    fn change(self, rotation: &KeyRotationManifest) -> Option<([u8; 32], [u8; 32])> {
        match self {
            Self::Release => rotation.release_change(),
            Self::Content => rotation.content_change(),
        }
        .ok()
        .flatten()
    }
}

fn corrupt(reason: impl Into<String>) -> UpdaterError {
    UpdaterError::TrustStateCorrupt {
        reason: reason.into(),
    }
}

impl TrustState {
    /// Reads the record at `path`. A missing file is an empty record (a fresh install).
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if the file exists and cannot be read, [`UpdaterError::TrustStateCorrupt`]
    /// if it is not a record this build understands.
    pub fn load(path: &Path) -> Result<Self, UpdaterError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(source) => {
                return Err(UpdaterError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|e| corrupt(format!("{} does not parse: {e}", path.display())))?;
        if state.schema_version != TRUST_STATE_SCHEMA_VERSION {
            return Err(corrupt(format!(
                "schema_version {} is not supported (expected {TRUST_STATE_SCHEMA_VERSION})",
                state.schema_version
            )));
        }
        if state.rotations.len() > MAX_ROTATIONS {
            return Err(corrupt(
                "it records more rotations than an install may hold",
            ));
        }
        Ok(state)
    }

    /// Writes the record atomically to `dest` under `root` (the state directory).
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if the write fails or a component of the path is a symlink.
    ///
    /// # Panics
    ///
    /// Never: a [`TrustState`] has no content `serde_json` could fail to serialize.
    pub fn save(&self, root: &Path, dest: &Path) -> Result<(), UpdaterError> {
        let bytes = serde_json::to_vec_pretty(self).expect("TrustState serializes");
        write_atomically(root, dest, &bytes).map_err(|source| UpdaterError::Io {
            path: dest.to_path_buf(),
            source,
        })
    }

    fn empty() -> Self {
        Self {
            schema_version: TRUST_STATE_SCHEMA_VERSION,
            rotations: Vec::new(),
        }
    }

    /// How many rotations are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rotations.len()
    }

    /// Whether no rotation is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rotations.is_empty()
    }

    /// Replays the record from the embedded keys against the embedded `recovery` key.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::TrustStateCorrupt`] when the record cannot be trusted (see the module doc),
    /// including when rotations are recorded but this build embeds no `recovery` key or no
    /// complete trust set to replay them from.
    pub fn resolve(&self) -> Result<Resolved, UpdaterError> {
        let embedded = TrustedKeys::embedded();
        self.resolve_with(embedded.as_ref(), RECOVERY_PUBLIC_KEY.as_ref())
    }

    pub(crate) fn resolve_with(
        &self,
        embedded: Option<&TrustedKeys>,
        recovery: Option<&[u8; 32]>,
    ) -> Result<Resolved, UpdaterError> {
        let (Some(embedded), Some(recovery)) = (embedded, recovery) else {
            return Err(corrupt(
                "rotations are recorded but this build embeds no complete trust set to replay them from",
            ));
        };
        let mut keys = *embedded;
        let mut applied = None;
        let mut lineage = vec![embedded.release];
        for (i, rotation) in self.rotations.iter().enumerate() {
            rotation
                .verify_signature_with(Some(recovery))
                .map_err(|e| corrupt(format!("rotation {} does not verify: {e}", i + 1)))?;
            if applied.is_some_and(|v| rotation.release_version <= v) {
                return Err(corrupt(format!(
                    "rotation {} does not have a higher release_version than the one before",
                    i + 1
                )));
            }
            for role in [Role::Release, Role::Content] {
                let Some((retired, new)) = role.change(rotation) else {
                    continue;
                };
                let current = role.get(&keys);
                let later_installs_current = self.rotations[i + 1..]
                    .iter()
                    .any(|later| role.change(later).is_some_and(|(_, n)| n == current));
                if current == retired {
                    role.set(&mut keys, new);
                } else if current != new && !later_installs_current {
                    return Err(corrupt(format!(
                        "rotation {} does not lead from the keys this build embeds",
                        i + 1
                    )));
                }
                if matches!(role, Role::Release) {
                    lineage.push(new);
                }
            }
            applied = Some(rotation.release_version);
        }
        // The embedded set is not judged here (the test set has `release` and `content` on one
        // key on purpose); a rotation must not leave the roles worse off than that.
        if !self.rotations.is_empty()
            && (keys.release == keys.content
                || keys.release == *recovery
                || keys.content == *recovery)
        {
            return Err(corrupt("the recorded rotations leave two roles on one key"));
        }
        Ok(Resolved {
            release_rotated: keys.release != embedded.release,
            content_rotated: keys.content != embedded.content,
            keys,
            applied_release_version: applied,
            release_lineage: lineage,
        })
    }

    /// Verifies `rotation` against the keys in force now and, when it passes every check of
    /// [`KeyRotationManifest::verify`], records it and returns the keys to trust from here on.
    /// Nothing is written: the caller saves the record, and the keys apply from the next load.
    ///
    /// `installed_release` is the installed binary release (`None` on bootstrap): the rotation
    /// must be newer than it and than every recorded rotation, one counter for both (ADR-0027).
    ///
    /// # Errors
    ///
    /// Everything [`Self::resolve`] and [`KeyRotationManifest::verify`] return, and
    /// [`UpdaterError::TrustStateFull`].
    pub fn adopt(
        &mut self,
        rotation: &KeyRotationManifest,
        installed_release: Option<u64>,
        now: u64,
    ) -> Result<TrustedKeys, UpdaterError> {
        let embedded = TrustedKeys::embedded();
        self.adopt_with(
            rotation,
            embedded.as_ref(),
            RECOVERY_PUBLIC_KEY.as_ref(),
            installed_release,
            now,
        )
    }

    pub(crate) fn adopt_with(
        &mut self,
        rotation: &KeyRotationManifest,
        embedded: Option<&TrustedKeys>,
        recovery: Option<&[u8; 32]>,
        installed_release: Option<u64>,
        now: u64,
    ) -> Result<TrustedKeys, UpdaterError> {
        if embedded.is_none() || recovery.is_none() {
            return Err(UpdaterError::SigningKeyUnprovisioned);
        }
        if self.rotations.len() >= MAX_ROTATIONS {
            return Err(UpdaterError::TrustStateFull(MAX_ROTATIONS));
        }
        let resolved = self.resolve_with(embedded, recovery)?;
        let applied = resolved.applied_release_version.max(installed_release);
        let next = rotation.verify_with(recovery, &resolved.keys, applied, now)?;
        self.rotations.push(rotation.clone());
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;
    use crate::{hash::hex_encode, rotation::ROTATION_SCHEMA_VERSION};

    const ISSUED: u64 = 1_760_000_000;
    const NOW: u64 = ISSUED + 60;

    fn pair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn public(seed: u8) -> [u8; 32] {
        pair(seed).public_key().as_ref().try_into().unwrap()
    }

    /// The test `recovery` key stands in for the embedded one: every function here takes the
    /// embedded keys and `recovery` as arguments, so no build feature decides the outcome.
    fn recovery() -> [u8; 32] {
        public(0x43)
    }

    fn embedded() -> TrustedKeys {
        TrustedKeys {
            release: public(0x11),
            content: public(0x22),
        }
    }

    fn rotation(
        version: u64,
        release: Option<([u8; 32], [u8; 32])>,
        content: Option<([u8; 32], [u8; 32])>,
    ) -> KeyRotationManifest {
        let (new_release_key, retired_release_key) = split(release);
        let (new_content_key, retired_content_key) = split(content);
        let mut m = KeyRotationManifest {
            expires_at: ISSUED + 24 * 3600,
            issued_at: ISSUED,
            new_content_key,
            new_release_key,
            reason: "scheduled".into(),
            release_version: version,
            retired_content_key,
            retired_release_key,
            schema_version: ROTATION_SCHEMA_VERSION,
            signature: String::new(),
        };
        m.sign(&pair(0x43));
        m
    }

    fn split(pair: Option<([u8; 32], [u8; 32])>) -> (Option<String>, Option<String>) {
        pair.map_or((None, None), |(retired, new)| {
            (Some(hex_encode(&new)), Some(hex_encode(&retired)))
        })
    }

    fn state(rotations: Vec<KeyRotationManifest>) -> TrustState {
        TrustState {
            schema_version: TRUST_STATE_SCHEMA_VERSION,
            rotations,
        }
    }

    fn resolve(state: &TrustState, embedded: &TrustedKeys) -> Result<Resolved, UpdaterError> {
        state.resolve_with(Some(embedded), Some(&recovery()))
    }

    fn adopt(
        state: &mut TrustState,
        rotation: &KeyRotationManifest,
        installed: Option<u64>,
    ) -> Result<TrustedKeys, UpdaterError> {
        state.adopt_with(
            rotation,
            Some(&embedded()),
            Some(&recovery()),
            installed,
            NOW,
        )
    }

    #[test]
    fn an_empty_record_is_the_embedded_keys() {
        let resolved = resolve(&state(vec![]), &embedded()).unwrap();
        assert_eq!(resolved.keys, embedded());
        assert_eq!(resolved.applied_release_version, None);
        assert!(!resolved.release_rotated && !resolved.content_rotated);
    }

    #[test]
    fn an_empty_record_does_not_judge_the_embedded_set() {
        // The public test set has release and content on one key (ADR-0016's shortcut).
        let shared = TrustedKeys {
            release: public(0x42),
            content: public(0x42),
        };
        assert_eq!(resolve(&state(vec![]), &shared).unwrap().keys, shared);
    }

    #[test]
    fn rotations_apply_in_order_and_the_highest_version_is_remembered() {
        let r1 = rotation(5, Some((public(0x11), public(0x51))), None);
        let r2 = rotation(
            7,
            Some((public(0x51), public(0x52))),
            Some((public(0x22), public(0x53))),
        );
        let resolved = resolve(&state(vec![r1, r2]), &embedded()).unwrap();
        assert_eq!(resolved.keys.release, public(0x52));
        assert_eq!(resolved.keys.content, public(0x53));
        assert_eq!(resolved.applied_release_version, Some(7));
        assert!(resolved.release_rotated && resolved.content_rotated);
        assert_eq!(
            resolved.release_lineage,
            [public(0x11), public(0x51), public(0x52)]
        );
    }

    #[test]
    fn adopting_a_rotation_records_it_and_the_next_load_trusts_its_keys() {
        let mut record = state(vec![]);
        let r1 = rotation(5, Some((public(0x11), public(0x51))), None);
        let next = adopt(&mut record, &r1, Some(4)).unwrap();
        assert_eq!(next.release, public(0x51));
        assert_eq!(record.len(), 1);
        assert_eq!(
            resolve(&record, &embedded()).unwrap().keys.release,
            public(0x51)
        );
    }

    #[test]
    fn a_rotation_is_refused_when_it_is_not_newer_than_a_release_or_a_recorded_rotation() {
        let mut record = state(vec![]);
        let r1 = rotation(5, Some((public(0x11), public(0x51))), None);
        // The installed release is at 5: a rotation numbered 5 would be a rollback of the counter.
        assert!(matches!(
            adopt(&mut record, &r1, Some(5)),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 5,
                current: 5
            })
        ));
        assert!(record.is_empty(), "a refused rotation records nothing");
        adopt(&mut record, &r1, Some(4)).unwrap();
        let r2 = rotation(5, Some((public(0x51), public(0x52))), None);
        assert!(matches!(
            adopt(&mut record, &r2, None),
            Err(UpdaterError::ReleaseNotNewer { .. })
        ));
        // The same rotation again, whatever the installed release: refused.
        assert!(adopt(&mut record, &r1, None).is_err());
        assert_eq!(record.len(), 1);
    }

    #[test]
    fn a_rotation_that_does_not_verify_or_does_not_apply_is_not_recorded() {
        let mut record = state(vec![]);
        let mut forged = rotation(5, Some((public(0x11), public(0x51))), None);
        forged.sign(&pair(0x77));
        assert!(matches!(
            adopt(&mut record, &forged, None),
            Err(UpdaterError::SignatureInvalid)
        ));
        let foreign = rotation(5, Some((public(0x99), public(0x51))), None);
        assert!(matches!(
            adopt(&mut record, &foreign, None),
            Err(UpdaterError::RotationDoesNotApply { .. })
        ));
        assert!(record.is_empty());
    }

    #[test]
    fn a_build_without_a_complete_trust_set_adopts_nothing() {
        let mut record = state(vec![]);
        let r1 = rotation(5, Some((public(0x11), public(0x51))), None);
        for (embedded, recovery) in [
            (None, Some(recovery())),
            (Some(embedded()), None),
            (None, None),
        ] {
            assert!(matches!(
                record.adopt_with(&r1, embedded.as_ref(), recovery.as_ref(), None, NOW),
                Err(UpdaterError::SigningKeyUnprovisioned)
            ));
        }
    }

    #[test]
    fn a_record_older_than_the_embedded_keys_never_takes_a_role_backward() {
        // The record rotated K1 -> K2 -> K3; a newer build embeds K2, then one embeds K3.
        let r1 = rotation(5, Some((public(0x11), public(0x51))), None);
        let r2 = rotation(7, Some((public(0x51), public(0x52))), None);
        let record = state(vec![r1, r2]);
        for embedded_release in [public(0x11), public(0x51), public(0x52)] {
            let embedded = TrustedKeys {
                release: embedded_release,
                content: public(0x22),
            };
            let resolved = resolve(&record, &embedded).unwrap();
            assert_eq!(
                resolved.keys.release,
                public(0x52),
                "embedded {embedded_release:02x?} must end on the latest key"
            );
            assert_eq!(resolved.applied_release_version, Some(7));
        }
    }

    #[test]
    fn a_record_for_other_embedded_keys_is_refused_not_ignored() {
        let record = state(vec![rotation(5, Some((public(0x11), public(0x51))), None)]);
        let other = TrustedKeys {
            release: public(0x66),
            content: public(0x22),
        };
        assert!(matches!(
            resolve(&record, &other),
            Err(UpdaterError::TrustStateCorrupt { .. })
        ));
    }

    #[test]
    fn an_edited_or_reordered_record_is_refused() {
        let r1 = rotation(5, Some((public(0x11), public(0x51))), None);
        let r2 = rotation(7, Some((public(0x51), public(0x52))), None);
        // Reordered: version goes down.
        assert!(matches!(
            resolve(&state(vec![r2.clone(), r1.clone()]), &embedded()),
            Err(UpdaterError::TrustStateCorrupt { .. })
        ));
        // A key edited after signing.
        let mut edited = r1.clone();
        edited.new_release_key = Some(hex_encode(&public(0x99)));
        assert!(matches!(
            resolve(&state(vec![edited]), &embedded()),
            Err(UpdaterError::TrustStateCorrupt { .. })
        ));
        // The first rotation dropped: the second no longer leads from the embedded keys.
        assert!(matches!(
            resolve(&state(vec![r2]), &embedded()),
            Err(UpdaterError::TrustStateCorrupt { .. })
        ));
        // Signed by anything but recovery.
        let mut forged = r1;
        forged.sign(&pair(0x42));
        assert!(matches!(
            resolve(&state(vec![forged]), &embedded()),
            Err(UpdaterError::TrustStateCorrupt { .. })
        ));
    }

    #[test]
    fn a_rotation_that_expired_after_it_was_applied_still_replays() {
        // The window is checked when a rotation is adopted, not each time the record is read.
        let record = state(vec![rotation(5, Some((public(0x11), public(0x51))), None)]);
        assert!(resolve(&record, &embedded()).is_ok());
    }

    #[test]
    fn the_record_is_bounded() {
        // The limit is checked before the record is replayed, so any MAX_ROTATIONS entries do.
        let one = rotation(1, Some((public(0x11), public(0x51))), None);
        let mut record = state(vec![one; MAX_ROTATIONS]);
        let next = rotation(1000, Some((public(0x51), public(0x52))), None);
        assert!(matches!(
            record.adopt_with(&next, Some(&embedded()), Some(&recovery()), None, NOW),
            Err(UpdaterError::TrustStateFull(MAX_ROTATIONS))
        ));
        assert_eq!(record.len(), MAX_ROTATIONS);
    }

    #[test]
    fn a_missing_file_is_a_fresh_install_and_a_saved_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TRUST_STATE_FILE);
        assert!(TrustState::load(&path).unwrap().is_empty());

        let record = state(vec![rotation(5, Some((public(0x11), public(0x51))), None)]);
        record.save(dir.path(), &path).unwrap();
        assert_eq!(TrustState::load(&path).unwrap(), record);
    }

    #[test]
    fn a_file_that_exists_and_is_not_a_record_is_corrupt_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TRUST_STATE_FILE);
        for bad in [
            "",
            "{ not json",
            "[]",
            r#"{"schema_version":1,"rotations":[],"extra":1}"#,
            r#"{"schema_version":2,"rotations":[]}"#,
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(
                matches!(
                    TrustState::load(&path),
                    Err(UpdaterError::TrustStateCorrupt { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_roles_split_cannot_be_collapsed_by_the_record() {
        // Two valid rotations, each fine alone, that together put release on the content key.
        let r1 = rotation(5, None, Some((public(0x22), public(0x51))));
        let r2 = rotation(7, Some((public(0x11), public(0x51))), None);
        assert!(matches!(
            resolve(&state(vec![r1, r2]), &embedded()),
            Err(UpdaterError::TrustStateCorrupt { .. })
        ));
    }
}
