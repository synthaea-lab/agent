//! The key-rotation release (ADR-0027 decision 1): a signed manifest that names a replacement
//! `release` and/or `content` key and the key it retires, signed by the offline `recovery` key and
//! by nothing else. A manifest signed by `release` or `content` cannot change the trust set, which
//! is what lets a compromised `release` key be replaced without touching the endpoints by hand.
//!
//! The shape is the one ADR-0027 decision 5 chose over TUF's metadata: one signed payload, roles
//! by key, a root of trust (`recovery`) that can rotate the other two. Where it differs from TUF's
//! threshold and expiry rules, and why, is written in ADR-0027 ("The key-rotation release").
//!
//! Verification only, like [`crate::content`] and [`crate::snapshot`]: fetching the manifest,
//! remembering the rotated keys across restarts and feeding them to the verifiers is the agent
//! binary's job (`updater` is a LEAF crate, see [`crate`]). What is here is pure: the checks run
//! against the key state and the clock the caller passes, so every rule is tested without either.

use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    error::UpdaterError,
    hash::{hex_decode, hex_encode},
    key::RECOVERY_PUBLIC_KEY,
};

/// The only `schema_version` this build accepts, versioned independently of the other manifests.
pub const ROTATION_SCHEMA_VERSION: u32 = 1;

/// The longest a rotation may stay applicable after it is issued: 30 days. **Provisional**: long
/// enough for an offline fleet to come back and for the recovery holders to meet again, short
/// enough that a rotation held back by an attacker stops being applicable (the freeze case the
/// ADR compares with TUF's expiry). Calibrate with the first lab drill.
pub const MAX_VALIDITY_SECS: u64 = 30 * 24 * 60 * 60;

/// How far past "now" `issued_at` may be before the manifest is refused: a few minutes of clock
/// skew is normal, a manifest dated days ahead would outlive its window.
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 15 * 60;

/// The longest `reason`, in bytes: it is for the audit trail, not a place to put a document.
pub const MAX_REASON_BYTES: usize = 256;

/// The two keys a rotation can change: what an agent trusts to sign releases and content.
/// `recovery` is not in it: no rotation changes `recovery` (a lost one needs a reinstall,
/// ADR-0027 consequences).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedKeys {
    /// Verifies binary release manifests.
    pub release: [u8; 32],
    /// Verifies content manifests.
    pub content: [u8; 32],
}

/// A signed key-rotation manifest. Field order is alphabetical and fixed by declaration:
/// canonicalization depends on it, exactly like [`crate::ReleaseManifest`]. A role is rotated when
/// its `new_*_key` and `retired_*_key` are both present, and both must be, so the manifest always
/// says which key it replaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationManifest {
    /// Unix seconds after which the rotation is no longer applicable.
    pub expires_at: u64,
    /// Unix seconds when `recovery` signed it.
    pub issued_at: u64,
    /// Lowercase hex of the new `content` key, when `content` is rotated.
    pub new_content_key: Option<String>,
    /// Lowercase hex of the new `release` key, when `release` is rotated.
    pub new_release_key: Option<String>,
    /// Why, for the audit trail (`scheduled`, `suspected exposure of the release key`, ...).
    pub reason: String,
    /// Like any release (ADR-0015 decision 2): strictly greater than the highest release or
    /// rotation the agent applied, see [`Self::check_release_version`].
    pub release_version: u64,
    /// The `content` key this replaces: it must be the one the agent trusts now.
    pub retired_content_key: Option<String>,
    /// The `release` key this replaces: it must be the one the agent trusts now.
    pub retired_release_key: Option<String>,
    /// Must equal [`ROTATION_SCHEMA_VERSION`], checked before anything else.
    pub schema_version: u32,
    /// Lowercase-hex Ed25519 signature over [`Self::canonical_bytes`], computed with this field
    /// forced to `""`.
    pub signature: String,
}

impl KeyRotationManifest {
    /// The bytes signed and verified: 2-space-indented JSON, `signature` forced to `""`, fields
    /// in the alphabetical order of the struct.
    fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = Self {
            signature: String::new(),
            ..self.clone()
        };
        serde_json::to_vec_pretty(&unsigned)
            .expect("KeyRotationManifest has no non-serializable content")
    }

    /// Signs in place with `sign`, which receives the canonical bytes [`Self::verify_signature`]
    /// checks and returns the 64-byte Ed25519 signature over them: the `recovery` key never
    /// leaves its custody (a token, or the air-gapped machine of the ceremony), the caller only
    /// hands it bytes. `signature` is left empty if `sign` fails.
    ///
    /// # Errors
    ///
    /// Whatever `sign` returns.
    pub fn sign_with<E>(
        &mut self,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    ) -> Result<(), E> {
        self.signature.clear();
        let sig = sign(&self.canonical_bytes())?;
        self.signature = hex_encode(&sig);
        Ok(())
    }

    /// Signs in place with a key pair. For tests and the public test `recovery` key; production
    /// signs through [`Self::sign_with`].
    #[cfg(any(test, feature = "test-key"))]
    pub fn sign(&mut self, key_pair: &ring::signature::Ed25519KeyPair) {
        self.signature.clear();
        let sig = key_pair.sign(&self.canonical_bytes());
        self.signature = hex_encode(sig.as_ref());
    }

    fn release_change(&self) -> Result<RoleChange, UpdaterError> {
        role_change(
            &self.retired_release_key,
            &self.new_release_key,
            "the release key needs both a retired and a new key, or neither",
        )
    }

    fn content_change(&self) -> Result<RoleChange, UpdaterError> {
        role_change(
            &self.retired_content_key,
            &self.new_content_key,
            "the content key needs both a retired and a new key, or neither",
        )
    }

    /// The shape of the manifest, whatever its signature: the checks a signer runs before it
    /// signs and a verifier runs before it trusts a single field.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::SchemaVersionUnsupported`], or [`UpdaterError::RotationMalformed`] naming
    /// the first problem: no role rotated, a role with only half of its pair, a key that is not
    /// 64 lowercase hex characters or is all zeros, a key replaced by itself, the same new key for
    /// both roles, an empty or over-long reason, or a validity window that is empty or longer than
    /// [`MAX_VALIDITY_SECS`].
    pub fn validate(&self) -> Result<(), UpdaterError> {
        if self.schema_version != ROTATION_SCHEMA_VERSION {
            return Err(UpdaterError::SchemaVersionUnsupported {
                found: self.schema_version,
                expected: ROTATION_SCHEMA_VERSION,
            });
        }
        let release = self.release_change()?;
        let content = self.content_change()?;
        match (release, content) {
            (None, None) => return Err(malformed("it rotates no key")),
            (Some((_, new_release)), Some((_, new_content))) if new_release == new_content => {
                return Err(malformed(
                    "release and content would get the same key: the roles are split on purpose",
                ));
            }
            _ => {}
        }
        if self.reason.trim().is_empty() || self.reason.len() > MAX_REASON_BYTES {
            return Err(malformed(
                "the reason is empty or longer than MAX_REASON_BYTES",
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(malformed("it expires before it is issued"));
        }
        if self.expires_at - self.issued_at > MAX_VALIDITY_SECS {
            return Err(malformed(
                "its validity window is longer than MAX_VALIDITY_SECS",
            ));
        }
        Ok(())
    }

    /// Checks [`Self::validate`] and the Ed25519 signature against [`RECOVERY_PUBLIC_KEY`], the
    /// `recovery` key of the trust set. A manifest signed by `release` or `content` does not
    /// verify here.
    ///
    /// # Errors
    ///
    /// Everything [`Self::validate`] returns, [`UpdaterError::SigningKeyUnprovisioned`] when this
    /// build embeds no `recovery` key, or [`UpdaterError::SignatureInvalid`].
    pub fn verify_signature(&self) -> Result<(), UpdaterError> {
        self.verify_signature_with(RECOVERY_PUBLIC_KEY.as_ref())
    }

    fn verify_signature_with(&self, recovery: Option<&[u8; 32]>) -> Result<(), UpdaterError> {
        self.validate()?;
        let recovery = recovery.ok_or(UpdaterError::SigningKeyUnprovisioned)?;
        let signature = hex_decode(&self.signature).ok_or(UpdaterError::SignatureInvalid)?;
        UnparsedPublicKey::new(&signature::ED25519, recovery)
            .verify(&self.canonical_bytes(), &signature)
            .map_err(|_| UpdaterError::SignatureInvalid)
    }

    /// Anti-rollback (ADR-0015 decision 2, ADR-0027 decision 5): rejects a rotation whose
    /// `release_version` is not strictly greater than `current`. A rotation is a release like any
    /// other, so `current` is the greater of the installed release and the last rotation applied
    /// (`None`: neither exists), and the next release or rotation must go above this one.
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

    /// Whether the rotation is within its window at `now` (Unix seconds): not expired, and not
    /// issued further in the future than [`CLOCK_SKEW_TOLERANCE_SECS`].
    ///
    /// # Errors
    ///
    /// [`UpdaterError::RotationExpired`] or [`UpdaterError::RotationNotYetValid`].
    pub fn check_window(&self, now: u64) -> Result<(), UpdaterError> {
        if now >= self.expires_at {
            return Err(UpdaterError::RotationExpired {
                expires_at: self.expires_at,
                now,
            });
        }
        if self.issued_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(UpdaterError::RotationNotYetValid {
                issued_at: self.issued_at,
                now,
            });
        }
        Ok(())
    }

    /// Everything an agent checks before it adopts the rotation, in this order: shape, the
    /// `recovery` signature, the window, `release_version`, and that the keys it retires are the
    /// keys the agent trusts now. Returns the keys to trust from here on.
    ///
    /// The last check is what makes a rotation apply once and to one state: a replay finds the
    /// retired key already gone, and a manifest written for a fleet on an older key does not apply
    /// to a host that moved on (`recovery` signs one manifest per key state it needs to move).
    ///
    /// # Errors
    ///
    /// Everything [`Self::verify_signature`], [`Self::check_window`] and
    /// [`Self::check_release_version`] return, [`UpdaterError::RotationDoesNotApply`] when a
    /// retired key is not the trusted one, and [`UpdaterError::RotationMalformed`] when the result
    /// would leave `release` and `content` equal, or one of them equal to `recovery`.
    pub fn verify(
        &self,
        current: &TrustedKeys,
        applied_release_version: Option<u64>,
        now: u64,
    ) -> Result<TrustedKeys, UpdaterError> {
        self.verify_with(
            RECOVERY_PUBLIC_KEY.as_ref(),
            current,
            applied_release_version,
            now,
        )
    }

    fn verify_with(
        &self,
        recovery: Option<&[u8; 32]>,
        current: &TrustedKeys,
        applied_release_version: Option<u64>,
        now: u64,
    ) -> Result<TrustedKeys, UpdaterError> {
        self.verify_signature_with(recovery)?;
        self.check_window(now)?;
        self.check_release_version(applied_release_version)?;
        let mut next = *current;
        if let Some((retired, new)) = self.release_change()? {
            if retired != current.release {
                return Err(UpdaterError::RotationDoesNotApply { role: "release" });
            }
            next.release = new;
        }
        if let Some((retired, new)) = self.content_change()? {
            if retired != current.content {
                return Err(UpdaterError::RotationDoesNotApply { role: "content" });
            }
            next.content = new;
        }
        // `recovery` was checked present above.
        if recovery.is_some_and(|r| next.release == *r || next.content == *r) {
            return Err(malformed(
                "a rotated key is the recovery key: the offline key never signs routine releases",
            ));
        }
        if next.release == next.content {
            return Err(malformed(
                "the rotation would leave release and content on one key",
            ));
        }
        Ok(next)
    }
}

/// `(retired, new)` for a role, `None` when the role is not rotated.
type RoleChange = Option<([u8; 32], [u8; 32])>;

fn malformed(why: &'static str) -> UpdaterError {
    UpdaterError::RotationMalformed(why)
}

fn role_change(
    retired: &Option<String>,
    new: &Option<String>,
    half_a_pair: &'static str,
) -> Result<RoleChange, UpdaterError> {
    let (retired, new) = match (retired, new) {
        (None, None) => return Ok(None),
        (Some(retired), Some(new)) => (retired, new),
        _ => return Err(malformed(half_a_pair)),
    };
    let retired = parse_key(retired)?;
    let new = parse_key(new)?;
    if retired == new {
        return Err(malformed("a key cannot replace itself"));
    }
    Ok(Some((retired, new)))
}

/// 64 lowercase hex characters, not all zeros. Uppercase is refused so a key has one spelling
/// and a manifest one set of canonical bytes.
fn parse_key(text: &str) -> Result<[u8; 32], UpdaterError> {
    let key: [u8; 32] = hex_decode(text)
        .and_then(|bytes| bytes.try_into().ok())
        .filter(|_| text == text.to_ascii_lowercase())
        .ok_or_else(|| malformed("a key is not 64 lowercase hex characters"))?;
    if key == [0; 32] {
        return Err(malformed("a key is all zeros"));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;
    use crate::{
        key::{CONTENT_PUBLIC_KEY, RELEASE_PUBLIC_KEY, test_key_pair, test_recovery_key_pair},
        manifest::ReleaseManifest,
    };

    const ISSUED: u64 = 1_760_000_000;
    const NOW: u64 = ISSUED + 60;

    fn pair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn public_hex(seed: u8) -> String {
        hex_encode(pair(seed).public_key().as_ref())
    }

    /// The agent's state: the test `release` and `content` key (one key in the test set), made
    /// two distinct keys so rotating one of them is a legal move.
    fn current() -> TrustedKeys {
        TrustedKeys {
            release: [0x11; 32],
            content: [0x22; 32],
        }
    }

    fn unsigned() -> KeyRotationManifest {
        KeyRotationManifest {
            expires_at: ISSUED + 7 * 24 * 3600,
            issued_at: ISSUED,
            new_content_key: None,
            new_release_key: Some(public_hex(0x51)),
            reason: "scheduled".into(),
            release_version: 9,
            retired_content_key: None,
            retired_release_key: Some(hex_encode(&current().release)),
            schema_version: ROTATION_SCHEMA_VERSION,
            signature: String::new(),
        }
    }

    fn signed(mut m: KeyRotationManifest) -> KeyRotationManifest {
        m.sign(&test_recovery_key_pair());
        m
    }

    fn verify(m: &KeyRotationManifest) -> Result<TrustedKeys, UpdaterError> {
        m.verify(&current(), Some(8), NOW)
    }

    /// The file the golden test reads. Regenerate with `GOLDEN_REGENERATE=1 cargo test -p updater
    /// golden` after a deliberate change to the envelope, and bump `schema_version` with it.
    const GOLDEN_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/key-rotation-golden.json"
    );

    #[derive(Deserialize, Serialize)]
    struct Golden {
        recovery_public_key: String,
        current_release_key: String,
        current_content_key: String,
        applied_release_version: u64,
        now: u64,
        manifest: KeyRotationManifest,
    }

    fn golden_manifest() -> KeyRotationManifest {
        KeyRotationManifest {
            new_content_key: Some("ab".repeat(32)),
            retired_content_key: Some(hex_encode(&current().content)),
            reason: "suspected exposure of the release key".into(),
            ..unsigned()
        }
    }

    #[test]
    fn the_golden_fixture_verifies_and_resigning_it_gives_the_same_signature() {
        let recovery = hex_encode(test_recovery_key_pair().public_key().as_ref());
        if std::env::var_os("GOLDEN_REGENERATE").is_some() {
            let golden = Golden {
                recovery_public_key: recovery.clone(),
                current_release_key: hex_encode(&current().release),
                current_content_key: hex_encode(&current().content),
                applied_release_version: 8,
                now: NOW,
                manifest: signed(golden_manifest()),
            };
            std::fs::write(
                GOLDEN_PATH,
                format!("{}\n", serde_json::to_string_pretty(&golden).unwrap()),
            )
            .unwrap();
        }
        let golden: Golden =
            serde_json::from_str(&std::fs::read_to_string(GOLDEN_PATH).unwrap()).unwrap();
        assert_eq!(
            golden.recovery_public_key, recovery,
            "the fixture is signed by the test recovery key"
        );
        let state = TrustedKeys {
            release: hex_decode(&golden.current_release_key)
                .unwrap()
                .try_into()
                .unwrap(),
            content: hex_decode(&golden.current_content_key)
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let next = golden
            .manifest
            .verify(&state, Some(golden.applied_release_version), golden.now)
            .unwrap();
        assert_eq!(hex_encode(&next.release), public_hex(0x51));
        assert_eq!(hex_encode(&next.content), "ab".repeat(32));

        // Ed25519 is deterministic: the same canonical bytes under the same key give the same
        // signature, so any drift in the canonical form (field order, indentation, `null` for an
        // absent key) fails here instead of in a fleet.
        assert_eq!(signed(golden.manifest.clone()), golden.manifest);
    }

    #[test]
    fn the_golden_canonical_form_is_pinned_in_text() {
        let text = String::from_utf8(golden_manifest().canonical_bytes()).unwrap();
        let fields: Vec<&str> = text
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix('"'))
            .filter_map(|l| l.split('"').next())
            .collect();
        assert_eq!(
            fields,
            [
                "expires_at",
                "issued_at",
                "new_content_key",
                "new_release_key",
                "reason",
                "release_version",
                "retired_content_key",
                "retired_release_key",
                "schema_version",
                "signature",
            ]
        );
        assert!(text.contains("\n  \"expires_at\": "), "2-space indent");
        assert!(text.ends_with("\"signature\": \"\"\n}"));
    }

    #[test]
    fn a_rotation_signed_by_recovery_replaces_the_named_release_key() {
        let next = verify(&signed(unsigned())).unwrap();
        assert_eq!(hex_encode(&next.release), public_hex(0x51));
        assert_eq!(
            next.content,
            current().content,
            "the other role is untouched"
        );
    }

    #[test]
    fn a_rotation_can_replace_both_keys_at_once() {
        let m = signed(KeyRotationManifest {
            new_content_key: Some(public_hex(0x52)),
            retired_content_key: Some(hex_encode(&current().content)),
            ..unsigned()
        });
        let next = verify(&m).unwrap();
        assert_eq!(hex_encode(&next.release), public_hex(0x51));
        assert_eq!(hex_encode(&next.content), public_hex(0x52));
    }

    #[test]
    fn only_the_recovery_key_can_rotate_the_trust_set() {
        // The `release` key, the `content` key (the same key in the test set), a stranger.
        for signer in [test_key_pair(), pair(0x77)] {
            let mut m = unsigned();
            m.sign(&signer);
            assert!(
                matches!(verify(&m), Err(UpdaterError::SignatureInvalid)),
                "a manifest signed by a non-recovery key must not rotate anything"
            );
        }
    }

    #[test]
    fn a_rotation_does_not_verify_as_a_release_manifest_and_a_release_does_not_verify_as_a_rotation()
     {
        // The recovery key's signature covers rotation bytes only; and the release signature of
        // a real release manifest is not a rotation signature.
        let mut release = ReleaseManifest::new(9, std::collections::BTreeMap::new());
        release.sign(&test_recovery_key_pair());
        assert!(matches!(
            release.verify_signature(),
            Err(UpdaterError::SignatureInvalid)
        ));
        let rotation = signed(unsigned());
        let as_json = serde_json::to_string(&rotation).unwrap();
        assert!(serde_json::from_str::<ReleaseManifest>(&as_json).is_err());
        let release_json = serde_json::to_string(&release).unwrap();
        assert!(serde_json::from_str::<KeyRotationManifest>(&release_json).is_err());
    }

    #[test]
    fn a_field_changed_after_signing_does_not_verify() {
        let good = signed(unsigned());
        type Change = fn(&mut KeyRotationManifest);
        let changes: [Change; 8] = [
            |m| m.expires_at += 1,
            |m| m.issued_at += 1,
            |m| m.new_release_key = Some("cd".repeat(32)),
            |m| m.new_content_key = Some("cd".repeat(32)),
            |m| m.reason = "other".into(),
            |m| m.release_version += 1,
            |m| m.retired_release_key = Some("cd".repeat(32)),
            |m| m.retired_content_key = Some("cd".repeat(32)),
        ];
        for change in changes {
            let mut m = good.clone();
            change(&mut m);
            let outcome = verify(&m);
            assert!(
                matches!(
                    outcome,
                    Err(UpdaterError::SignatureInvalid | UpdaterError::RotationMalformed(_))
                ),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn a_malformed_or_missing_signature_does_not_verify() {
        for bad in ["", "zz", &"ab".repeat(63)] {
            let mut m = signed(unsigned());
            m.signature = bad.into();
            assert!(matches!(verify(&m), Err(UpdaterError::SignatureInvalid)));
        }
    }

    #[test]
    fn a_build_without_a_recovery_key_verifies_nothing() {
        let m = signed(unsigned());
        assert!(matches!(
            m.verify_with(None, &current(), Some(8), NOW),
            Err(UpdaterError::SigningKeyUnprovisioned)
        ));
    }

    #[test]
    fn an_unknown_schema_version_is_refused_before_anything_else() {
        let mut m = signed(unsigned());
        m.schema_version += 1;
        assert!(matches!(
            verify(&m),
            Err(UpdaterError::SchemaVersionUnsupported { .. })
        ));
    }

    #[test]
    fn an_unknown_field_is_refused_when_parsing() {
        let mut value = serde_json::to_value(signed(unsigned())).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<KeyRotationManifest>(value).is_err());
    }

    #[test]
    fn a_rotation_is_a_release_and_must_be_newer_than_what_was_applied() {
        let m = signed(unsigned());
        assert!(m.verify(&current(), Some(8), NOW).is_ok());
        assert!(m.verify(&current(), None, NOW).is_ok());
        for applied in [9, 10] {
            assert!(matches!(
                m.verify(&current(), Some(applied), NOW),
                Err(UpdaterError::ReleaseNotNewer { offered: 9, current }) if current == applied
            ));
        }
    }

    #[test]
    fn a_rotation_applies_once_a_replay_finds_its_retired_key_gone() {
        let m = signed(unsigned());
        let after = verify(&m).unwrap();
        // Same manifest, the agent's state moved on. (`release_version` would refuse it too,
        // this checks the second, independent guard.)
        assert!(matches!(
            m.verify(&after, Some(8), NOW),
            Err(UpdaterError::RotationDoesNotApply { role: "release" })
        ));
    }

    #[test]
    fn a_rotation_written_for_another_key_state_does_not_apply() {
        let m = signed(KeyRotationManifest {
            retired_release_key: Some("cd".repeat(32)),
            ..unsigned()
        });
        assert!(matches!(
            verify(&m),
            Err(UpdaterError::RotationDoesNotApply { role: "release" })
        ));
        let m = signed(KeyRotationManifest {
            new_content_key: Some(public_hex(0x52)),
            retired_content_key: Some("cd".repeat(32)),
            ..unsigned()
        });
        assert!(matches!(
            verify(&m),
            Err(UpdaterError::RotationDoesNotApply { role: "content" })
        ));
    }

    #[test]
    fn an_expired_rotation_is_refused_and_so_is_one_issued_in_the_future() {
        let m = signed(unsigned());
        assert!(m.check_window(m.expires_at - 1).is_ok());
        for now in [m.expires_at, m.expires_at + 1] {
            assert!(matches!(
                m.check_window(now),
                Err(UpdaterError::RotationExpired { .. })
            ));
        }
        assert!(m.check_window(ISSUED - CLOCK_SKEW_TOLERANCE_SECS).is_ok());
        assert!(matches!(
            m.check_window(ISSUED - CLOCK_SKEW_TOLERANCE_SECS - 1),
            Err(UpdaterError::RotationNotYetValid { .. })
        ));
        assert!(matches!(
            m.verify(&current(), Some(8), m.expires_at),
            Err(UpdaterError::RotationExpired { .. })
        ));
    }

    #[test]
    fn a_validity_window_that_is_empty_or_too_long_is_malformed() {
        for (issued, expires) in [
            (ISSUED, ISSUED),
            (ISSUED, ISSUED - 1),
            (ISSUED, ISSUED + MAX_VALIDITY_SECS + 1),
        ] {
            let m = signed(KeyRotationManifest {
                issued_at: issued,
                expires_at: expires,
                ..unsigned()
            });
            assert!(matches!(
                verify(&m),
                Err(UpdaterError::RotationMalformed(_))
            ));
        }
        let longest = KeyRotationManifest {
            expires_at: ISSUED + MAX_VALIDITY_SECS,
            ..unsigned()
        };
        assert!(verify(&signed(longest)).is_ok());
    }

    #[test]
    fn a_manifest_that_names_no_key_or_half_a_pair_is_malformed() {
        type Change = fn(&mut KeyRotationManifest);
        let changes: [Change; 4] = [
            |m| {
                m.new_release_key = None;
                m.retired_release_key = None;
            },
            |m| m.retired_release_key = None,
            |m| m.new_release_key = None,
            |m| m.new_content_key = Some(public_hex(0x52)),
        ];
        for change in changes {
            let mut m = unsigned();
            change(&mut m);
            assert!(matches!(
                signed(m).validate(),
                Err(UpdaterError::RotationMalformed(_))
            ));
        }
    }

    #[test]
    fn a_key_that_is_not_one_canonical_hex_key_is_malformed() {
        let upper = public_hex(0x51).to_ascii_uppercase();
        for bad in [
            "",
            "unprovisioned",
            &public_hex(0x51)[..62],
            &format!("{}00", public_hex(0x51)),
            &upper,
            &"00".repeat(32),
        ] {
            let m = signed(KeyRotationManifest {
                new_release_key: Some(bad.to_owned()),
                ..unsigned()
            });
            assert!(
                matches!(verify(&m), Err(UpdaterError::RotationMalformed(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_key_cannot_replace_itself_and_two_roles_cannot_share_the_new_key() {
        let same = signed(KeyRotationManifest {
            new_release_key: unsigned().retired_release_key,
            ..unsigned()
        });
        assert!(matches!(
            verify(&same),
            Err(UpdaterError::RotationMalformed(_))
        ));
        let shared = signed(KeyRotationManifest {
            new_content_key: unsigned().new_release_key,
            retired_content_key: Some(hex_encode(&current().content)),
            ..unsigned()
        });
        assert!(matches!(
            verify(&shared),
            Err(UpdaterError::RotationMalformed(_))
        ));
    }

    #[test]
    fn a_rotation_cannot_collapse_the_roles_or_hand_a_role_to_recovery() {
        // release's new key is the content key in force: the split would be gone.
        let collapse = signed(KeyRotationManifest {
            new_release_key: Some(hex_encode(&current().content)),
            ..unsigned()
        });
        assert!(matches!(
            verify(&collapse),
            Err(UpdaterError::RotationMalformed(_))
        ));
        // The offline key must not become a routine signing key.
        let recovery = hex_encode(test_recovery_key_pair().public_key().as_ref());
        let to_recovery = signed(KeyRotationManifest {
            new_release_key: Some(recovery),
            ..unsigned()
        });
        assert!(matches!(
            verify(&to_recovery),
            Err(UpdaterError::RotationMalformed(_))
        ));
    }

    #[test]
    fn an_empty_or_over_long_reason_is_malformed() {
        for reason in [String::new(), "  ".into(), "x".repeat(MAX_REASON_BYTES + 1)] {
            let m = signed(KeyRotationManifest {
                reason,
                ..unsigned()
            });
            assert!(matches!(
                verify(&m),
                Err(UpdaterError::RotationMalformed(_))
            ));
        }
        let limit = signed(KeyRotationManifest {
            reason: "x".repeat(MAX_REASON_BYTES),
            ..unsigned()
        });
        assert!(verify(&limit).is_ok());
    }

    #[test]
    fn the_embedded_test_set_is_a_state_a_rotation_can_start_from() {
        // In the test set `release` and `content` are one key: a rotation of one of them is legal
        // (it leaves them different), a rotation of both to one key is not.
        let (release, content) = (
            (*RELEASE_PUBLIC_KEY).unwrap(),
            (*CONTENT_PUBLIC_KEY).unwrap(),
        );
        let state = TrustedKeys { release, content };
        let m = signed(KeyRotationManifest {
            retired_release_key: Some(hex_encode(&release)),
            ..unsigned()
        });
        let next = m.verify(&state, None, NOW).unwrap();
        assert_ne!(next.release, next.content);
    }

    #[test]
    fn signing_through_a_closure_gives_the_signature_sign_gives_and_a_failure_leaves_none() {
        let direct = signed(unsigned());
        let key = test_recovery_key_pair();
        let mut through = unsigned();
        through.signature = "stale".into();
        through
            .sign_with(|message| Ok::<_, ()>(key.sign(message).as_ref().to_vec()))
            .unwrap();
        assert_eq!(through, direct);

        let mut refused = unsigned();
        assert!(refused.sign_with(|_| Err("token removed")).is_err());
        assert!(refused.signature.is_empty());
    }
}
