//! Signing a manifest file with the key the operator provides (a file or a token).

use anyhow::Context as _;
use updater::{ContentManifest, KeyRotationManifest, ReleaseManifest};

use crate::signer::{Signer, sign_checked};

/// Which manifest shape a file holds. Explicit on the command line: the two are
/// verified differently by the agent, and guessing from the content would let a
/// wrong file be signed without notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Kind {
    /// A binary release (`agent apply-release`, ADR-0015).
    Release,
    /// A content release for one ring (`agent apply-content-manifest`, ADR-0016).
    Content,
    /// A key rotation, signed by the offline `recovery` key only (ADR-0027).
    Rotation,
}

/// A signed manifest and whether the key embedded in this build of `updater`
/// accepts it.
pub(crate) struct Signed {
    /// The manifest, pretty-printed JSON with its signature filled in.
    pub(crate) json: String,
    /// What the agent will say about it if built with the same embedded key.
    pub(crate) accepted_by_embedded_key: bool,
    /// One line naming the manifest, for the operator.
    pub(crate) summary: String,
}

/// Signs `manifest_json` of `kind` with `signer`.
///
/// Refuses a manifest the agent would reject whatever its signature (unsafe entry
/// paths, an unsupported schema version): a valid signature only proves who signed
/// it, so signing such a file would only hide the problem until an agent refuses it.
///
/// # Errors
///
/// The text is not a manifest of `kind`, it fails the checks above, or the signer fails or
/// answers with a signature that does not verify under its own public key.
pub(crate) fn sign(kind: Kind, manifest_json: &str, signer: &dyn Signer) -> anyhow::Result<Signed> {
    match kind {
        Kind::Release => {
            let mut manifest: ReleaseManifest =
                serde_json::from_str(manifest_json).context("not a release manifest")?;
            manifest.validate_entry_paths()?;
            manifest.sign_with(|message| sign_checked(signer, message))?;
            Ok(Signed {
                accepted_by_embedded_key: manifest.verify_signature().is_ok(),
                summary: format!(
                    "release manifest v{} ({} entries)",
                    manifest.release_version,
                    manifest.entries.len()
                ),
                json: serde_json::to_string_pretty(&manifest)?,
            })
        }
        Kind::Content => {
            let mut manifest: ContentManifest =
                serde_json::from_str(manifest_json).context("not a content manifest")?;
            if let Some(entry) = manifest.entries.iter().find(|e| !e.is_safe_relative_path()) {
                anyhow::bail!(
                    "entry path {:?} is not safe to write under the content directory",
                    entry.path
                );
            }
            manifest.sign_with(|message| sign_checked(signer, message))?;
            Ok(Signed {
                accepted_by_embedded_key: manifest.verify_signature().is_ok(),
                summary: format!(
                    "content manifest v{} for ring {} ({} entries)",
                    manifest.release_version,
                    manifest.ring,
                    manifest.entries.len()
                ),
                json: serde_json::to_string_pretty(&manifest)?,
            })
        }
        Kind::Rotation => {
            let mut manifest: KeyRotationManifest =
                serde_json::from_str(manifest_json).context("not a key-rotation manifest")?;
            manifest.validate()?;
            manifest.sign_with(|message| sign_checked(signer, message))?;
            Ok(Signed {
                accepted_by_embedded_key: manifest.verify_signature().is_ok(),
                summary: format!(
                    "key rotation v{} ({}), valid until {}",
                    manifest.release_version,
                    rotated_roles(&manifest),
                    manifest.expires_at
                ),
                json: serde_json::to_string_pretty(&manifest)?,
            })
        }
    }
}

/// Which roles a rotation changes, for the operator.
fn rotated_roles(manifest: &KeyRotationManifest) -> String {
    let mut roles = Vec::new();
    if manifest.new_release_key.is_some() {
        roles.push("release");
    }
    if manifest.new_content_key.is_some() {
        roles.push("content");
    }
    roles.join(" and ")
}

#[cfg(test)]
mod tests {
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::signer::FileKey;

    const RELEASE: &str =
        r#"{"entries":{"agent":"00"},"release_version":3,"schema_version":1,"signature":""}"#;
    const CONTENT: &str = r#"{"entries":[{"path":"rules/sigma/linux/a.yml","type":"rule","sha256":"00","size":1}],"release_version":2,"released_at":"2026-10-01T00:00:00Z","ring":"canary_0","schema_version":1,"signature":""}"#;

    fn rotation_json() -> String {
        crate::rotation::build(crate::rotation::Request {
            release_version: 9,
            release: Some(("aa".repeat(32), "bb".repeat(32))),
            content: None,
            reason: "scheduled".into(),
            issued_at: 1_760_000_000,
            valid_for_secs: 7 * 24 * 3600,
        })
        .map(|m| serde_json::to_string(&m).unwrap())
        .unwrap()
    }

    fn recovery_key() -> FileKey {
        FileKey::new(updater::key::test_recovery_key_pair())
    }

    fn other_key() -> FileKey {
        FileKey::new(Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap())
    }

    fn test_key() -> FileKey {
        FileKey::new(updater::key::test_key_pair())
    }

    #[test]
    fn a_release_signed_with_the_embedded_key_verifies_and_one_signed_with_another_key_does_not() {
        let ours = sign(Kind::Release, RELEASE, &test_key()).unwrap();
        assert!(ours.accepted_by_embedded_key);
        let signed: ReleaseManifest = serde_json::from_str(&ours.json).unwrap();
        assert!(signed.verify_signature().is_ok());

        let theirs = sign(Kind::Release, RELEASE, &other_key()).unwrap();
        assert!(!theirs.accepted_by_embedded_key);
        assert_ne!(ours.json, theirs.json);
    }

    #[test]
    fn a_content_manifest_signs_and_verifies_the_same_way() {
        let signed = sign(Kind::Content, CONTENT, &test_key()).unwrap();
        assert!(signed.accepted_by_embedded_key);
        assert!(
            signed.summary.contains("ring canary_0"),
            "{}",
            signed.summary
        );
        assert!(
            !sign(Kind::Content, CONTENT, &other_key())
                .unwrap()
                .accepted_by_embedded_key
        );
    }

    #[test]
    fn a_manifest_the_agent_would_reject_is_not_signed() {
        let escaping = RELEASE.replace("\"agent\"", "\"../agent\"");
        let err = sign(Kind::Release, &escaping, &test_key())
            .err()
            .expect("an escaping path must be refused")
            .to_string();
        assert!(err.contains("../agent"), "{err}");

        let unsafe_content = CONTENT.replace("rules/sigma/linux/a.yml", "../a.yml");
        assert!(sign(Kind::Content, &unsafe_content, &test_key()).is_err());
    }

    #[test]
    fn the_wrong_kind_is_an_error_not_a_silent_signature() {
        assert!(sign(Kind::Release, CONTENT, &test_key()).is_err());
        assert!(sign(Kind::Content, RELEASE, &test_key()).is_err());
    }

    #[test]
    fn a_rotation_is_accepted_when_the_recovery_key_signs_it_and_not_when_release_does() {
        let by_recovery = sign(Kind::Rotation, &rotation_json(), &recovery_key()).unwrap();
        assert!(by_recovery.accepted_by_embedded_key);
        assert!(
            by_recovery.summary.contains("release"),
            "{}",
            by_recovery.summary
        );
        let signed: KeyRotationManifest = serde_json::from_str(&by_recovery.json).unwrap();
        assert!(signed.verify_signature().is_ok());

        // The release key signs it without complaint, and the agent will not take it.
        let by_release = sign(Kind::Rotation, &rotation_json(), &test_key()).unwrap();
        assert!(!by_release.accepted_by_embedded_key);
    }

    #[test]
    fn a_rotation_the_agent_would_reject_is_not_signed() {
        let one_key_for_both = rotation_json()
            .replace(
                "\"new_content_key\":null",
                &format!("\"new_content_key\":\"{}\"", "aa".repeat(32)),
            )
            .replace(
                "\"retired_content_key\":null",
                &format!("\"retired_content_key\":\"{}\"", "cc".repeat(32)),
            );
        assert!(sign(Kind::Rotation, &one_key_for_both, &recovery_key()).is_err());
        assert!(sign(Kind::Rotation, RELEASE, &recovery_key()).is_err());
        assert!(sign(Kind::Release, &rotation_json(), &recovery_key()).is_err());
    }
}
