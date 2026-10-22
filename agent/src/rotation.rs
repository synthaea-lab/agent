//! `apply-key-rotation` (ADR-0027): fetch the key-rotation manifest the control plane offers (or
//! read one from a file), verify it against the embedded `recovery` key and the keys this install
//! trusts now, and record it under the state directory so every later `apply-release`,
//! `apply-content-manifest` and integrity pass verifies against the rotated keys.
//!
//! The embedded keys are compile-time statics and stay what they are: what is recorded is the
//! signed manifests, replayed and re-verified from the embedded keys on every load
//! ([`updater::trust_state`], which also says what happens when the record is absent, older than
//! the embedded keys or corrupt). Composed here rather than in `updater` because `updater` is a
//! LEAF crate and may not depend on `transport`.
//!
//! Server contract (the server side is a separate slice): `GET /api/release/key-rotation` → the
//! signed [`updater::KeyRotationManifest`] this agent should apply, or 404 when none is pending.
//! The agent does not trust the answer: the signature, the key state it retires, its window and
//! its `release_version` decide.

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use updater::{KeyRotationManifest, UpdaterError, trust_state::TrustState};

/// Where the manifest comes from.
pub(crate) enum Source<'a> {
    /// A file, for an offline or lab install.
    File(&'a Path),
    /// The control plane.
    Server(&'a crate::content::Endpoint),
}

/// What [`apply`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The rotation was recorded; these roles now verify against their new key.
    Applied {
        release_version: u64,
        roles: Vec<&'static str>,
    },
    /// The control plane has nothing pending.
    NothingPending,
    /// The rotation is not newer than what was applied (a replay, or already recorded).
    AlreadyApplied { offered: u64, current: u64 },
}

/// Subcommand `apply-key-rotation`.
///
/// # Errors
///
/// The key state or the manifest cannot be read, the rotation fails verification (nothing is
/// recorded), or the record cannot be written.
pub(crate) fn cmd_apply_key_rotation(
    source: &Source<'_>,
    state_dir: &Path,
    allow_test_key: bool,
) -> anyhow::Result<Outcome> {
    // Before any file or network work, as for `apply-release`.
    crate::trust::ensure_recovery_key_trusted(allow_test_key)?;
    let Some(rotation) = fetch(source)? else {
        println!("no key rotation pending");
        return Ok(Outcome::NothingPending);
    };
    let outcome = apply(&rotation, state_dir, installed_release(state_dir), now()?)?;
    match &outcome {
        Outcome::Applied {
            release_version,
            roles,
        } => println!(
            "applied key rotation {release_version}: {} verif{} against the new key from now on",
            roles.join(" and "),
            if roles.len() == 1 { "ies" } else { "y" }
        ),
        Outcome::AlreadyApplied { offered, current } => {
            println!("key rotation {offered} is not newer than {current}: nothing to do");
        }
        Outcome::NothingPending => {}
    }
    Ok(outcome)
}

fn fetch(source: &Source<'_>) -> anyhow::Result<Option<KeyRotationManifest>> {
    match source {
        Source::File(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            Ok(Some(
                serde_json::from_str(&text).context("not a key-rotation manifest")?,
            ))
        }
        Source::Server(endpoint) => {
            let client = crate::content::build_client(
                &endpoint.server,
                endpoint.cert.as_deref(),
                endpoint.key.as_deref(),
                endpoint.ca_cert.as_deref(),
            )?;
            match client.get_json(&client.config().key_rotation_url()) {
                Ok(rotation) => Ok(Some(rotation)),
                Err(transport::TransportError::ServerError { status: 404, .. }) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
    }
}

/// Verifies `rotation` against the keys in force under `state_dir` and records it. Nothing is
/// written unless every check passes; the record is replaced atomically.
///
/// # Errors
///
/// A record that cannot be trusted, a rotation that fails [`TrustState::adopt`] (other than not
/// being newer, which is [`Outcome::AlreadyApplied`]), or a failed write.
pub(crate) fn apply(
    rotation: &KeyRotationManifest,
    state_dir: &Path,
    installed_release: Option<u64>,
    now: u64,
) -> anyhow::Result<Outcome> {
    let path = crate::trust::record_path(state_dir);
    let mut record = TrustState::load(&path)?;
    match record.adopt(rotation, installed_release, now) {
        Ok(_) => {}
        Err(UpdaterError::ReleaseNotNewer { offered, current }) => {
            return Ok(Outcome::AlreadyApplied { offered, current });
        }
        Err(e) => return Err(e.into()),
    }
    record.save(state_dir, &path)?;
    let mut roles = Vec::new();
    if rotation.new_release_key.is_some() {
        roles.push("release");
    }
    if rotation.new_content_key.is_some() {
        roles.push("content");
    }
    Ok(Outcome::Applied {
        release_version: rotation.release_version,
        roles,
    })
}

/// The installed binary release: rotations share its counter. Linux only, like the layout.
fn installed_release(state_dir: &Path) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        updater::layout::Layout::new(state_dir).current_release_version()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state_dir;
        None
    }
}

fn now() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the clock is before 1970")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ring::signature::KeyPair as _;
    use updater::{
        hash::hex_encode,
        key::{CONTENT_PUBLIC_KEY, RELEASE_PUBLIC_KEY, test_key_pair, test_recovery_key_pair},
        rotation::ROTATION_SCHEMA_VERSION,
    };

    use super::*;

    const ISSUED: u64 = 1_760_000_000;
    const NOW: u64 = ISSUED + 60;

    fn new_key(seed: u8) -> [u8; 32] {
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
            .unwrap()
            .public_key()
            .as_ref()
            .try_into()
            .unwrap()
    }

    /// A rotation of `release` from the embedded test key to `new`.
    fn rotation(version: u64, retired: [u8; 32], new: [u8; 32]) -> KeyRotationManifest {
        let mut m = KeyRotationManifest {
            expires_at: ISSUED + 3600,
            issued_at: ISSUED,
            new_content_key: None,
            new_release_key: Some(hex_encode(&new)),
            reason: "test".into(),
            release_version: version,
            retired_content_key: None,
            retired_release_key: Some(hex_encode(&retired)),
            schema_version: ROTATION_SCHEMA_VERSION,
            signature: String::new(),
        };
        m.sign(&test_recovery_key_pair());
        m
    }

    fn embedded_release() -> [u8; 32] {
        RELEASE_PUBLIC_KEY.unwrap()
    }

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("agent-rotation-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_fresh_install_trusts_the_embedded_keys() {
        let state = dir("fresh");
        let keys = crate::trust::load(&state).unwrap();
        assert_eq!(keys.release, *RELEASE_PUBLIC_KEY);
        assert_eq!(keys.content, *CONTENT_PUBLIC_KEY);
        assert_eq!(keys.applied_release_version, None);
    }

    #[test]
    fn an_applied_rotation_survives_a_restart_and_moves_the_release_key() {
        let state = dir("survives");
        let outcome = apply(
            &rotation(5, embedded_release(), new_key(0x51)),
            &state,
            Some(4),
            NOW,
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Applied {
                release_version: 5,
                roles: vec!["release"]
            }
        );
        // A different process: nothing is cached, the record is read again.
        let keys = crate::trust::load(&state).unwrap();
        assert_eq!(keys.release, Some(new_key(0x51)));
        assert_eq!(
            keys.content, *CONTENT_PUBLIC_KEY,
            "the other role is untouched"
        );
        assert_eq!(keys.applied_release_version, Some(5));
        assert_eq!(keys.release_lineage, [embedded_release(), new_key(0x51)]);
    }

    #[test]
    fn after_a_rotation_the_old_release_key_no_longer_verifies_a_release_and_the_new_one_does() {
        let state = dir("verifies");
        apply(
            &rotation(5, embedded_release(), new_key(0x51)),
            &state,
            None,
            NOW,
        )
        .unwrap();
        let keys = crate::trust::load(&state).unwrap();

        let mut by_old = updater::ReleaseManifest::new(6, std::collections::BTreeMap::new());
        by_old.sign(&test_key_pair());
        assert!(matches!(
            by_old.verify_signature_with(keys.release.as_ref()),
            Err(UpdaterError::SignatureInvalid)
        ));

        let new_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x51; 32]).unwrap();
        let mut by_new = updater::ReleaseManifest::new(6, std::collections::BTreeMap::new());
        by_new.sign(&new_pair);
        assert!(by_new.verify_signature_with(keys.release.as_ref()).is_ok());
    }

    #[test]
    fn a_replayed_or_older_rotation_changes_nothing() {
        let state = dir("replay");
        let first = rotation(5, embedded_release(), new_key(0x51));
        apply(&first, &state, None, NOW).unwrap();
        let before = std::fs::read(crate::trust::record_path(&state)).unwrap();

        assert_eq!(
            apply(&first, &state, None, NOW).unwrap(),
            Outcome::AlreadyApplied {
                offered: 5,
                current: 5
            }
        );
        // Older number, even though it would otherwise apply to the original key state.
        let older = rotation(4, embedded_release(), new_key(0x52));
        assert!(matches!(
            apply(&older, &state, None, NOW).unwrap(),
            Outcome::AlreadyApplied {
                offered: 4,
                current: 5
            }
        ));
        assert_eq!(
            std::fs::read(crate::trust::record_path(&state)).unwrap(),
            before
        );
    }

    #[test]
    fn a_rotation_is_not_newer_than_the_installed_release_either() {
        let state = dir("shared-counter");
        assert!(matches!(
            apply(
                &rotation(5, embedded_release(), new_key(0x51)),
                &state,
                Some(5),
                NOW
            )
            .unwrap(),
            Outcome::AlreadyApplied {
                offered: 5,
                current: 5
            }
        ));
        assert!(!crate::trust::record_path(&state).exists());
    }

    #[test]
    fn a_forged_or_expired_rotation_records_nothing() {
        let state = dir("refused");
        let mut forged = rotation(5, embedded_release(), new_key(0x51));
        forged.sign(&test_key_pair());
        assert!(apply(&forged, &state, None, NOW).is_err());
        let expired = rotation(5, embedded_release(), new_key(0x51));
        assert!(apply(&expired, &state, None, ISSUED + 7200).is_err());
        assert!(!crate::trust::record_path(&state).exists());
    }

    #[test]
    fn a_corrupt_record_is_refused_and_a_deleted_one_is_a_fresh_install() {
        let state = dir("corrupt");
        apply(
            &rotation(5, embedded_release(), new_key(0x51)),
            &state,
            None,
            NOW,
        )
        .unwrap();
        let path = crate::trust::record_path(&state);

        std::fs::write(&path, b"{ truncated").unwrap();
        assert!(
            crate::trust::load(&state).is_err(),
            "never a silent fallback"
        );
        assert!(
            crate::trust::ensure_release_key_trusted(&state, true).is_err(),
            "apply-release refuses before touching the network"
        );
        assert!(crate::trust::ensure_content_key_trusted(&state, true).is_err());

        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            crate::trust::load(&state).unwrap().release,
            *RELEASE_PUBLIC_KEY,
            "an absent file is a fresh install; deleting it needs the state directory's owner"
        );
    }

    #[test]
    fn a_test_key_build_that_rotated_the_release_key_needs_no_acknowledgement_for_it() {
        let state = dir("ack");
        assert!(crate::trust::ensure_release_key_trusted(&state, false).is_err());
        apply(
            &rotation(5, embedded_release(), new_key(0x51)),
            &state,
            None,
            NOW,
        )
        .unwrap();
        assert!(crate::trust::ensure_release_key_trusted(&state, false).is_ok());
        assert!(
            crate::trust::ensure_content_key_trusted(&state, false).is_err(),
            "content still runs on the public test key"
        );
    }

    #[test]
    fn a_rotation_file_is_read_and_applied_through_the_command() {
        let state = dir("command");
        let file = state.join("rotation.json");
        std::fs::write(
            &file,
            serde_json::to_vec(&rotation(5, embedded_release(), new_key(0x51))).unwrap(),
        )
        .unwrap();
        // The real clock is past the test rotation's window: refused, nothing recorded.
        assert!(cmd_apply_key_rotation(&Source::File(&file), &state, true).is_err());
        assert!(!crate::trust::record_path(&state).exists());
        // Not a manifest at all.
        std::fs::write(&file, b"{}").unwrap();
        assert!(cmd_apply_key_rotation(&Source::File(&file), &state, true).is_err());
        // The public test recovery key needs the acknowledgement, like the other test keys.
        assert!(cmd_apply_key_rotation(&Source::File(&file), &state, false).is_err());
    }
}
