//! The refusal to act on a manifest the build cannot really verify (ADR-0015 Deferred,
//! ADR-0027): a build that trusts the public test key acts only on an explicit acknowledgement
//! (`--allow-test-key`, which exists only in a `test-key` build), and a build that embeds no
//! production key yet cannot verify anything, so it says so instead of failing at the
//! signature.

use std::path::{Path, PathBuf};

use updater::{
    key::{CONTENT_PUBLIC_KEY, RECOVERY_PUBLIC_KEY, RELEASE_PUBLIC_KEY, SYNTHAEA_UPDATER_TEST_KEY},
    trust_state::{TRUST_STATE_FILE, TrustState},
};

/// What a manifest is verified for, to word the refusal.
#[derive(Clone, Copy)]
pub(crate) enum Manifest {
    /// Only `apply-release` builds this, and that command is Linux-only.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Release,
    Content,
    /// A key rotation, verified against the `recovery` key.
    Rotation,
}

/// The keys this install trusts now (ADR-0027): the embedded ones, then the key rotations it
/// applied, replayed and re-verified from the record under the state directory
/// ([`updater::trust_state`]). Loaded where the verification happens, never cached across
/// commands, so a rotation applied by another process is in force at the next check.
// The release key, the shared counter and the lineage are read by `apply-release` and the
// integrity check, which are Linux-only (ADR-0015 Deferred).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Keys {
    /// Verifies binary release manifests; `None` when no `release` key is provisioned.
    pub(crate) release: Option<[u8; 32]>,
    /// Verifies content manifests; `None` when no `content` key is provisioned.
    pub(crate) content: Option<[u8; 32]>,
    /// The highest `release_version` of a rotation applied here: releases share its counter.
    pub(crate) applied_release_version: Option<u64>,
    /// Every `release` key this install has trusted, for re-checking a manifest that was
    /// promoted under an earlier one.
    pub(crate) release_lineage: Vec<[u8; 32]>,
    release_rotated: bool,
    content_rotated: bool,
}

/// Where the record of applied rotations lives for a given state directory.
pub(crate) fn record_path(state_dir: &Path) -> PathBuf {
    state_dir.join(TRUST_STATE_FILE)
}

/// The keys in force under `state_dir`. No record is a fresh install: the embedded keys.
///
/// # Errors
///
/// A record that exists and cannot be trusted ([`updater::UpdaterError::TrustStateCorrupt`]) or
/// read: refused rather than answered with the embedded keys, which may have been rotated away
/// from. The operator removes the file on purpose, knowing what that re-trusts.
pub(crate) fn load(state_dir: &Path) -> anyhow::Result<Keys> {
    let record = TrustState::load(&record_path(state_dir))?;
    if record.is_empty() {
        return Ok(Keys {
            release: *RELEASE_PUBLIC_KEY,
            content: *CONTENT_PUBLIC_KEY,
            applied_release_version: None,
            release_lineage: RELEASE_PUBLIC_KEY.iter().copied().collect(),
            release_rotated: false,
            content_rotated: false,
        });
    }
    let resolved = record.resolve()?;
    Ok(Keys {
        release: Some(resolved.keys.release),
        content: Some(resolved.keys.content),
        applied_release_version: resolved.applied_release_version,
        release_lineage: resolved.release_lineage,
        release_rotated: resolved.release_rotated,
        content_rotated: resolved.content_rotated,
    })
}

impl Manifest {
    fn consequence(self) -> &'static str {
        match self {
            Self::Release => "anyone who can serve the release routes could get code run as root",
            Self::Content => {
                "anyone who can serve the content routes could weaken detection with forged rules"
            }
            Self::Rotation => {
                "anyone who can serve the rotation route could replace the keys releases are \
                 verified against, and then get code run as root"
            }
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Release => "releases",
            Self::Content => "content",
            Self::Rotation => "key rotations",
        }
    }
}

/// Refuses to act when the embedded key is the public test key and `allow_test_key` is not
/// set, or when no key is embedded at all.
///
/// `test_key` is `updater::key::SYNTHAEA_UPDATER_TEST_KEY` and `provisioned` is whether the
/// key for this manifest exists, passed in so every state is testable.
///
/// # Errors
///
/// An error naming what is missing: the acknowledgement, or the production key.
pub(crate) fn ensure_key_trusted(
    manifest: Manifest,
    test_key: bool,
    provisioned: bool,
    allow_test_key: bool,
) -> anyhow::Result<()> {
    if !provisioned {
        anyhow::bail!(
            "this build embeds no production signing key for {} (ADR-0027: \
             crates/updater/keys is unprovisioned), so it cannot verify them; refusing",
            manifest.noun()
        );
    }
    if !test_key {
        return Ok(());
    }
    if !allow_test_key {
        let how = if cfg!(feature = "test-key") {
            "Pass --allow-test-key to acknowledge this in a lab (ADR-0015 Deferred)"
        } else {
            "This build has no --allow-test-key; rebuild the agent with its `test-key` feature \
             for a lab (ADR-0027)"
        };
        anyhow::bail!(
            "this build verifies {} against the public test key, so {}; refusing. {how}",
            manifest.noun(),
            manifest.consequence()
        );
    }
    eprintln!(
        "warning: --allow-test-key: {} are verified against the public test key; this is safe \
         only against a control plane you trust",
        manifest.noun()
    );
    Ok(())
}

/// [`ensure_key_trusted`] for the release key in force under `state_dir`. Used by
/// `apply-release`, which is Linux-only (ADR-0015 Deferred). Returns the keys it checked.
///
/// # Errors
///
/// As [`ensure_key_trusted`], or the record of rotations cannot be trusted ([`load`]).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn ensure_release_key_trusted(
    state_dir: &Path,
    allow_test_key: bool,
) -> anyhow::Result<Keys> {
    let keys = load(state_dir)?;
    ensure_key_trusted(
        Manifest::Release,
        SYNTHAEA_UPDATER_TEST_KEY && !keys.release_rotated,
        keys.release.is_some(),
        allow_test_key,
    )?;
    Ok(keys)
}

/// [`ensure_key_trusted`] for the content key in force under `state_dir`. Returns the keys it
/// checked.
///
/// # Errors
///
/// As [`ensure_key_trusted`], or the record of rotations cannot be trusted ([`load`]).
pub(crate) fn ensure_content_key_trusted(
    state_dir: &Path,
    allow_test_key: bool,
) -> anyhow::Result<Keys> {
    let keys = load(state_dir)?;
    ensure_key_trusted(
        Manifest::Content,
        SYNTHAEA_UPDATER_TEST_KEY && !keys.content_rotated,
        keys.content.is_some(),
        allow_test_key,
    )?;
    Ok(keys)
}

/// [`ensure_key_trusted`] for the `recovery` key, which signs key rotations. It is never
/// rotated, so it is the embedded one.
///
/// # Errors
///
/// As [`ensure_key_trusted`].
pub(crate) fn ensure_recovery_key_trusted(allow_test_key: bool) -> anyhow::Result<()> {
    ensure_key_trusted(
        Manifest::Rotation,
        SYNTHAEA_UPDATER_TEST_KEY,
        RECOVERY_PUBLIC_KEY.is_some(),
        allow_test_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_test_key_is_refused_without_the_acknowledgement() {
        for manifest in [Manifest::Release, Manifest::Content, Manifest::Rotation] {
            let err = ensure_key_trusted(manifest, true, true, false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("--allow-test-key"), "{err}");
            assert!(err.contains("public test key"), "{err}");
        }
    }

    #[test]
    fn the_acknowledgement_lets_a_test_key_build_proceed() {
        assert!(ensure_key_trusted(Manifest::Release, true, true, true).is_ok());
        assert!(ensure_key_trusted(Manifest::Content, true, true, true).is_ok());
    }

    #[test]
    fn a_production_key_needs_no_acknowledgement() {
        assert!(ensure_key_trusted(Manifest::Release, false, true, false).is_ok());
        assert!(ensure_key_trusted(Manifest::Content, false, true, true).is_ok());
    }

    #[test]
    fn a_build_without_a_production_key_refuses_even_with_the_acknowledgement() {
        for allow in [false, true] {
            let err = ensure_key_trusted(Manifest::Release, false, false, allow)
                .unwrap_err()
                .to_string();
            assert!(err.contains("no production signing key"), "{err}");
        }
    }

    #[test]
    fn a_content_refusal_names_what_a_forged_content_release_can_do() {
        let err = ensure_key_trusted(Manifest::Content, true, true, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("weaken detection"), "{err}");
    }
}
