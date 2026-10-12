//! The refusal to act on a manifest the build cannot really verify (ADR-0015 Deferred,
//! ADR-0027): a build that trusts the public test key acts only on an explicit acknowledgement
//! (`--allow-test-key`, which exists only in a `test-key` build), and a build that embeds no
//! production key yet cannot verify anything, so it says so instead of failing at the
//! signature.

/// What a manifest is verified for, to word the refusal.
#[derive(Clone, Copy)]
pub(crate) enum Manifest {
    /// Only `apply-release` builds this, and that command is Linux-only.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Release,
    Content,
}

impl Manifest {
    fn consequence(self) -> &'static str {
        match self {
            Self::Release => "anyone who can serve the release routes could get code run as root",
            Self::Content => {
                "anyone who can serve the content routes could weaken detection with forged rules"
            }
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Release => "releases",
            Self::Content => "content",
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

/// [`ensure_key_trusted`] for this build's release key. Used by `apply-release`, which is
/// Linux-only (ADR-0015 Deferred).
///
/// # Errors
///
/// As [`ensure_key_trusted`].
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn ensure_release_key_trusted(allow_test_key: bool) -> anyhow::Result<()> {
    ensure_key_trusted(
        Manifest::Release,
        updater::key::SYNTHAEA_UPDATER_TEST_KEY,
        updater::key::RELEASE_PUBLIC_KEY.is_some(),
        allow_test_key,
    )
}

/// [`ensure_key_trusted`] for this build's content key.
///
/// # Errors
///
/// As [`ensure_key_trusted`].
pub(crate) fn ensure_content_key_trusted(allow_test_key: bool) -> anyhow::Result<()> {
    ensure_key_trusted(
        Manifest::Content,
        updater::key::SYNTHAEA_UPDATER_TEST_KEY,
        updater::key::CONTENT_PUBLIC_KEY.is_some(),
        allow_test_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_test_key_is_refused_without_the_acknowledgement() {
        for manifest in [Manifest::Release, Manifest::Content] {
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
