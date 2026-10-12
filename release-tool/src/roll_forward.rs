//! The corrective release that withdraws content (ADR-0032).
//!
//! An agent never goes to a lower release number, so content a later release added cannot be
//! taken off an agent that already applied it by serving it an older release. It is withdrawn
//! by a *newer* release that carries the earlier content again: the agent fetches what differs
//! and removes what the new manifest no longer lists. This builds that manifest from an earlier
//! one, unsigned: the operator signs it like any other (`release-tool sign --kind content`).

use anyhow::Context as _;
use updater::ContentManifest;

/// Rebuilds `earlier_json` (a content manifest, signed or not) as the unsigned release
/// `release_version`, with the same ring and entries and the given `released_at`.
///
/// # Errors
///
/// The text is not a content manifest, `release_version` is not above the earlier one, or
/// `released_at` is not a UTC timestamp of the form `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn roll_forward(
    earlier_json: &str,
    release_version: u64,
    released_at: &str,
) -> anyhow::Result<ContentManifest> {
    let mut manifest: ContentManifest =
        serde_json::from_str(earlier_json).context("not a content manifest")?;
    anyhow::ensure!(
        release_version > manifest.release_version,
        "the corrective release must be numbered above the release it restores (v{}); and above \
         every release of the ring so far, which this tool cannot know: check the control plane",
        manifest.release_version
    );
    anyhow::ensure!(
        is_utc_timestamp(released_at),
        "--released-at must be a UTC timestamp like 2026-10-12T09:30:00Z, got {released_at:?}"
    );
    manifest.release_version = release_version;
    released_at.clone_into(&mut manifest.released_at);
    manifest.signature.clear();
    Ok(manifest)
}

/// `YYYY-MM-DDTHH:MM:SSZ`: the shape every content manifest carries.
fn is_utc_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 20
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b'T',
            13 | 16 => *b == b':',
            19 => *b == b'Z',
            _ => b.is_ascii_digit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{Kind, sign};

    const V2: &str = r#"{"entries":[{"path":"rules/sigma/linux/a.yml","type":"rule","sha256":"00","size":1}],"release_version":2,"released_at":"2026-10-01T00:00:00Z","ring":"canary_0","schema_version":1,"signature":"deadbeef"}"#;

    #[test]
    fn the_corrective_release_carries_the_earlier_content_under_a_higher_number() {
        let corrective = roll_forward(V2, 5, "2026-10-12T09:30:00Z").unwrap();
        assert_eq!(corrective.release_version, 5);
        assert_eq!(corrective.released_at, "2026-10-12T09:30:00Z");
        assert_eq!(corrective.ring, "canary_0");
        assert_eq!(corrective.entries.len(), 1);
        assert_eq!(corrective.entries[0].path, "rules/sigma/linux/a.yml");
        assert!(
            corrective.signature.is_empty(),
            "the old signature must not survive"
        );
    }

    #[test]
    fn it_signs_and_the_agent_would_accept_it() {
        let corrective = roll_forward(V2, 5, "2026-10-12T09:30:00Z").unwrap();
        let signed = sign(
            Kind::Content,
            &serde_json::to_string(&corrective).unwrap(),
            &updater::key::test_key_pair(),
        )
        .unwrap();
        assert!(signed.accepted_by_embedded_key);
        assert!(signed.summary.contains("v5"), "{}", signed.summary);
    }

    #[test]
    fn a_number_that_is_not_above_the_restored_release_is_refused() {
        for version in [1, 2] {
            let err = roll_forward(V2, version, "2026-10-12T09:30:00Z").unwrap_err();
            assert!(err.to_string().contains("numbered above"), "{err}");
        }
    }

    #[test]
    fn a_malformed_timestamp_or_manifest_is_refused() {
        for stamp in [
            "",
            "2026-10-12",
            "2026-10-12 09:30:00Z",
            "2026-10-12T09:30:00+02:00",
        ] {
            assert!(roll_forward(V2, 5, stamp).is_err(), "{stamp:?}");
        }
        assert!(roll_forward("{}", 5, "2026-10-12T09:30:00Z").is_err());
    }
}
