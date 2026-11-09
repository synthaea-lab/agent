//! The corrective release that withdraws content (ADR-0032).
//!
//! An agent never goes to a lower release number, so content a later release added cannot be
//! taken off an agent that already applied it by serving it an older release. It is withdrawn
//! by a *newer* release that carries the earlier content again: the agent fetches what differs
//! and removes what the new manifest no longer lists. This builds that manifest from an earlier
//! one, unsigned: the operator signs it like any other (`release-tool sign --kind content`).

use anyhow::Context as _;
use updater::ContentManifest;

/// What a corrective release changes against the release the ring is on now.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Change {
    /// Paths the ring has now that the corrective release no longer lists: agents delete them.
    pub(crate) removed: Vec<String>,
    /// Paths both list with different bytes: the artifact store is keyed by content hash
    /// (#804), so the earlier bytes need nothing restored at any path — they are still under
    /// their own hash, wherever they were first uploaded, unless that hash predates #804 and
    /// the server was never migrated off the old path-keyed layout (see
    /// `docs/operations/content.md`).
    pub(crate) different_bytes: Vec<String>,
    /// Paths only the earlier release lists: agents fetch them again (their bytes must be in the
    /// store under their hash).
    pub(crate) brought_back: Vec<String>,
    pub(crate) unchanged: usize,
}

/// Compares the earlier release being restored with the release the ring is on now.
pub(crate) fn compare(earlier: &ContentManifest, current: &ContentManifest) -> Change {
    fn had<'a>(manifest: &'a ContentManifest, path: &str) -> Option<&'a updater::ContentEntry> {
        manifest.entries.iter().find(|entry| entry.path == path)
    }
    let mut change = Change::default();
    for entry in &current.entries {
        if had(earlier, &entry.path).is_none() {
            change.removed.push(entry.path.clone());
        }
    }
    for entry in &earlier.entries {
        match had(current, &entry.path) {
            None => change.brought_back.push(entry.path.clone()),
            Some(now) if now.sha256 != entry.sha256 => {
                change.different_bytes.push(entry.path.clone());
            }
            Some(_) => change.unchanged += 1,
        }
    }
    change.removed.sort();
    change.different_bytes.sort();
    change.brought_back.sort();
    change
}

/// Rebuilds `earlier_json` (a content manifest as it was published, signed) as the unsigned
/// release `release_version`, with the same ring and entries and the given `released_at`.
///
/// The earlier manifest's signature is **verified first** against the key this build embeds:
/// the offline signing step is the trust boundary, and a manifest taken from storage the
/// control plane holds (which can be altered) must not come out of it validly signed with
/// edited entries (review of #782).
///
/// # Errors
///
/// The text is not a content manifest, its signature does not verify (unsigned, edited after
/// signing, signed by another key, or this build embeds no key), it lists nothing,
/// `release_version` is not above the earlier one, or `released_at` is not a real UTC
/// timestamp of the form `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn roll_forward(
    earlier_json: &str,
    release_version: u64,
    released_at: &str,
) -> anyhow::Result<ContentManifest> {
    let mut manifest: ContentManifest =
        serde_json::from_str(earlier_json).context("not a content manifest")?;
    manifest.verify_signature().map_err(|error| {
        anyhow::anyhow!(
            "the earlier manifest's signature does not verify ({error}): only a manifest that \
             was signed with the key the agents embed can be restored; take it from the \
             release archive, not from a store that may have been altered"
        )
    })?;
    anyhow::ensure!(
        !manifest.entries.is_empty(),
        "the earlier manifest lists no entries: restoring it would leave agents with no content"
    );
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

/// `YYYY-MM-DDTHH:MM:SSZ` with real field values (month 1-12, day 1-31, hour below 24, minute
/// and second below 60): the shape every content manifest carries.
fn is_utc_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 20
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b'T',
            13 | 16 => *b == b':',
            19 => *b == b'Z',
            _ => b.is_ascii_digit(),
        });
    let field = |from: usize, to: usize| text[from..to].parse::<u32>().unwrap_or(u32::MAX);
    shaped
        && (1..=12).contains(&field(5, 7))
        && (1..=31).contains(&field(8, 10))
        && field(11, 13) < 24
        && field(14, 16) < 60
        && field(17, 19) < 60
}

#[cfg(test)]
mod tests {
    use updater::{ContentEntry, ContentManifest, key::test_key_pair};

    use super::*;
    use crate::sign::{Kind, sign};

    fn entry(path: &str, sha256: &str) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: sha256.to_string(),
            size: 1,
            content_type: "rule".to_string(),
        }
    }

    fn manifest(release_version: u64, entries: Vec<ContentEntry>) -> ContentManifest {
        ContentManifest {
            entries,
            release_version,
            released_at: "2026-10-01T00:00:00Z".to_string(),
            ring: "canary_0".to_string(),
            schema_version: updater::content::CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        }
    }

    /// An earlier release as it was published: signed with the key the agents embed.
    fn signed_v2() -> String {
        let mut v2 = manifest(2, vec![entry("rules/sigma/linux/a.yml", &"a".repeat(64))]);
        v2.sign(&test_key_pair());
        serde_json::to_string(&v2).unwrap()
    }

    #[test]
    fn the_corrective_release_carries_the_earlier_content_under_a_higher_number() {
        let corrective = roll_forward(&signed_v2(), 5, "2026-10-12T09:30:00Z").unwrap();
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
        let corrective = roll_forward(&signed_v2(), 5, "2026-10-12T09:30:00Z").unwrap();
        let signed = sign(
            Kind::Content,
            &serde_json::to_string(&corrective).unwrap(),
            &crate::signer::FileKey::new(test_key_pair()),
        )
        .unwrap();
        assert!(signed.accepted_by_embedded_key);
        assert!(signed.summary.contains("v5"), "{}", signed.summary);
    }

    #[test]
    fn an_earlier_manifest_that_was_never_signed_is_refused() {
        let unsigned =
            serde_json::to_string(&manifest(2, vec![entry("a.yml", &"a".repeat(64))])).unwrap();
        let error = roll_forward(&unsigned, 5, "2026-10-12T09:30:00Z").unwrap_err();
        assert!(error.to_string().contains("signature"), "{error}");
    }

    #[test]
    fn an_earlier_manifest_edited_after_it_was_signed_is_refused() {
        // From a tampered control-plane store: the offline signing step must not turn an
        // edited entry list into a validly signed release (review of #782).
        let mut tampered: ContentManifest = serde_json::from_str(&signed_v2()).unwrap();
        tampered.entries[0].sha256 = "b".repeat(64);
        let error = roll_forward(
            &serde_json::to_string(&tampered).unwrap(),
            5,
            "2026-10-12T09:30:00Z",
        )
        .unwrap_err();
        assert!(error.to_string().contains("signature"), "{error}");
        // And one signed by some other key.
        let mut foreign = manifest(2, vec![entry("a.yml", &"a".repeat(64))]);
        foreign.sign(&ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap());
        assert!(
            roll_forward(
                &serde_json::to_string(&foreign).unwrap(),
                5,
                "2026-10-12T09:30:00Z"
            )
            .is_err()
        );
    }

    #[test]
    fn an_earlier_manifest_that_lists_nothing_is_refused() {
        let mut empty = manifest(2, vec![]);
        empty.sign(&test_key_pair());
        let error = roll_forward(
            &serde_json::to_string(&empty).unwrap(),
            5,
            "2026-10-12T09:30:00Z",
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("no entries") || error.to_string().contains("lists nothing"),
            "{error}"
        );
    }

    #[test]
    fn a_number_that_is_not_above_the_restored_release_is_refused() {
        for version in [1, 2] {
            let error = roll_forward(&signed_v2(), version, "2026-10-12T09:30:00Z").unwrap_err();
            assert!(error.to_string().contains("numbered above"), "{error}");
        }
    }

    #[test]
    fn a_malformed_or_impossible_timestamp_or_manifest_is_refused() {
        for stamp in [
            "",
            "2026-10-12",
            "2026-10-12 09:30:00Z",
            "2026-10-12T09:30:00+02:00",
            "2026-99-99T99:99:99Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-10-32T00:00:00Z",
            "2026-10-12T24:00:00Z",
            "2026-10-12T09:60:00Z",
            "2026-10-12T09:30:61Z",
        ] {
            assert!(roll_forward(&signed_v2(), 5, stamp).is_err(), "{stamp:?}");
        }
        assert!(roll_forward("{}", 5, "2026-10-12T09:30:00Z").is_err());
        assert!(roll_forward(&signed_v2(), 5, "2026-12-31T23:59:59Z").is_ok());
    }

    #[test]
    fn the_comparison_names_what_would_be_removed_and_what_needs_its_bytes_back() {
        let earlier = manifest(
            2,
            vec![
                entry("rules/same.yml", &"1".repeat(64)),
                entry("rules/modified.yml", &"2".repeat(64)),
                entry("rules/dropped-by-v4.yml", &"3".repeat(64)),
            ],
        );
        let current = manifest(
            4,
            vec![
                entry("rules/same.yml", &"1".repeat(64)),
                entry("rules/modified.yml", &"9".repeat(64)),
                entry("rules/added-by-v4.yml", &"4".repeat(64)),
            ],
        );
        let change = compare(&earlier, &current);
        assert_eq!(change.removed, ["rules/added-by-v4.yml"]);
        assert_eq!(change.different_bytes, ["rules/modified.yml"]);
        assert_eq!(change.brought_back, ["rules/dropped-by-v4.yml"]);
        assert_eq!(change.unchanged, 1);
    }
}
