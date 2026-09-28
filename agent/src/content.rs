//! Content-manifest fetch and verification (ADR-0016, issue #30/#73's real
//! blocker for detection-as-code ring deployment): the agent-side half of
//! "fetch a signed manifest for my ring, verify it, know what changed."
//!
//! Deliberately stops there. Downloading artifacts (`GET /api/content/artifact`,
//! already real server-side) and reloading rules/models into a running
//! `DetectionSink` are follow-up work — this is the smallest real, testable
//! slice that unblocks #73's own tracking doc, not the full content-distribution
//! pipeline ADR-0016 describes end to end.
//!
//! Composed here rather than in `crates/updater` because `updater` is a LEAF
//! crate and may not depend on `transport` (`tools/check-deps.py`) — see that
//! crate's module doc.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use updater::{ContentEntry, ContentManifest, UpdaterError};

/// What this agent has already applied for one ring — the local half of the
/// anti-rollback/dedup check. Persisted as plain JSON next to the agent's other
/// state (no signature: this is the agent's own record of its own state, not
/// something an adversary gains anything by forging locally — the same trust
/// boundary `updater::banlist` already accepts for its ban list).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ContentState {
    /// The highest `release_version` successfully applied, keyed by ring —
    /// per review (PR #509), a single shared counter would let an agent that
    /// is ever pointed at a different ring (a ring reassignment, or a
    /// mismatched manifest that predates the `plan` ring check) lock itself
    /// out of that ring's own real releases as "not newer than installed",
    /// even after the mismatch itself is caught. `None`/absent for a ring is
    /// day zero for it, same as `ReleaseManifest::check_release_version`'s
    /// `None` case.
    #[serde(default)]
    pub(crate) release_version: BTreeMap<String, u64>,
    /// path -> sha256 of every artifact currently applied.
    #[serde(default)]
    pub(crate) entries: BTreeMap<String, String>,
}

impl ContentState {
    /// Loads the persisted state from `path`. A missing file is a fresh
    /// install, not an error — same posture as `updater::banlist::BannedVersions::load`.
    pub(crate) fn load(path: &Path) -> Result<Self, std::io::Error> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// The last-applied `release_version` for `ring`, or `None` if this ring
    /// has never been applied.
    fn release_version_for(&self, ring: &str) -> Option<u64> {
        self.release_version.get(ring).copied()
    }
}

/// What a fetched manifest means for this agent, right now: whether it's
/// already fully applied, and if not, exactly which entries are missing or
/// stale.
#[derive(Debug, PartialEq)]
pub(crate) struct FetchPlan {
    pub(crate) release_version: u64,
    pub(crate) to_fetch: Vec<ContentEntry>,
}

/// Verifies `manifest` (signature + anti-rollback against `state`) and reports
/// which entries this agent still needs to fetch. Pure — no I/O, no network —
/// so it's unit-testable without a live server; `cmd_check_content_manifest`
/// is the thin composition that actually fetches and calls this.
///
/// # Errors
///
/// Propagates [`UpdaterError::SchemaVersionUnsupported`],
/// [`UpdaterError::SignatureInvalid`], [`UpdaterError::RingMismatch`] (checked
/// right after the signature — a valid signature only proves who signed the
/// manifest, not that it's the one for `ring`), or
/// [`UpdaterError::ReleaseNotNewer`] — the same checks a binary self-update
/// manifest gets, applied to content.
pub(crate) fn plan(
    manifest: &ContentManifest,
    ring: &str,
    state: &ContentState,
) -> Result<FetchPlan, UpdaterError> {
    manifest.verify_signature()?;
    manifest.check_ring(ring)?;
    manifest.check_release_version(state.release_version_for(ring))?;
    let to_fetch = manifest
        .entries_to_fetch(&state.entries)
        .into_iter()
        .cloned()
        .collect();
    Ok(FetchPlan {
        release_version: manifest.release_version,
        to_fetch,
    })
}

/// Fetches the content manifest for `ring` from `server`, verifies it, and
/// prints a report of what has changed — does not download artifacts or apply
/// anything (see module doc). `state_path` is where this agent's own
/// [`ContentState`] is read from; a fresh install with no file yet reports
/// every entry in the manifest as needing a fetch.
///
/// # Errors
///
/// Returns an error if the server is unreachable, the manifest fails
/// verification, or it is not newer than the last-applied release for this
/// ring (an operator re-running the check sees this as "up to date", not a
/// crash — see the caller's own message mapping, `commands::content` on the
/// CLI side).
pub(crate) fn cmd_check_content_manifest(
    server: &str,
    ring: &str,
    cert: Option<&Path>,
    key: Option<&Path>,
    state_path: &Path,
) -> anyhow::Result<()> {
    let mut config = transport::TransportConfig::new(server);
    if let (Some(cert), Some(key)) = (cert, key) {
        config = config.with_client_cert(PathBuf::from(cert), PathBuf::from(key));
    }
    let client = transport::TransportClient::new(config)?;
    let url = client.config().content_manifest_url(ring);
    let manifest: ContentManifest = client.get_json(&url)?;

    let state = ContentState::load(state_path)?;
    match plan(&manifest, ring, &state) {
        Ok(plan) => {
            println!(
                "ring {ring}: release {} available, {} entr{} to fetch",
                plan.release_version,
                plan.to_fetch.len(),
                if plan.to_fetch.len() == 1 { "y" } else { "ies" }
            );
            for entry in &plan.to_fetch {
                println!(
                    "  {} ({}, {} bytes, sha256={})",
                    entry.path, entry.content_type, entry.size, entry.sha256
                );
            }
        }
        Err(UpdaterError::ReleaseNotNewer { offered, current }) => {
            println!("ring {ring}: up to date (release {current}, server offers {offered})");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a manifest and signs it exactly the way `updater::content`'s own
    /// tests do (this crate can't call that module's private signing helper
    /// directly): canonical bytes with `signature` forced empty, 2-space-indent
    /// JSON, Ed25519 over that, hex-encoded. Then round-trips through JSON so
    /// tests exercise what a real fetch would actually deserialize.
    fn signed_manifest_json(release_version: u64, entries: Vec<ContentEntry>) -> ContentManifest {
        signed_manifest_json_for_ring("canary_0", release_version, entries)
    }

    fn signed_manifest_json_for_ring(
        ring: &str,
        release_version: u64,
        entries: Vec<ContentEntry>,
    ) -> ContentManifest {
        let mut m = ContentManifest {
            entries,
            release_version,
            released_at: "2026-09-23T16:00:00Z".to_string(),
            ring: ring.to_string(),
            schema_version: updater::content::CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        };
        let bytes = serde_json::to_vec_pretty(&m).unwrap();
        let sig = updater::key::test_key_pair().sign(&bytes);
        m.signature = updater::hash::hex_encode(sig.as_ref());
        serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap()
    }

    fn entry(path: &str) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: "a".repeat(64),
            size: 10,
            content_type: "rule".to_string(),
        }
    }

    #[test]
    fn a_fresh_install_needs_every_entry() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let state = ContentState::default();
        let result = plan(&manifest, "canary_0", &state).unwrap();
        assert_eq!(result.release_version, 1);
        assert_eq!(result.to_fetch.len(), 1);
    }

    #[test]
    fn an_already_applied_entry_is_not_refetched() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let mut state = ContentState::default();
        state
            .entries
            .insert("rules/a.sigma".to_string(), "a".repeat(64));
        let result = plan(&manifest, "canary_0", &state).unwrap();
        assert!(result.to_fetch.is_empty());
    }

    #[test]
    fn a_manifest_no_newer_than_the_applied_release_is_rejected() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let mut state = ContentState::default();
        state.release_version.insert("canary_0".to_string(), 1);
        assert!(matches!(
            plan(&manifest, "canary_0", &state),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 1,
                current: 1
            })
        ));
    }

    #[test]
    fn a_tampered_manifest_is_rejected_before_the_release_version_check() {
        let mut manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        manifest.entries.push(entry("rules/injected.sigma"));
        let state = ContentState::default();
        assert!(matches!(
            plan(&manifest, "canary_0", &state),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_correctly_signed_manifest_for_another_ring_is_rejected() {
        // Concrete attack this pins (PR #509 review): a prod agent requests
        // `prod` but is served (or a stale response cache/misrouted request
        // returns) a validly-signed `canary_0` manifest with a higher
        // release_version. Without a ring check this would verify and be
        // accepted, applying the least-vetted ring's content to a prod agent.
        let manifest = signed_manifest_json(99, vec![entry("rules/a.sigma")]);
        let state = ContentState::default();
        assert!(matches!(
            plan(&manifest, "prod", &state),
            Err(UpdaterError::RingMismatch { requested, found })
                if requested == "prod" && found == "canary_0"
        ));
    }

    #[test]
    fn anti_rollback_state_is_scoped_per_ring() {
        // A ring reassignment (or an agent that has fetched more than one
        // ring's manifest) must not have one ring's higher release_version
        // lock out another ring's own, independently-numbered releases.
        let mut state = ContentState::default();
        state.release_version.insert("canary_0".to_string(), 50);

        // release_version 10 for `prod` — lower than canary_0's 50, but prod
        // has never been applied in this state, so it must still pass.
        let prod_manifest = signed_manifest_json_for_ring("prod", 10, vec![entry("rules/a.sigma")]);

        let result = plan(&prod_manifest, "prod", &state).unwrap();
        assert_eq!(result.release_version, 10);
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("content-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn content_state_load_on_a_missing_file_is_a_fresh_default() {
        let dir = tmp("missing");
        let state = ContentState::load(&dir.join("does-not-exist.json")).unwrap();
        assert_eq!(state, ContentState::default());
    }

    #[test]
    fn content_state_round_trips_through_disk() {
        let dir = tmp("round-trip");
        let path = dir.join("content-state.json");
        let mut state = ContentState {
            release_version: BTreeMap::from([("canary_0".to_string(), 3)]),
            entries: BTreeMap::new(),
        };
        state
            .entries
            .insert("rules/a.sigma".to_string(), "a".repeat(64));
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();

        let loaded = ContentState::load(&path).unwrap();
        assert_eq!(loaded, state);
    }
}
