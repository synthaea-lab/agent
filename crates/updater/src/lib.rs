//! # updater
//!
//! The update client: self-update of the agent binaries (staged, verified, with
//! rollback) and download/verification of detection content and ML models via canary
//! rings. Must keep working when everything else is degraded — an agent that cannot
//! update is an agent an attacker gets to keep.
//!
//! This first slice implements ADR-0015's Linux-first scope: binary self-update —
//! manifest signing/verification ([`manifest`]), the `bootstrap`/`current`/`versions`
//! layout and its atomic symlink swap (`layout`, Linux-only), and the local ban
//! list ([`banlist`]) that `rollback` (Linux-only) reads and writes. Content
//! distribution (rules/models via canary rings, issues #73/#49) and Windows/macOS
//! binary self-update are out of scope — see the ADR's Deferred section.
//!
//! Deliberately library-only: wiring this into `agent`/`watchdog` (heartbeat
//! registration via `tamper::heartbeat::SilenceMonitor`, supervised restart,
//! download transport) is the `agent` binary's job, not this crate's — `updater` is
//! a LEAF crate and may not depend on `tamper` or `transport`
//! (`tools/check-deps.py`); only a binary may compose all three.

pub mod banlist;
pub mod error;
pub mod hash;
pub mod key;
#[cfg(target_os = "linux")]
pub mod layout;
pub mod manifest;

pub use error::UpdaterError;
pub use manifest::ReleaseManifest;

/// Rolls back from a release that failed its health check (ADR-0015 Decision 6):
/// repoints `current` at `previous` (or `bootstrap` if `previous` is `None` — the
/// very first release after `bootstrap` failed), then bans `failed` so it is
/// refused even if offered again.
///
/// # Errors
///
/// Propagates [`UpdaterError::Io`] from the symlink swap or the ban-list write.
/// The symlink swap runs first: if the ban-list write then fails, `current` has
/// already moved off the failed release — the higher-priority half of rollback —
/// even though the anti-repeat guard did not get recorded that time.
#[cfg(target_os = "linux")]
pub fn rollback(
    layout: &layout::Layout,
    ban_list_path: &std::path::Path,
    previous: Option<u64>,
    failed: u64,
) -> Result<(), UpdaterError> {
    match previous {
        Some(release_version) => layout.promote(release_version)?,
        None => layout.reset_to_bootstrap()?,
    }
    let mut banned = banlist::BannedVersions::load(ban_list_path)?;
    banned.ban(failed);
    banned.save(ban_list_path)
}

#[cfg(all(test, target_os = "linux"))]
mod integration_tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use crate::{
        UpdaterError, hash::hash_file, key::test_key_pair, layout::Layout,
        manifest::ReleaseManifest, rollback,
    };

    /// End-to-end happy path: sign a manifest, stage a release, verify it,
    /// promote it, then roll it back and confirm the failed version is banned
    /// and refused on a second offer — the full ADR-0015 Decision 2/5/6 chain in
    /// one test, not just its parts in isolation.
    #[test]
    fn sign_stage_verify_promote_then_rollback_and_ban() {
        let base = tempfile::tempdir().unwrap();
        let layout = Layout::new(base.path());
        fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();

        // Stage release 1 and promote it as the known-good "previous" release.
        let release_1_dir = layout.version_dir(1);
        fs::create_dir_all(&release_1_dir).unwrap();
        fs::write(release_1_dir.join("agent"), b"release 1 binary").unwrap();
        layout.promote(1).unwrap();

        // Stage release 2: signed manifest, per-file hash verification, promote.
        let release_2_dir = layout.version_dir(2);
        fs::create_dir_all(&release_2_dir).unwrap();
        fs::write(release_2_dir.join("agent"), b"release 2 binary").unwrap();
        let hash = hash_file(&release_2_dir.join("agent")).unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("agent"), hash);
        let mut manifest = ReleaseManifest::new(2, entries);
        manifest.sign(&test_key_pair());

        manifest.verify_signature().unwrap();
        manifest
            .check_release_version(layout.current_release_version())
            .unwrap();
        layout.verify_staged(&manifest).unwrap();
        layout.persist_manifest(&manifest).unwrap();
        layout.promote(2).unwrap();
        assert_eq!(layout.current_release_version(), Some(2));

        // A later, unrelated process (the agent's periodic self-integrity check,
        // issue #71) reads the manifest back from disk and re-verifies its
        // signature before trusting it as a root of trust — the exact sequence
        // `agent::integrity` runs on a cadence.
        let reloaded = layout.read_manifest(2).unwrap();
        assert_eq!(reloaded, manifest);
        reloaded.verify_signature().unwrap();

        // Release 2's health check fails: roll back to release 1, ban release 2.
        let ban_list_path = base.path().join("banned_versions.json");
        rollback(&layout, &ban_list_path, Some(1), 2).unwrap();
        assert_eq!(layout.current_release_version(), Some(1));

        let banned = crate::banlist::BannedVersions::load(&ban_list_path).unwrap();
        assert!(banned.is_banned(2));

        // A second offer of the exact same failed release is refused — the same
        // manifest that verified and staged cleanly the first time is now
        // rejected once the ban list is consulted, independent of its signature
        // or release_version ordering staying perfectly valid.
        assert!(matches!(
            banned.check(manifest.release_version),
            Err(UpdaterError::ReleaseBanned(2))
        ));
    }

    #[test]
    fn a_manifest_whose_release_version_regresses_is_rejected_before_staging() {
        let base = tempfile::tempdir().unwrap();
        let layout = Layout::new(base.path());
        fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        fs::create_dir_all(layout.versions_dir()).unwrap();
        std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        fs::create_dir_all(layout.version_dir(5)).unwrap();
        layout.promote(5).unwrap();

        let mut manifest = ReleaseManifest::new(3, BTreeMap::new());
        manifest.sign(&test_key_pair());

        assert!(matches!(
            manifest.check_release_version(layout.current_release_version()),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 3,
                current: 5
            })
        ));
    }
}
