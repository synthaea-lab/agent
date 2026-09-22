//! The on-disk layout: `bootstrap`/`current`/`versions` (ADR-0015 Decision 5,
//! extending `packaging/linux/README.md`'s existing convention). Linux-only — see
//! `CLAUDE.md`'s platform-code exception for `updater` and ADR-0015's Deferred
//! section (Windows/macOS self-update need their own design).

use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use crate::error::UpdaterError;
use crate::hash::hash_file;
use crate::manifest::ReleaseManifest;

/// Name of the `current` symlink, directly under [`Layout::base_dir`].
const CURRENT_LINK: &str = "current";
/// Name of the package-installed bootstrap directory, directly under the base
/// directory — never written by this crate.
const BOOTSTRAP_DIR: &str = "bootstrap";
/// Name of the updater-managed versions directory, directly under the base
/// directory.
const VERSIONS_DIR: &str = "versions";

/// The `bootstrap`/`current`/`versions` layout rooted at one base directory
/// (`/var/lib/synthaea` in production; a temp dir in tests).
#[derive(Debug, Clone)]
pub struct Layout {
    base_dir: PathBuf,
}

impl Layout {
    #[must_use]
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// The package-installed bootstrap directory. Never written by this crate.
    #[must_use]
    pub fn bootstrap_dir(&self) -> PathBuf {
        self.base_dir.join(BOOTSTRAP_DIR)
    }

    /// The updater-managed versions directory (parent of every `version_dir`).
    #[must_use]
    pub fn versions_dir(&self) -> PathBuf {
        self.base_dir.join(VERSIONS_DIR)
    }

    /// The `current` symlink's own path (not its target — see
    /// [`Self::resolve_active_dir`]).
    #[must_use]
    pub fn current_link(&self) -> PathBuf {
        self.base_dir.join(CURRENT_LINK)
    }

    /// The directory a given release stages into and, once promoted, runs from.
    #[must_use]
    pub fn version_dir(&self, release_version: u64) -> PathBuf {
        self.versions_dir().join(format!("v{release_version}"))
    }

    /// Resolves `current`'s target, falling back to [`Self::bootstrap_dir`] if the
    /// symlink is missing, unreadable, or resolves outside the expected
    /// `bootstrap`/`versions` set (ADR-0015 Decision 9). Never fails — this is the
    /// fallback path a crashed or tampered install still has to start from.
    #[must_use]
    pub fn resolve_active_dir(&self) -> PathBuf {
        let Ok(target) = fs::read_link(self.current_link()) else {
            return self.bootstrap_dir();
        };
        let resolved = if target.is_absolute() {
            target
        } else {
            self.base_dir.join(target)
        };
        if resolved == self.bootstrap_dir() || resolved.starts_with(self.versions_dir()) {
            resolved
        } else {
            self.bootstrap_dir()
        }
    }

    /// The `release_version` `current` points at, or `None` if it points at
    /// `bootstrap` (day 0, ADR-0015 Decision 7) or the link was corrupt and fell
    /// back to `bootstrap` (see [`Self::resolve_active_dir`]).
    #[must_use]
    pub fn current_release_version(&self) -> Option<u64> {
        let active = self.resolve_active_dir();
        let name = active.file_name()?.to_str()?;
        name.strip_prefix('v')?.parse().ok()
    }

    /// Verifies every file `manifest` lists exists under
    /// `version_dir(manifest.release_version)` and hashes to the value the
    /// manifest recorded. Does not check the manifest's signature — call
    /// [`ReleaseManifest::verify_signature`] first.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::StagedFileMissing`] or [`UpdaterError::StagedFileMismatch`]
    /// for the first entry that fails; [`UpdaterError::Io`] on an unexpected I/O
    /// error while hashing.
    pub fn verify_staged(&self, manifest: &ReleaseManifest) -> Result<(), UpdaterError> {
        let dir = self.version_dir(manifest.release_version);
        for (rel_path, expected) in &manifest.entries {
            let full_path = dir.join(rel_path);
            if !full_path.is_file() {
                return Err(UpdaterError::StagedFileMissing {
                    path: rel_path.clone(),
                });
            }
            let actual = hash_file(&full_path).map_err(|source| UpdaterError::Io {
                path: full_path.clone(),
                source,
            })?;
            if &actual != expected {
                return Err(UpdaterError::StagedFileMismatch {
                    path: rel_path.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Atomically repoints `current` at `version_dir(release_version)`
    /// (ADR-0015 Decision 5).
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if creating the temp symlink or the rename fails.
    pub fn promote(&self, release_version: u64) -> Result<(), UpdaterError> {
        self.swap_current_to(&self.version_dir(release_version))
    }

    /// Repoints `current` back at `bootstrap` (ADR-0015 Decision 9's fallback,
    /// used deliberately here rather than only automatically — e.g. when every
    /// known version directory is gone).
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if creating the temp symlink or the rename fails.
    pub fn reset_to_bootstrap(&self) -> Result<(), UpdaterError> {
        self.swap_current_to(&self.bootstrap_dir())
    }

    /// Builds the new symlink at a temp path beside `current`, then `rename(2)`s
    /// it over the real one — a crash mid-swap leaves either the old or the new
    /// target, never a half-written one (ADR-0015 Decision 5).
    fn swap_current_to(&self, target: &Path) -> Result<(), UpdaterError> {
        let tmp = self.base_dir.join(format!(".{CURRENT_LINK}.tmp"));
        // A leftover from a crash mid-swap, before the rename below ever ran —
        // symlink() below would otherwise fail with AlreadyExists.
        if let Err(source) = fs::remove_file(&tmp)
            && source.kind() != io::ErrorKind::NotFound
        {
            return Err(UpdaterError::Io { path: tmp, source });
        }
        symlink(target, &tmp).map_err(|source| UpdaterError::Io {
            path: tmp.clone(),
            source,
        })?;
        fs::rename(&tmp, self.current_link()).map_err(|source| UpdaterError::Io {
            path: self.current_link(),
            source,
        })
    }

    /// Deletes a superseded release's directory entirely (ADR-0015 Decision 8:
    /// called once the *new* release has passed its health check, keeping exactly
    /// two release trees on disk at steady state). Never call this on the release
    /// `current` still points at. Idempotent — an already-gone directory is not
    /// an error.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if the directory exists but cannot be removed.
    pub fn prune(&self, release_version: u64) -> Result<(), UpdaterError> {
        let dir = self.version_dir(release_version);
        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(UpdaterError::Io { path: dir, source }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        fs::create_dir_all(layout.versions_dir()).unwrap();
        symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        (dir, layout)
    }

    #[test]
    fn day_zero_current_points_at_bootstrap_and_has_no_release_version() {
        let (_dir, layout) = layout();
        assert_eq!(layout.resolve_active_dir(), layout.bootstrap_dir());
        assert_eq!(layout.current_release_version(), None);
    }

    #[test]
    fn a_missing_current_link_falls_back_to_bootstrap() {
        let (_dir, layout) = layout();
        fs::remove_file(layout.current_link()).unwrap();
        assert_eq!(layout.resolve_active_dir(), layout.bootstrap_dir());
    }

    #[test]
    fn a_current_link_pointing_outside_the_layout_falls_back_to_bootstrap() {
        let (dir, layout) = layout();
        fs::remove_file(layout.current_link()).unwrap();
        let outside = dir.path().parent().unwrap().join("not-synthaea-at-all");
        fs::create_dir_all(&outside).ok();
        symlink(&outside, layout.current_link()).unwrap();
        assert_eq!(layout.resolve_active_dir(), layout.bootstrap_dir());
    }

    #[test]
    fn promote_atomically_repoints_current_and_is_read_back_correctly() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(3)).unwrap();
        layout.promote(3).unwrap();
        assert_eq!(layout.resolve_active_dir(), layout.version_dir(3));
        assert_eq!(layout.current_release_version(), Some(3));
    }

    #[test]
    fn promote_can_be_called_repeatedly_without_leftover_tmp_symlink_errors() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(1)).unwrap();
        fs::create_dir_all(layout.version_dir(2)).unwrap();
        layout.promote(1).unwrap();
        layout.promote(2).unwrap();
        assert_eq!(layout.current_release_version(), Some(2));
    }

    #[test]
    fn reset_to_bootstrap_reverses_a_promote() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(5)).unwrap();
        layout.promote(5).unwrap();
        layout.reset_to_bootstrap().unwrap();
        assert_eq!(layout.resolve_active_dir(), layout.bootstrap_dir());
        assert_eq!(layout.current_release_version(), None);
    }

    fn manifest_for(dir: &Path, release_version: u64) -> ReleaseManifest {
        fs::create_dir_all(dir).unwrap();
        let file_path = dir.join("agent");
        fs::write(&file_path, b"binary contents").unwrap();
        let hash = hash_file(&file_path).unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("agent"), hash);
        ReleaseManifest::new(release_version, entries)
    }

    #[test]
    fn verify_staged_accepts_a_correctly_hashed_release() {
        let (_dir, layout) = layout();
        let manifest = manifest_for(&layout.version_dir(4), 4);
        assert!(layout.verify_staged(&manifest).is_ok());
    }

    #[test]
    fn verify_staged_rejects_a_missing_file() {
        let (_dir, layout) = layout();
        let mut manifest = manifest_for(&layout.version_dir(4), 4);
        manifest
            .entries
            .insert(PathBuf::from("watchdog"), "c".repeat(64));
        assert!(matches!(
            layout.verify_staged(&manifest),
            Err(UpdaterError::StagedFileMissing { .. })
        ));
    }

    #[test]
    fn verify_staged_rejects_a_hash_mismatch() {
        let (_dir, layout) = layout();
        let mut manifest = manifest_for(&layout.version_dir(4), 4);
        manifest
            .entries
            .insert(PathBuf::from("agent"), "0".repeat(64));
        assert!(matches!(
            layout.verify_staged(&manifest),
            Err(UpdaterError::StagedFileMismatch { .. })
        ));
    }

    #[test]
    fn prune_removes_a_superseded_version_directory() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(1)).unwrap();
        layout.prune(1).unwrap();
        assert!(!layout.version_dir(1).exists());
    }

    #[test]
    fn prune_is_idempotent_on_an_already_gone_directory() {
        let (_dir, layout) = layout();
        assert!(layout.prune(99).is_ok());
    }
}
