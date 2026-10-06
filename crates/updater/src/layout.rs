//! The on-disk layout: `bootstrap`/`current`/`versions` (ADR-0015 Decision 5,
//! extending `packaging/linux/README.md`'s existing convention). Linux-only — see
//! `CLAUDE.md`'s platform-code exception for `updater` and ADR-0015's Deferred
//! section (Windows/macOS self-update need their own design).

use std::{
    ffi::OsStr,
    fs, io,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt, symlink},
    },
    path::{Path, PathBuf},
};

use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{AtFlags, CWD, Dir, Gid, Mode, OFlags, Uid, chownat, fchown, openat},
    io::Errno,
};

use crate::{
    banlist::BannedVersions, error::UpdaterError, hash::hash_file, manifest::ReleaseManifest,
};

/// Name of the `current` symlink, directly under [`Layout::base_dir`].
const CURRENT_LINK: &str = "current";
/// Name of the package-installed bootstrap directory, directly under the base
/// directory — never written by this crate.
const BOOTSTRAP_DIR: &str = "bootstrap";
/// Name of the updater-managed versions directory, directly under the base
/// directory.
const VERSIONS_DIR: &str = "versions";
/// Name of the marker file a release writes into its own directory once it has
/// passed its post-promotion health check (ADR-0015 Decision 6).
const HEALTHY_MARKER: &str = ".healthy";

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
        self.versions_dir().join(version_dir_name(release_version))
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

    /// Name of the manifest file [`Self::persist_manifest`]/[`Self::read_manifest`]
    /// read and write, directly under `version_dir(manifest.release_version)`.
    const MANIFEST_FILE: &'static str = "manifest.json";

    /// Writes `manifest` to `version_dir(manifest.release_version)/manifest.json` —
    /// the durable copy issue #71's periodic self-integrity check reads back later,
    /// after this process (and the download that staged the release) is long gone.
    /// Call after [`Self::verify_staged`] succeeds, before or alongside
    /// [`Self::promote`]; this crate does not bundle the write into either of those
    /// so a caller that only wants to stage-and-verify (without ever promoting,
    /// e.g. a dry run) is not forced to leave a manifest file behind.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if the version directory does not exist or the write
    /// fails.
    ///
    /// # Panics
    ///
    /// Never in practice: [`ReleaseManifest`] contains no type `serde_json` cannot
    /// serialize (same invariant `ReleaseManifest`'s own `canonical_bytes` relies
    /// on).
    pub fn persist_manifest(&self, manifest: &ReleaseManifest) -> Result<(), UpdaterError> {
        let path = self
            .version_dir(manifest.release_version)
            .join(Self::MANIFEST_FILE);
        let bytes = serde_json::to_vec_pretty(manifest)
            .expect("ReleaseManifest has no non-serializable content");
        fs::write(&path, bytes).map_err(|source| UpdaterError::Io { path, source })
    }

    /// Reads back the manifest [`Self::persist_manifest`] wrote for `release_version`.
    /// Does not verify the signature or re-check staged files — same division of
    /// labor as [`Self::verify_staged`]: this reads bytes back, the caller decides
    /// whether to trust them (call [`ReleaseManifest::verify_signature`] on the
    /// result before treating it as a root of trust — a manifest file readable from
    /// disk is not the same as one this install actually verified and promoted).
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if the file cannot be read (including "does not
    /// exist" — callers checking the *currently active* release should consult
    /// [`Self::current_release_version`] first and skip the read entirely on
    /// `None`, the honest bootstrap/day-0 case where nothing was ever promoted).
    /// [`UpdaterError::ManifestCorrupt`] if the file exists but is not a valid
    /// [`ReleaseManifest`].
    pub fn read_manifest(&self, release_version: u64) -> Result<ReleaseManifest, UpdaterError> {
        let path = self.version_dir(release_version).join(Self::MANIFEST_FILE);
        let bytes = fs::read(&path).map_err(|source| UpdaterError::Io {
            path: path.clone(),
            source,
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|source| UpdaterError::ManifestCorrupt { path, source })
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

    /// Every release directory under `versions/`, ascending. A name that is not
    /// `v<number>` (a stray file, a half-staged temp directory) is ignored: only
    /// directories this crate itself creates count as releases.
    #[must_use]
    pub fn installed_versions(&self) -> Vec<u64> {
        let Ok(entries) = fs::read_dir(self.versions_dir()) else {
            return Vec::new();
        };
        let mut versions: Vec<u64> = entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_prefix('v')?
                    .parse::<u64>()
                    .ok()
            })
            .collect();
        versions.sort_unstable();
        versions
    }

    /// The release a failed `release_version` should roll back to: the newest
    /// installed release strictly older than it that is **known good**, meaning
    /// it passed its own health check ([`Self::mark_healthy`]) and is not on the
    /// ban list. `None` means fall back to `bootstrap`, the one floor that is
    /// always good. A release that was never proven, or that failed, must not be
    /// a rollback target: landing on it just runs a known-bad release again (PR
    /// #533 review).
    #[must_use]
    pub fn rollback_target(&self, release_version: u64, banned: &BannedVersions) -> Option<u64> {
        self.installed_versions()
            .into_iter()
            .rev()
            .find(|&v| v < release_version && !banned.is_banned(v) && self.is_healthy(v))
    }

    /// Records that `release_version` passed its health check (ADR-0015
    /// Decision 6), so a later start of the same release is not put on probation
    /// again. Written through a same-directory temp file and `rename` like every
    /// other file this crate persists.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if the marker cannot be written.
    pub fn mark_healthy(&self, release_version: u64) -> Result<(), UpdaterError> {
        let dir = self.version_dir(release_version);
        let marker = dir.join(HEALTHY_MARKER);
        let tmp = dir.join(format!("{HEALTHY_MARKER}.tmp"));
        fs::write(&tmp, b"").map_err(|source| UpdaterError::Io {
            path: tmp.clone(),
            source,
        })?;
        fs::rename(&tmp, &marker).map_err(|source| UpdaterError::Io {
            path: marker,
            source,
        })
    }

    /// Whether `release_version` has passed its health check
    /// ([`Self::mark_healthy`]).
    #[must_use]
    pub fn is_healthy(&self, release_version: u64) -> bool {
        self.version_dir(release_version)
            .join(HEALTHY_MARKER)
            .is_file()
    }

    /// Hands `versions/` and the whole `versions/vN` tree to the identity that owns
    /// the base directory — the service user the package created it for — so the
    /// watchdog can write `.healthy` into the release and delete it on rollback or
    /// recovery even when `apply-release` ran as root (#656). Symlinks are
    /// re-owned, never followed.
    ///
    /// The walk is descriptor-relative: the release is opened from `versions/`, which
    /// is opened from the base directory, with `O_NOFOLLOW | O_DIRECTORY`, and every
    /// entry below is opened or re-owned relative to the descriptor of the directory
    /// being walked (`openat`, `fchownat` with `AT_SYMLINK_NOFOLLOW`, `fchown` on the
    /// directory's own descriptor). No path is resolved again once a descriptor is
    /// held. That matters because the service user may own the parent from the start
    /// (the package gives it the whole of `/var/lib/synthaea`, and `versions/` is
    /// handed over on every run), and the owner of a directory can rename any entry in
    /// it: swapping an entry for a symlink between listing and re-owning would
    /// otherwise make this process, running as root, re-own whatever it points at.
    /// A swapped entry now fails the open or is re-owned as the link itself.
    ///
    /// The order is still post-order, `versions/` last: a directory is handed over
    /// only after everything under it.
    ///
    /// The base directory is the reference rather than a configured user name
    /// because the package already gives it to the service user; a layout owned by
    /// the caller (a dev run, the tests) makes this a no-op.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if the base directory cannot be read, `versions/` or the
    /// release is missing or is not a real directory (a symlink is refused, before
    /// anything is re-owned), the tree is deeper than [`MAX_ADOPT_DEPTH`], or a path
    /// cannot be re-owned.
    pub fn adopt_service_ownership(&self, release_version: u64) -> Result<(), UpdaterError> {
        let owner = fs::metadata(&self.base_dir).map_err(|source| UpdaterError::Io {
            path: self.base_dir.clone(),
            source,
        })?;
        self.adopt_with(
            release_version,
            Uid::from_raw(owner.uid()),
            Gid::from_raw(owner.gid()),
            &mut |_| {},
        )
    }

    /// [`Self::adopt_service_ownership`] for explicit ids, calling `visit` with each
    /// path (as a label: it is never resolved) just before it is re-owned, so a test
    /// can assert the order of the walk.
    fn adopt_with(
        &self,
        release_version: u64,
        uid: Uid,
        gid: Gid,
        visit: &mut dyn FnMut(&Path),
    ) -> Result<(), UpdaterError> {
        let dirs = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let versions_path = self.versions_dir();
        let release_path = self.version_dir(release_version);
        // Everything is opened before anything is re-owned, so a missing or swapped
        // release leaves `versions/` as it was. The base directory itself is
        // followed: its own parent is root's, and a packaged base may be a symlink.
        let base = open_at(CWD, &self.base_dir, dirs)?;
        let versions = open_at(&base, Path::new(VERSIONS_DIR), dirs | OFlags::NOFOLLOW)?;
        let release = open_at(
            &versions,
            Path::new(&version_dir_name(release_version)),
            dirs | OFlags::NOFOLLOW,
        )?;

        chown_dir_tree(&release, &release_path, (uid, gid), 0, visit)?;
        visit(&versions_path);
        fchown(&versions, Some(uid), Some(gid)).map_err(|e| errno_at(&versions_path, e))
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

/// The directory name of a release under `versions/`.
fn version_dir_name(release_version: u64) -> String {
    format!("v{release_version}")
}

/// How deep [`Layout::adopt_service_ownership`] will descend. A release is a handful
/// of levels; the bound keeps a hostile tree from exhausting descriptors or the stack.
pub const MAX_ADOPT_DEPTH: usize = 64;

fn errno_at(path: &Path, errno: Errno) -> UpdaterError {
    UpdaterError::Io {
        path: path.to_path_buf(),
        source: errno.into(),
    }
}

fn open_at(dir: impl AsFd, name: &Path, flags: OFlags) -> Result<OwnedFd, UpdaterError> {
    openat(dir, name, flags, Mode::empty()).map_err(|e| errno_at(name, e))
}

/// Re-owns everything under the directory `dir` (named `path`, as a label only) and
/// then the directory itself, children first. A symlink is re-owned itself and never
/// opened; every operation is relative to a descriptor already held.
fn chown_dir_tree(
    dir: &OwnedFd,
    path: &Path,
    (uid, gid): (Uid, Gid),
    depth: usize,
    visit: &mut dyn FnMut(&Path),
) -> Result<(), UpdaterError> {
    if depth > MAX_ADOPT_DEPTH {
        return Err(UpdaterError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "release tree is too deep"),
        });
    }
    let entries = Dir::read_from(dir).map_err(|e| errno_at(path, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| errno_at(path, e))?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let child_path = path.join(OsStr::from_bytes(name.to_bytes()));
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match openat(dir, name, flags, Mode::empty()) {
            Ok(child) => chown_dir_tree(&child, &child_path, (uid, gid), depth + 1, visit)?,
            // Not a directory: a file, or a symlink (`O_NOFOLLOW` refuses it), which
            // is re-owned as the link itself.
            Err(Errno::NOTDIR | Errno::LOOP) => {
                visit(&child_path);
                chownat(dir, name, Some(uid), Some(gid), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| errno_at(&child_path, e))?;
            }
            Err(e) => return Err(errno_at(&child_path, e)),
        }
    }
    visit(path);
    fchown(dir, Some(uid), Some(gid)).map_err(|e| errno_at(path, e))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

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
    fn a_persisted_manifest_round_trips_through_read() {
        let (_dir, layout) = layout();
        let manifest = manifest_for(&layout.version_dir(4), 4);
        layout.persist_manifest(&manifest).unwrap();
        assert_eq!(layout.read_manifest(4).unwrap(), manifest);
    }

    #[test]
    fn read_manifest_fails_for_a_version_with_no_persisted_manifest() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(7)).unwrap();
        assert!(matches!(
            layout.read_manifest(7),
            Err(UpdaterError::Io { .. })
        ));
    }

    #[test]
    fn read_manifest_reports_corrupt_json_distinctly_from_a_missing_file() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(9)).unwrap();
        fs::write(layout.version_dir(9).join("manifest.json"), b"not json").unwrap();
        assert!(matches!(
            layout.read_manifest(9),
            Err(UpdaterError::ManifestCorrupt { .. })
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

    #[test]
    fn installed_versions_lists_release_directories_ascending_and_ignores_strays() {
        let (_dir, layout) = layout();
        for v in [10, 2, 7] {
            fs::create_dir_all(layout.version_dir(v)).unwrap();
        }
        fs::create_dir_all(layout.versions_dir().join("not-a-release")).unwrap();
        fs::create_dir_all(layout.versions_dir().join("vX")).unwrap();
        fs::write(layout.versions_dir().join("v99"), b"a file, not a dir").unwrap();
        assert_eq!(layout.installed_versions(), vec![2, 7, 10]);
    }

    #[test]
    fn rollback_target_is_the_newest_older_release_that_is_healthy_and_not_banned() {
        let (_dir, layout) = layout();
        for v in [1, 3, 4, 5] {
            fs::create_dir_all(layout.version_dir(v)).unwrap();
        }
        // 1 and 3 proved themselves; 4 never did; 3 later ended up banned.
        layout.mark_healthy(1).unwrap();
        layout.mark_healthy(3).unwrap();
        let mut banned = BannedVersions::default();
        assert_eq!(layout.rollback_target(5, &banned), Some(3));
        assert_eq!(
            layout.rollback_target(5, &banned),
            layout.rollback_target(4, &banned),
            "an unproven release (4) is never a target"
        );
        banned.ban(3);
        assert_eq!(
            layout.rollback_target(5, &banned),
            Some(1),
            "banned 3 is skipped"
        );
        assert_eq!(
            layout.rollback_target(1, &banned),
            None,
            "nothing older: bootstrap"
        );
        // A release that is not installed still has a well-defined target.
        assert_eq!(layout.rollback_target(9, &banned), Some(1));
    }

    #[test]
    fn with_no_proven_release_the_target_is_bootstrap() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(1)).unwrap();
        assert_eq!(layout.rollback_target(2, &BannedVersions::default()), None);
    }

    #[test]
    fn a_release_is_unhealthy_until_it_is_marked() {
        let (_dir, layout) = layout();
        fs::create_dir_all(layout.version_dir(2)).unwrap();
        assert!(!layout.is_healthy(2));
        layout.mark_healthy(2).unwrap();
        assert!(layout.is_healthy(2));
        assert!(!layout.is_healthy(3), "the marker is per release");
    }

    #[test]
    fn marking_a_release_that_is_not_installed_fails_instead_of_creating_it() {
        let (_dir, layout) = layout();
        assert!(matches!(
            layout.mark_healthy(42),
            Err(UpdaterError::Io { .. })
        ));
        assert!(!layout.version_dir(42).exists());
    }

    #[test]
    fn adopting_ownership_on_a_layout_the_caller_owns_changes_nothing_and_keeps_symlinks() {
        let (_dir, layout) = layout();
        let release = layout.version_dir(2);
        fs::create_dir_all(release.join("sub")).unwrap();
        fs::write(release.join("sub/agent"), b"x").unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), release.join("link")).unwrap();

        layout.adopt_service_ownership(2).unwrap();

        assert_eq!(fs::read(release.join("sub/agent")).unwrap(), b"x");
        assert!(
            fs::symlink_metadata(release.join("link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "a symlink stays a symlink"
        );
    }

    #[test]
    fn adopting_ownership_of_a_release_that_is_not_installed_fails_instead_of_creating_it() {
        let (_dir, layout) = layout();
        assert!(layout.adopt_service_ownership(9).is_err());
        assert!(!layout.version_dir(9).exists());
    }

    /// The caller's own ids, which `chown` accepts without being root: the walk can run
    /// for real in the tests.
    fn own_ids(layout: &Layout) -> (Uid, Gid) {
        let meta = fs::metadata(&layout.base_dir).unwrap();
        (Uid::from_raw(meta.uid()), Gid::from_raw(meta.gid()))
    }

    /// A directory the service user owns is one it can rename entries in, so the walk
    /// must hand each directory over after everything under it (#656 review).
    #[test]
    fn a_directory_is_handed_over_only_after_everything_under_it() {
        let (dir, layout) = layout();
        let release = layout.version_dir(2);
        fs::create_dir_all(release.join("a/b")).unwrap();
        fs::write(release.join("a/b/file"), b"x").unwrap();
        fs::write(release.join("agent"), b"x").unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret"), b"x").unwrap();
        symlink(&outside, release.join("a/link")).unwrap();
        let (uid, gid) = own_ids(&layout);

        let mut order = Vec::new();
        layout
            .adopt_with(2, uid, gid, &mut |path| order.push(path.to_path_buf()))
            .unwrap();

        let position = |p: &Path| order.iter().position(|o| o == p).unwrap();
        for path in &order {
            for later in order.iter().filter(|o| o.starts_with(path) && *o != path) {
                assert!(
                    position(later) < position(path),
                    "{} was handed over before {}, which is under it",
                    path.display(),
                    later.display()
                );
            }
        }
        assert_eq!(
            order.last(),
            Some(&layout.versions_dir()),
            "versions/ is last"
        );
        assert_eq!(
            order[order.len() - 2],
            release,
            "the release directory comes right before versions/"
        );
        assert!(
            order.contains(&release.join("a/link")),
            "the link itself is re-owned"
        );
        assert!(
            !order.iter().any(|p| p.starts_with(&outside)),
            "a symlink to a directory is never descended into"
        );
    }

    #[test]
    fn a_release_or_versions_swapped_for_a_symlink_is_refused_before_anything_is_handed_over() {
        // The release is a symlink to a directory, then `versions/` itself is one.
        for swap_versions in [false, true] {
            let (dir, layout) = layout();
            let target = dir.path().join("elsewhere");
            fs::create_dir_all(target.join("v2")).unwrap();
            if swap_versions {
                fs::remove_dir_all(layout.versions_dir()).unwrap();
                symlink(&target, layout.versions_dir()).unwrap();
            } else {
                symlink(target.join("v2"), layout.version_dir(2)).unwrap();
            }
            let (uid, gid) = own_ids(&layout);

            let mut visited = 0;
            let result = layout.adopt_with(2, uid, gid, &mut |_| visited += 1);

            assert!(result.is_err(), "swap_versions={swap_versions}");
            assert_eq!(visited, 0, "swap_versions={swap_versions}");
        }
    }

    #[test]
    fn a_tree_deeper_than_the_bound_is_refused_not_walked() {
        let (_dir, layout) = layout();
        let mut deep = layout.version_dir(2);
        for _ in 0..=MAX_ADOPT_DEPTH + 1 {
            deep.push("d");
        }
        fs::create_dir_all(&deep).unwrap();
        let (uid, gid) = own_ids(&layout);

        assert!(layout.adopt_with(2, uid, gid, &mut |_| {}).is_err());
    }

    /// The real thing, which needs root (or a user namespace where one is root and
    /// another uid is mapped: `unshare -U --map-root-user --map-users=auto
    /// --map-groups=auto cargo test -p updater adopting`). Skipped otherwise.
    #[test]
    fn adopting_ownership_re_owns_a_root_owned_release_to_the_base_owner() {
        // `/proc/self` belongs to the effective uid.
        if fs::metadata("/proc/self").unwrap().uid() != 0 {
            eprintln!("skipped: needs root to re-own to another uid");
            return;
        }
        const SERVICE: u32 = 1;
        let (dir, layout) = layout();
        let release = layout.version_dir(2);
        fs::create_dir_all(release.join("sub")).unwrap();
        fs::write(release.join("sub/agent"), b"x").unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, b"x").unwrap();
        symlink(&outside, release.join("link")).unwrap();
        std::os::unix::fs::lchown(&layout.base_dir, Some(SERVICE), Some(SERVICE)).unwrap();

        layout.adopt_service_ownership(2).unwrap();

        let owner = |p: &Path| {
            let m = fs::symlink_metadata(p).unwrap();
            (m.uid(), m.gid())
        };
        for path in [
            layout.versions_dir(),
            release.clone(),
            release.join("sub"),
            release.join("sub/agent"),
            release.join("link"),
        ] {
            assert_eq!(owner(&path), (SERVICE, SERVICE), "{}", path.display());
        }
        assert_eq!(owner(&outside), (0, 0), "the link's target is not touched");
        assert_eq!(
            owner(&layout.bootstrap_dir()),
            (0, 0),
            "bootstrap is not touched"
        );
    }
}
