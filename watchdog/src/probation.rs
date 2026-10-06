//! Post-promotion health gate (ADR-0015 Decision 6, issue #30): a release that
//! `updater` has just promoted is on *probation* until its agent proves it is
//! alive. The proof is the progress-backed heartbeat (#102) advancing within
//! [`PROBATION_DEADLINE`] of the watchdog starting; if it never does, the
//! release is rolled back and banned, and the watchdog exits so the service
//! manager restarts it from the rolled-back `current`.
//!
//! The watchdog runs *from* the release it supervises (`ExecStart` is
//! `current/watchdog`), so it identifies its own release from its executable's
//! path and never guesses from `current`: a watchdog started from `bootstrap/`
//! (day 0, or after a full reset) has no probation — `bootstrap/` is the floor
//! rollback lands on, and nothing is rolled back past it. Linux-only, like the
//! `updater` layout it drives (ADR-0015 Deferred: Windows/macOS self-update).

use std::time::Duration;

/// How long a freshly promoted release has to show a heartbeat advance. The same
/// 120s every other sensor gets before it is called silent
/// (`agent::commands::linux::NO_CANARY_SILENCE_DEADLINE_NS`, cited by ADR-0015
/// Decision 6) — deliberately not a new number.
pub(crate) const PROBATION_DEADLINE: Duration = Duration::from_secs(120);

/// Where a release stands after one observation. Only Linux ever constructs one
/// (no release is on probation elsewhere), hence the allow.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Not enough evidence either way yet.
    Pending,
    /// The heartbeat advanced: the release is alive.
    Proven,
    /// The deadline passed without the heartbeat advancing.
    Failed,
}

/// The pure decision behind [`Probation::verdict`], split out so it is testable
/// without a clock or a filesystem. Progress wins over an expired deadline that
/// is observed in the same poll: a heartbeat that advanced right at the
/// boundary is life, not failure.
#[must_use]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn decide(elapsed: Duration, deadline: Duration, advanced: bool) -> Verdict {
    if advanced {
        Verdict::Proven
    } else if elapsed >= deadline {
        Verdict::Failed
    } else {
        Verdict::Pending
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::Probation;

/// Off Linux there is no versioned layout, so no release is ever on probation:
/// an uninhabited type keeps `supervise`'s `Option<Probation>` plumbing
/// platform-neutral while making a constructed value impossible.
#[cfg(not(target_os = "linux"))]
pub(crate) enum Probation {}

#[cfg(not(target_os = "linux"))]
impl Probation {
    pub(crate) fn detect_for_current(_exe: &std::path::Path) -> Option<Self> {
        None
    }
    pub(crate) fn verdict(&self, _advanced: bool) -> Verdict {
        match *self {}
    }
    pub(crate) fn release(&self) -> u64 {
        match *self {}
    }
    pub(crate) fn previous(&self) -> Option<u64> {
        match *self {}
    }
    pub(crate) fn prove(&self) -> Result<(), updater::UpdaterError> {
        match *self {}
    }
    pub(crate) fn roll_back(&self) -> Result<(), updater::UpdaterError> {
        match *self {}
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use updater::{UpdaterError, banlist::BannedVersions, layout::Layout};

    use super::{PROBATION_DEADLINE, Verdict, decide};

    /// Name of the local ban list directly under the layout's base directory
    /// (`packaging/linux/README.md`: `/var/lib/synthaea/banned_versions.json`).
    const BAN_LIST: &str = "banned_versions.json";

    /// One release under observation, with everything needed to settle it.
    pub(crate) struct Probation {
        layout: Layout,
        ban_list: PathBuf,
        release: u64,
        previous: Option<u64>,
        started: Instant,
        deadline: Duration,
    }

    impl Probation {
        /// Puts the release this executable belongs to on probation, or `None`
        /// when it should not be: the executable is not in `versions/vN/` (a
        /// bootstrap or development run), the release already passed its health
        /// check, or `current` no longer points at it (someone promoted again;
        /// this process is on its way out and must not roll anything back).
        pub(crate) fn detect_for_current(exe: &Path) -> Option<Self> {
            Self::detect(exe)
        }

        pub(crate) fn detect(exe: &Path) -> Option<Self> {
            let release_dir = exe.parent()?;
            let versions_dir = release_dir.parent()?;
            if versions_dir.file_name()? != "versions" {
                return None;
            }
            let layout = Layout::new(versions_dir.parent()?);
            let release: u64 = release_dir
                .file_name()?
                .to_str()?
                .strip_prefix('v')?
                .parse()
                .ok()?;
            if layout.is_healthy(release) || layout.current_release_version() != Some(release) {
                return None;
            }
            let ban_list = versions_dir.parent()?.join(BAN_LIST);
            // An unreadable ban list is treated as empty: this only narrows the
            // rollback target, and `rollback_target` still demands `.healthy`.
            let banned = BannedVersions::load(&ban_list).unwrap_or_default();
            Some(Self {
                previous: layout.rollback_target(release, &banned),
                ban_list,
                layout,
                release,
                started: Instant::now(),
                deadline: PROBATION_DEADLINE,
            })
        }

        /// A shorter deadline, for tests that cannot wait two minutes.
        #[cfg(test)]
        pub(crate) fn with_deadline(mut self, deadline: Duration) -> Self {
            self.deadline = deadline;
            self
        }

        pub(crate) fn release(&self) -> u64 {
            self.release
        }

        /// The release a failure rolls back to; `None` means `bootstrap`.
        pub(crate) fn previous(&self) -> Option<u64> {
            self.previous
        }

        /// Settles the release given whether the agent's heartbeat has advanced
        /// since the watchdog started.
        pub(crate) fn verdict(&self, advanced: bool) -> Verdict {
            decide(self.started.elapsed(), self.deadline, advanced)
        }

        /// The release passed: remember it, and delete everything older than the
        /// release it would roll back to so exactly two trees stay on disk
        /// (ADR-0015 Decision 8).
        ///
        /// # Errors
        ///
        /// [`UpdaterError::Io`] if the marker cannot be written. A failed prune
        /// is not an error: an old directory left behind costs disk, not
        /// safety, and the next proven release retries it.
        pub(crate) fn prove(&self) -> Result<(), UpdaterError> {
            self.layout.mark_healthy(self.release)?;
            let keep_from = self.previous.unwrap_or(self.release);
            for version in self.layout.installed_versions() {
                if version < keep_from {
                    let _ = self.layout.prune(version);
                }
            }
            Ok(())
        }

        /// The release failed: repoint `current` at the previous release (or
        /// `bootstrap`) and ban this one. Refuses when `current` has already
        /// moved on, so a stale watchdog cannot undo a newer promotion.
        ///
        /// # Errors
        ///
        /// Propagates [`UpdaterError`] from the symlink swap or ban-list write. A
        /// failed removal of the release's directory is not an error; it is in the
        /// returned report (`None` when the rollback did not run).
        pub(crate) fn roll_back(&self) -> Result<Option<updater::RollbackReport>, UpdaterError> {
            if self.layout.current_release_version() != Some(self.release) {
                return Ok(None);
            }
            updater::rollback(&self.layout, &self.ban_list, self.previous, self.release).map(Some)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;

        use super::*;

        /// `base/{bootstrap,versions/v<N>...}` with `current -> versions/v<current>`.
        fn install(versions: &[u64], current: Option<u64>) -> (tempfile::TempDir, Layout) {
            let dir = tempfile::tempdir().unwrap();
            let layout = Layout::new(dir.path());
            fs::create_dir_all(layout.bootstrap_dir()).unwrap();
            fs::create_dir_all(layout.versions_dir()).unwrap();
            std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
            for &v in versions {
                fs::create_dir_all(layout.version_dir(v)).unwrap();
            }
            if let Some(v) = current {
                layout.promote(v).unwrap();
            }
            (dir, layout)
        }

        fn exe_of(layout: &Layout, release: u64) -> PathBuf {
            layout.version_dir(release).join("watchdog")
        }

        #[test]
        fn a_freshly_promoted_release_is_on_probation_with_its_predecessor_recorded() {
            let (_dir, layout) = install(&[1, 2], Some(2));
            layout.mark_healthy(1).unwrap();
            let probation = Probation::detect(&exe_of(&layout, 2)).unwrap();
            assert_eq!(probation.release(), 2);
            assert_eq!(probation.previous(), Some(1));
        }

        #[test]
        fn the_first_release_after_bootstrap_has_no_previous_release() {
            let (_dir, layout) = install(&[1], Some(1));
            let probation = Probation::detect(&exe_of(&layout, 1)).unwrap();
            assert_eq!(probation.previous(), None);
        }

        #[test]
        fn a_bootstrap_run_is_never_on_probation() {
            let (_dir, layout) = install(&[1], None);
            assert!(Probation::detect(&layout.bootstrap_dir().join("watchdog")).is_none());
            // A development binary outside any layout, too.
            assert!(Probation::detect(Path::new("/usr/local/bin/watchdog")).is_none());
        }

        #[test]
        fn a_release_that_already_passed_is_not_put_on_probation_again() {
            let (_dir, layout) = install(&[1, 2], Some(2));
            layout.mark_healthy(2).unwrap();
            assert!(Probation::detect(&exe_of(&layout, 2)).is_none());
        }

        #[test]
        fn a_watchdog_whose_release_is_no_longer_current_is_not_on_probation() {
            let (_dir, layout) = install(&[1, 2, 3], Some(3));
            assert!(Probation::detect(&exe_of(&layout, 2)).is_none());
        }

        #[test]
        fn progress_proves_the_release_and_an_expired_deadline_fails_it() {
            let d = Duration::from_secs(120);
            assert_eq!(decide(Duration::from_secs(1), d, false), Verdict::Pending);
            assert_eq!(decide(Duration::from_secs(1), d, true), Verdict::Proven);
            assert_eq!(decide(d, d, false), Verdict::Failed);
            assert_eq!(
                decide(d * 5, d, true),
                Verdict::Proven,
                "progress observed in the same poll as the deadline is life"
            );
        }

        #[test]
        fn roll_back_repoints_current_and_bans_the_failed_release() {
            let (dir, layout) = install(&[1, 2], Some(2));
            layout.mark_healthy(1).unwrap();
            let probation = Probation::detect(&exe_of(&layout, 2)).unwrap();
            probation.roll_back().unwrap();
            assert_eq!(layout.current_release_version(), Some(1));
            assert!(
                !layout.version_dir(2).exists(),
                "the failed release's directory is removed"
            );
            let banned = fs::read_to_string(dir.path().join(BAN_LIST)).unwrap();
            assert!(banned.contains('2'), "ban list: {banned}");
        }

        #[test]
        fn rolling_back_the_first_release_lands_on_bootstrap() {
            let (_dir, layout) = install(&[1], Some(1));
            let probation = Probation::detect(&exe_of(&layout, 1)).unwrap();
            probation.roll_back().unwrap();
            assert_eq!(layout.current_release_version(), None);
            assert_eq!(layout.resolve_active_dir(), layout.bootstrap_dir());
        }

        #[test]
        fn a_stale_watchdog_cannot_roll_back_a_newer_promotion() {
            let (dir, layout) = install(&[1, 2], Some(2));
            let probation = Probation::detect(&exe_of(&layout, 2)).unwrap();
            fs::create_dir_all(layout.version_dir(3)).unwrap();
            layout.promote(3).unwrap();
            probation.roll_back().unwrap();
            assert_eq!(layout.current_release_version(), Some(3));
            assert!(!dir.path().join(BAN_LIST).exists());
        }

        #[test]
        fn proving_marks_the_release_and_prunes_only_what_is_older_than_its_predecessor() {
            let (_dir, layout) = install(&[1, 2, 3, 4], Some(4));
            layout.mark_healthy(3).unwrap();
            Probation::detect(&exe_of(&layout, 4))
                .unwrap()
                .prove()
                .unwrap();
            assert!(layout.is_healthy(4));
            assert_eq!(
                layout.installed_versions(),
                vec![3, 4],
                "the current release and the one it rolls back to stay"
            );
        }

        /// Promotes `release`, which is not yet healthy, the way `apply-release`
        /// does, and returns its probation.
        fn promote(layout: &Layout, release: u64) -> Probation {
            fs::create_dir_all(layout.version_dir(release)).unwrap();
            layout.promote(release).unwrap();
            Probation::detect(&exe_of(layout, release)).unwrap()
        }

        #[test]
        fn a_good_release_a_bad_one_and_a_good_one_keeps_the_last_proven_release() {
            // PR #533 review: `prove` used to prune below the banned release,
            // deleting the last release that ever proved healthy.
            let (_dir, layout) = install(&[2], Some(2));
            layout.mark_healthy(2).unwrap();

            promote(&layout, 3).roll_back().unwrap();
            assert_eq!(layout.current_release_version(), Some(2));

            let v4 = promote(&layout, 4);
            assert_eq!(v4.previous(), Some(2), "not the banned release 3");
            v4.prove().unwrap();
            assert_eq!(layout.installed_versions(), vec![2, 4]);
        }

        #[test]
        fn two_bad_releases_in_a_row_both_roll_back_to_the_last_proven_release() {
            // PR #533 review: the second bad release used to roll back onto the
            // first, a release already known to be broken.
            let (dir, layout) = install(&[2], Some(2));
            layout.mark_healthy(2).unwrap();

            promote(&layout, 3).roll_back().unwrap();
            let v4 = promote(&layout, 4);
            assert_eq!(v4.previous(), Some(2));
            v4.roll_back().unwrap();

            assert_eq!(layout.current_release_version(), Some(2));
            let banned = fs::read_to_string(dir.path().join(BAN_LIST)).unwrap();
            assert!(banned.contains('3') && banned.contains('4'), "{banned}");
        }

        #[test]
        fn a_banned_release_still_on_disk_is_never_the_rollback_target() {
            // A directory left behind by an older watchdog (or a failed prune).
            let (dir, layout) = install(&[2, 3], Some(3));
            layout.mark_healthy(2).unwrap();
            layout.mark_healthy(3).unwrap();
            fs::write(dir.path().join(BAN_LIST), "[3]").unwrap();
            let v4 = promote(&layout, 4);
            assert_eq!(v4.previous(), Some(2));
        }

        #[test]
        fn a_release_that_never_proved_itself_is_not_a_rollback_target() {
            let (_dir, layout) = install(&[1], Some(1));
            // 1 was promoted but never marked healthy: bootstrap is the floor.
            let v2 = promote(&layout, 2);
            assert_eq!(v2.previous(), None);
        }
    }
}
