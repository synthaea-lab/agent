//! Pre-start recovery for a release whose watchdog cannot be executed.
//!
//! systemd runs this command from the package-installed bootstrap watchdog before
//! each service start. It probes the active watchdog with `--help` (supported by
//! both old and new Clap-based releases); a failed exec rolls `current` back to the
//! previous known-good release or the bootstrap floor and bans the failed release.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use anyhow::Context as _;
use updater::{banlist::BannedVersions, layout::Layout};

const BAN_LIST: &str = "banned_versions.json";

pub(crate) fn recover_if_current_is_unexecutable(base_dir: &Path) -> anyhow::Result<()> {
    recover_with_probe(base_dir, watchdog_can_execute)
}

fn watchdog_can_execute(watchdog: &Path) -> bool {
    Command::new(watchdog)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn recover_with_probe(
    base_dir: &Path,
    can_execute: impl FnOnce(&Path) -> bool,
) -> anyhow::Result<()> {
    let layout = Layout::new(base_dir);
    let Some(failed) = layout.current_release_version() else {
        return Ok(());
    };

    let watchdog = layout.version_dir(failed).join("watchdog");
    if can_execute(&watchdog) {
        return Ok(());
    }

    let ban_list_path = base_dir.join(BAN_LIST);
    let banned = BannedVersions::load(&ban_list_path).context("read updater ban list")?;
    let previous = layout.rollback_target(failed, &banned);
    updater::rollback(&layout, &ban_list_path, previous, failed)
        .context("roll back unexecutable watchdog release")?;

    match previous {
        Some(version) => eprintln!(
            "[watchdog] release {failed} could not execute; rolled back to known-good release {version}"
        ),
        None => {
            eprintln!("[watchdog] release {failed} could not execute; rolled back to bootstrap");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::*;

    fn install(versions: &[u64], current: u64) -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        fs::create_dir_all(layout.bootstrap_dir()).unwrap();
        fs::create_dir_all(layout.versions_dir()).unwrap();
        symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
        for version in versions {
            fs::create_dir_all(layout.version_dir(*version)).unwrap();
            if *version < current {
                layout.mark_healthy(*version).unwrap();
            }
        }
        layout.promote(current).unwrap();
        (dir, layout)
    }

    #[test]
    fn execution_probe_accepts_a_runnable_watchdog_and_rejects_a_non_executable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("watchdog-ok");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(watchdog_can_execute(&executable));

        let denied = dir.path().join("watchdog-denied");
        fs::write(&denied, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&denied, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!watchdog_can_execute(&denied));
    }

    #[test]
    fn a_working_watchdog_is_left_alone() {
        let (dir, layout) = install(&[1, 2], 2);
        recover_with_probe(dir.path(), |_| true).unwrap();
        assert_eq!(layout.current_release_version(), Some(2));
    }

    #[test]
    fn an_unexecutable_watchdog_rolls_back_and_is_banned() {
        let (dir, layout) = install(&[1, 2], 2);
        recover_with_probe(dir.path(), |_| false).unwrap();
        assert_eq!(layout.current_release_version(), Some(1));
        assert!(!layout.version_dir(2).exists());
        assert!(
            BannedVersions::load(&dir.path().join(BAN_LIST))
                .unwrap()
                .is_banned(2)
        );
    }

    #[test]
    fn the_first_unexecutable_release_returns_to_bootstrap() {
        let (dir, layout) = install(&[1], 1);
        recover_with_probe(dir.path(), |_| false).unwrap();
        assert_eq!(layout.current_release_version(), None);
        assert!(
            BannedVersions::load(&dir.path().join(BAN_LIST))
                .unwrap()
                .is_banned(1)
        );
    }
}
