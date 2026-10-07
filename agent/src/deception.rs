//! Canary planting at agent start (issue #81): turns the operator's `[deception]` table
//! into planted decoy files and the [`Tripwires`] the detection sink matches events with.
//!
//! The per-install seed lives in the state directory, next to the inventory. Everything
//! here degrades: a seed that cannot be read or a directory that cannot be written costs
//! the tripwires, never the agent.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use deception::{Inventory, Kind, Placement, Seed, Tripwires};

const SEED_LEN: usize = 32;

fn deception_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("deception")
}

fn inventory_path(state_dir: &Path) -> PathBuf {
    deception_dir(state_dir).join("inventory.json")
}

fn seed_path(state_dir: &Path) -> PathBuf {
    deception_dir(state_dir).join("seed")
}

/// The install's seed: read from the state directory, or generated once and written there
/// with owner-only permissions. A seed file of the wrong length is an error, not a reason
/// to regenerate: new names would orphan the canaries already planted.
fn load_or_create_seed(state_dir: &Path) -> io::Result<Seed> {
    let path = seed_path(state_dir);
    match fs::read(&path) {
        Ok(bytes) => {
            let bytes: [u8; SEED_LEN] = bytes.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "seed file is not 32 bytes")
            })?;
            return Ok(Seed::from_bytes(bytes));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::create_dir_all(deception_dir(state_dir))?;
    let mut bytes = [0u8; SEED_LEN];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(&path)?.write_all(&bytes)?;
    Ok(Seed::from_bytes(bytes))
}

/// Plants the configured canaries and returns the tripwires over everything inventoried.
/// `None` when nothing is configured or planting failed (said in the log).
///
/// With no directories configured, canaries planted by an earlier run are removed: dropping
/// the `[deception]` table is how an operator turns the feature off, and it leaves no residue.
pub(crate) fn start(config: &config::DeceptionConfig, state_dir: &Path) -> Option<Tripwires> {
    let inventory = inventory_path(state_dir);
    if config.canary_dirs.is_empty() {
        retire(&inventory);
        return None;
    }
    let seed = match load_or_create_seed(state_dir) {
        Ok(seed) => seed,
        Err(error) => {
            tracing::error!(%error, "deception: no seed, no canaries planted");
            return None;
        }
    };
    let placements: Vec<Placement> = config
        .canary_dirs
        .iter()
        .map(|dir| Placement {
            dir: dir.clone(),
            kinds: Kind::ALL.to_vec(),
        })
        .collect();
    match deception::plant(&deception::plan(&seed, &placements), &inventory) {
        Ok(report) => tracing::info!(
            planted = report.planted.len(),
            unchanged = report.unchanged.len(),
            skipped = report.skipped.len(),
            "deception: canaries planted"
        ),
        Err(error) => {
            tracing::error!(%error, "deception: planting failed");
            return None;
        }
    }
    match Inventory::load(&inventory) {
        Ok(inventory) => Some(Tripwires::from_inventory(&inventory)).filter(|t| !t.is_empty()),
        Err(error) => {
            tracing::error!(%error, "deception: inventory unreadable, no tripwires");
            None
        }
    }
}

/// Removes canaries a previous run planted, when the operator no longer configures any.
fn retire(inventory: &Path) {
    match deception::remove(inventory) {
        Ok(report) if report.is_clean() => {
            if !report.removed.is_empty() {
                tracing::info!(
                    removed = report.removed.len(),
                    "deception: canaries removed"
                );
            }
        }
        Ok(report) => tracing::warn!(
            refused = report.refused.len(),
            failed = report.failed.len(),
            "deception: some canaries could not be removed"
        ),
        Err(error) => tracing::error!(%error, "deception: removing old canaries failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for(dirs: &[&Path]) -> config::DeceptionConfig {
        config::DeceptionConfig {
            canary_dirs: dirs.iter().map(|d| d.to_path_buf()).collect(),
        }
    }

    #[test]
    fn nothing_configured_plants_nothing() {
        let state = tempfile::tempdir().unwrap();
        assert!(start(&config_for(&[]), state.path()).is_none());
        assert!(!deception_dir(state.path()).exists());
    }

    #[test]
    fn configured_directories_get_one_canary_per_kind_and_a_tripwire_each() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let tripwires = start(&config_for(&[dir.path()]), state.path()).unwrap();
        assert_eq!(tripwires.len(), Kind::ALL.len());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), Kind::ALL.len());
    }

    #[test]
    fn a_restart_keeps_the_same_canaries() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = start(&config_for(&[dir.path()]), state.path()).unwrap();
        let second = start(&config_for(&[dir.path()]), state.path()).unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), Kind::ALL.len());
    }

    #[test]
    fn two_installs_get_different_canary_names() {
        let (state_a, state_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        start(&config_for(&[dir_a.path()]), state_a.path()).unwrap();
        start(&config_for(&[dir_b.path()]), state_b.path()).unwrap();
        let names = |d: &Path| -> Vec<_> {
            let mut n: Vec<_> = fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            n.sort();
            n
        };
        assert_ne!(names(dir_a.path()), names(dir_b.path()));
    }

    #[test]
    fn dropping_the_configuration_removes_what_was_planted() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        start(&config_for(&[dir.path()]), state.path()).unwrap();
        assert!(start(&config_for(&[]), state.path()).is_none());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_truncated_seed_file_plants_nothing_instead_of_renaming_the_canaries() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(deception_dir(state.path())).unwrap();
        fs::write(seed_path(state.path()), b"short").unwrap();
        assert!(start(&config_for(&[dir.path()]), state.path()).is_none());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn the_seed_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let state = tempfile::tempdir().unwrap();
        load_or_create_seed(state.path()).unwrap();
        let mode = fs::metadata(seed_path(state.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
