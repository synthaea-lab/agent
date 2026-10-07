//! The canary lifecycle: plant, verify and remove (refresh is not built yet), with an on-disk inventory.
//!
//! The inventory is the contract for the packaging residue rule: every file this crate
//! creates is in it before it exists, and [`remove`] deletes exactly those files, so an
//! uninstall leaves no decoy behind and touches nothing that was not planted.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plan::{Canary, DECOY_HEADER, Kind};

/// Inventory file format version.
const INVENTORY_VERSION: u32 = 1;

/// What can go wrong planting, reading or removing canaries.
#[derive(Debug, thiserror::Error)]
pub enum DeceptionError {
    /// A filesystem operation failed.
    #[error("{path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The inventory file exists but is not a valid inventory.
    #[error("inventory {path} is not valid: {reason}")]
    Corrupt {
        /// The inventory path.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> DeceptionError + '_ {
    move |source| DeceptionError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// One planted canary, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryEntry {
    /// Where the file is.
    pub path: PathBuf,
    /// What it pretends to be.
    pub kind: Kind,
    /// Lowercase hex SHA-256 of the content as planted.
    pub sha256: String,
}

/// Every canary this install planted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    version: u32,
    /// The canaries, in the order they were planted.
    pub entries: Vec<InventoryEntry>,
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            version: INVENTORY_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Inventory {
    /// Reads the inventory at `path`; a missing file is an empty inventory.
    ///
    /// # Errors
    ///
    /// [`DeceptionError::Io`] if the file cannot be read, [`DeceptionError::Corrupt`] if it
    /// is not a valid inventory of a known version.
    pub fn load(path: &Path) -> Result<Self, DeceptionError> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(io_at(path)(e)),
        };
        let inventory: Self =
            serde_json::from_slice(&bytes).map_err(|e| DeceptionError::Corrupt {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        if inventory.version != INVENTORY_VERSION {
            return Err(DeceptionError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("unknown version {}", inventory.version),
            });
        }
        Ok(inventory)
    }

    /// Writes the inventory to `path` through a same-directory temp file and a rename, so
    /// a crash leaves the old inventory or the new one, never half of one.
    ///
    /// # Errors
    ///
    /// [`DeceptionError::Io`] if it cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), DeceptionError> {
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| DeceptionError::Corrupt {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        // A leftover from a crash is cleared first (removing a symlink removes the link, not
        // its target), then the file is created exclusively: `create_new` refuses a path that
        // appeared in between, including a symlink, instead of writing through it.
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_at(&tmp)(e)),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io_at(&tmp))?;
        file.write_all(&bytes).map_err(io_at(&tmp))?;
        // Data on disk before the rename makes it visible: otherwise a power loss can leave
        // the new name over an empty file.
        file.sync_all().map_err(io_at(&tmp))?;
        drop(file);
        fs::rename(&tmp, path).map_err(io_at(path))
    }
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Why a canary was not planted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skipped {
    /// The directory does not exist. Canaries never create directories: that would put
    /// something where the operator did not point.
    NoDirectory,
    /// A file already exists there that is not this install's canary. It is never
    /// overwritten.
    Occupied,
    /// This install planted a canary here and the file is gone: someone deleted it. It is
    /// not recreated (refreshing is a separate policy), and the caller can tell this from a
    /// user's file being in the way.
    Missing,
}

/// What [`plant`] did.
#[derive(Debug, Default)]
pub struct PlantReport {
    /// Created by this call.
    pub planted: Vec<PathBuf>,
    /// Already planted by this install, with the planted content: left alone.
    pub unchanged: Vec<PathBuf>,
    /// Not planted, and why.
    pub skipped: Vec<(PathBuf, Skipped)>,
}

/// Plants `canaries` and records each one in the inventory at `inventory_path`.
///
/// A canary is written into the inventory **before** its file is created and dropped from
/// it again if the creation fails, so a crash between the two leaves an inventoried path
/// with no file (harmless to [`remove`]) and never a file the inventory does not know. Files
/// are created with `create_new`: an existing file is never overwritten. Planting again is
/// idempotent.
///
/// # Errors
///
/// [`DeceptionError`] if the inventory cannot be read or written, or a file cannot be
/// written for a reason other than the directory missing or the path being taken.
pub fn plant(canaries: &[Canary], inventory_path: &Path) -> Result<PlantReport, DeceptionError> {
    let mut inventory = Inventory::load(inventory_path)?;
    let mut report = PlantReport::default();
    for canary in canaries {
        let sha256 = sha256_hex(canary.content.as_bytes());
        if let Some(known) = inventory.entries.iter().find(|e| e.path == canary.path) {
            match fs::read(&canary.path) {
                Ok(bytes) if sha256_hex(&bytes) == known.sha256 => {
                    report.unchanged.push(canary.path.clone());
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    report.skipped.push((canary.path.clone(), Skipped::Missing));
                }
                _ => {
                    report
                        .skipped
                        .push((canary.path.clone(), Skipped::Occupied));
                }
            }
            continue;
        }
        if canary.path.parent().is_none_or(|dir| !dir.is_dir()) {
            report
                .skipped
                .push((canary.path.clone(), Skipped::NoDirectory));
            continue;
        }
        inventory.entries.push(InventoryEntry {
            path: canary.path.clone(),
            kind: canary.kind,
            sha256,
        });
        inventory.save(inventory_path)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&canary.path)
        {
            Ok(mut file) => {
                file.write_all(canary.content.as_bytes())
                    .map_err(io_at(&canary.path))?;
                report.planted.push(canary.path.clone());
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                inventory.entries.pop();
                inventory.save(inventory_path)?;
                report
                    .skipped
                    .push((canary.path.clone(), Skipped::Occupied));
            }
            Err(e) => {
                inventory.entries.pop();
                inventory.save(inventory_path)?;
                return Err(io_at(&canary.path)(e));
            }
        }
    }
    Ok(report)
}

/// How an inventoried canary differs from what was planted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftKind {
    /// The file is gone.
    Missing,
    /// It is not a regular file any more (a directory, or a symlink).
    NotARegularFile,
    /// The content no longer hashes to the planted value.
    Modified,
}

/// One drifted canary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    /// The canary's path.
    pub path: PathBuf,
    /// What changed.
    pub kind: DriftKind,
}

/// Compares every inventoried canary with the disk. An empty result means all are intact.
/// A drifted canary is a fact worth reporting, not an alert by itself: the tripwire on the
/// event stream is what says who touched it.
#[must_use]
pub fn verify(inventory: &Inventory) -> Vec<Drift> {
    inventory
        .entries
        .iter()
        .filter_map(|entry| {
            let kind = match fs::symlink_metadata(&entry.path) {
                Err(_) => DriftKind::Missing,
                Ok(meta) if !meta.is_file() => DriftKind::NotARegularFile,
                Ok(_) => match fs::read(&entry.path) {
                    Ok(bytes) if sha256_hex(&bytes) == entry.sha256 => return None,
                    Ok(_) => DriftKind::Modified,
                    Err(_) => DriftKind::Missing,
                },
            };
            Some(Drift {
                path: entry.path.clone(),
                kind,
            })
        })
        .collect()
}

/// What [`remove`] did.
#[derive(Debug, Default)]
pub struct RemoveReport {
    /// Deleted.
    pub removed: Vec<PathBuf>,
    /// Already gone.
    pub missing: Vec<PathBuf>,
    /// Not deleted because the path is no longer a regular file (a symlink or directory put
    /// there since): deleting through it could remove something that is not ours.
    pub refused: Vec<PathBuf>,
    /// Could not be deleted.
    pub failed: Vec<(PathBuf, io::Error)>,
    /// Left alone and dropped from the inventory: the file at the path is no longer a
    /// canary (its content changed and it does not start with [`DECOY_HEADER`], or it is too
    /// big to be one), so it is someone's own data.
    pub foreign: Vec<PathBuf>,
}

impl RemoveReport {
    /// True when nothing is left behind: no refusal and no failure.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.refused.is_empty() && self.failed.is_empty()
    }
}

/// The most bytes of a file [`remove`] reads to decide whether it is still a canary. A
/// canary is a few hundred bytes; anything larger was replaced.
const MAX_CANARY_BYTES: u64 = 64 * 1024;

/// What [`ownership`] found at an inventoried path.
enum Ownership {
    /// Still this install's canary.
    Ours,
    /// Someone's own data that replaced the canary.
    Foreign,
    /// Not a regular file any more, or it changed while being read: a swap in progress.
    Changed,
}

/// Size and modification time: what a swap of the path for another file changes and a
/// read-only look cannot fake. Not an inode comparison, which would need a platform branch
/// this crate does not have (see [`ownership`]).
fn identity(meta: &fs::Metadata) -> (u64, Option<std::time::SystemTime>) {
    (meta.len(), meta.modified().ok())
}

/// True when the path still names a regular file that looks like the one that was opened.
fn still_the_opened_file(path: &Path, opened: &fs::Metadata) -> bool {
    fs::symlink_metadata(path).is_ok_and(|now| now.is_file() && identity(&now) == identity(opened))
}

/// Whether the file at an inventoried path is still this install's canary: unchanged, or
/// modified but still carrying the decoy header (an attacker or a tool appended to it).
/// Content that has neither is someone's own data that replaced the canary.
///
/// The file is opened once and judged from that descriptor (its type, then its content), and
/// the path is checked again afterwards: a path swapped for a symlink or another file while
/// it was read is [`Ownership::Changed`], not deleted. This narrows the race between looking
/// and deleting; it does not close it. `O_NOFOLLOW | O_NONBLOCK` on open (which also stops a
/// FIFO swapped in from blocking the open) and an inode comparison would, and both need a
/// `cfg(unix)` branch that this crate, by the platform-code rule, does not have.
fn ownership(entry: &InventoryEntry) -> io::Result<Ownership> {
    use io::Read as _;
    let file = fs::File::open(&entry.path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Ok(Ownership::Changed);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CANARY_BYTES + 1).read_to_end(&mut bytes)?;
    if !still_the_opened_file(&entry.path, &opened) {
        return Ok(Ownership::Changed);
    }
    if bytes.len() as u64 > MAX_CANARY_BYTES {
        return Ok(Ownership::Foreign);
    }
    let ours = sha256_hex(&bytes) == entry.sha256 || bytes.starts_with(DECOY_HEADER.as_bytes());
    Ok(if ours {
        Ownership::Ours
    } else {
        Ownership::Foreign
    })
}

/// Deletes every canary in the inventory at `inventory_path`, then the inventory itself if
/// nothing was refused or failed. A canary that was modified is still deleted as long as it
/// carries the decoy header; one replaced by other content is left alone and reported in
/// [`RemoveReport::foreign`]. One that is no longer a regular file is refused.
///
/// # Errors
///
/// [`DeceptionError`] if the inventory cannot be read or rewritten.
pub fn remove(inventory_path: &Path) -> Result<RemoveReport, DeceptionError> {
    let mut inventory = Inventory::load(inventory_path)?;
    let mut report = RemoveReport::default();
    let mut kept = Vec::new();
    for entry in inventory.entries.drain(..) {
        match fs::symlink_metadata(&entry.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => report.missing.push(entry.path),
            Err(e) => {
                report.failed.push((entry.path.clone(), e));
                kept.push(entry);
            }
            Ok(meta) if !meta.is_file() => {
                report.refused.push(entry.path.clone());
                kept.push(entry);
            }
            Ok(_) => match ownership(&entry) {
                Ok(Ownership::Ours) => match fs::remove_file(&entry.path) {
                    Ok(()) => report.removed.push(entry.path),
                    Err(e) => {
                        report.failed.push((entry.path.clone(), e));
                        kept.push(entry);
                    }
                },
                Ok(Ownership::Foreign) => report.foreign.push(entry.path),
                Ok(Ownership::Changed) => {
                    report.refused.push(entry.path.clone());
                    kept.push(entry);
                }
                Err(e) => {
                    report.failed.push((entry.path.clone(), e));
                    kept.push(entry);
                }
            },
        }
    }
    if kept.is_empty() {
        match fs::remove_file(inventory_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_at(inventory_path)(e)),
        }
    } else {
        inventory.entries = kept;
        inventory.save(inventory_path)?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Placement, Seed, plan};

    fn setup() -> (tempfile::TempDir, PathBuf, Vec<Canary>) {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().join("share");
        fs::create_dir(&share).unwrap();
        let canaries = plan(
            &Seed::from_bytes([5; 32]),
            &[Placement {
                dir: share,
                kinds: vec![Kind::Credentials, Kind::Finance],
            }],
        );
        let inventory = dir.path().join("canaries.json");
        (dir, inventory, canaries)
    }

    #[test]
    fn plant_creates_the_files_and_inventories_them() {
        let (_dir, inventory, canaries) = setup();
        let report = plant(&canaries, &inventory).unwrap();
        assert_eq!(report.planted.len(), 2);
        for c in &canaries {
            assert_eq!(fs::read_to_string(&c.path).unwrap(), c.content);
        }
        let saved = Inventory::load(&inventory).unwrap();
        assert_eq!(saved.entries.len(), 2);
        assert!(verify(&saved).is_empty());
    }

    #[test]
    fn planting_twice_changes_nothing() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        let again = plant(&canaries, &inventory).unwrap();
        assert!(again.planted.is_empty());
        assert_eq!(again.unchanged.len(), 2);
        assert_eq!(Inventory::load(&inventory).unwrap().entries.len(), 2);
    }

    #[test]
    fn a_deleted_canary_is_reported_missing_and_not_recreated() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        fs::remove_file(&canaries[0].path).unwrap();
        let again = plant(&canaries, &inventory).unwrap();
        assert_eq!(
            again.skipped,
            vec![(canaries[0].path.clone(), Skipped::Missing)]
        );
        assert!(!canaries[0].path.exists());
    }

    #[test]
    fn a_canary_replaced_by_another_file_is_occupied_not_missing() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        fs::write(&canaries[0].path, "someone else's content").unwrap();
        let again = plant(&canaries, &inventory).unwrap();
        assert_eq!(
            again.skipped,
            vec![(canaries[0].path.clone(), Skipped::Occupied)]
        );
    }

    #[test]
    fn an_existing_file_is_never_overwritten_or_inventoried() {
        let (_dir, inventory, canaries) = setup();
        fs::write(&canaries[0].path, "the user's own file").unwrap();
        let report = plant(&canaries, &inventory).unwrap();
        assert_eq!(report.planted.len(), 1);
        assert_eq!(
            report.skipped,
            vec![(canaries[0].path.clone(), Skipped::Occupied)]
        );
        assert_eq!(
            fs::read_to_string(&canaries[0].path).unwrap(),
            "the user's own file"
        );
        let saved = Inventory::load(&inventory).unwrap();
        assert!(saved.entries.iter().all(|e| e.path != canaries[0].path));
        // And removing must not delete the user's file.
        remove(&inventory).unwrap();
        assert!(canaries[0].path.exists());
    }

    #[test]
    fn a_missing_directory_is_skipped_not_created() {
        let (dir, inventory, _) = setup();
        let gone = dir.path().join("not-there");
        let canaries = plan(
            &Seed::from_bytes([6; 32]),
            &[Placement {
                dir: gone.clone(),
                kinds: vec![Kind::Notes],
            }],
        );
        let report = plant(&canaries, &inventory).unwrap();
        assert_eq!(report.skipped[0].1, Skipped::NoDirectory);
        assert!(!gone.exists());
    }

    #[test]
    fn remove_deletes_every_canary_and_the_inventory() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        let report = remove(&inventory).unwrap();
        assert_eq!(report.removed.len(), 2);
        assert!(report.is_clean());
        assert!(canaries.iter().all(|c| !c.path.exists()));
        assert!(!inventory.exists(), "no residue: the inventory goes too");
    }

    #[test]
    fn a_modified_canary_keeping_its_header_is_removed() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        let mut grown = canaries[0].content.clone();
        grown.push_str("\nappended by someone");
        fs::write(&canaries[0].path, grown).unwrap();
        let report = remove(&inventory).unwrap();
        assert!(report.foreign.is_empty());
        assert!(!canaries[0].path.exists());
    }

    #[test]
    fn a_canary_replaced_by_the_users_own_data_is_left_alone_and_dropped() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        fs::write(&canaries[0].path, "my real passwords").unwrap();
        let report = remove(&inventory).unwrap();
        assert_eq!(report.foreign, vec![canaries[0].path.clone()]);
        assert!(report.is_clean());
        assert_eq!(
            fs::read_to_string(&canaries[0].path).unwrap(),
            "my real passwords"
        );
        assert!(!canaries[1].path.exists());
        assert!(!inventory.exists());
    }

    #[test]
    fn a_large_replacement_is_left_alone() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        let mut big = DECOY_HEADER.to_string();
        big.push_str(&"x".repeat(MAX_CANARY_BYTES as usize));
        fs::write(&canaries[0].path, big).unwrap();
        let report = remove(&inventory).unwrap();
        assert_eq!(report.foreign.len(), 1);
        assert!(canaries[0].path.exists());
    }

    #[test]
    fn a_stale_inventory_temp_file_does_not_block_saving() {
        let (_dir, inventory, canaries) = setup();
        fs::write(inventory.with_extension("tmp"), "left by a crash").unwrap();
        plant(&canaries, &inventory).unwrap();
        assert_eq!(Inventory::load(&inventory).unwrap().entries.len(), 2);
        assert!(!inventory.with_extension("tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_at_the_temp_name_is_not_written_through() {
        let (dir, inventory, canaries) = setup();
        let victim = dir.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        std::os::unix::fs::symlink(&victim, inventory.with_extension("tmp")).unwrap();
        plant(&canaries, &inventory).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(Inventory::load(&inventory).unwrap().entries.len(), 2);
    }

    #[test]
    fn a_path_that_changed_since_it_was_opened_is_not_the_opened_file() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        let path = &canaries[0].path;
        let opened = fs::metadata(path).unwrap();
        assert!(still_the_opened_file(path, &opened));
        // Grown in place (size changes), then replaced by something that is not a file.
        fs::write(path, "a different, longer content than the canary had").unwrap();
        assert!(!still_the_opened_file(path, &opened));
        fs::remove_file(path).unwrap();
        fs::create_dir(path).unwrap();
        assert!(!still_the_opened_file(path, &opened));
        fs::remove_dir(path).unwrap();
        assert!(!still_the_opened_file(path, &opened));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_swapped_in_after_the_open_is_not_the_opened_file() {
        let (dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        let path = &canaries[0].path;
        let opened = fs::metadata(path).unwrap();
        let target = dir.path().join("users-file");
        fs::write(&target, &canaries[0].content).unwrap();
        fs::remove_file(path).unwrap();
        std::os::unix::fs::symlink(&target, path).unwrap();
        assert!(!still_the_opened_file(path, &opened));
    }

    #[test]
    fn a_modified_canary_is_reported_by_verify_and_still_removed() {
        let (_dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        fs::write(
            &canaries[0].path,
            format!("{}\ntampered with", canaries[0].content),
        )
        .unwrap();
        fs::remove_file(&canaries[1].path).unwrap();
        let drift = verify(&Inventory::load(&inventory).unwrap());
        assert_eq!(
            drift,
            vec![
                Drift {
                    path: canaries[0].path.clone(),
                    kind: DriftKind::Modified
                },
                Drift {
                    path: canaries[1].path.clone(),
                    kind: DriftKind::Missing
                },
            ]
        );
        let report = remove(&inventory).unwrap();
        assert_eq!(report.removed, vec![canaries[0].path.clone()]);
        assert_eq!(report.missing, vec![canaries[1].path.clone()]);
        assert!(report.is_clean());
    }

    #[cfg(unix)]
    #[test]
    fn a_canary_replaced_by_a_symlink_is_refused_not_followed() {
        let (dir, inventory, canaries) = setup();
        plant(&canaries, &inventory).unwrap();
        let precious = dir.path().join("precious");
        fs::write(&precious, "keep me").unwrap();
        fs::remove_file(&canaries[0].path).unwrap();
        std::os::unix::fs::symlink(&precious, &canaries[0].path).unwrap();

        let report = remove(&inventory).unwrap();

        assert_eq!(report.refused, vec![canaries[0].path.clone()]);
        assert!(!report.is_clean());
        assert_eq!(fs::read_to_string(&precious).unwrap(), "keep me");
        assert!(
            inventory.exists(),
            "the inventory keeps what was not removed"
        );
        assert_eq!(Inventory::load(&inventory).unwrap().entries.len(), 1);
    }

    #[test]
    fn a_corrupt_or_future_inventory_is_an_error_not_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canaries.json");
        fs::write(&path, "not json").unwrap();
        assert!(matches!(
            Inventory::load(&path),
            Err(DeceptionError::Corrupt { .. })
        ));
        fs::write(&path, r#"{"version": 99, "entries": []}"#).unwrap();
        assert!(matches!(
            Inventory::load(&path),
            Err(DeceptionError::Corrupt { .. })
        ));
        assert!(
            Inventory::load(&dir.path().join("absent.json"))
                .unwrap()
                .entries
                .is_empty()
        );
    }
}
