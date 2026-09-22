//! The local ban list (ADR-0015 Decision 6): release versions that failed a
//! previous health check on this install and must be refused even if offered
//! again. A bare JSON array — no signature needed, since it only ever narrows
//! what this specific install will accept, the same trust boundary as the
//! install itself.

use std::{collections::BTreeSet, fs, io, path::Path};

use crate::error::UpdaterError;

/// The set of release versions banned on this install.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BannedVersions(BTreeSet<u64>);

impl BannedVersions {
    /// Loads the ban list from `path`. A missing file is an empty ban list — no
    /// release has ever failed a health check here yet — not an error.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if `path` exists but cannot be read, or its content
    /// is not a JSON array of integers.
    pub fn load(path: &Path) -> Result<Self, UpdaterError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(UpdaterError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let versions: Vec<u64> = serde_json::from_str(&text).map_err(|err| UpdaterError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, err),
        })?;
        Ok(Self(versions.into_iter().collect()))
    }

    /// Writes the ban list to `path` as a bare, sorted JSON array of integers.
    ///
    /// # Errors
    ///
    /// [`UpdaterError::Io`] if `path` cannot be written.
    ///
    /// # Panics
    ///
    /// Never — `Vec<u64>` has no content `serde_json` could fail to serialize.
    pub fn save(&self, path: &Path) -> Result<(), UpdaterError> {
        let versions: Vec<u64> = self.0.iter().copied().collect();
        let text = serde_json::to_string_pretty(&versions)
            .expect("Vec<u64> has no non-serializable content");
        fs::write(path, text).map_err(|source| UpdaterError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Marks `release_version` as banned. Idempotent.
    pub fn ban(&mut self, release_version: u64) {
        self.0.insert(release_version);
    }

    /// Whether `release_version` has previously failed a health check on this
    /// install.
    #[must_use]
    pub fn is_banned(&self, release_version: u64) -> bool {
        self.0.contains(&release_version)
    }

    /// Gate a manifest offer against the ban list — the caller-facing counterpart
    /// to [`Self::is_banned`] for a verification pipeline that wants a `Result`,
    /// alongside [`crate::ReleaseManifest::verify_signature`] and
    /// [`crate::ReleaseManifest::check_release_version`].
    ///
    /// # Errors
    ///
    /// [`UpdaterError::ReleaseBanned`] if `release_version` [`Self::is_banned`].
    pub fn check(&self, release_version: u64) -> Result<(), UpdaterError> {
        if self.is_banned(release_version) {
            Err(UpdaterError::ReleaseBanned(release_version))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loading_a_missing_file_is_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_versions.json");
        let loaded = BannedVersions::load(&path).unwrap();
        assert!(!loaded.is_banned(1));
    }

    #[test]
    fn a_banned_version_round_trips_through_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_versions.json");

        let mut banned = BannedVersions::default();
        banned.ban(7);
        banned.save(&path).unwrap();

        let loaded = BannedVersions::load(&path).unwrap();
        assert!(loaded.is_banned(7));
        assert!(!loaded.is_banned(8));
    }

    #[test]
    fn banning_is_idempotent() {
        let mut banned = BannedVersions::default();
        banned.ban(3);
        banned.ban(3);
        assert!(banned.is_banned(3));
        assert_eq!(banned.0.len(), 1);
    }

    #[test]
    fn the_saved_file_is_a_bare_json_array() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_versions.json");
        let mut banned = BannedVersions::default();
        banned.ban(2);
        banned.ban(1);
        banned.save(&path).unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value, serde_json::json!([1, 2]));
    }

    #[test]
    fn check_turns_a_banned_release_into_an_error() {
        let mut banned = BannedVersions::default();
        banned.ban(4);
        assert!(banned.check(3).is_ok());
        assert!(matches!(
            banned.check(4),
            Err(UpdaterError::ReleaseBanned(4))
        ));
    }

    #[test]
    fn corrupt_content_is_rejected_not_silently_treated_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_versions.json");
        fs::write(&path, "{ not json").unwrap();
        assert!(BannedVersions::load(&path).is_err());
    }
}
