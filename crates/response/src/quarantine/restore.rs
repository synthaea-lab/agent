//! Listing what is quarantined and putting a file back.

#[cfg(unix)]
use super::copy::restore_file_with_mode;
use super::copy::{move_file_no_clobber, sha256_file};
use super::invalid;
use super::origin::decode_origin_record;
use super::permissions::{secure_existing_files, secure_quarantine_dir};
use super::slots::{is_sha256_hex, parse_slot_stem, quarantine_slots, sidecar_slot};
use std::path::{Path, PathBuf};

/// Reverses one [`quarantine_file`](super::quarantine_file) operation for `sha256_hex`: moves one matching
/// payload back to its original path and removes that slot's sidecar. If identical
/// payloads came from multiple paths, repeated calls restore each slot in turn. New
/// sidecars restore the original Unix mode; older path-only sidecars restore with the
/// safe read-only, non-executable `0400` mode.
///
/// # Errors
///
/// Propagates any I/O failure (sidecar missing, restore path unwritable, ...) — unlike
/// the outcome enums above, this is a direct action an analyst invoked and expects to
/// know about immediately if it didn't work. Also fails, changing nothing, with
/// `InvalidData` when `sha256_hex` is not a lowercase SHA-256 digest or the stored file
/// no longer hashes to its name, and with `AlreadyExists` when the original path is
/// occupied (a restore never overwrites). Once the file is back at its original path
/// the restore has succeeded: failing to remove the quarantined copy or the sidecar
/// afterwards is not an error, and [`is_still_quarantined`] reports it. A failure
/// before that point changes nothing, including on the cross-filesystem copy path,
/// where a half-written destination is removed.
pub fn unquarantine(quarantine_dir: &Path, sha256_hex: &str) -> std::io::Result<PathBuf> {
    // The digest becomes a file name under `quarantine_dir`: refuse anything that
    // is not exactly what `quarantine_file` writes, so it cannot name a path
    // outside the directory.
    if !is_sha256_hex(sha256_hex) {
        return Err(invalid("not a lowercase SHA-256 hex digest"));
    }
    // Nothing was ever quarantined here: say so before `secure_quarantine_dir` creates the
    // directory or changes the mode of one somebody else made.
    if let Err(error) = std::fs::symlink_metadata(quarantine_dir)
        && error.kind() == std::io::ErrorKind::NotFound
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no payload with this digest is quarantined",
        ));
    }
    secure_quarantine_dir(quarantine_dir)?;
    secure_existing_files(quarantine_dir)?;
    let slots = quarantine_slots(quarantine_dir, sha256_hex)?;
    if slots.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no payload with this digest is quarantined",
        ));
    }

    let mut occupied = None;
    let mut tampered = None;
    for (stored, origin_path) in slots {
        if !stored.exists() {
            continue;
        }
        let sidecar = std::fs::read(&origin_path)?;
        if sidecar.is_empty() {
            continue;
        }
        let record = decode_origin_record(&sidecar)?;
        let original = record.original;

        // Every slot is named from the content digest; reject tampering before
        // giving a quarantined payload back to an operator.
        // A slot that no longer matches is reported, but the slots after it are still tried:
        // one tampered copy must not make an intact one unrecoverable.
        if sha256_file(&stored)? != sha256_hex {
            tampered = Some(invalid("quarantined file no longer matches its hash"));
            continue;
        }
        #[cfg(unix)]
        let restore = match record.mode {
            Some(mode) => restore_file_with_mode(&stored, &original, mode & 0o777, sha256_hex),
            None => move_file_no_clobber(&stored, &original),
        };
        #[cfg(not(unix))]
        let restore = move_file_no_clobber(&stored, &original);
        match restore {
            Ok(()) => {
                let _ = std::fs::remove_file(&origin_path);
                return Ok(original);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                occupied = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(tampered.or(occupied).unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no restorable payload with this digest is quarantined",
        )
    }))
}

/// One payload waiting in a quarantine directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedFile {
    /// SHA-256 of the payload: its file name in the quarantine directory and the
    /// argument [`unquarantine`] takes.
    pub sha256_hex: String,
    /// Where it was before it was quarantined, and where [`unquarantine`] puts it back.
    pub original: PathBuf,
}

/// Lists what is in `quarantine_dir`, sorted by digest and original path. A directory that does
/// not exist yet lists as empty: nothing has been quarantined.
///
/// # Errors
///
/// Propagates a failure reading or securing the directory. A malformed or unreadable
/// sidecar is warned about and skipped so one bad companion cannot hide other entries.
/// A sidecar whose name is not a digest slot is not one of ours and is skipped. Existing
/// entries are tightened on Unix when this command is used.
pub fn list_quarantined(quarantine_dir: &Path) -> std::io::Result<Vec<QuarantinedFile>> {
    match std::fs::read_dir(quarantine_dir) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    secure_quarantine_dir(quarantine_dir)?;
    secure_existing_files(quarantine_dir)?;
    let entries = std::fs::read_dir(quarantine_dir)?;
    let mut found = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let Some((sha256_hex, _slot)) = sidecar_slot(&path) else {
            continue;
        };
        let Some(stored_name) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".origin"))
        else {
            continue;
        };
        let stored = path.with_file_name(stored_name);
        if !stored.is_file() {
            continue;
        }
        let sidecar = match std::fs::read(&path) {
            Ok(sidecar) => sidecar,
            Err(error) => {
                tracing::warn!(
                    sidecar = %path.display(),
                    %error,
                    "ignoring unreadable quarantine sidecar"
                );
                continue;
            }
        };
        if sidecar.is_empty() {
            tracing::warn!(
                sidecar = %path.display(),
                "ignoring empty quarantine sidecar"
            );
            continue;
        }
        let record = match decode_origin_record(&sidecar) {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(
                    sidecar = %path.display(),
                    %error,
                    "ignoring invalid quarantine sidecar"
                );
                continue;
            }
        };
        found.push(QuarantinedFile {
            sha256_hex,
            original: record.original,
        });
    }
    found.sort_by(|a, b| {
        a.sha256_hex
            .cmp(&b.sha256_hex)
            .then_with(|| a.original.cmp(&b.original))
    });
    Ok(found)
}

/// Whether anything of `sha256_hex` is still in `quarantine_dir`: the stored
/// payload or its sidecar. After a successful [`unquarantine`] this should be
/// `false`; `true` means a cleanup step failed after the file was restored (a
/// read-only or busy quarantine directory), which the caller should report.
#[must_use]
pub fn is_still_quarantined(quarantine_dir: &Path, sha256_hex: &str) -> bool {
    if !is_sha256_hex(sha256_hex) {
        return false;
    }
    std::fs::read_dir(quarantine_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            let stem = name.strip_suffix(".origin").unwrap_or(name);
            parse_slot_stem(stem)
        })
        .any(|(digest, _)| digest == sha256_hex)
}
