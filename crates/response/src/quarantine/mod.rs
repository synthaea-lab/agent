//! Automated quarantine of a payload a scan confirms malicious (issue #25).
//!
//! A quarantined file is moved into `quarantine_dir`, named by its SHA-256 hex digest
//! (with a numeric suffix when identical payloads come from multiple paths), made
//! non-executable on Unix, and paired with an `.origin` sidecar holding its original
//! path and original Unix mode — the state [`unquarantine`] needs to reverse the action
//! (issue #25: "reversible where possible"). Legacy sidecars contain only the path and
//! restore with the safe `0400` mode.
//!
//! On Unix the source is opened once (`O_NOFOLLOW`, checked with `fstat`) and then hashed and
//! moved through that descriptor, so a name swapped for a symlink after the check cannot
//! redirect the move or the `chmod` (#689). Known limits: `O_NOFOLLOW` covers the last path
//! component only, so a symlinked parent directory under an attacker's control is still
//! followed (`openat2` with `RESOLVE_NO_SYMLINKS`, Linux 5.6+, would close that); and the
//! check of the source's name and its removal are not atomic. A source that is written to
//! while it is processed is not refused (a writer could then defeat the quarantine): it is
//! copied from the descriptor into a private file, hashed as it is copied and filed under that
//! digest, so the stored bytes and their digest agree whatever the writer does; the copy is
//! bounded, like the hash that precedes it, to the length the file had when it was opened, so a
//! writer that keeps appending cannot make either grow or run without end, and a snapshot left
//! by a killed agent is swept at the next quarantine (an in-flight one is protected by an
//! advisory lock; on a filesystem without `flock`, such as some NFS and FUSE mounts, only a
//! snapshot untouched for an hour is taken). Bytes appended after the open are not stored: the outcome is still
//! `Quarantined`, with the digest of the prefix. A write is noticed from the size and the
//! modification time, so one that keeps both (an overwrite within a single timestamp tick, a
//! write through a shared mapping) can go unnoticed; this depends on the filesystem and was not
//! measured. The re-check after the link or the copy narrows the window between the hash and
//! the removal of the source name but cannot close it: a write after the last check still
//! leaves stored bytes that differ from the digest (`restore` then reports a mismatch).
//! When the file is copied rather than linked, only the opened name is removed:
//! other hard links to the original inode keep their execute bits. A hard-linked
//! payload shares its inode with the source, so a process that already holds it open for
//! writing can still change the quarantined file (`restore` then reports a hash mismatch);
//! containment holds, since it is `0400` and no name is left at the source.
//!
//! Unix permissions are tightened here because `set_readonly` alone preserves the
//! execute bits. The Windows agent does not wire automated quarantine yet. A Windows ACL
//! restricted to SYSTEM and Administrators is not implemented here because it cannot be
//! compile-checked in this sandbox; its ACL policy must be established before that path is
//! enabled.
//!
//! The quarantine directory's final component and each file whose mode is tightened are
//! opened without following symlinks, and permissions are applied through those descriptors.
//! This prevents a concurrent symlink swap from redirecting a mode change. Parent path
//! components are still followed, and a process running as the quarantine owner (or with
//! equivalent privilege) can still replace entries or edit sidecar contents; `0700` isolates
//! other local users, not another process with the same identity.

use policy::ResponsePolicy;
use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

mod copy;
mod origin;
mod permissions;
mod restore;
mod slots;
mod snapshot;
mod source;

pub use self::restore::{QuarantinedFile, is_still_quarantined, list_quarantined, unquarantine};

use self::copy::move_file_no_clobber;
use self::origin::encode_origin_record;
use self::permissions::{
    secure_existing_files, secure_payload, secure_quarantine_dir, secure_sidecar,
};
use self::slots::slot_stem;
#[cfg(unix)]
use self::snapshot::is_written_after_hash;
#[cfg(unix)]
use self::snapshot::quarantine_snapshot;
#[cfg(unix)]
use self::snapshot::sweep_stale_snapshots;
use self::source::Source;

/// What happened to a quarantine attempt — see [`crate::kill::KillOutcome`] for why
/// this is one enum covering both the acted and observe-only cases rather than two
/// separate code paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    /// `path` was moved into `quarantine_dir` under a digest-based name. Identical
    /// payloads use a numeric suffix so each original path has its own record.
    Quarantined {
        /// The path the file had before it was moved.
        original: PathBuf,
        /// Where the file now lives inside `quarantine_dir`.
        quarantined_at: PathBuf,
        /// Lowercase hex SHA-256 of the quarantined content.
        sha256_hex: String,
    },
    /// `policy.quarantine_enabled` was false — `path` was left untouched.
    ObserveOnly {
        /// The path that would have been quarantined.
        path: PathBuf,
    },
    /// Policy allowed it, but hashing or the move failed (already gone, permission
    /// denied, ...). `error` is the underlying `io::Error` rendered to a string.
    Failed {
        /// The path whose quarantine failed.
        path: PathBuf,
        /// The underlying `io::Error`, rendered to a string.
        error: String,
    },
}

/// Policy-gates quarantining `path` into `quarantine_dir` (created if missing).
///
/// # Errors
///
/// Never returns `Err`; a failure hashing or moving the file is reported as
/// [`QuarantineOutcome::Failed`] for the same reason [`crate::kill::kill_process`]
/// reports rather than propagates.
#[must_use]
pub fn quarantine_file(
    path: &Path,
    quarantine_dir: &Path,
    policy: &ResponsePolicy,
) -> QuarantineOutcome {
    if !policy.quarantine_enabled {
        return QuarantineOutcome::ObserveOnly {
            path: path.to_path_buf(),
        };
    }
    match try_quarantine(path, quarantine_dir) {
        Ok((quarantined_at, sha256_hex)) => QuarantineOutcome::Quarantined {
            original: path.to_path_buf(),
            quarantined_at,
            sha256_hex,
        },
        Err(e) => QuarantineOutcome::Failed {
            path: path.to_path_buf(),
            error: e.to_string(),
        },
    }
}

fn try_quarantine(path: &Path, quarantine_dir: &Path) -> std::io::Result<(PathBuf, String)> {
    // Open once and do everything from that descriptor (#689): the check, the hash and the
    // move then all concern one inode, whatever happens to the path in between.
    let source = Source::open(path)?;
    let sha256_hex = source.sha256(path)?;
    secure_quarantine_dir(quarantine_dir)?;
    // Tighten legacy entries, including orphaned or pre-created wide files, before using the
    // directory again. A failure is fail-closed: do not add a new payload to an insecure store.
    secure_existing_files(quarantine_dir)?;
    // A leftover of a killed agent goes at the next quarantine, written source or not.
    #[cfg(unix)]
    sweep_stale_snapshots(quarantine_dir);

    // Somebody is writing to the file (a dropper still downloading, or an attacker keeping it
    // busy): the digest may not be the digest of what a link or a copy would now store.
    // Refusing would let a writer defeat the quarantine, so take a private snapshot instead.
    #[cfg(unix)]
    if source.written_since_open()? {
        return quarantine_snapshot(&source, path, quarantine_dir);
    }
    match store_in_slot(&source, path, path, quarantine_dir, &sha256_hex) {
        #[cfg(unix)]
        Err(error) if is_written_after_hash(&error) => {
            quarantine_snapshot(&source, path, quarantine_dir)
        }
        stored => stored.map(|quarantined_at| (quarantined_at, sha256_hex)),
    }
}

/// Reserves a slot for `sha256_hex`, then moves `source` (named `from`) into it. `origin`
/// is the path recorded in the sidecar, which [`unquarantine`] restores to.
fn store_in_slot(
    source: &Source,
    from: &Path,
    origin: &Path,
    quarantine_dir: &Path,
    sha256_hex: &str,
) -> std::io::Result<PathBuf> {
    // Reserve the sidecar before moving the source. A failed sidecar write leaves
    // the source untouched; a later move failure removes the reservation. Each
    // duplicate digest receives its own slot so every live copy is contained.
    let mut slot = 0u64;
    loop {
        let stem = slot_stem(sha256_hex, slot);
        let quarantined_at = quarantine_dir.join(&stem);
        let origin_path = quarantine_dir.join(format!("{stem}.origin"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut sidecar = match options.open(&origin_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                slot = slot.checked_add(1).ok_or(error)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let origin_record = encode_origin_record(origin, source.original_mode());
        if let Err(error) = sidecar
            .write_all(&origin_record)
            .and_then(|()| sidecar.sync_all())
        {
            drop(sidecar);
            let _ = std::fs::remove_file(&origin_path);
            return Err(error);
        }
        drop(sidecar);
        if let Err(error) = secure_sidecar(&origin_path) {
            let _ = std::fs::remove_file(&origin_path);
            return Err(error);
        }

        match move_and_secure(
            from,
            &quarantined_at,
            |from, to| source.move_into_quarantine(from, to),
            secure_payload,
            move_file_no_clobber,
        ) {
            Ok(()) => return Ok(quarantined_at),
            Err(failure) => {
                if !failure.retained_in_quarantine {
                    let _ = std::fs::remove_file(&origin_path);
                }
                if failure.error.kind() == std::io::ErrorKind::AlreadyExists
                    && !failure.retained_in_quarantine
                {
                    slot = slot.checked_add(1).ok_or(failure.error)?;
                    continue;
                }
                return Err(failure.error);
            }
        }
    }
}

struct QuarantineMoveFailure {
    error: std::io::Error,
    retained_in_quarantine: bool,
}

fn move_and_secure(
    from: &Path,
    to: &Path,
    move_file: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    secure: impl FnOnce(&Path) -> std::io::Result<()>,
    rollback: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), QuarantineMoveFailure> {
    if let Err(error) = move_file(from, to) {
        let retained_in_quarantine =
            error.kind() != std::io::ErrorKind::AlreadyExists && to.exists();
        return Err(QuarantineMoveFailure {
            error,
            retained_in_quarantine,
        });
    }
    if let Err(security_error) = secure(to) {
        return match rollback(to, from) {
            Ok(()) => Err(QuarantineMoveFailure {
                error: security_error,
                retained_in_quarantine: false,
            }),
            Err(rollback_error) => Err(QuarantineMoveFailure {
                error: std::io::Error::other(format!(
                    "could not secure the quarantined payload ({security_error}); rollback to {} failed ({rollback_error}); the payload and origin record remain in quarantine at {}",
                    from.display(),
                    to.display()
                )),
                retained_in_quarantine: true,
            }),
        };
    }
    Ok(())
}

fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
