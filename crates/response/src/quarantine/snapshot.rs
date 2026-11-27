//! The private copy quarantine takes of a file it cannot move, and the sweep of copies left behind.

use std::path::{Path, PathBuf};

use super::{copy::sha256_copy, source::Source, store_in_slot};

/// Quarantines a source that is being written to: copies it from the descriptor into a private
/// file in the quarantine directory, hashing the bytes as they are copied, and files that
/// copy under that digest. The stored bytes and their digest agree by construction, whatever
/// the writer does, and the writer cannot stop the quarantine. The source's name is removed
/// afterwards, only while it still names the opened file.
#[cfg(unix)]
pub(super) fn quarantine_snapshot(
    source: &Source,
    path: &Path,
    quarantine_dir: &Path,
) -> std::io::Result<(PathBuf, String)> {
    // `_in_flight` keeps the advisory lock on the temporary file until it is in its slot or
    // removed, so that no sweep of another process takes it for a leftover.
    let (temp, sha256_hex, _in_flight) =
        copy_prefix_hashed(&source.file, quarantine_dir, source.snapshot.0)?;
    let stored = Source::open(&temp)
        .and_then(|snapshot| store_in_slot(&snapshot, &temp, path, quarantine_dir, &sha256_hex));
    // Gone already once the snapshot was moved into its slot; this covers a failure.
    let _ = std::fs::remove_file(&temp);
    let quarantined_at = stored?;
    if let Err(error) = source.remove_name_if_same(path) {
        let _ = std::fs::remove_file(&quarantined_at);
        if let Some(name) = quarantined_at.file_name().and_then(|n| n.to_str()) {
            let _ = std::fs::remove_file(quarantined_at.with_file_name(format!("{name}.origin")));
        }
        return Err(error);
    }
    Ok((quarantined_at, sha256_hex))
}

/// How long a partial snapshot must have been left alone before a sweep may take it, so that
/// one that has just been created (and not yet locked) is not taken.
#[cfg(unix)]
pub(super) const SNAPSHOT_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a partial snapshot must have been left alone before a sweep may take it when the
/// filesystem cannot lock files at all (some NFS and FUSE mounts): nothing then marks a
/// snapshot in flight but its modification time, which the copy keeps fresh while it writes.
#[cfg(unix)]
pub(super) const UNLOCKABLE_GRACE: std::time::Duration = std::time::Duration::from_secs(3600);

/// What an attempt at the advisory lock of a snapshot found.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SnapshotLock {
    /// The lock was taken: no snapshot in flight holds this file.
    Acquired,
    /// Another descriptor holds it (or the answer is unclear): a snapshot may be in flight.
    Held,
    /// The filesystem does not support `flock`: the lock says nothing either way.
    Unsupported,
}

/// Takes the advisory lock a snapshot holds while it is in flight, without waiting.
#[cfg(unix)]
pub(super) fn try_lock_exclusive(file: &std::fs::File) -> SnapshotLock {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `flock` on a descriptor that stays open for the whole call; it retains nothing.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return SnapshotLock::Acquired;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOLCK | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL) => {
            SnapshotLock::Unsupported
        }
        _ => SnapshotLock::Held,
    }
}

/// Whether a sweep may take a snapshot that is `age` old and whose lock attempt gave `lock`.
/// Where locks work, the lock decides; where they do not, only a long silence does.
#[cfg(unix)]
pub(super) fn may_take_snapshot(age: std::time::Duration, lock: &SnapshotLock) -> bool {
    age >= SNAPSHOT_GRACE
        && match lock {
            SnapshotLock::Acquired => true,
            SnapshotLock::Held => false,
            SnapshotLock::Unsupported => age >= UNLOCKABLE_GRACE,
        }
}

/// Removes the partial snapshots (`.incoming-<pid>-<n>`) that a process which was killed
/// mid-copy left in `dir`. A snapshot in flight, of this process or of any other (a second
/// agent, the CLI), holds an advisory lock on its file, so a file is taken only when the lock
/// can be had and it is older than [`SNAPSHOT_GRACE`]. That does not depend on the pid, which
/// is the same (1) for every process in a container. On a filesystem without `flock` a file
/// is taken only after [`UNLOCKABLE_GRACE`] without a write. Best effort.
#[cfg(unix)]
pub(super) fn sweep_stale_snapshots(dir: &Path) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(".incoming-")) else {
            continue;
        };
        if rest
            .split('-')
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        // Like `Source::open`: never follow a link, never block on a FIFO. Only a regular file
        // is a snapshot; anything else under that name is left alone.
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(entry.path())
        else {
            continue;
        };
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        let Some(age) = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .filter(|_| metadata.is_file())
        else {
            continue;
        };
        // Only a file old enough is locked at all: a fresh one may not have been locked by its
        // own snapshot yet, and taking the lock here would make that attempt fail.
        if age >= SNAPSHOT_GRACE && may_take_snapshot(age, &try_lock_exclusive(&file)) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Copies the first `len` bytes of the open file (rewound) to a new private file in `dir`,
/// returning its path and the SHA-256 of the bytes written to it. The caller passes the length
/// the file had when it was opened, so a writer that keeps appending cannot make the hash or
/// the copy grow, or run, without bound (the stored bytes are a consistent prefix and the
/// digest is that prefix's). The returned file holds the advisory lock that tells a sweep the
/// snapshot is in flight: the caller keeps it until the snapshot is stored or removed.
#[cfg(unix)]
pub(super) fn copy_prefix_hashed(
    file: &std::fs::File,
    dir: &Path,
    len: u64,
) -> std::io::Result<(PathBuf, String, std::fs::File)> {
    use std::{
        io::{Read as _, Seek as _},
        os::unix::fs::OpenOptionsExt as _,
    };
    let mut source = file.try_clone()?;
    source.rewind()?;
    let mut source = source.take(len);
    let mut attempt = 0u64;
    let (temp, mut out) = loop {
        let temp = dir.join(format!(".incoming-{}-{attempt}", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(out) => break (temp, out),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.checked_add(1).ok_or(error)?;
            }
            Err(error) => return Err(error),
        }
    };
    // Nobody else can hold the lock of a file that did not exist a moment ago; a failure here
    // is not worth failing the snapshot for. Without the lock, only the grace period protects
    // the file, and only while the copy keeps writing (its mtime stays fresh): a copy that
    // stalls for longer than `SNAPSHOT_GRACE` on a slow device could be swept by another
    // process. That is accepted, because it needs a failed lock on a new file and a stall.
    let _ = try_lock_exclusive(&out);
    match sha256_copy(&mut source, &mut out).and_then(|digest| out.sync_all().map(|()| digest)) {
        Ok(digest) => Ok((temp, digest, out)),
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            Err(error)
        }
    }
}

/// Raised between the hash and the store when the source was written to in that window:
/// the caller takes a snapshot and hashes that instead of refusing.
#[cfg(unix)]
#[derive(Debug)]
pub(super) struct WrittenAfterHash;

#[cfg(unix)]
impl std::fmt::Display for WrittenAfterHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the quarantine source was written to after it was hashed")
    }
}

#[cfg(unix)]
impl std::error::Error for WrittenAfterHash {}

#[cfg(unix)]
pub(super) fn is_written_after_hash(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<WrittenAfterHash>())
}
