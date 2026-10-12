//! Automated quarantine of a payload a scan confirms malicious (issue #25).
//!
//! A quarantined file is moved into `quarantine_dir`, named by its SHA-256 hex digest
//! (with a numeric suffix when identical payloads come from multiple paths), made
//! non-executable on Unix, and paired with an `.origin` sidecar holding its original
//! path — the only state [`unquarantine`] needs to reverse the action (issue #25:
//! "reversible where possible").
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
//! execute bits. The Windows agent does not wire automated quarantine yet; its ACL
//! policy must be established before that path is enabled.

use std::{
    fmt::Write as _,
    io::Write as _,
    path::{Path, PathBuf},
};

use policy::ResponsePolicy;

/// What happened to a quarantine attempt — see [`crate::kill::KillOutcome`] for why
/// this is one enum covering both the acted and observe-only cases rather than two
/// separate code paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    /// `path` was moved into `quarantine_dir` under a digest-based name. Identical
    /// payloads use a numeric suffix so each original path has its own record.
    Quarantined {
        original: PathBuf,
        quarantined_at: PathBuf,
        sha256_hex: String,
    },
    /// `policy.quarantine_enabled` was false — `path` was left untouched.
    ObserveOnly { path: PathBuf },
    /// Policy allowed it, but hashing or the move failed (already gone, permission
    /// denied, ...). `error` is the underlying `io::Error` rendered to a string.
    Failed { path: PathBuf, error: String },
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
        let mut sidecar = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&origin_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                slot = slot.checked_add(1).ok_or(error)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = sidecar
            .write_all(origin.to_string_lossy().as_bytes())
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

/// Quarantines a source that is being written to: copies it from the descriptor into a private
/// file in the quarantine directory, hashing the bytes as they are copied, and files that
/// copy under that digest. The stored bytes and their digest agree by construction, whatever
/// the writer does, and the writer cannot stop the quarantine. The source's name is removed
/// afterwards, only while it still names the opened file.
#[cfg(unix)]
fn quarantine_snapshot(
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
const SNAPSHOT_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a partial snapshot must have been left alone before a sweep may take it when the
/// filesystem cannot lock files at all (some NFS and FUSE mounts): nothing then marks a
/// snapshot in flight but its modification time, which the copy keeps fresh while it writes.
#[cfg(unix)]
const UNLOCKABLE_GRACE: std::time::Duration = std::time::Duration::from_secs(3600);

/// What an attempt at the advisory lock of a snapshot found.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum SnapshotLock {
    /// The lock was taken: no snapshot in flight holds this file.
    Acquired,
    /// Another descriptor holds it (or the answer is unclear): a snapshot may be in flight.
    Held,
    /// The filesystem does not support `flock`: the lock says nothing either way.
    Unsupported,
}

/// Takes the advisory lock a snapshot holds while it is in flight, without waiting.
#[cfg(unix)]
fn try_lock_exclusive(file: &std::fs::File) -> SnapshotLock {
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
fn may_take_snapshot(age: std::time::Duration, lock: &SnapshotLock) -> bool {
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
fn sweep_stale_snapshots(dir: &Path) {
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
fn copy_prefix_hashed(
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
struct WrittenAfterHash;

#[cfg(unix)]
impl std::fmt::Display for WrittenAfterHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the quarantine source was written to after it was hashed")
    }
}

#[cfg(unix)]
impl std::error::Error for WrittenAfterHash {}

#[cfg(unix)]
fn is_written_after_hash(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<WrittenAfterHash>())
}

/// The file being quarantined, opened once.
///
/// On Unix the source is opened with `O_NOFOLLOW` and checked with `fstat` on the descriptor,
/// then hashed and moved *through that descriptor*, so a path swapped for a symlink (or for
/// another file) after the check cannot redirect the move or the `chmod` that follows, and
/// the digest is the digest of the inode that is stored (#689). Elsewhere the path is
/// checked and used as before.
struct Source {
    #[cfg(unix)]
    file: std::fs::File,
    /// `(device, inode)` of the opened file, to recognise its name again before removing it.
    #[cfg(unix)]
    id: (u64, u64),
    /// Size and modification time at open: what an in-place write between the hash and the
    /// store changes, so that content is never stored under a digest it no longer has.
    #[cfg(unix)]
    snapshot: (u64, i64, i64),
}

#[cfg(unix)]
fn snapshot_of(metadata: &std::fs::Metadata) -> (u64, i64, i64) {
    use std::os::unix::fs::MetadataExt as _;
    (metadata.len(), metadata.mtime(), metadata.mtime_nsec())
}

fn not_a_regular_file() -> std::io::Error {
    invalid("quarantine source must be a regular, non-symlink file")
}

impl Source {
    #[cfg(unix)]
    fn open(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        // `O_NONBLOCK` so that opening a FIFO does not block: it is refused by the `fstat`
        // just below.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    not_a_regular_file()
                } else {
                    error
                }
            })?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(not_a_regular_file());
        }
        Ok(Self {
            id: (metadata.dev(), metadata.ino()),
            snapshot: snapshot_of(&metadata),
            file,
        })
    }

    #[cfg(not(unix))]
    fn open(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(not_a_regular_file());
        }
        Ok(Self {})
    }

    /// SHA-256 of the opened file (of `path` where there is no descriptor to read). Reads at
    /// most the length the file had when it was opened, so a writer that keeps appending
    /// cannot keep the hash from finishing: the digest is that of the prefix, which is what
    /// [`quarantine_snapshot`] stores if the file changed.
    fn sha256(&self, path: &Path) -> std::io::Result<String> {
        #[cfg(unix)]
        {
            use std::io::Read as _;
            let _ = path;
            sha256_reader(&mut (&self.file).take(self.snapshot.0))
        }
        #[cfg(not(unix))]
        sha256_file(path)
    }

    /// Puts the opened file into quarantine at `to` and removes its name `from`, but only
    /// while `from` still names it: a name that now points at something else is not ours to
    /// delete. Never replaces `to`.
    ///
    /// The check of `from` and the removal of its name are two steps, not one atomic one: a
    /// swap in that last window can at worst make the removal act on a link or a file that
    /// took the name. It cannot redirect what was stored, nor any `chmod` (#689).
    #[cfg(unix)]
    fn move_into_quarantine(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.move_into_quarantine_with(from, to, || {})
    }

    /// [`Self::move_into_quarantine`] with a hook that runs after the link or the copy and
    /// before the check that follows them: the only way for a test to write in that window.
    #[cfg(unix)]
    fn move_into_quarantine_with(
        &self,
        from: &Path,
        to: &Path,
        after_store: impl FnOnce(),
    ) -> std::io::Result<()> {
        if self.written_since_open()? {
            return Err(std::io::Error::other(WrittenAfterHash));
        }
        let linked = match link_open_file(&self.file, to) {
            Ok(()) => true,
            // No link to give (another filesystem, an unlinked file, too many links, a
            // filesystem or policy that refuses hard links, a platform without
            // `/proc/self/fd`): copy from the same descriptor, no further than the length
            // at open. Any other error (no space, no descriptors left) is the real answer and
            // is not turned into a possibly large copy.
            Err(error) if can_fall_back_to_copy(&error) => {
                copy_open_file_no_clobber(&self.file, to, self.snapshot.0)?;
                false
            }
            Err(error) => return Err(error),
        };
        after_store();
        // A write during the link or the copy: the digest may not be that of what is stored.
        // Undo and let the caller take a snapshot, which is hashed as it is copied.
        if self.written_since_open()? {
            let _ = std::fs::remove_file(to);
            return Err(std::io::Error::other(WrittenAfterHash));
        }
        self.release_name(from, to, linked)
    }

    /// Removes the name `from` once the opened file is stored at `to`, but only while it
    /// still names that file: a name that now points at something else is not ours to delete.
    ///
    /// When `from` was taken by something else after a hard link, the link and the name share
    /// the opened inode, which `secure_payload` then makes `0400`, so no name of it stays
    /// executable and `Ok` is the right answer. After a copy nothing ties the opened file to
    /// its other names: if it still has one it may stay executable there, so that is an error
    /// and the copy is removed. When the name was replaced or removed, the opened file has no
    /// name left (the usual swap) and disappears once closed: the copy is all that is left, so
    /// that is fine.
    #[cfg(unix)]
    fn release_name(&self, from: &Path, to: &Path, linked: bool) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        match std::fs::symlink_metadata(from) {
            Ok(m) if m.file_type().is_file() && (m.dev(), m.ino()) == self.id => {
                if let Err(error) = std::fs::remove_file(from) {
                    let _ = std::fs::remove_file(to);
                    return Err(error);
                }
            }
            Ok(_) if !linked && self.file.metadata()?.nlink() > 0 => {
                let _ = std::fs::remove_file(to);
                return Err(invalid(
                    "the source name no longer refers to the file that was checked; \
                     nothing was quarantined",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether the opened file was written to since it was opened (size or modification time
    /// differ): the digest then may not be that of what a link or a copy would store.
    #[cfg(unix)]
    fn written_since_open(&self) -> std::io::Result<bool> {
        Ok(snapshot_of(&self.file.metadata()?) != self.snapshot)
    }

    /// Removes the name `from` while it still names the opened file.
    #[cfg(unix)]
    fn remove_name_if_same(&self, from: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        match std::fs::symlink_metadata(from) {
            Ok(m) if m.file_type().is_file() && (m.dev(), m.ino()) == self.id => {
                std::fs::remove_file(from)
            }
            _ => Ok(()),
        }
    }

    #[cfg(not(unix))]
    fn move_into_quarantine(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        move_to_quarantine(from, to)
    }
}

/// Links the open file's inode at `to` without replacing anything (`AlreadyExists`
/// otherwise). Through `/proc/self/fd` with `AT_SYMLINK_FOLLOW`, the one way to link an
/// open file without privileges: the new name is that inode, whatever any path says.
#[cfg(target_os = "linux")]
fn link_open_file(file: &std::fs::File, to: &Path) -> std::io::Result<()> {
    use std::{
        ffi::CString,
        os::{fd::AsRawFd as _, unix::ffi::OsStrExt as _},
    };
    let old = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(std::io::Error::other)?;
    let new = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| invalid("quarantine path contains a NUL byte"))?;
    // SAFETY: `old` and `new` are valid NUL-terminated strings that live for the whole
    // call, and `linkat` does not retain either pointer.
    let rc = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Whether a failed `link_open_file` means "cannot link this one", for which copying from the
/// descriptor is the answer, rather than a real failure to report. `EPERM` is what `linkat`
/// returns on a filesystem without hard links (vfat) and under `fs.protected_hardlinks`;
/// `EOPNOTSUPP` is what some FUSE and network filesystems return. `EACCES` is not here: a
/// directory we cannot write to cannot take a copy either.
#[cfg(unix)]
fn can_fall_back_to_copy(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EXDEV
                || code == libc::ENOENT
                || code == libc::EMLINK
                || code == libc::EPERM
                || code == libc::EOPNOTSUPP
        )
}

/// No `/proc/self/fd` to link through: the caller copies from the descriptor instead.
#[cfg(all(unix, not(target_os = "linux")))]
fn link_open_file(_file: &std::fs::File, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Copies the open file to a new file `to` that must not exist, from the descriptor
/// (rewound), carrying its permissions. Copies at most `len` bytes (the length the file had
/// when it was opened), so a writer cannot make the copy grow without end.
#[cfg(unix)]
fn copy_open_file_no_clobber(file: &std::fs::File, to: &Path, len: u64) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _};
    let mut src = file.try_clone()?;
    src.rewind()?;
    copy_open_no_clobber_with(src, to, |src, dst| {
        std::io::copy(&mut src.take(len), dst)?;
        dst.set_permissions(src.metadata()?.permissions())
    })
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

fn slot_stem(sha256_hex: &str, slot: u64) -> String {
    if slot == 0 {
        sha256_hex.to_owned()
    } else {
        format!("{sha256_hex}.{slot}")
    }
}

fn secure_quarantine_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid("quarantine directory must not be a symlink"));
    }
    if !metadata.is_dir() {
        return Err(invalid("quarantine path must be a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
        let me = unsafe { libc::geteuid() };
        if quarantine_dir_needs_chmod(metadata.uid() == me, metadata.mode())? {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Whether an existing quarantine directory has to be set to `0700`, or is refused.
///
/// Ours: tightened, as before. Somebody else's: left alone when it already is `0700` (an
/// administrator running `list` or `restore` on the service user's directory), refused when
/// its mode would have to change, since changing the mode of a directory the agent does not
/// own is not the agent's call (#689).
#[cfg(unix)]
fn quarantine_dir_needs_chmod(owned_by_me: bool, mode: u32) -> std::io::Result<bool> {
    if owned_by_me {
        return Ok(true);
    }
    if mode & 0o7777 == 0o700 {
        return Ok(false);
    }
    Err(invalid(
        "quarantine directory is owned by another user and is not mode 0700; refusing to change it",
    ))
}

fn secure_payload(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
    }
    #[cfg(not(unix))]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)
    }
}

fn secure_sidecar(_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Reverses one [`quarantine_file`] operation for `sha256_hex`: moves one matching
/// payload back to its original path and removes that slot's sidecar. If identical
/// payloads came from multiple paths, repeated calls restore each slot in turn. The
/// restored file keeps the safe read-only, non-executable state.
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
        let content = std::fs::read_to_string(&origin_path)?;
        if content.is_empty() {
            continue;
        }
        let original = PathBuf::from(content);

        // Every slot is named from the content digest; reject tampering before
        // giving a quarantined payload back to an operator.
        // A slot that no longer matches is reported, but the slots after it are still tried:
        // one tampered copy must not make an intact one unrecoverable.
        if sha256_file(&stored)? != sha256_hex {
            tampered = Some(invalid("quarantined file no longer matches its hash"));
            continue;
        }
        match move_file_no_clobber(&stored, &original) {
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
/// Propagates a failure reading the directory or a sidecar. A sidecar whose name
/// is not a digest slot is not one of ours and is skipped. Existing entries are
/// tightened on Unix when this command is used.
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
        let original = std::fs::read_to_string(&path)?;
        if original.is_empty() {
            continue;
        }
        found.push(QuarantinedFile {
            sha256_hex,
            original: PathBuf::from(original),
        });
    }
    found.sort_by(|a, b| {
        a.sha256_hex
            .cmp(&b.sha256_hex)
            .then_with(|| a.original.cmp(&b.original))
    });
    Ok(found)
}

fn secure_existing_files(quarantine_dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(quarantine_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(invalid("quarantine entries must not be symlinks"));
        }
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if sidecar_slot(&path).is_some() {
            secure_sidecar(&path)?;
        } else if payload_slot(&path).is_some() {
            secure_payload(&path)?;
        }
    }
    Ok(())
}

fn quarantine_slots(
    quarantine_dir: &Path,
    sha256_hex: &str,
) -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    let mut slots = Vec::new();
    for entry in std::fs::read_dir(quarantine_dir)? {
        let path = entry?.path();
        let Some((digest, slot)) = sidecar_slot(&path) else {
            continue;
        };
        if digest == sha256_hex {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".origin"))
                .ok_or_else(|| invalid("invalid quarantine sidecar name"))?;
            slots.push((slot, quarantine_dir.join(name), path));
        }
    }
    slots.sort_by_key(|(slot, _, _)| *slot);
    Ok(slots
        .into_iter()
        .map(|(_, stored, sidecar)| (stored, sidecar))
        .collect())
}

fn sidecar_slot(path: &Path) -> Option<(String, u64)> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".origin")?;
    parse_slot_stem(stem)
}

fn payload_slot(path: &Path) -> Option<(String, u64)> {
    let stem = path.file_name()?.to_str()?;
    parse_slot_stem(stem)
}

fn parse_slot_stem(stem: &str) -> Option<(String, u64)> {
    if let Some((digest, suffix)) = stem.split_once('.') {
        let slot = suffix.parse::<u64>().ok()?;
        return (slot > 0 && suffix == slot.to_string() && is_sha256_hex(digest))
            .then(|| (digest.to_owned(), slot));
    }
    is_sha256_hex(stem).then(|| (stem.to_owned(), 0))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Moves `from` to `to`, failing with `AlreadyExists` instead of replacing
/// whatever is at `to` — restoring must never destroy a file that has since
/// taken the original's place. `hard_link` is the atomic no-replace primitive;
/// across filesystems it fails, and the copy fallback uses `create_new` for the
/// same guarantee.
///
/// Once this returns `Ok` the file is complete at `to`. Removing `from` is
/// best-effort after that: it is a duplicate by then, and failing to delete it
/// must not turn a finished restore into an error (a retry would only fail with
/// `AlreadyExists` on the very file that was restored).
fn move_file_no_clobber(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(e),
        Err(_) => copy_no_clobber(from, to)?,
    }
    let _ = std::fs::remove_file(from);
    Ok(())
}

/// Moves a source into quarantine by path, without leaving its original path live. Unlike
/// restore, failure to remove the source after creating the destination is an
/// error: both copies must not be reported as a successful quarantine. Unix quarantines go
/// through [`Source::move_into_quarantine`] instead, which holds the file open (#689).
#[cfg(any(test, not(unix)))]
fn move_to_quarantine(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Err(error),
        Err(_) => copy_no_clobber(from, to)?,
    }
    if let Err(error) = std::fs::remove_file(from) {
        let _ = std::fs::remove_file(to);
        return Err(error);
    }
    Ok(())
}

/// Copies `from` to a new file `to`, carrying the read-only bit that `hard_link`
/// would have kept for free.
fn copy_no_clobber(from: &Path, to: &Path) -> std::io::Result<()> {
    copy_no_clobber_with(from, to, |src, dst| {
        std::io::copy(src, dst)?;
        dst.set_permissions(src.metadata()?.permissions())
    })
}

/// [`copy_no_clobber`] with the fill step injected, so its failure path can be
/// exercised. If `fill` fails, the half-written `to` is removed: this call
/// created it one line earlier, so deleting it is safe, and leaving it would
/// break "a failed restore changes nothing" and jam every retry behind our own
/// debris. If `create_new` itself fails (`AlreadyExists`) nothing was created and
/// nothing is removed: the file at `to` is somebody else's.
fn copy_no_clobber_with(
    from: &Path,
    to: &Path,
    fill: impl FnOnce(&mut std::fs::File, &mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    copy_open_no_clobber_with(std::fs::File::open(from)?, to, fill)
}

/// [`copy_no_clobber_with`] for a source that is already open.
fn copy_open_no_clobber_with(
    mut src: std::fs::File,
    to: &Path,
    fill: impl FnOnce(&mut std::fs::File, &mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    if let Err(e) = fill(&mut src, &mut dst) {
        drop(dst); // an open file cannot be removed on Windows
        let _ = std::fs::remove_file(to);
        return Err(e);
    }
    Ok(())
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

#[cfg(test)]
fn origin_sidecar_path(quarantine_dir: &Path, sha256_hex: &str) -> PathBuf {
    quarantine_dir.join(format!("{sha256_hex}.origin"))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    sha256_reader(&mut std::fs::File::open(path)?)
}

fn sha256_reader(file: &mut impl std::io::Read) -> std::io::Result<String> {
    sha256_copy(file, &mut std::io::sink())
}

/// Copies `from` to `to` and returns the SHA-256 of exactly the bytes copied.
fn sha256_copy(
    from: &mut impl std::io::Read,
    to: &mut impl std::io::Write,
) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        to.write_all(&buf[..n])?;
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        // Writing to a `String` cannot fail — `fmt::Write`'s `Result` exists for
        // formatters that do I/O, not this one; nothing to propagate.
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "response-quarantine-test-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn policy_disabled_leaves_the_file_in_place() {
        let dir = temp_dir("observe-only");
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"not actually malware").unwrap();
        let policy = ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: false,
        };

        let outcome = quarantine_file(&payload, &dir.join("quarantine"), &policy);

        assert_eq!(
            outcome,
            QuarantineOutcome::ObserveOnly {
                path: payload.clone()
            }
        );
        assert!(payload.exists(), "observe-only must not touch the file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_quarantined_file_moves_read_only_and_can_be_restored() {
        let dir = temp_dir("roundtrip");
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"not actually malware").unwrap();
        let quarantine_dir = dir.join("quarantine");
        let policy = ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
        };

        let outcome = quarantine_file(&payload, &quarantine_dir, &policy);
        let (quarantined_at, sha256_hex) = match outcome {
            QuarantineOutcome::Quarantined {
                quarantined_at,
                sha256_hex,
                ref original,
            } => {
                assert_eq!(original, &payload);
                (quarantined_at, sha256_hex)
            }
            other => panic!("expected Quarantined, got {other:?}"),
        };

        assert!(
            !payload.exists(),
            "the original path must be empty after quarantine"
        );
        assert!(quarantined_at.exists());
        assert!(
            std::fs::metadata(&quarantined_at)
                .unwrap()
                .permissions()
                .readonly(),
            "a quarantined file must be read-only"
        );

        let restored = unquarantine(&quarantine_dir, &sha256_hex).unwrap();
        assert_eq!(restored, payload);
        assert!(
            payload.exists(),
            "unquarantine must restore the original file"
        );
        assert_eq!(std::fs::read(&payload).unwrap(), b"not actually malware");
        assert!(
            !quarantine_dir.join(format!("{sha256_hex}.origin")).exists(),
            "the sidecar must be removed after a successful restore"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_digests_are_quarantined_and_restored_individually() {
        let dir = temp_dir("duplicate-digest");
        let first = dir.join("first");
        let second = dir.join("second");
        std::fs::write(&first, b"same bytes").unwrap();
        std::fs::write(&second, b"same bytes").unwrap();
        let quarantine_dir = dir.join("quarantine");
        let policy = ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
        };

        let first_result = quarantine_file(&first, &quarantine_dir, &policy);
        let QuarantineOutcome::Quarantined {
            sha256_hex,
            quarantined_at: first_stored,
            ..
        } = first_result
        else {
            panic!("first payload must be quarantined");
        };
        let second_result = quarantine_file(&second, &quarantine_dir, &policy);
        let QuarantineOutcome::Quarantined {
            sha256_hex: second_digest,
            quarantined_at: second_stored,
            ..
        } = second_result
        else {
            panic!("duplicate payload must also be quarantined");
        };
        assert_eq!(sha256_hex, second_digest);
        assert_ne!(first_stored, second_stored);
        assert!(!first.exists());
        assert!(!second.exists());
        assert_eq!(
            std::fs::read_to_string(origin_sidecar_path(&quarantine_dir, &sha256_hex)).unwrap(),
            first.to_string_lossy()
        );
        assert_eq!(
            std::fs::read_to_string(quarantine_dir.join(format!("{sha256_hex}.1.origin"))).unwrap(),
            second.to_string_lossy()
        );
        assert_eq!(list_quarantined(&quarantine_dir).unwrap().len(), 2);
        assert!(is_still_quarantined(&quarantine_dir, &sha256_hex));
        assert_eq!(unquarantine(&quarantine_dir, &sha256_hex).unwrap(), first);
        assert!(is_still_quarantined(&quarantine_dir, &sha256_hex));
        assert_eq!(unquarantine(&quarantine_dir, &sha256_hex).unwrap(), second);
        assert!(!is_still_quarantined(&quarantine_dir, &sha256_hex));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_payload_security_rolls_back_to_source() {
        let dir = temp_dir("secure-rollback");
        let source = dir.join("source");
        let stored = dir.join("stored");
        std::fs::write(&source, b"payload").unwrap();
        let error = move_and_secure(
            &source,
            &stored,
            move_to_quarantine,
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected",
                ))
            },
            move_file_no_clobber,
        )
        .unwrap_err();
        assert!(!error.retained_in_quarantine);
        assert_eq!(error.error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(source.exists());
        assert!(!stored.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_move_failure_keeps_its_quarantine_record() {
        let dir = temp_dir("partial-move");
        let source = dir.join("source");
        let stored = dir.join("stored");
        std::fs::write(&source, b"payload").unwrap();
        std::fs::write(&stored, b"partially moved payload").unwrap();
        let error = move_and_secure(
            &source,
            &stored,
            |_, _| Err(std::io::Error::other("injected partial move failure")),
            secure_payload,
            move_file_no_clobber,
        )
        .unwrap_err();
        assert!(error.retained_in_quarantine);
        assert!(source.exists());
        assert!(stored.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_rollback_retains_payload_for_inspection() {
        let dir = temp_dir("failed-rollback");
        let source = dir.join("source");
        let stored = dir.join("stored");
        std::fs::write(&source, b"payload").unwrap();
        let error = move_and_secure(
            &source,
            &stored,
            move_to_quarantine,
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected",
                ))
            },
            |_, _| Err(std::io::Error::other("injected rollback failure")),
        )
        .unwrap_err();
        assert!(error.retained_in_quarantine);
        assert!(error.error.to_string().contains("remain in quarantine"));
        assert!(!source.exists());
        assert_eq!(std::fs::read(&stored).unwrap(), b"payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_removes_execute_and_tightens_existing_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir("unix-modes");
        let payload = dir.join("payload");
        std::fs::write(&payload, b"executable payload").unwrap();
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();
        let quarantine_dir = dir.join("quarantine");
        std::fs::create_dir(&quarantine_dir).unwrap();
        std::fs::set_permissions(&quarantine_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let outcome = quarantine_file(
            &payload,
            &quarantine_dir,
            &ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled: true,
            },
        );
        let (stored, digest) = match outcome {
            QuarantineOutcome::Quarantined {
                quarantined_at,
                sha256_hex,
                ..
            } => (quarantined_at, sha256_hex),
            other => panic!("expected quarantine, got {other:?}"),
        };
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&quarantine_dir), 0o700);
        assert_eq!(mode(&stored), 0o400);
        assert_eq!(mode(&origin_sidecar_path(&quarantine_dir, &digest)), 0o600);

        let restored = unquarantine(&quarantine_dir, &digest).unwrap();
        assert_eq!(restored, payload);
        assert_eq!(
            mode(&restored),
            0o400,
            "restore must not re-enable execution"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn listing_tightens_legacy_quarantine_entries() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir("legacy-modes");
        let quarantine_dir = dir.join("quarantine");
        std::fs::create_dir(&quarantine_dir).unwrap();
        let payload = b"legacy payload";
        let payload_path = dir.join("payload");
        std::fs::write(&payload_path, payload).unwrap();
        let digest = sha256_file(&payload_path).unwrap();
        let stored = quarantine_dir.join(&digest);
        let sidecar = origin_sidecar_path(&quarantine_dir, &digest);
        std::fs::write(&stored, payload).unwrap();
        std::fs::write(&sidecar, payload_path.to_string_lossy().as_bytes()).unwrap();
        std::fs::set_permissions(&quarantine_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644)).unwrap();

        let listed = list_quarantined(&quarantine_dir).unwrap();
        assert_eq!(listed.len(), 1);
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&quarantine_dir), 0o700);
        assert_eq!(mode(&stored), 0o400);
        assert_eq!(mode(&sidecar), 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_reports_failed_not_a_panic() {
        let dir = temp_dir("missing");
        let policy = ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
        };

        let outcome = quarantine_file(
            &dir.join("does-not-exist"),
            &dir.join("quarantine"),
            &policy,
        );

        assert!(matches!(outcome, QuarantineOutcome::Failed { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_payload_is_refused_without_changing_its_target() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = temp_dir("symlink-source");
        let target = dir.join("target");
        let source = dir.join("source-link");
        std::fs::write(&target, b"payload target").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, &source).unwrap();

        let outcome = quarantine_file(
            &source,
            &dir.join("quarantine"),
            &ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled: true,
            },
        );
        assert!(matches!(outcome, QuarantineOutcome::Failed { .. }));
        assert!(source.is_symlink());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(!dir.join("quarantine").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #689: the name is swapped for a symlink to a victim file after the source was opened
    /// and checked. The move must store the inode that was checked, leave the symlink and its
    /// target alone, and the `chmod` that follows must not reach the victim.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_symlink_swapped_in_after_the_check_does_not_redirect_the_move_or_the_chmod() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = temp_dir("swap-symlink");
        let source = dir.join("payload");
        let victim = dir.join("victim");
        let stored = dir.join("stored");
        std::fs::write(&source, b"the payload").unwrap();
        std::fs::write(&victim, b"someone else's file").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();

        let opened = Source::open(&source).unwrap();
        let digest = opened.sha256(&source).unwrap();
        // The race: between the check and the move, the name becomes a symlink.
        std::fs::remove_file(&source).unwrap();
        symlink(&victim, &source).unwrap();

        move_and_secure(
            &source,
            &stored,
            |from, to| opened.move_into_quarantine(from, to),
            secure_payload,
            move_file_no_clobber,
        )
        .unwrap_or_else(|failure| panic!("move failed: {}", failure.error));

        assert!(!std::fs::symlink_metadata(&stored).unwrap().is_symlink());
        assert_eq!(
            sha256_file(&stored).unwrap(),
            digest,
            "stored what was hashed"
        );
        assert_eq!(std::fs::read(&stored).unwrap(), b"the payload");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644,
            "the symlink's target is untouched"
        );
        assert!(
            std::fs::symlink_metadata(&source).unwrap().is_symlink(),
            "a name that is no longer ours is left alone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #689: the file is replaced by another one after it was hashed. What is stored is the
    /// file that was hashed, so the digest it is filed under is its own.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_replaced_after_hashing_is_stored_under_its_own_digest() {
        let dir = temp_dir("swap-file");
        let source = dir.join("payload");
        let other = dir.join("other");
        let stored = dir.join("stored");
        std::fs::write(&source, b"hashed content").unwrap();
        std::fs::write(&other, b"replacement content").unwrap();

        let opened = Source::open(&source).unwrap();
        let digest = opened.sha256(&source).unwrap();
        std::fs::rename(&other, &source).unwrap();

        opened.move_into_quarantine(&source, &stored).unwrap();

        assert_eq!(sha256_file(&stored).unwrap(), digest);
        assert_eq!(
            std::fs::read(&source).unwrap(),
            b"replacement content",
            "the replacement is not ours to remove"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #689: a file deleted after it was opened cannot be linked; it is copied from the
    /// descriptor, which is also the path taken across filesystems.
    #[cfg(unix)]
    #[test]
    fn a_file_unlinked_after_the_check_is_still_stored_from_its_descriptor() {
        let dir = temp_dir("unlinked-source");
        let source = dir.join("payload");
        let stored = dir.join("stored");
        std::fs::write(&source, b"still readable").unwrap();

        let opened = Source::open(&source).unwrap();
        let digest = opened.sha256(&source).unwrap();
        std::fs::remove_file(&source).unwrap();

        opened.move_into_quarantine(&source, &stored).unwrap();

        assert_eq!(sha256_file(&stored).unwrap(), digest);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_copy_from_a_descriptor_ignores_a_symlink_that_took_the_name() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("copy-from-fd");
        let source = dir.join("payload");
        let victim = dir.join("victim");
        let stored = dir.join("stored");
        std::fs::write(&source, b"the payload").unwrap();
        std::fs::write(&victim, b"someone else's file").unwrap();

        let opened = Source::open(&source).unwrap();
        std::fs::remove_file(&source).unwrap();
        symlink(&victim, &source).unwrap();

        copy_open_file_no_clobber(&opened.file, &stored, u64::MAX).unwrap();

        assert_eq!(std::fs::read(&stored).unwrap(), b"the payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linking_an_open_file_never_replaces_an_existing_name() {
        let dir = temp_dir("link-no-clobber");
        let source = dir.join("payload");
        let taken = dir.join("taken");
        std::fs::write(&source, b"payload").unwrap();
        std::fs::write(&taken, b"already here").unwrap();

        let opened = Source::open(&source).unwrap();
        let error = opened.move_into_quarantine(&source, &taken).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&taken).unwrap(), b"already here");
        assert!(source.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn only_the_cannot_link_errors_fall_back_to_a_copy() {
        for code in [
            libc::EXDEV,
            libc::ENOENT,
            libc::EMLINK,
            libc::EPERM,
            libc::EOPNOTSUPP,
        ] {
            assert!(can_fall_back_to_copy(&std::io::Error::from_raw_os_error(
                code
            )));
        }
        assert!(can_fall_back_to_copy(&std::io::Error::from(
            std::io::ErrorKind::Unsupported
        )));
        for code in [libc::ENOSPC, libc::EACCES, libc::EMFILE, libc::EIO] {
            assert!(
                !can_fall_back_to_copy(&std::io::Error::from_raw_os_error(code)),
                "errno {code}"
            );
        }
    }

    /// #713 review: after a copy, a name that was taken by something else must not end as
    /// "quarantined" while the checked file may stay executable under another name.
    #[cfg(unix)]
    #[test]
    fn a_copy_is_refused_when_another_file_took_the_name() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("copy-name-taken");
        let source = dir.join("payload");
        let stored = dir.join("stored");
        std::fs::write(&source, b"the payload").unwrap();
        let opened = Source::open(&source).unwrap();
        copy_open_file_no_clobber(&opened.file, &stored, u64::MAX).unwrap();
        std::fs::rename(&source, dir.join("moved-elsewhere")).unwrap();
        symlink(dir.join("moved-elsewhere"), &source).unwrap();

        let error = opened.release_name(&source, &stored, false).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!stored.exists(), "the copy is not kept");
        assert!(std::fs::symlink_metadata(&source).unwrap().is_symlink());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_name_that_is_gone_or_taken_after_a_link_is_not_an_error() {
        let dir = temp_dir("name-gone-or-taken");
        let source = dir.join("payload");
        let stored = dir.join("stored");
        std::fs::write(&source, b"the payload").unwrap();
        let opened = Source::open(&source).unwrap();
        std::fs::write(&stored, b"stands for the stored copy").unwrap();
        std::fs::remove_file(&source).unwrap();
        // Gone: fine after a copy as after a link.
        opened.release_name(&source, &stored, false).unwrap();
        opened.release_name(&source, &stored, true).unwrap();
        // Taken by another file after a link: the shared inode is secured by the caller.
        std::fs::write(&source, b"somebody else's").unwrap();
        opened.release_name(&source, &stored, true).unwrap();
        // Taken after a copy while the checked file has no name left (the usual swap): it
        // disappears once closed, the copy is all that remains, so this is fine too.
        opened.release_name(&source, &stored, false).unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), b"somebody else's");
        assert!(stored.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 review: a write between the open and the store is noticed, and the store itself
    /// reports it with a marker the caller turns into a snapshot, not into a refusal.
    #[cfg(unix)]
    #[test]
    fn a_source_written_to_after_it_was_opened_is_noticed_not_refused_by_the_hash() {
        use std::io::Write as _;

        let dir = temp_dir("written-after-open");
        let source = dir.join("payload");
        let stored = dir.join("stored");
        std::fs::write(&source, b"the payload").unwrap();
        let opened = Source::open(&source).unwrap();
        opened.sha256(&source).unwrap();
        assert!(!opened.written_since_open().unwrap());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(b" and more")
            .unwrap();

        assert!(opened.written_since_open().unwrap());
        assert!(opened.sha256(&source).is_ok(), "hashing is not refused");
        let error = opened.move_into_quarantine(&source, &stored).unwrap_err();
        assert!(is_written_after_hash(&error));
        assert!(!stored.exists());
        assert!(source.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_source_whose_modification_time_moved_is_noticed_even_at_the_same_size() {
        let dir = temp_dir("mtime-moved");
        let source = dir.join("payload");
        std::fs::write(&source, b"the payload").unwrap();
        let opened = Source::open(&source).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
            .unwrap();

        assert!(opened.written_since_open().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 review: the snapshot is filed under the digest of the bytes it holds, the source
    /// name is removed, nothing is left behind, and the payload can be restored. What is stored
    /// is the prefix the file had when it was opened, not what was appended since.
    #[cfg(unix)]
    #[test]
    fn a_snapshot_of_a_written_source_is_stored_under_its_own_digest_and_restores() {
        use std::io::Write as _;

        let dir = temp_dir("snapshot");
        let source = dir.join("payload");
        let qdir = dir.join("quarantine");
        std::fs::write(&source, b"first").unwrap();
        secure_quarantine_dir(&qdir).unwrap();
        let opened = Source::open(&source).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(b" and more")
            .unwrap();

        let (stored, digest) = quarantine_snapshot(&opened, &source, &qdir).unwrap();

        assert_eq!(sha256_file(&stored).unwrap(), digest);
        assert_eq!(std::fs::read(&stored).unwrap(), b"first");
        assert!(!source.exists(), "the name is removed");
        assert!(
            std::fs::read_dir(&qdir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".incoming")),
            "no temporary file is left"
        );
        assert_eq!(unquarantine(&qdir, &digest).unwrap(), source);
        assert_eq!(std::fs::read(&source).unwrap(), b"first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 review (second round): the hash and the snapshot both use the length from the
    /// open, so appending after it changes neither the digest nor the stored bytes, whatever
    /// the writer does in between.
    #[cfg(unix)]
    #[test]
    fn hash_and_snapshot_both_stop_at_the_length_the_file_had_when_opened() {
        use std::io::Write as _;

        let dir = temp_dir("prefix-at-open");
        let source = dir.join("payload");
        let qdir = dir.join("quarantine");
        std::fs::write(&source, b"original bytes").unwrap();
        secure_quarantine_dir(&qdir).unwrap();
        let opened = Source::open(&source).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(&[b'x'; 4096])
            .unwrap();

        let hashed = opened.sha256(&source).unwrap();
        let (stored, digest) = quarantine_snapshot(&opened, &source, &qdir).unwrap();

        assert_eq!(hashed, sha256_reader(&mut &b"original bytes"[..]).unwrap());
        assert_eq!(digest, hashed, "both steps saw the same prefix");
        assert_eq!(std::fs::read(&stored).unwrap(), b"original bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 review (second round): the sweep runs at every quarantine, so a leftover of a
    /// killed agent does not wait for a written source to be cleaned up.
    #[cfg(unix)]
    #[test]
    fn a_leftover_snapshot_is_swept_by_an_ordinary_quarantine() {
        let dir = temp_dir("sweep-on-quarantine");
        let source = dir.join("payload");
        let qdir = dir.join("quarantine");
        secure_quarantine_dir(&qdir).unwrap();
        let stale = qdir.join(".incoming-1-0");
        std::fs::write(&stale, b"partial").unwrap();
        backdate(&stale);
        std::fs::write(&source, b"not being written").unwrap();

        try_quarantine(&source, &qdir).unwrap();

        assert!(!stale.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 review: the snapshot is bounded to the length the file had when it started, so a
    /// file that grew since is stored as a consistent prefix, hashed as that prefix.
    #[cfg(unix)]
    #[test]
    fn a_snapshot_copies_at_most_the_length_it_started_with() {
        let dir = temp_dir("bounded-snapshot");
        let source = dir.join("payload");
        std::fs::write(&source, vec![9u8; 5000]).unwrap();
        let file = std::fs::File::open(&source).unwrap();

        let (stored, digest, _lock) = copy_prefix_hashed(&file, &dir, 1000).unwrap();

        let bytes = std::fs::read(&stored).unwrap();
        assert_eq!(bytes.len(), 1000, "a growing file ends the copy");
        assert_eq!(digest, sha256_file(&stored).unwrap());
        assert_eq!(digest, sha256_reader(&mut &bytes[..]).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Makes `path` look as if it had been left an hour ago.
    #[cfg(unix)]
    fn backdate(path: &Path) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
    }

    /// #713 review: a partial snapshot left by a process that was killed is swept, whatever
    /// its pid (1 in every container); one that is locked (in flight, of this process or of
    /// another), a fresh one and everything else are kept.
    #[cfg(unix)]
    #[test]
    fn only_abandoned_partial_snapshots_are_swept() {
        let dir = temp_dir("sweep-snapshots");
        let stale = dir.join(".incoming-1-0");
        let stale_same_pid = dir.join(format!(".incoming-{}-0", std::process::id()));
        let in_flight = dir.join(".incoming-4242-0");
        let fresh = dir.join(".incoming-4343-0");
        let stored = dir.join("0".repeat(64));
        let odd = dir.join(".incoming-notapid-0");
        for path in [&stale, &stale_same_pid, &in_flight, &fresh, &stored, &odd] {
            std::fs::write(path, b"x").unwrap();
        }
        for path in [&stale, &stale_same_pid, &in_flight, &odd] {
            backdate(path);
        }
        let lock = std::fs::File::open(&in_flight).unwrap();
        assert_eq!(try_lock_exclusive(&lock), SnapshotLock::Acquired);

        sweep_stale_snapshots(&dir);

        assert!(!stale.exists(), "abandoned, pid of another process");
        assert!(
            !stale_same_pid.exists(),
            "abandoned, pid reused (1 in a container)"
        );
        assert!(in_flight.exists(), "locked by a snapshot in flight");
        assert!(fresh.exists(), "just created, maybe not locked yet");
        assert!(stored.exists());
        assert!(odd.exists(), "a name that is not ours is not touched");
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 follow-up: where `flock` does not work, only a long silence lets a sweep take a
    /// snapshot; where it works, the lock decides.
    #[cfg(unix)]
    #[test]
    fn the_sweep_decision_depends_on_what_the_lock_can_tell() {
        use std::time::Duration;
        let secs = Duration::from_secs;
        assert!(may_take_snapshot(secs(3600), &SnapshotLock::Acquired));
        assert!(
            !may_take_snapshot(secs(5), &SnapshotLock::Acquired),
            "too fresh"
        );
        assert!(
            !may_take_snapshot(secs(7200), &SnapshotLock::Held),
            "in flight"
        );
        assert!(!may_take_snapshot(secs(60), &SnapshotLock::Unsupported));
        assert!(may_take_snapshot(secs(3600), &SnapshotLock::Unsupported));
    }

    /// #713 follow-up: the sweep neither blocks on a FIFO nor follows a link under a snapshot
    /// name, and leaves both alone.
    #[cfg(unix)]
    #[test]
    fn the_sweep_ignores_a_fifo_and_a_link_under_a_snapshot_name() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = temp_dir("sweep-odd-entries");
        let fifo = dir.join(".incoming-1-1");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let target = dir.join("target");
        std::fs::write(&target, b"x").unwrap();
        backdate(&target);
        let link = dir.join(".incoming-2-2");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let swept = dir.clone();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            sweep_stale_snapshots(&swept);
            let _ = done.send(());
        });
        finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the sweep must not block on a FIFO");

        assert!(fifo.exists(), "not a regular file: left alone");
        assert!(
            link.symlink_metadata().is_ok(),
            "a link is not followed or removed"
        );
        assert!(target.exists(), "what the link points at is untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 follow-up: a write between the link (or the copy) and the check that follows is
    /// noticed, the stored name is undone and the source name is untouched, so that the caller
    /// goes on to the snapshot.
    #[cfg(unix)]
    #[test]
    fn a_write_during_the_link_undoes_it_and_sends_the_caller_to_the_snapshot() {
        use std::io::Write as _;
        let dir = temp_dir("write-during-link");
        let source = dir.join("payload");
        let stored = dir.join("stored");
        std::fs::write(&source, vec![1u8; 4096]).unwrap();
        let opened = Source::open(&source).unwrap();

        let error = opened
            .move_into_quarantine_with(&source, &stored, || {
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&source)
                    .unwrap();
                file.write_all(b"more").unwrap();
            })
            .unwrap_err();

        assert!(is_written_after_hash(&error));
        assert!(!stored.exists(), "the link or copy is removed");
        assert!(source.exists(), "the source name is not touched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 review: the copy used when a file cannot be linked stops at the length given, so
    /// a writer that keeps appending cannot make it run without end.
    #[cfg(unix)]
    #[test]
    fn the_copy_fallback_stops_at_the_length_at_open() {
        let dir = temp_dir("bounded-copy");
        let source = dir.join("payload");
        let stored = dir.join("stored");
        std::fs::write(&source, vec![5u8; 5000]).unwrap();
        let opened = Source::open(&source).unwrap();

        copy_open_file_no_clobber(&opened.file, &stored, 1000).unwrap();

        assert_eq!(std::fs::read(&stored).unwrap().len(), 1000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #713 review (measured by the reviewer): a writer that keeps appending must not make the
    /// quarantine fail, and what is stored must match the digest it is filed under.
    #[cfg(unix)]
    #[test]
    fn a_file_that_keeps_being_written_is_still_quarantined() {
        use std::{
            io::Write as _,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
        };

        let dir = temp_dir("busy-writer");
        let source = dir.join("payload");
        std::fs::write(&source, vec![7u8; 4 * 1024 * 1024]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let (source, stop) = (source.clone(), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match std::fs::OpenOptions::new().append(true).open(&source) {
                        Ok(mut file) => {
                            let _ = file.write_all(b"x");
                        }
                        Err(_) => break,
                    }
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
            })
        };

        let outcome = quarantine_file(
            &source,
            &dir.join("quarantine"),
            &ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled: true,
            },
        );
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();

        let QuarantineOutcome::Quarantined {
            quarantined_at,
            sha256_hex,
            ..
        } = outcome
        else {
            panic!("a busy writer must not defeat the quarantine: {outcome:?}");
        };
        assert_eq!(sha256_file(&quarantined_at).unwrap(), sha256_hex);
        assert!(!source.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO under the file's name must be refused, not waited on.
    #[cfg(unix)]
    #[test]
    fn a_fifo_source_is_refused_without_blocking() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

        let dir = temp_dir("fifo-source");
        let fifo = dir.join("pipe");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `name` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

        let outcome = quarantine_file(
            &fifo,
            &dir.join("quarantine"),
            &ResponsePolicy {
                kill_enabled: false,
                quarantine_enabled: true,
            },
        );

        assert!(
            matches!(outcome, QuarantineOutcome::Failed { .. }),
            "{outcome:?}"
        );
        assert!(!dir.join("quarantine").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #689 (review note): a tampered slot returned early, so the intact copies of the same
    /// digest after it could never be restored.
    #[test]
    fn a_tampered_slot_does_not_hide_an_intact_one_of_the_same_digest() {
        let dir = temp_dir("tampered-then-intact");
        let first = dir.join("first");
        let second = dir.join("second");
        std::fs::write(&first, b"same bytes").unwrap();
        std::fs::write(&second, b"same bytes").unwrap();
        let qdir = dir.join("quarantine");
        let policy = ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
        };
        let QuarantineOutcome::Quarantined {
            sha256_hex: digest,
            quarantined_at: first_stored,
            ..
        } = quarantine_file(&first, &qdir, &policy)
        else {
            panic!("first payload must be quarantined");
        };
        assert!(matches!(
            quarantine_file(&second, &qdir, &policy),
            QuarantineOutcome::Quarantined { .. }
        ));
        let mut perms = std::fs::metadata(&first_stored).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&first_stored, perms).unwrap();
        std::fs::write(&first_stored, b"swapped by someone").unwrap();

        let restored = unquarantine(&qdir, &digest).unwrap();

        assert_eq!(restored, second);
        assert_eq!(std::fs::read(&second).unwrap(), b"same bytes");
        assert!(!first.exists(), "the tampered copy is not put back");
        // What is left is the tampered slot, still refused.
        let err = unquarantine(&qdir, &digest).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #689 (review note): asking to restore from a quarantine that was never created must
    /// not create it.
    #[test]
    fn restoring_from_a_quarantine_that_does_not_exist_creates_nothing() {
        let dir = temp_dir("restore-nothing");
        let qdir = dir.join("never-created");

        let err = unquarantine(&qdir, &"0".repeat(64)).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(!qdir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_of_another_user_is_left_alone_only_when_it_is_already_private() {
        // Ours: always set to 0700, whatever it was.
        assert!(quarantine_dir_needs_chmod(true, 0o040_755).unwrap());
        assert!(quarantine_dir_needs_chmod(true, 0o040_700).unwrap());
        // Someone else's and already 0700 (root running `list`): no chmod, no refusal.
        assert!(!quarantine_dir_needs_chmod(false, 0o040_700).unwrap());
        // Someone else's and it would have to change: refused.
        for mode in [0o040_755, 0o040_750, 0o040_777, 0o040_500] {
            let err = quarantine_dir_needs_chmod(false, mode).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{mode:o}");
        }
    }

    /// #689 (review note): an existing directory that belongs to someone else is refused, not
    /// `chmod`ed. `/usr` is root's; as root it would be this process's own, so the test only
    /// runs unprivileged (it must never reach the `chmod`).
    #[cfg(unix)]
    #[test]
    fn a_quarantine_directory_owned_by_another_user_is_refused() {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let err = secure_quarantine_dir(Path::new("/usr")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    fn quarantine_one(dir: &Path, name: &str, body: &[u8]) -> (PathBuf, PathBuf, String) {
        let payload = dir.join(name);
        std::fs::write(&payload, body).unwrap();
        let quarantine_dir = dir.join("quarantine");
        let policy = ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
        };
        match quarantine_file(&payload, &quarantine_dir, &policy) {
            QuarantineOutcome::Quarantined { sha256_hex, .. } => {
                (payload, quarantine_dir, sha256_hex)
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
    }

    #[test]
    fn listing_a_directory_that_does_not_exist_yet_is_empty() {
        let dir = temp_dir("list-missing");
        assert_eq!(
            list_quarantined(&dir.join("quarantine")).unwrap(),
            Vec::new()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_listing_names_each_payload_and_where_it_came_from_sorted_by_digest() {
        let dir = temp_dir("list");
        let (p1, qdir, d1) = quarantine_one(&dir, "one.bin", b"first payload");
        let (p2, _, d2) = quarantine_one(&dir, "two.bin", b"second payload");
        // Something that is not ours must be ignored, not treated as a payload.
        std::fs::write(qdir.join("stray.origin"), "/etc/passwd").unwrap();

        let listed = list_quarantined(&qdir).unwrap();

        let mut expected = vec![
            QuarantinedFile {
                sha256_hex: d1,
                original: p1,
            },
            QuarantinedFile {
                sha256_hex: d2,
                original: p2,
            },
        ];
        expected.sort_by(|a, b| a.sha256_hex.cmp(&b.sha256_hex));
        assert_eq!(listed, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restoring_never_overwrites_a_file_that_took_the_originals_place() {
        let dir = temp_dir("no-clobber");
        let (payload, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
        std::fs::write(&payload, b"a different, legitimate file").unwrap();

        let err = unquarantine(&qdir, &digest).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&payload).unwrap(),
            b"a different, legitimate file"
        );
        assert!(
            qdir.join(&digest).exists(),
            "the quarantined copy must stay"
        );
        assert!(
            qdir.join(format!("{digest}.origin")).exists(),
            "and its sidecar"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_quarantined_file_altered_in_place_is_not_restored() {
        let dir = temp_dir("tampered");
        let (payload, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
        let stored = qdir.join(&digest);
        let mut perms = std::fs::metadata(&stored).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&stored, perms).unwrap();
        std::fs::write(&stored, b"swapped by someone").unwrap();

        let err = unquarantine(&qdir, &digest).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(!payload.exists(), "nothing may be put back");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_digest_that_could_name_a_path_outside_the_directory_is_refused() {
        let dir = temp_dir("traversal");
        for bad in [
            "../../etc/passwd",
            "",
            "abc",
            &"A".repeat(64),
            &"g".repeat(64),
        ] {
            let err = unquarantine(&dir.join("quarantine"), bad).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_copy_that_fails_midway_leaves_nothing_at_the_destination() {
        let dir = temp_dir("copy-fails");
        let from = dir.join("from.bin");
        let to = dir.join("to.bin");
        std::fs::write(&from, b"the quarantined payload").unwrap();

        let err = copy_no_clobber_with(&from, &to, |_, dst| {
            use std::io::Write as _;
            dst.write_all(b"half of it")?; // the disk fills up here
            Err(std::io::Error::other("no space left on device"))
        })
        .unwrap_err();

        assert_eq!(err.to_string(), "no space left on device");
        assert!(!to.exists(), "our own half-written file must be removed");
        assert_eq!(std::fs::read(&from).unwrap(), b"the quarantined payload");
        // And a retry is not jammed behind that debris.
        copy_no_clobber(&from, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"the quarantined payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_copy_never_removes_a_file_it_did_not_create() {
        let dir = temp_dir("copy-not-ours");
        let from = dir.join("from.bin");
        let to = dir.join("to.bin");
        std::fs::write(&from, b"payload").unwrap();
        std::fs::write(&to, b"somebody else's file").unwrap();

        let err = copy_no_clobber_with(&from, &to, |_, _| {
            panic!("nothing may be written when the destination exists")
        })
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&to).unwrap(), b"somebody else's file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_completed_copy_carries_the_read_only_bit() {
        let dir = temp_dir("copy-readonly");
        let from = dir.join("from.bin");
        let to = dir.join("to.bin");
        std::fs::write(&from, b"payload").unwrap();
        let mut perms = std::fs::metadata(&from).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&from, perms).unwrap();

        copy_no_clobber(&from, &to).unwrap();

        assert!(std::fs::metadata(&to).unwrap().permissions().readonly());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_is_left_after_a_normal_restore() {
        let dir = temp_dir("leftover-none");
        let (_, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
        assert!(
            is_still_quarantined(&qdir, &digest),
            "it is quarantined before the restore"
        );
        unquarantine(&qdir, &digest).unwrap();
        assert!(!is_still_quarantined(&qdir, &digest));
        assert!(
            !is_still_quarantined(&qdir, "../../etc/passwd"),
            "a bad digest is never 'quarantined'"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A quarantine directory with legacy read-only permissions. `None` when this
    /// process ignores permissions (root), where the scenario cannot be built.
    #[cfg(unix)]
    fn legacy_read_only_quarantine(name: &str) -> Option<(PathBuf, PathBuf, PathBuf, String)> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir(name);
        let (payload, qdir, digest) = quarantine_one(&dir, "payload.bin", b"malware");
        std::fs::set_permissions(&qdir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(qdir.join("probe"), b"x").is_ok() {
            let _ = std::fs::remove_file(qdir.join("probe"));
            return None;
        }
        Some((dir, payload, qdir, digest))
    }

    #[cfg(unix)]
    #[test]
    fn restore_tightens_legacy_read_only_directory_before_cleanup() {
        let Some((dir, payload, qdir, digest)) = legacy_read_only_quarantine("leftover") else {
            return; // root ignores directory permissions
        };

        let restored = unquarantine(&qdir, &digest);

        assert_eq!(
            restored.unwrap(),
            payload,
            "the file is back, so the restore worked"
        );
        assert_eq!(std::fs::read(&payload).unwrap(), b"malware");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&qdir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(
            !is_still_quarantined(&qdir, &digest),
            "successful restore must remove the payload and sidecar"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
