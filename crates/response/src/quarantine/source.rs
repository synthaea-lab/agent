//! The file being quarantined, held open so that what is hashed is what is stored.

use std::path::Path;

#[cfg(unix)]
use super::copy::{copy_open_no_clobber_with, sha256_reader};
#[cfg(not(unix))]
use super::copy::{move_to_quarantine, sha256_file};
use super::invalid;
#[cfg(unix)]
use super::snapshot::WrittenAfterHash;

/// The file being quarantined, opened once.
///
/// On Unix the source is opened with `O_NOFOLLOW` and checked with `fstat` on the descriptor,
/// then hashed and moved *through that descriptor*, so a path swapped for a symlink (or for
/// another file) after the check cannot redirect the move or the `chmod` that follows, and
/// the digest is the digest of the inode that is stored (#689). Elsewhere the path is
/// checked and used as before.
pub(super) struct Source {
    #[cfg(unix)]
    pub(super) file: std::fs::File,
    /// `(device, inode)` of the opened file, to recognise its name again before removing it.
    #[cfg(unix)]
    pub(super) id: (u64, u64),
    /// Size and modification time at open: what an in-place write between the hash and the
    /// store changes, so that content is never stored under a digest it no longer has.
    #[cfg(unix)]
    pub(super) snapshot: (u64, i64, i64),
    /// Original permission bits to restore after analyst-initiated unquarantine.
    pub(super) original_mode: Option<u32>,
}

#[cfg(unix)]
pub(super) fn snapshot_of(metadata: &std::fs::Metadata) -> (u64, i64, i64) {
    use std::os::unix::fs::MetadataExt as _;
    (metadata.len(), metadata.mtime(), metadata.mtime_nsec())
}

pub(super) fn not_a_regular_file() -> std::io::Error {
    invalid("quarantine source must be a regular, non-symlink file")
}

impl Source {
    #[cfg(unix)]
    pub(super) fn open(path: &Path) -> std::io::Result<Self> {
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
            original_mode: Some(metadata.mode() & 0o7777),
            file,
        })
    }

    #[cfg(not(unix))]
    pub(super) fn open(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(not_a_regular_file());
        }
        Ok(Self {
            original_mode: None,
        })
    }

    pub(super) fn original_mode(&self) -> Option<u32> {
        self.original_mode
    }

    /// SHA-256 of the opened file (of `path` where there is no descriptor to read). Reads at
    /// most the length the file had when it was opened, so a writer that keeps appending
    /// cannot keep the hash from finishing: the digest is that of the prefix, which is what
    /// [`quarantine_snapshot`] stores if the file changed.
    pub(super) fn sha256(&self, path: &Path) -> std::io::Result<String> {
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
    pub(super) fn move_into_quarantine(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.move_into_quarantine_with(from, to, || {})
    }

    /// [`Self::move_into_quarantine`] with a hook that runs after the link or the copy and
    /// before the check that follows them: the only way for a test to write in that window.
    #[cfg(unix)]
    pub(super) fn move_into_quarantine_with(
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
    pub(super) fn release_name(&self, from: &Path, to: &Path, linked: bool) -> std::io::Result<()> {
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
    pub(super) fn written_since_open(&self) -> std::io::Result<bool> {
        Ok(snapshot_of(&self.file.metadata()?) != self.snapshot)
    }

    /// Removes the name `from` while it still names the opened file.
    #[cfg(unix)]
    pub(super) fn remove_name_if_same(&self, from: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        match std::fs::symlink_metadata(from) {
            Ok(m) if m.file_type().is_file() && (m.dev(), m.ino()) == self.id => {
                std::fs::remove_file(from)
            }
            _ => Ok(()),
        }
    }

    #[cfg(not(unix))]
    pub(super) fn move_into_quarantine(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        move_to_quarantine(from, to)
    }
}

/// Links the open file's inode at `to` without replacing anything (`AlreadyExists`
/// otherwise). Through `/proc/self/fd` with `AT_SYMLINK_FOLLOW`, the one way to link an
/// open file without privileges: the new name is that inode, whatever any path says.
#[cfg(target_os = "linux")]
pub(super) fn link_open_file(file: &std::fs::File, to: &Path) -> std::io::Result<()> {
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
pub(super) fn can_fall_back_to_copy(error: &std::io::Error) -> bool {
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
pub(super) fn link_open_file(_file: &std::fs::File, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Copies the open file to a new file `to` that must not exist, from the descriptor
/// (rewound), carrying its permissions. Copies at most `len` bytes (the length the file had
/// when it was opened), so a writer cannot make the copy grow without end.
#[cfg(unix)]
pub(super) fn copy_open_file_no_clobber(
    file: &std::fs::File,
    to: &Path,
    len: u64,
) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _};
    let mut src = file.try_clone()?;
    src.rewind()?;
    copy_open_no_clobber_with(src, to, |src, dst| {
        std::io::copy(&mut src.take(len), dst)?;
        dst.set_permissions(src.metadata()?.permissions())
    })
}
