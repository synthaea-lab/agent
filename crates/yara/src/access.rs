//! Whose file is this to read? The scan request comes from a process that opened a path
//! for writing, and the agent reads it with `CAP_DAC_READ_SEARCH`, which no ordinary
//! user has. Without a check, any local user can aim the agent at any file by name: the
//! sensor fires at `sys_enter_openat`, before the kernel's permission check, so even an
//! open that fails with `EACCES` queues the path (#594).
//!
//! [`Requester::open`] reads on the requester's behalf: it resolves the path, requires
//! the requester to be able to search every directory on the way and read the file, and
//! opens the file only then. This covers a symlink the requester planted too, because
//! the check is on the resolved path.
//!
//! The rule is the plain owner/group/other mode bits. It knows nothing of ACLs,
//! supplementary groups or capabilities, so it fails closed: a file the requester could
//! reach only through those is not scanned. Root (uid 0) is never restricted.
//!
//! Unix only. Elsewhere there is no uid to check, and every path is allowed as before.

use std::{fs::File, io, path::Path};

/// The user behind a scan request, as the sensor saw them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requester {
    pub uid: u32,
    pub gid: u32,
}

/// Why [`Requester::open`] did not hand back a file.
#[derive(Debug)]
pub enum Refused {
    /// The requester could not read the file or search a directory on the way: not the
    /// agent's to read on their behalf.
    NotAllowed,
    /// Not a regular file (a FIFO, a device, a directory).
    NotRegular,
}

#[cfg(unix)]
impl Requester {
    /// Opens `path` for reading on behalf of this user.
    ///
    /// # Errors
    ///
    /// The `io::Error` of resolving or opening the path (a vanished dropper payload is
    /// the normal case); the inner `Err` says why a file the agent *could* open was
    /// refused.
    pub fn open(&self, path: &Path) -> io::Result<Result<File, Refused>> {
        if self.uid == 0 {
            return open_regular(path);
        }
        // Resolved, so a planted symlink is judged by where it leads. The kernel's
        // `fs.protected_symlinks` covers sticky directories only, and not on every host.
        let resolved = std::fs::canonicalize(path)?;
        for dir in resolved.ancestors().skip(1) {
            if !self.permits(&std::fs::metadata(dir)?, 0o1) {
                return Ok(Err(Refused::NotAllowed));
            }
        }
        // Checked on the opened file, not on the path: the mode and owner are those of
        // the inode actually read, whatever the path was swapped to meanwhile.
        let file = match open_regular(&resolved)? {
            Ok(file) => file,
            refused => return Ok(refused),
        };
        Ok(if self.permits(&file.metadata()?, 0o4) {
            Ok(file)
        } else {
            Err(Refused::NotAllowed)
        })
    }

    /// Whether the mode bits give this user `bit` (4 read, 1 search/execute).
    fn permits(&self, meta: &std::fs::Metadata, bit: u32) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        let mode = meta.mode();
        let class = if meta.uid() == self.uid {
            bit << 6
        } else if meta.gid() == self.gid {
            bit << 3
        } else {
            bit
        };
        mode & class != 0
    }
}

#[cfg(not(unix))]
impl Requester {
    /// No uid to check on this platform: opens as the agent always did.
    ///
    /// # Errors
    ///
    /// The `io::Error` of opening the path.
    pub fn open(&self, path: &Path) -> io::Result<Result<File, Refused>> {
        open_regular(path)
    }
}

/// Opens `path` if it is a regular file. The `stat` comes first because opening a FIFO
/// with no writer blocks forever.
fn open_regular(path: &Path) -> io::Result<Result<File, Refused>> {
    if !std::fs::metadata(path)?.is_file() {
        return Ok(Err(Refused::NotRegular));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Ok(Err(Refused::NotRegular));
    }
    Ok(Ok(file))
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use super::*;

    /// A user that owns nothing the tests create.
    const STRANGER: Requester = Requester {
        uid: 4_000_000,
        gid: 4_000_000,
    };

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("yara-access-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file(path: &Path, mode: u32) {
        std::fs::write(path, b"content").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn owner_of(path: &Path) -> Requester {
        let meta = std::fs::metadata(path).unwrap();
        Requester {
            uid: meta.uid(),
            gid: meta.gid(),
        }
    }

    fn allowed(requester: Requester, path: &Path) -> bool {
        matches!(requester.open(path), Ok(Ok(_)))
    }

    fn refused(requester: Requester, path: &Path) -> bool {
        matches!(requester.open(path), Ok(Err(Refused::NotAllowed)))
    }

    #[test]
    fn the_owner_reads_a_private_file_and_a_stranger_does_not() {
        let d = dir("private");
        let f = d.join("secret");
        file(&f, 0o600);
        assert!(allowed(owner_of(&f), &f));
        assert!(refused(STRANGER, &f));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_world_readable_file_is_read_for_anyone() {
        let d = dir("world");
        let f = d.join("public");
        file(&f, 0o644);
        assert!(allowed(STRANGER, &f));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_group_bits_apply_to_the_files_group_only() {
        let d = dir("group");
        let f = d.join("shared");
        file(&f, 0o640);
        let owner = owner_of(&f);
        assert!(allowed(
            Requester {
                uid: 4_000_000,
                gid: owner.gid
            },
            &f
        ));
        assert!(refused(STRANGER, &f));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_world_readable_file_in_a_directory_the_user_cannot_search_is_refused() {
        let d = dir("hidden-dir");
        let private = d.join("private");
        std::fs::create_dir(&private).unwrap();
        let f = private.join("public-but-unreachable");
        file(&f, 0o644);
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(refused(STRANGER, &f));
        assert!(allowed(owner_of(&f), &f));
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_symlink_is_judged_by_where_it_leads() {
        let d = dir("symlink");
        let target = d.join("root-only");
        file(&target, 0o600);
        let link = d.join("planted");
        symlink(&target, &link).unwrap();
        // The link itself is readable by anyone (symlink modes mean nothing); the file
        // behind it is not.
        assert!(refused(STRANGER, &link));
        assert!(allowed(owner_of(&target), &link));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn root_is_not_restricted_and_a_directory_is_not_regular() {
        let d = dir("root");
        let f = d.join("secret");
        file(&f, 0o600);
        let root = Requester { uid: 0, gid: 0 };
        assert!(allowed(root, &f));
        assert!(matches!(root.open(&d), Ok(Err(Refused::NotRegular))));
        assert!(matches!(
            owner_of(&f).open(&d),
            Ok(Err(Refused::NotRegular))
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_vanished_file_is_an_io_error_not_a_refusal() {
        let d = dir("vanished");
        let err = STRANGER.open(&d.join("gone")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&d);
    }
}
