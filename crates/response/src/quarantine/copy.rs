//! Moving and copying files without ever overwriting one, hashing what is copied.

use std::path::Path;

use super::invalid;

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
pub(super) fn move_file_no_clobber(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(e),
        Err(_) => copy_no_clobber(from, to)?,
    }
    let _ = std::fs::remove_file(from);
    Ok(())
}

/// Restores a new-format Unix quarantine entry without exposing a partially copied file.
/// Creating the destination as `0400` also keeps it private until the bytes are complete;
/// the requested original mode is applied through the open descriptor only after syncing.
#[cfg(unix)]
pub(super) fn restore_file_with_mode(
    from: &Path,
    to: &Path,
    mode: u32,
    expected_digest: &str,
) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut source = std::fs::File::open(from)?;
    let mut destination = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(to)?;
    let restored = sha256_copy(&mut source, &mut destination)
        .and_then(|digest| {
            if digest == expected_digest {
                Ok(())
            } else {
                Err(invalid("quarantined file no longer matches its hash"))
            }
        })
        .and_then(|_| destination.sync_all())
        .and_then(|()| destination.set_permissions(std::fs::Permissions::from_mode(mode)));
    drop(destination);
    if let Err(error) = restored {
        let _ = std::fs::remove_file(to);
        return Err(error);
    }
    // The restored path is the successful outcome; removing the old quarantine link is cleanup.
    let _ = std::fs::remove_file(from);
    Ok(())
}

/// Moves a source into quarantine by path, without leaving its original path live. Unlike
/// restore, failure to remove the source after creating the destination is an
/// error: both copies must not be reported as a successful quarantine. Unix quarantines go
/// through [`Source::move_into_quarantine`] instead, which holds the file open (#689).
#[cfg(any(test, not(unix)))]
pub(super) fn move_to_quarantine(from: &Path, to: &Path) -> std::io::Result<()> {
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
pub(super) fn copy_no_clobber(from: &Path, to: &Path) -> std::io::Result<()> {
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
pub(super) fn copy_no_clobber_with(
    from: &Path,
    to: &Path,
    fill: impl FnOnce(&mut std::fs::File, &mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    copy_open_no_clobber_with(std::fs::File::open(from)?, to, fill)
}

/// [`copy_no_clobber_with`] for a source that is already open.
pub(super) fn copy_open_no_clobber_with(
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

pub(super) fn sha256_file(path: &Path) -> std::io::Result<String> {
    sha256_reader(&mut std::fs::File::open(path)?)
}

pub(super) fn sha256_reader(file: &mut impl std::io::Read) -> std::io::Result<String> {
    sha256_copy(file, &mut std::io::sink())
}

/// Copies `from` to `to` and returns the SHA-256, in lowercase hex, of exactly the bytes copied.
pub(super) fn sha256_copy(
    from: &mut impl std::io::Read,
    to: &mut impl std::io::Write,
) -> std::io::Result<String> {
    file_hash::sha256_copy(from, to).map(|digest| file_hash::hex(&digest))
}
