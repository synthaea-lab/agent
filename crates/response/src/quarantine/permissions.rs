//! Ownership and modes of the quarantine directory and what it holds.

use std::path::Path;

use super::{
    invalid,
    slots::{payload_slot, sidecar_slot},
};

pub(super) fn secure_quarantine_dir(path: &Path) -> std::io::Result<()> {
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    error
                } else {
                    invalid("quarantine path must be a real directory, not a symlink")
                }
            })?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() {
            return Err(invalid("quarantine path must be a directory"));
        }
        // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
        let me = unsafe { libc::geteuid() };
        if quarantine_dir_needs_chmod(metadata.uid() == me, metadata.mode())? {
            directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("quarantine directory must not be a symlink"));
        }
        if !metadata.is_dir() {
            return Err(invalid("quarantine path must be a directory"));
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
pub(super) fn quarantine_dir_needs_chmod(owned_by_me: bool, mode: u32) -> std::io::Result<bool> {
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

pub(super) fn secure_payload(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        set_unix_file_mode(path, 0o400)
    }
    #[cfg(not(unix))]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)
    }
}

pub(super) fn secure_sidecar(_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        set_unix_file_mode(_path, 0o600)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn set_unix_file_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("quarantine entry must be a regular file"));
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

pub(super) fn secure_existing_files(quarantine_dir: &Path) -> std::io::Result<()> {
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
