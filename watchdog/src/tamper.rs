//! Tamper resistance for the on-disk install surface (issue #103).
//!
//! Kill resistance (`supervise`/`service`) assumes an attacker who kills a process;
//! this assumes one with local root who never kills anything — instead editing the
//! service definition, swapping the agent binary on disk, or dropping the install
//! directory's permissions to plant a replacement later. None of this stops root
//! outright (nothing can): the goal is detection, friction, and an audit trail for a
//! legitimately-installed, admin-consented agent, matching the issue's framing.
//!
//! Linux only for now. Windows service-ACL hardening and macOS's Endpoint Security
//! system-extension path are tracked in the issue but not implemented here.

use std::{fs::File, io::Read as _, path::Path};

/// Hashes a file's contents with SHA-256. Same buffered-read shape as
/// `enrich::hash_file` (`sha2` 0.11 dropped `impl Write for Sha256`, so
/// `io::copy` doesn't apply — read into a buffer and feed `Digest::update` by hand).
///
/// # Errors
/// Propagates any I/O error opening or reading `path`.
pub(crate) fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Refuses to proceed if `dir` is world-writable (mode & `0o002`). An attacker with
/// write access to the agent's own install directory can drop a replacement binary
/// the instant this process's own integrity check (`BinaryPin`) passes — a
/// world-writable install directory undermines that check's entire premise, so
/// this is checked independently of it.
///
/// # Errors
/// Returns an error if `dir`'s metadata cannot be read, or if it is world-writable.
#[cfg(unix)]
pub(crate) fn refuse_world_writable_dir(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(dir)
        .map_err(|e| anyhow::anyhow!("cannot stat install directory {}: {e}", dir.display()))?
        .permissions()
        .mode();
    anyhow::ensure!(
        mode & 0o002 == 0,
        "install directory {} is world-writable (mode {:o}) — refusing to \
         install/supervise from an untrusted location",
        dir.display(),
        mode & 0o777
    );
    Ok(())
}

/// Sets `path`'s permission bits to exactly `mode`, clearing any group/world-write
/// bit a lax umask left set when the file was written.
///
/// # Errors
/// Propagates any I/O error reading or setting `path`'s permissions.
#[cfg(unix)]
pub(crate) fn harden_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Sets `path`'s owner and group to root (uid/gid 0) — mode bits alone
/// (`harden_permissions`) still leave a non-root-owned install artifact one
/// `chmod` away from being writable by its own (non-root) owner again.
/// `install`/`uninstall` already require root to write these paths at all
/// (`/etc/systemd/system`, the resolved binary paths), so this is normalizing
/// ownership on a path this process could already write, not an escalation.
///
/// # Errors
/// Propagates any I/O error setting `path`'s owner.
#[cfg(unix)]
pub(crate) fn harden_ownership(path: &Path) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, Some(0), Some(0))
}

/// A binary's SHA-256, pinned at one point in time (watchdog startup) so every
/// later spawn can be checked against that baseline — see [`BinaryPin::verify`].
/// Pure file I/O, no `cfg` gate: hashing and comparing bytes is exactly as
/// meaningful on every platform, even though only Linux wires it up so far.
pub(crate) struct BinaryPin {
    path: std::path::PathBuf,
    digest: [u8; 32],
}

impl BinaryPin {
    /// Hashes `path` now and remembers the result.
    ///
    /// # Errors
    /// Propagates any I/O error reading `path`.
    pub(crate) fn pin(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            digest: sha256_file(path)?,
        })
    }

    /// Re-hashes the pinned path and reports whether it still matches. An I/O
    /// error (binary deleted, permission changed) counts as a mismatch — the
    /// caller's response ("do not launch this") is the same either way.
    #[must_use]
    pub(crate) fn verify(&self) -> bool {
        sha256_file(&self.path)
            .map(|current| current == self.digest)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// A path under the OS temp dir unique to this test process+call, so
    /// concurrent test runs never collide on the same file.
    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "synthaea-tamper-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn pin_matches_an_unmodified_file() {
        let path = temp_path("unmodified");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"agent binary contents")
            .unwrap();
        let pin = BinaryPin::pin(&path).unwrap();
        assert!(pin.verify());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn pin_detects_a_swapped_file() {
        // The exact scenario #103 describes: the file at the same path now has
        // different bytes.
        let path = temp_path("swapped");
        std::fs::write(&path, b"agent binary contents").unwrap();
        let pin = BinaryPin::pin(&path).unwrap();
        std::fs::write(&path, b"a different, tampered binary").unwrap();
        assert!(!pin.verify());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn pin_detects_a_deleted_file() {
        let path = temp_path("deleted");
        std::fs::write(&path, b"agent binary contents").unwrap();
        let pin = BinaryPin::pin(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!pin.verify());
    }

    #[cfg(unix)]
    #[test]
    fn refuse_world_writable_dir_rejects_a_world_writable_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_path("world-writable-dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(refuse_world_writable_dir(&dir).is_err());
        std::fs::remove_dir(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn refuse_world_writable_dir_accepts_a_normal_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_path("normal-dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(refuse_world_writable_dir(&dir).is_ok());
        std::fs::remove_dir(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn harden_permissions_clears_the_world_write_bit() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = temp_path("harden");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        harden_permissions(&path, 0o644).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn harden_ownership_sets_root_when_running_as_root() {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: chown(2) to root requires root — not running as root here");
            return;
        }
        use std::os::unix::fs::MetadataExt as _;
        let path = temp_path("ownership");
        std::fs::write(&path, b"x").unwrap();
        harden_ownership(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.uid(), 0);
        assert_eq!(meta.gid(), 0);
        std::fs::remove_file(&path).ok();
    }
}
