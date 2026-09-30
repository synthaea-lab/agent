//! Symlink-safe, atomic file writes (issue #30, PR #520 review): the one place
//! that writes content and release files, shared by the agent's content apply
//! and release staging so both get the same guarantees.
//!
//! Cross-platform on purpose (std only): content distribution has no Linux-only
//! constraint, unlike [`crate::layout`].

use std::{io::Write as _, path::Path};

/// Refuses if `dest`, or any of its already-existing path components
/// *under* `root`, is a symlink — checked with [`std::fs::symlink_metadata`]
/// (never follows a symlink, unlike [`std::fs::metadata`]). This agent can
/// run with elevated rights (PR #520 review), so a symlink planted anywhere
/// under the content directory it writes into — not just at the leaf —
/// could otherwise redirect a write outside that directory entirely.
///
/// Deliberately does **not** walk `root`'s own ancestors: real systems
/// routinely have a symlink somewhere above any given directory (macOS's
/// `/var` is itself `-> /private/var`, which is exactly what turned this
/// check into a false positive on every `std::env::temp_dir()`-rooted test
/// before this fix — CI on macOS caught it) and none of that is under this
/// caller's control or part of the threat this check defends against. `root`
/// itself is trusted — the caller has already validated it — only what gets
/// created *under* it, by this process, is what needs checking.
///
/// # Errors
///
/// Returns an error naming the offending path if any existing component
/// under `root` is a symlink.
pub fn reject_symlink_components(root: &Path, dest: &Path) -> std::io::Result<()> {
    let relative = dest.strip_prefix(root).unwrap_or(dest);
    let mut probe = root.to_path_buf();
    for component in relative.components() {
        probe.push(component);
        if let Ok(meta) = std::fs::symlink_metadata(&probe)
            && meta.file_type().is_symlink()
        {
            return Err(std::io::Error::other(format!(
                "refusing to write: {} is a symlink",
                probe.display()
            )));
        }
    }
    Ok(())
}

/// Writes `bytes` to `dest` atomically: to a same-directory temporary file
/// first (so the eventual `rename` stays on one filesystem), `fsync`ed, then
/// renamed over `dest` (PR #520 review). A `rename` onto an existing path
/// replaces it in one filesystem operation — a reader (or a re-run of this
/// same command after a crash) only ever sees the complete old file or the
/// complete new one, never a truncated one. [`reject_symlink_components`] is
/// checked both before and after creating any missing parent directories
/// (the latter guards a symlink race in between; `create_dir_all` itself
/// cannot produce a symlink, since it only creates plain directories).
/// `rename` does not follow a symlink at `dest` itself on any platform this
/// agent targets — it replaces the link, never writes through it — so this
/// covers the parent-directory case that actually mattered.
///
/// The temp file is opened with `create_new`, so a symlink (or anything else)
/// pre-planted at its name makes the write fail rather than be followed
/// (PR #520 review round 3); it is removed if the write or rename fails.
///
/// `root` bounds the symlink check ([`reject_symlink_components`]) to `dest`'s
/// components under it — `dest` must be `root` or a descendant of it.
///
/// # Errors
///
/// Returns an error if any existing path component under `root` is a
/// symlink, or if any filesystem operation fails.
pub fn write_atomically(root: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_with_mode(root, dest, bytes, None)
}

/// [`write_atomically`], creating the file with Unix permission `mode` (e.g.
/// `0o755` for a release binary) before it becomes visible at `dest` — set on the
/// temp file, so there is no window where `dest` exists with the wrong mode. On
/// non-Unix platforms `mode` is ignored.
///
/// # Errors
///
/// As [`write_atomically`].
pub fn write_executable_atomically(root: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_with_mode(root, dest, bytes, Some(0o755))
}

fn write_with_mode(
    root: &Path,
    dest: &Path,
    bytes: &[u8],
    mode: Option<u32>,
) -> std::io::Result<()> {
    reject_symlink_components(root, dest)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    reject_symlink_components(root, dest)?;

    let file_name = dest.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination path has no file name",
        )
    })?;
    let tmp_path = dest.with_file_name(format!(
        "{}.tmp-{}",
        file_name.to_string_lossy(),
        unique_suffix()
    ));

    // `create_new` (O_EXCL / CREATE_NEW) fails on any existing entry —
    // including a dangling symlink planted at the temp name — instead of
    // following it, so the write can never land outside `root`.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut tmp_file = options.open(&tmp_path)?;
    let written = tmp_file
        .write_all(bytes)
        .and_then(|()| tmp_file.sync_all())
        .and_then(|()| {
            drop(tmp_file);
            std::fs::rename(&tmp_path, dest)
        });
    if written.is_err() {
        // Best effort: the original error is the one worth reporting.
        let _ = std::fs::remove_file(&tmp_path);
    }
    written
}

/// Unpredictable-enough temp-file suffix: PID, wall-clock nanoseconds and a
/// process-wide counter. Uniqueness is not what protects against planted
/// links (`create_new` is); it only keeps an attacker from pre-creating the
/// name cheaply and makes benign collisions vanishingly rare.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "{}-{nanos:x}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fsutil-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomically_writes_the_full_content() {
        let dir = tmp("atomic-happy-path");
        let dest = dir.join("rules").join("beacon.sigma");
        write_atomically(&dir, &dest, b"title: beacon\n").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"title: beacon\n");
        // The temp file used to get there is gone — renamed, not copied.
        let leftovers: Vec<_> = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(leftovers.len(), 1, "only the final file should remain");
    }

    #[test]
    fn write_atomically_overwrites_an_existing_file_completely() {
        let dir = tmp("atomic-overwrite");
        let dest = dir.join("beacon.sigma");
        write_atomically(&dir, &dest, b"old, much longer content here").unwrap();
        write_atomically(&dir, &dest, b"new").unwrap();
        // Not "newlonger" or any splice of the two — a full replacement.
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomically_refuses_a_symlinked_destination() {
        let dir = tmp("atomic-symlink-dest");
        let real_target = dir.join("outside-content-dir.txt");
        std::fs::write(&real_target, b"pre-existing, must not be touched").unwrap();
        let content_dir = dir.join("content");
        let dest = content_dir.join("rules").join("beacon.sigma");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real_target, &dest).unwrap();

        // `rename` would not actually write through this symlink (it
        // replaces the link itself), but the explicit refusal is the
        // documented, auditable behavior rather than relying on that
        // platform-specific rename semantic.
        let err = write_atomically(&content_dir, &dest, b"malicious").unwrap_err();
        assert!(err.to_string().contains("symlink"), "got: {err}");
        assert_eq!(
            std::fs::read(&real_target).unwrap(),
            b"pre-existing, must not be touched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_atomically_refuses_when_a_parent_directory_is_a_symlink() {
        let dir = tmp("atomic-symlink-parent");
        let real_dir = dir.join("real-elsewhere");
        std::fs::create_dir_all(&real_dir).unwrap();
        let content_dir = dir.join("content");
        std::fs::create_dir_all(&content_dir).unwrap();
        // `content/rules` is a symlink to a directory outside `content/`.
        std::os::unix::fs::symlink(&real_dir, content_dir.join("rules")).unwrap();

        let dest = content_dir.join("rules").join("beacon.sigma");
        let err = write_atomically(&content_dir, &dest, b"malicious").unwrap_err();
        assert!(err.to_string().contains("symlink"), "got: {err}");
        assert!(
            !real_dir.join("beacon.sigma").exists(),
            "must not have written through the symlinked parent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_atomically_never_follows_a_symlink_planted_at_the_temp_name() {
        let dir = tmp("atomic-symlink-tmp");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"ORIGINAL").unwrap();
        let content_dir = dir.join("content");
        let dest = content_dir.join("rules").join("beacon.sigma");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        // Plant links at every plausible temp name, including the old
        // predictable `<name>.tmp-<pid>` form.
        std::os::unix::fs::symlink(
            &victim,
            dest.with_file_name(format!("beacon.sigma.tmp-{}", std::process::id())),
        )
        .unwrap();

        write_atomically(&content_dir, &dest, b"SIGNED-CONTENT").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"ORIGINAL");
        assert!(!std::fs::symlink_metadata(&dest).unwrap().is_symlink());
        assert_eq!(std::fs::read(&dest).unwrap(), b"SIGNED-CONTENT");
    }

    #[cfg(windows)]
    #[test]
    fn write_atomically_refuses_a_directory_junction_parent() {
        let dir = tmp("atomic-junction-parent");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let content_dir = dir.join("content");
        std::fs::create_dir_all(&content_dir).unwrap();
        let junction = content_dir.join("rules");
        // Junctions need no privilege, unlike file symlinks.
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(status.status.success(), "mklink /J failed");

        let dest = junction.join("beacon.sigma");
        let err = write_atomically(&content_dir, &dest, b"malicious").unwrap_err();
        assert!(err.to_string().contains("symlink"), "got: {err}");
        assert!(!outside.join("beacon.sigma").exists());
    }

    #[test]
    fn write_atomically_does_not_trip_on_a_symlink_above_root() {
        // The exact bug this test pins (caught by macOS CI): `root`'s own
        // ancestors are not checked, only components under it — on macOS
        // `/var` is itself `-> /private/var`, so `std::env::temp_dir()`
        // (which every other test in this module is rooted under) sits
        // below a real, benign symlink that has nothing to do with this
        // agent's content directory.
        let dir = tmp("atomic-symlink-above-root");
        let dest = dir.join("rules").join("beacon.sigma");
        // `dir` itself is under `std::env::temp_dir()`, which is a symlink
        // on macOS — this must still succeed.
        write_atomically(&dir, &dest, b"title: beacon\n").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"title: beacon\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_executable_atomically_sets_the_mode_before_the_file_appears() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmp("exec-mode");
        let dest = dir.join("bin").join("agent");
        write_executable_atomically(&dir, &dest, b"#!/bin/sh\n").unwrap();
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn write_atomically_writes_non_executable_files_by_default() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = tmp("plain-mode");
            let dest = dir.join("rules.sigma");
            write_atomically(&dir, &dest, b"x").unwrap();
            assert_eq!(
                std::fs::metadata(&dest).unwrap().permissions().mode() & 0o111,
                0,
                "no execute bit on ordinary content"
            );
        }
    }
}
