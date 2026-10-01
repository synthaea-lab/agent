//! Automated quarantine of a payload a scan confirms malicious (issue #25).
//!
//! A quarantined file is moved into `quarantine_dir`, renamed to its own SHA-256 hex
//! digest (a duplicate digest is refused, and the audit record's hash *is* the
//! on-disk name — no separate index to keep in sync), made non-executable on Unix,
//! and paired with a `<digest>.origin` sidecar holding the original absolute path —
//! the only state [`unquarantine`] needs to reverse the action (issue #25: "reversible
//! where possible").
//!
//! Unix permissions are tightened here because `set_readonly` alone preserves the
//! execute bits. The Windows agent does not wire automated quarantine yet; its ACL
//! policy must be established before that path is enabled.

use std::{
    fmt::Write as _,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use policy::ResponsePolicy;

/// What happened to a quarantine attempt — see [`crate::kill::KillOutcome`] for why
/// this is one enum covering both the acted and observe-only cases rather than two
/// separate code paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    /// `path` was moved into `quarantine_dir` under the name `sha256_hex`.
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
    let sha256_hex = sha256_file(path)?;
    secure_quarantine_dir(quarantine_dir)?;
    let quarantined_at = quarantine_dir.join(&sha256_hex);
    let origin_path = origin_sidecar_path(quarantine_dir, &sha256_hex);
    if quarantined_at.exists() || origin_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "a quarantined payload or sidecar with this digest already exists",
        ));
    }

    move_file(path, &quarantined_at)?;
    secure_payload(&quarantined_at)?;

    // Lossy on a non-UTF-8 path (rare but real on Linux) — the sidecar is a plain
    // text file, not a byte-exact path store; accepted for this first cut rather
    // than pulling in an OsStr-preserving serialization for an edge case.
    let mut sidecar = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&origin_path)?;
    sidecar.write_all(path.to_string_lossy().as_bytes())?;
    drop(sidecar);
    secure_sidecar(&origin_path)?;

    Ok((quarantined_at, sha256_hex))
}

fn secure_quarantine_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid("quarantine directory must not be a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn secure_payload(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        return std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400));
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

/// Reverses [`quarantine_file`]: moves the payload back to the original path recorded
/// in its `.origin` sidecar, then removes the sidecar. The restored file keeps the
/// read-only bit [`quarantine_file`] set — a deliberate choice not reversed here: an
/// analyst restoring a payload for investigation should have to explicitly decide it's
/// safe to make writable/executable again, not get that back for free.
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
    let origin_path = origin_sidecar_path(quarantine_dir, sha256_hex);
    let original = PathBuf::from(std::fs::read_to_string(&origin_path)?);
    let stored = quarantine_dir.join(sha256_hex);

    // The file's name is its hash, so a mismatch means it was altered in place
    // since quarantine; handing an analyst a different file than the audit
    // record describes is worse than failing.
    if sha256_file(&stored)? != sha256_hex {
        return Err(invalid("quarantined file no longer matches its hash"));
    }
    move_file_no_clobber(&stored, &original)?;
    // The file is back: the restore has happened. Dropping the sidecar is
    // cleanup, and [`is_still_quarantined`] tells a caller when it did not work.
    let _ = std::fs::remove_file(&origin_path);

    Ok(original)
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

/// Lists what is in `quarantine_dir`, sorted by digest. A directory that does
/// not exist yet lists as empty: nothing has been quarantined.
///
/// # Errors
///
/// Propagates a failure reading the directory or a sidecar. A sidecar whose name
/// is not a digest is not one of ours and is skipped.
pub fn list_quarantined(quarantine_dir: &Path) -> std::io::Result<Vec<QuarantinedFile>> {
    let entries = match std::fs::read_dir(quarantine_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut found = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let Some(sha256_hex) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".origin"))
            .filter(|digest| is_sha256_hex(digest))
        else {
            continue;
        };
        found.push(QuarantinedFile {
            sha256_hex: sha256_hex.to_string(),
            original: PathBuf::from(std::fs::read_to_string(&path)?),
        });
    }
    found.sort_by(|a, b| a.sha256_hex.cmp(&b.sha256_hex));
    Ok(found)
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
    let mut src = std::fs::File::open(from)?;
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
    is_sha256_hex(sha256_hex)
        && (quarantine_dir.join(sha256_hex).exists()
            || origin_sidecar_path(quarantine_dir, sha256_hex).exists())
}

fn origin_sidecar_path(quarantine_dir: &Path, sha256_hex: &str) -> PathBuf {
    quarantine_dir.join(format!("{sha256_hex}.origin"))
}

/// `std::fs::rename` fails with `EXDEV` across filesystems (e.g. `/tmp` on a tmpfs,
/// the quarantine directory on the real disk) — falls back to copy-then-remove, the
/// same rename-first-then-copy tolerance any `mv`-alike needs.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(from, to)?;
            std::fs::remove_file(from)
        }
    }
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
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
    fn a_duplicate_digest_does_not_replace_the_first_origin() {
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
        let QuarantineOutcome::Quarantined { sha256_hex, .. } = first_result else {
            panic!("first payload must be quarantined");
        };
        let second_result = quarantine_file(&second, &quarantine_dir, &policy);
        assert!(matches!(second_result, QuarantineOutcome::Failed { .. }));
        assert!(
            second.exists(),
            "failed quarantine must leave its source in place"
        );
        assert_eq!(
            std::fs::read_to_string(origin_sidecar_path(&quarantine_dir, &sha256_hex)).unwrap(),
            first.to_string_lossy()
        );
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

    /// A quarantine directory that refuses deletes, so the restore itself works
    /// (the file is linked into place) but removing the quarantined copy and the
    /// sidecar afterwards cannot. `None` when this process ignores permissions
    /// (root), where the scenario cannot be built and the test must skip.
    #[cfg(unix)]
    fn undeletable_quarantine(name: &str) -> Option<(PathBuf, PathBuf, PathBuf, String)> {
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
    fn make_deletable(qdir: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(qdir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_restore_that_cannot_clean_up_still_succeeds_and_says_something_is_left() {
        let Some((dir, payload, qdir, digest)) = undeletable_quarantine("leftover") else {
            return; // root ignores directory permissions
        };

        let restored = unquarantine(&qdir, &digest);

        make_deletable(&qdir);
        assert_eq!(
            restored.unwrap(),
            payload,
            "the file is back, so the restore worked"
        );
        assert_eq!(std::fs::read(&payload).unwrap(), b"malware");
        assert!(
            is_still_quarantined(&qdir, &digest),
            "the leftover must be reported, not hidden"
        );
        // A retry now refuses (the original is occupied) instead of overwriting.
        assert_eq!(
            unquarantine(&qdir, &digest).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
