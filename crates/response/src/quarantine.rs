//! Automated quarantine of a payload a scan confirms malicious (issue #25).
//!
//! A quarantined file is moved into `quarantine_dir`, renamed to its own SHA-256 hex
//! digest (so two quarantined files never collide on name, and the audit record's
//! hash *is* the on-disk name — no separate index to keep in sync), marked read-only,
//! and paired with a `<digest>.origin` sidecar holding the original absolute path —
//! the only state [`unquarantine`] needs to reverse the action (issue #25: "reversible
//! where possible").
//!
//! Platform-neutral: renaming, read-only, and reading/writing plain files are all
//! plain `std::fs` — no `#[cfg(target_os = ...)]` needed (contrast [`crate::kill`],
//! which does need one, injected by the caller instead of living in this crate).

use std::{
    fmt::Write as _,
    io::Read as _,
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
    std::fs::create_dir_all(quarantine_dir)?;
    let quarantined_at = quarantine_dir.join(&sha256_hex);

    move_file(path, &quarantined_at)?;

    let mut permissions = std::fs::metadata(&quarantined_at)?.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&quarantined_at, permissions)?;

    // Lossy on a non-UTF-8 path (rare but real on Linux) — the sidecar is a plain
    // text file, not a byte-exact path store; accepted for this first cut rather
    // than pulling in an OsStr-preserving serialization for an edge case.
    let origin_path = origin_sidecar_path(quarantine_dir, &sha256_hex);
    std::fs::write(&origin_path, path.to_string_lossy().as_bytes())?;

    Ok((quarantined_at, sha256_hex))
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
/// know about immediately if it didn't work.
pub fn unquarantine(quarantine_dir: &Path, sha256_hex: &str) -> std::io::Result<PathBuf> {
    let origin_path = origin_sidecar_path(quarantine_dir, sha256_hex);
    let original = std::fs::read_to_string(&origin_path)?;
    let original = PathBuf::from(original);

    move_file(&quarantine_dir.join(sha256_hex), &original)?;
    std::fs::remove_file(&origin_path)?;

    Ok(original)
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
}
