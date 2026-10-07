//! `agent quarantine list|restore`: the operator's way to see and reverse what
//! automated quarantine (issue #25) moved aside.
//!
//! The quarantine directory is derived from `--alerts`, the same "no separate
//! flag" convention `agent run` uses to place it ([`quarantine_dir_for`]), so
//! pass the same `--alerts` path the running agent was given.
//!
//! A restore is a privileged action that undoes a security decision, so it is
//! audited into the same alert log as the quarantine itself, whether it works or
//! not.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use crate::alerts::AlertLog;

/// Where `agent run` quarantines payloads for the alert log at `alerts`. The one
/// definition both `run` and this command use, so they cannot disagree.
pub(crate) fn quarantine_dir_for(alerts: &Path) -> PathBuf {
    alerts.with_file_name("quarantine")
}

/// Prints one line per quarantined payload: `<sha256>  <original path>`.
///
/// # Errors
///
/// Returns an error if the quarantine directory or a sidecar cannot be read, or
/// `out` cannot be written.
pub(crate) fn cmd_quarantine_list(alerts: &Path, out: &mut impl Write) -> anyhow::Result<()> {
    let items = response::list_quarantined(&quarantine_dir_for(alerts))?;
    if items.is_empty() {
        writeln!(out, "nothing is quarantined")?;
    }
    for item in items {
        writeln!(out, "{}  {}", item.sha256_hex, item.original.display())?;
    }
    Ok(())
}

/// Puts the payload with digest `sha256_hex` back at its original path and
/// records that in the alert log (`RESPONSE-UNQUARANTINE`).
///
/// # Errors
///
/// Returns the restore error (refused digest, altered payload, occupied
/// original path, I/O failure); the failure is audited first.
pub(crate) fn cmd_quarantine_restore(alerts: &Path, sha256_hex: &str) -> anyhow::Result<()> {
    let log = AlertLog::open(alerts, 8)?;
    let quarantine_dir = quarantine_dir_for(alerts);
    match response::unquarantine(&quarantine_dir, sha256_hex) {
        Ok(original) => {
            // The file is back, so this is a success; but if the quarantine
            // directory refused the cleanup, the payload is still listed there
            // and an operator has to be told, in the audit log as well.
            let leftover = response::is_still_quarantined(&quarantine_dir, sha256_hex).then(|| {
                format!(
                    "; the quarantined copy could not be removed and is still in {}: remove it by hand",
                    quarantine_dir.display()
                )
            });
            let leftover = leftover.as_deref().unwrap_or("");
            log.record(
                "RESPONSE-UNQUARANTINE",
                format!(
                    "restored {} ({sha256_hex}) from quarantine at an operator's request{leftover}",
                    original.display()
                ),
            );
            println!("restored {}", original.display());
            if !leftover.is_empty() {
                eprintln!("warning{leftover}");
            }
            Ok(())
        }
        Err(e) => {
            log.record(
                "RESPONSE-UNQUARANTINE",
                format!("failed to restore {sha256_hex} from quarantine: {e}"),
            );
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use response::QuarantineOutcome;

    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("quarantine-cmd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Quarantines one payload the way `agent run` does: next to the alert log.
    fn quarantined(dir: &Path) -> (PathBuf, PathBuf, String) {
        let alerts = dir.join("alerts.ndjson");
        let payload = dir.join("payload.bin");
        std::fs::write(&payload, b"marker payload").unwrap();
        let policy = policy::ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: true,
        };
        match response::quarantine_file(&payload, &quarantine_dir_for(&alerts), &policy) {
            QuarantineOutcome::Quarantined { sha256_hex, .. } => (alerts, payload, sha256_hex),
            other => panic!("expected Quarantined, got {other:?}"),
        }
    }

    #[test]
    fn the_quarantine_dir_sits_next_to_the_alert_log() {
        assert_eq!(
            quarantine_dir_for(Path::new("/var/lib/synthaea/alerts.ndjson")),
            Path::new("/var/lib/synthaea/quarantine")
        );
    }

    #[test]
    fn list_says_so_when_nothing_is_quarantined() {
        let dir = dir("list-empty");
        let mut out = Vec::new();
        cmd_quarantine_list(&dir.join("alerts.ndjson"), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "nothing is quarantined\n");
    }

    #[test]
    fn list_prints_the_digest_and_original_path() {
        let dir = dir("list");
        let (alerts, payload, digest) = quarantined(&dir);
        let mut out = Vec::new();
        cmd_quarantine_list(&alerts, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{digest}  {}\n", payload.display())
        );
    }

    #[test]
    fn a_restore_puts_the_file_back_and_is_audited() {
        let dir = dir("restore");
        let (alerts, payload, digest) = quarantined(&dir);
        cmd_quarantine_restore(&alerts, &digest).unwrap();
        assert_eq!(std::fs::read(&payload).unwrap(), b"marker payload");
        let log = std::fs::read_to_string(&alerts).unwrap();
        assert!(log.contains("RESPONSE-UNQUARANTINE"), "{log}");
        assert!(log.contains(&digest), "{log}");
        assert!(log.contains("restored"), "{log}");
    }

    #[test]
    fn a_failed_restore_is_audited_and_returns_the_error() {
        let dir = dir("restore-fail");
        let (alerts, payload, digest) = quarantined(&dir);
        std::fs::write(&payload, b"took the original's place").unwrap();
        let err = cmd_quarantine_restore(&alerts, &digest).unwrap_err();
        // The kind, not the message: the OS text is localized ("Impossible de
        // créer un fichier déjà existant." on a fr-FR Windows).
        assert_eq!(
            err.downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::AlreadyExists),
            "{err}"
        );
        let log = std::fs::read_to_string(&alerts).unwrap();
        assert!(log.contains("failed to restore"), "{log}");
        assert_eq!(
            std::fs::read(&payload).unwrap(),
            b"took the original's place"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_restore_tightens_legacy_directory_and_cleans_up() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = dir("restore-leftover");
        let (alerts, payload, digest) = quarantined(&dir);
        let qdir = quarantine_dir_for(&alerts);
        std::fs::set_permissions(&qdir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(qdir.join("probe"), b"x").is_ok() {
            return; // root ignores directory permissions: the scenario cannot be built
        }

        let restored = cmd_quarantine_restore(&alerts, &digest);

        restored.unwrap();
        assert_eq!(std::fs::read(&payload).unwrap(), b"marker payload");
        assert_eq!(
            std::fs::metadata(&qdir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let log = std::fs::read_to_string(&alerts).unwrap();
        assert!(log.contains("restored"), "{log}");
        assert!(!log.contains("could not be removed"), "{log}");
        assert!(!response::is_still_quarantined(&qdir, &digest));
    }
}
