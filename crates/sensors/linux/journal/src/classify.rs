//! Allowlist classification: turns a [`JournalRecord`] into a [`JournalEvent`], or
//! `None` for the (vast majority of) journal traffic outside the four categories in
//! this crate's scope (issue #93). Never ships the whole journal — a category not
//! listed here is silently ignored, not logged as "unclassified".
//!
//! **Unit lifecycle is classified by `JOB_TYPE`/`JOB_RESULT`, not by the systemd
//! message-catalog UUID** (`MESSAGE_ID`), even though systemd does publish stable
//! catalog constants for this (e.g. `SD_MESSAGE_UNIT_STARTED`). Two reasons: first,
//! `JOB_TYPE=start`/`JOB_RESULT=done` is what this crate's author could actually
//! verify against a real capture on this dev machine (see `record.rs`'s tests) —
//! copying an opaque hex constant from memory into a security-relevant classifier,
//! unverified, is exactly the kind of mistake that fails silently. Second, a
//! reviewer can read `JOB_TYPE`/`JOB_RESULT` and audit the logic without looking up
//! what a 32-hex-digit UUID means.
//!
//! sshd accept/failure and `su` are classified against the standard, documented
//! OpenSSH/PAM log line formats but are **not** verified against a real capture —
//! this dev sandbox has no `sshd`, and `su` here requires interactive auth this
//! non-interactive session can't provide. Flagged as a lab-validation follow-up
//! (see the crate doc's Status section), same as issue #91's kernel-dependent paths.

use crate::JournalRecord;

/// One classified journal record. Fields are best-effort (`Option`) — a category
/// match with a field we couldn't extract is still reported (the category itself is
/// the useful signal), just with that field empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEvent {
    /// Successful SSH login (`sshd`, "Accepted ..." — password or pubkey).
    SshAccepted {
        user: Option<String>,
        source_addr: Option<String>,
    },
    /// Failed SSH login attempt (bad password, or a nonexistent account probed).
    SshFailed {
        user: Option<String>,
        source_addr: Option<String>,
    },
    /// A PAM-backed session opened, keyed by the PAM service name (`"sudo"`,
    /// `"sshd"`, `"su"`, `"login"`, ...) — parsed from the standard
    /// `pam_unix(<service>:session):` prefix, so any PAM service using
    /// `pam_unix` is covered without a per-binary allowlist.
    PamSessionOpened {
        service: String,
        target_user: Option<String>,
    },
    /// The matching close for a [`JournalEvent::PamSessionOpened`].
    PamSessionClosed { service: String },
    /// A `sudo` invocation with its logged command line (the `sudo:session` PAM
    /// wrapper around it is reported separately as `PamSessionOpened`/`Closed`).
    SudoCommand {
        invoking_user: Option<String>,
        target_user: Option<String>,
        command: Option<String>,
    },
    /// A systemd unit finished starting successfully.
    UnitStarted { unit: Option<String> },
    /// A systemd unit finished stopping.
    UnitStopped { unit: Option<String> },
    /// A systemd unit's start job failed.
    UnitFailed { unit: Option<String> },
}

/// Classifies one journal record. `None` means "not one of #93's allowlisted
/// categories" — the normal case for most journal traffic.
#[must_use]
pub fn classify(record: &JournalRecord) -> Option<JournalEvent> {
    if let Some(event) = classify_unit_job(record) {
        return Some(event);
    }

    let identifier = record.syslog_identifier.as_deref().unwrap_or_default();

    // OpenSSH 9.8+ re-execs the per-connection worker into a separate
    // `sshd-session` binary (privsep refactor) that reports under that name
    // instead of the classic single-binary `sshd` — confirmed on real hardware
    // (Arch, 2026-09-18 lab validation): a stock Arch box's `Accepted`/PAM-session
    // lines never carried `SYSLOG_IDENTIFIER=sshd` at all, only `sshd-session`.
    // Both are checked so this doesn't silently go dark on either OpenSSH
    // generation.
    if (identifier == "sshd" || identifier == "sshd-session")
        && let Some(event) = classify_sshd(&record.message)
    {
        return Some(event);
    }

    if identifier == "sudo"
        && let Some(event) = classify_sudo_command(&record.message)
    {
        return Some(event);
    }

    classify_pam_session(&record.message)
}

fn classify_unit_job(record: &JournalRecord) -> Option<JournalEvent> {
    let job_type = record.job_type.as_deref()?;
    let job_result = record.job_result.as_deref()?;
    let unit = record.unit.clone();
    match (job_type, job_result) {
        ("start", "done") => Some(JournalEvent::UnitStarted { unit }),
        ("start", "failed") => Some(JournalEvent::UnitFailed { unit }),
        ("stop", "done") => Some(JournalEvent::UnitStopped { unit }),
        _ => None,
    }
}

fn classify_sshd(message: &str) -> Option<JournalEvent> {
    if let Some(rest) = message.strip_prefix("Accepted ") {
        // "password for alice from 10.0.0.5 port 51000 ssh2" (or "publickey for ...").
        let user = extract_between(rest, " for ", " from");
        let source_addr = extract_between(rest, " from ", " port");
        return Some(JournalEvent::SshAccepted { user, source_addr });
    }
    if let Some(rest) = message.strip_prefix("Failed password for invalid user ") {
        return Some(JournalEvent::SshFailed {
            user: extract_before(rest, " from"),
            source_addr: extract_between(rest, " from ", " port"),
        });
    }
    if let Some(rest) = message.strip_prefix("Failed password for ") {
        return Some(JournalEvent::SshFailed {
            user: extract_before(rest, " from"),
            source_addr: extract_between(rest, " from ", " port"),
        });
    }
    if let Some(rest) = message.strip_prefix("Invalid user ") {
        return Some(JournalEvent::SshFailed {
            user: extract_before(rest, " from"),
            source_addr: extract_between(rest, " from ", " port"),
        });
    }
    None
}

fn classify_sudo_command(message: &str) -> Option<JournalEvent> {
    let command_idx = message.find("COMMAND=")?;
    let command = Some(message[command_idx + "COMMAND=".len()..].trim().to_string());
    // Real format: "     lab : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=...".
    let invoking_user = message
        .trim_start()
        .split_once(" :")
        .map(|(user, _)| user.trim().to_string());
    let target_user = extract_field(message, "USER=");
    Some(JournalEvent::SudoCommand {
        invoking_user,
        target_user,
        command,
    })
}

fn classify_pam_session(message: &str) -> Option<JournalEvent> {
    let rest = message.strip_prefix("pam_unix(")?;
    let (service, _) = rest.split_once(':')?;
    let service = service.to_string();

    if message.contains("session opened for user") {
        let target_user = extract_between(message, "session opened for user ", "(");
        return Some(JournalEvent::PamSessionOpened {
            service,
            target_user,
        });
    }
    if message.contains("session closed for user") {
        return Some(JournalEvent::PamSessionClosed { service });
    }
    None
}

/// Substring strictly between the first `start` and the next `end` after it.
fn extract_between(haystack: &str, start: &str, end: &str) -> Option<String> {
    let after_start = haystack.split_once(start)?.1;
    let value = after_start.split(end).next()?;
    Some(value.trim().to_string())
}

/// Substring from the start of `haystack` up to the first `end`.
fn extract_before(haystack: &str, end: &str) -> Option<String> {
    Some(haystack.split(end).next()?.trim().to_string())
}

/// Value of a `key=value` pair embedded in a `;`/space-separated log line, e.g.
/// `USER=` in `"... ; USER=root ; COMMAND=..."`.
fn extract_field(haystack: &str, key: &str) -> Option<String> {
    let after = haystack.split_once(key)?.1;
    let value = after.split([' ', ';']).next()?;
    Some(value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_record;

    fn record_with(fields: &[(&str, &str)]) -> JournalRecord {
        let mut obj = serde_json::Map::new();
        obj.insert("__CURSOR".into(), "c".into());
        obj.insert("__REALTIME_TIMESTAMP".into(), "1".into());
        for (k, v) in fields {
            obj.insert((*k).to_string(), (*v).into());
        }
        let line = serde_json::to_string(&obj).unwrap();
        parse_record(&line).unwrap()
    }

    // --- unit lifecycle (JOB_TYPE/JOB_RESULT — real capture format) ------------

    #[test]
    fn unit_start_done_is_unit_started() {
        let r = record_with(&[
            ("JOB_TYPE", "start"),
            ("JOB_RESULT", "done"),
            ("UNIT", "sshd.service"),
            ("MESSAGE", "Started sshd.service."),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::UnitStarted {
                unit: Some("sshd.service".into())
            })
        );
    }

    #[test]
    fn unit_start_failed_is_unit_failed() {
        let r = record_with(&[
            ("JOB_TYPE", "start"),
            ("JOB_RESULT", "failed"),
            ("UNIT", "broken.service"),
            ("MESSAGE", "Failed to start broken.service."),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::UnitFailed {
                unit: Some("broken.service".into())
            })
        );
    }

    #[test]
    fn unit_stop_done_is_unit_stopped() {
        let r = record_with(&[
            ("JOB_TYPE", "stop"),
            ("JOB_RESULT", "done"),
            ("UNIT", "cron.service"),
            ("MESSAGE", "Stopped cron.service."),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::UnitStopped {
                unit: Some("cron.service".into())
            })
        );
    }

    #[test]
    fn unit_job_canceled_is_not_classified() {
        // Neither started, stopped, nor failed — outside the allowlist on purpose.
        let r = record_with(&[
            ("JOB_TYPE", "start"),
            ("JOB_RESULT", "canceled"),
            ("MESSAGE", "Job canceled."),
        ]);
        assert_eq!(classify(&r), None);
    }

    // --- sshd (documented format, not lab-verified — see module doc) -----------

    #[test]
    fn sshd_accepted_password() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            (
                "MESSAGE",
                "Accepted password for alice from 10.0.0.5 port 51000 ssh2",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::SshAccepted {
                user: Some("alice".into()),
                source_addr: Some("10.0.0.5".into()),
            })
        );
    }

    #[test]
    fn sshd_accepted_publickey() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            (
                "MESSAGE",
                "Accepted publickey for bob from 10.0.0.5 port 51000 ssh2: RSA SHA256:abc",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::SshAccepted {
                user: Some("bob".into()),
                source_addr: Some("10.0.0.5".into()),
            })
        );
    }

    #[test]
    fn sshd_failed_password_known_user() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            (
                "MESSAGE",
                "Failed password for alice from 10.0.0.5 port 51000 ssh2",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::SshFailed {
                user: Some("alice".into()),
                source_addr: Some("10.0.0.5".into()),
            })
        );
    }

    #[test]
    fn sshd_failed_password_invalid_user() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            (
                "MESSAGE",
                "Failed password for invalid user root from 10.0.0.5 port 51000 ssh2",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::SshFailed {
                user: Some("root".into()),
                source_addr: Some("10.0.0.5".into()),
            })
        );
    }

    #[test]
    fn sshd_invalid_user_burst_line() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            ("MESSAGE", "Invalid user admin from 10.0.0.5 port 51000"),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::SshFailed {
                user: Some("admin".into()),
                source_addr: Some("10.0.0.5".into()),
            })
        );
    }

    #[test]
    fn sshd_session_identifier_is_also_classified() {
        // Real capture (Arch, OpenSSH 9.8+ privsep refactor): the per-connection
        // worker reports as `sshd-session`, not the classic `sshd`.
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd-session"),
            (
                "MESSAGE",
                "Accepted publickey for vagrant from 172.18.96.1 port 23331 ssh2: ED25519 SHA256:abc",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::SshAccepted {
                user: Some("vagrant".into()),
                source_addr: Some("172.18.96.1".into()),
            })
        );
    }

    #[test]
    fn sshd_unrelated_message_is_not_classified() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sshd"),
            ("MESSAGE", "Server listening on 0.0.0.0 port 22."),
        ]);
        assert_eq!(classify(&r), None);
    }

    // --- sudo (real capture format) --------------------------------------------

    #[test]
    fn sudo_command_real_capture() {
        // Real line from this dev machine's journal.
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            (
                "MESSAGE",
                "     lab : TTY=pts/0 ; PWD=/mnt/d/projets persos ; USER=root ; COMMAND=/bin/echo hi",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::SudoCommand {
                invoking_user: Some("lab".into()),
                target_user: Some("root".into()),
                command: Some("/bin/echo hi".into()),
            })
        );
    }

    // --- PAM sessions (real capture format for the "sudo" service) -------------

    #[test]
    fn pam_session_opened_real_capture() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            (
                "MESSAGE",
                "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1001)",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamSessionOpened {
                service: "sudo".into(),
                target_user: Some("root".into()),
            })
        );
    }

    #[test]
    fn pam_session_closed_real_capture() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            (
                "MESSAGE",
                "pam_unix(sudo:session): session closed for user root",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamSessionClosed {
                service: "sudo".into(),
            })
        );
    }

    #[test]
    fn pam_session_for_sshd_service_is_classified_by_service_name() {
        // Not sudo-specific: any pam_unix service name is picked up generically.
        let r = record_with(&[(
            "MESSAGE",
            "pam_unix(sshd:session): session opened for user alice(uid=1002) by (uid=0)",
        )]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamSessionOpened {
                service: "sshd".into(),
                target_user: Some("alice".into()),
            })
        );
    }

    #[test]
    fn unrelated_record_is_not_classified() {
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "kernel"),
            ("MESSAGE", "eth0: link becomes ready"),
        ]);
        assert_eq!(classify(&r), None);
    }
}
