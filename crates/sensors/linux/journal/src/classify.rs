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
//!
//! `classify_pam` matches the `pam_unix(`/`pam_sss(` prefixes (#881), the latter
//! checked against SSSD's own upstream source rather than assumed (see the
//! function's doc). `pam_ldap` and `pam_faillock` are still not matched — not
//! confirmed safe to skip, just unconfirmed either way (`pam_ldap`) or a different
//! message shape entirely (`pam_faillock`) — so the T1548.003 burst-then-success
//! join (`crates/rules/src/sudo.rs`) can still silently miss failures on a host
//! using either. A host stacking `pam_unix` and `pam_sss` as two authenticators for
//! the *same* account (not the usual one-module-per-account-source arrangement)
//! would otherwise double-count one failed password as two, and `pam_sss` itself
//! logs its own "authentication failure" line even for an account it doesn't
//! manage (`PAM_USER_UNKNOWN`) — both mitigated one level up, in `tail.rs`'s
//! `ClassifiedJournal` (#881 review, `SherlockOmss` 2026-10-22): a one-line
//! lookahead retracts a `pam_sss` failure confirmed as `PAM_USER_UNKNOWN` by
//! [`pam_sss_reports_user_unknown`], and a pid-keyed dedup window drops a second
//! failure from the same pid as the first double-logged by a second stacked
//! module. `classify_pam` itself stays a stateless, one-record-at-a-time
//! classifier — neither mitigation needed state here. Neither `pam_unix` nor
//! `pam_sss`'s lines are live-validated against a real sssd host here (no such
//! host in this dev sandbox) — same documented-format caveat as the sshd lines
//! above.

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
    /// A PAM authentication failure (wrong password) for the `sudo`/`su`
    /// service — parsed from the standard `pam_unix(<service>:auth):
    /// authentication failure; ...` line. Only emitted for `sudo`/`su`:
    /// `sshd`'s own PAM auth failure is the same event [`JournalEvent::SshFailed`]
    /// already covers (its `"Failed password"` line), mapping both would
    /// double-count, same reasoning as [`JournalEvent::PamSessionOpened`]'s own
    /// restriction (#381, T1548.003).
    PamAuthFailure {
        service: String,
        /// The `logname=` field: who typed the (wrong) password. For `sudo` it is
        /// the join key when `user=` is missing from the line (the two name the
        /// same account there, see `target_user`); for `su` it is not projected
        /// into `schema::AuthEvent` (narrower than this raw shape), kept here for
        /// forensic completeness.
        invoking_user: Option<String>,
        /// The `user=` field: the account PAM checked a password against. For
        /// `su` this is the real target (the account being switched to); for
        /// `sudo` it is the invoker — `pam_unix(sudo:auth)` authenticates the
        /// invoker's own password, never the `-u` target, so this equals
        /// `invoking_user` on a sudo failure (#838). The PAM layer never learns
        /// a sudo attempt's intended target at all, let alone on a failure.
        target_user: Option<String>,
    },
    /// A `sudo` invocation with its logged command line (the `sudo:session` PAM
    /// wrapper around it is reported separately as `PamSessionOpened`/`Closed`).
    SudoCommand {
        invoking_user: Option<String>,
        /// The `USER=` field: the real escalation target (`root` by default, or
        /// whoever `-u` names). Unlike [`JournalEvent::PamAuthFailure`]'s own
        /// `target_user`, this is never the invoker — `classify_sudo_command`
        /// only runs on the `COMMAND=` line, logged once sudo has already
        /// authenticated and decided who to become. `auth::to_auth_event` swaps
        /// this out for `invoking_user` before keying `schema::AuthEvent`,
        /// precisely because it is *not* the same account a preceding failure
        /// would have named.
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

    classify_pam(&record.message)
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

/// Substrings `sudo` logs on the same `COMMAND=` line when the attempt did
/// **not** succeed — a wrong password, an account not in `sudoers`, a
/// `sudoers` rule that names the command but refuses it either on this host
/// or outright, no password available to try — checked before treating a
/// `COMMAND=` line as a privilege-escalation success, since a failed attempt
/// logs `COMMAND=` too, same line shape. The host-restriction marker,
/// `"user NOT authorized on host"` (`plugins/sudoers/logging.c`, sudo
/// 1.9.15p5), was added per review of #838 (Sollykhan, 2026-10-19): without
/// it, a denial from a host-restricted central `sudoers` (fleets where one
/// `sudoers` file is shared and scoped per host) was counted as a success.
const SUDO_COMMAND_FAILURE_MARKERS: &[&str] = &[
    "incorrect password attempt",
    "NOT in sudoers",
    "command not allowed",
    "a password is required",
    "user NOT authorized on host",
];

/// Whether a `sudo` `COMMAND=` line records a refused attempt. The reason sudo
/// gives is the first `" ; "`-separated segment after the `"<user> :"` prefix
/// (`lab : 3 incorrect password attempts ; TTY=...`; a success starts straight
/// at `TTY=`/`PWD=`), so only that segment is searched. Everything after it
/// (`PWD=`, `USER=`, `COMMAND=`) is chosen by the invoking user: scanning the
/// whole line would let a directory or an argument named like a marker turn a
/// real success into a dropped one, and with it silence the T1548.003 join
/// (#838 review).
fn sudo_attempt_failed(message: &str) -> bool {
    let Some((_, after_user)) = message.split_once(" :") else {
        return false;
    };
    let reason = after_user.split(" ; ").next().unwrap_or_default();
    SUDO_COMMAND_FAILURE_MARKERS
        .iter()
        .any(|marker| reason.contains(marker))
}

fn classify_sudo_command(message: &str) -> Option<JournalEvent> {
    if sudo_attempt_failed(message) {
        return None;
    }
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

/// Folds the PAM service name used for an interactive-login invocation into
/// the base service a brute-force attempt against it is tracked under.
/// PAM 1.5.3 ships separate `/etc/pam.d/su-l` and `/etc/pam.d/sudo-i` config
/// files, so `su -`/`su --login` and `sudo -i` log `pam_unix(su-l:...)`/
/// `pam_unix(sudo-i:...)` rather than `pam_unix(su:...)`/`pam_unix(sudo:...)`
/// — before this normalization, `classify_pam`'s exact-match on the service
/// name (and `auth::emitted_by`'s guard downstream) meant these two
/// interactive forms never produced a `PamSessionOpened`/`PamAuthFailure` at
/// all, so a brute force against either was invisible to T1548.003 and to
/// the T1110 burst counter (review of #838, Sollykhan 2026-10-19: "the most
/// common interactive forms"). Still the same `su`/`sudo` binary either way
/// (`_COMM` is unaffected), only the PAM service name PAM itself dispatches
/// on changes.
fn normalize_pam_service(service: &str) -> &str {
    match service {
        "su-l" => "su",
        "sudo-i" => "sudo",
        other => other,
    }
}

fn classify_pam(message: &str) -> Option<JournalEvent> {
    // pam_sss (SSSD): matched against the module's own upstream source
    // (src/sss_client/pam_sss.c, send_and_receive(), SSSD/sssd@master, checked
    // 2026-10-21), not assumed — its logger() call emits
    //   "authentication %s; logname=%s uid=%lu euid=%d tty=%s ruser=%s rhost=%s
    //   user=%s"
    // with "%s" filled in as "success"/"failure", in the same field order
    // extract_field below reads for pam_unix (#881, review by SherlockOmss).
    //
    // pam_ldap is deliberately NOT matched here — not because it is confirmed to
    // have no message of its own (no source checked for that), but because no
    // source was found that documents one; treat as "not covered, format
    // unknown", not "safely covered elsewhere". pam_faillock is also not
    // matched: its own log lines (lockout bookkeeping) are a different shape
    // entirely. Both are still open gaps (#881).
    //
    // Two risks were open here (host stacking pam_unix and pam_sss as two
    // authenticators for the same account could double-count one wrong password;
    // pam_sss's own "authentication failure" line also fires for PAM_USER_UNKNOWN,
    // an account it simply doesn't manage, not a wrong password) — both mitigated
    // one level up, in tail.rs's ClassifiedJournal, rather than here: this function
    // stays a stateless, one-record-at-a-time classifier, and both mitigations
    // need to look at more than one record (a pid-keyed dedup window for the
    // double-count; a one-line lookahead at the following "received for user
    // %s: %d (%s)" line for PAM_USER_UNKNOWN, via pam_sss_reports_user_unknown
    // below). See tail.rs's struct doc for the detail (#881 review, SherlockOmss
    // 2026-10-22).
    let rest = ["pam_unix(", "pam_sss("]
        .into_iter()
        .find_map(|prefix| message.strip_prefix(prefix))?;
    let (service, _) = rest.split_once(':')?;
    let service = normalize_pam_service(service).to_string();

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
    if (service == "sudo" || service == "su") && message.contains("authentication failure") {
        // Field order is fixed (logname, uid, euid, tty, ruser, rhost, user), but
        // "user=" is searched with a leading space: a bare `extract_field(..,
        // "user=")` would match inside `ruser=` first (it reads "r" + "user="),
        // taking the wrong, usually-empty field as the target.
        return Some(JournalEvent::PamAuthFailure {
            service,
            invoking_user: extract_field(message, "logname="),
            target_user: extract_field(message, " user="),
        });
    }
    None
}

/// True when `message` is `pam_sss`'s own "received for user %s: %d (...)" line
/// (`send_and_receive()`, SSSD/sssd@master, checked 2026-10-22) reporting
/// status 10 (`PAM_USER_UNKNOWN`) for `service` — the line `pam_sss` logs right
/// after an "authentication failure" line, in the same function call, when the
/// account it was asked about isn't one it manages. Only suppressed by the
/// host's `pam_sss.conf` `quiet_mode`, which this crate has no way to detect
/// from the journal alone — when it's set, this helper simply never confirms,
/// which is the documented, pre-existing gap, not a new one.
///
/// `(pam_sss review, #881)`. Used by `tail.rs`'s one-line lookahead to retract
/// a just-classified `PamAuthFailure`; not part of the classification
/// allowlist itself — this line is never, by itself, any `JournalEvent`.
pub(crate) fn pam_sss_reports_user_unknown(message: &str, service: &str) -> bool {
    let Some(rest) = message.strip_prefix("pam_sss(") else {
        return false;
    };
    let Some((msg_service, rest)) = rest.split_once(':') else {
        return false;
    };
    if normalize_pam_service(msg_service) != service {
        return false;
    }
    let Some((_, rest)) = rest.split_once("): ") else {
        return false;
    };
    let Some(rest) = rest.strip_prefix("received for user ") else {
        return false;
    };
    let Some((_, status)) = rest.split_once(": ") else {
        return false;
    };
    status.starts_with("10 (")
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
/// `USER=` in `"... ; USER=root ; COMMAND=..."`. An empty value (`key=` directly
/// followed by the next separator, e.g. `pam_unix`'s often-blank `ruser=`/`rhost=`)
/// maps to `None`, the same as the key being absent entirely — every caller treats
/// "field present but empty" and "field missing" as the same "nothing useful here"
/// case (review of #838, `SherlockOmss` 2026-10-19): `classify_pam`'s `sudo` fallback
/// from `target_user` to `invoking_user` (`auth.rs`) only runs on `None`, so an
/// empty `user=` was silently taking the `Some("")` branch and skipping it.
fn extract_field(haystack: &str, key: &str) -> Option<String> {
    let after = haystack.split_once(key)?.1;
    let value = after.split([' ', ';']).next()?.trim();
    (!value.is_empty()).then(|| value.to_string())
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

    #[test]
    fn sudo_command_line_is_not_classified_as_success_on_a_failed_attempt() {
        // Documented sudo log line shapes for a failed attempt: each still logs
        // `COMMAND=` on the same line as a successful one, so the line shape
        // alone cannot tell success from failure apart.
        for message in [
            "     lab : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/lab ; \
             USER=root ; COMMAND=/bin/echo hi",
            "     lab : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/lab ; USER=root ; \
             COMMAND=/bin/echo hi",
            "     lab : command not allowed ; TTY=pts/0 ; PWD=/home/lab ; USER=root ; \
             COMMAND=/bin/echo hi",
            "     lab : a password is required ; TTY=pts/0 ; COMMAND=/bin/echo hi",
            // sudo 1.9.15p5, plugins/sudoers/logging.c:297 (review of #838,
            // Sollykhan 2026-10-19): a host-restricted central sudoers denial —
            // without this marker, 5 of these plus a real success gave
            // (Success, PrivilegedSession) instead of (Failure, Failure, ...).
            "     lab : user NOT authorized on host ; TTY=pts/0 ; PWD=/home/lab ; \
             USER=root ; COMMAND=/bin/echo hi",
        ] {
            let r = record_with(&[("SYSLOG_IDENTIFIER", "sudo"), ("MESSAGE", message)]);
            assert_eq!(
                classify(&r),
                None,
                "classified a failure as a success: {message}"
            );
        }
    }

    #[test]
    fn a_marker_in_the_directory_or_the_command_does_not_make_a_success_a_failure() {
        // `PWD=` and `COMMAND=` are chosen by the invoking user: a directory or an
        // argument that reads like a failure marker must not drop a real success
        // (that would silence the T1548.003 join for whoever types it, #838).
        for message in [
            "     lab : TTY=pts/0 ; PWD=/tmp/a password is required ; USER=root ; \
             COMMAND=/bin/ls",
            "     lab : TTY=pts/0 ; PWD=/home/lab ; USER=root ; \
             COMMAND=/bin/echo user NOT in sudoers",
            "     lab : PWD=/home/lab ; USER=root ; \
             COMMAND=/bin/echo 3 incorrect password attempts ; command not allowed",
        ] {
            let r = record_with(&[("SYSLOG_IDENTIFIER", "sudo"), ("MESSAGE", message)]);
            assert!(
                matches!(classify(&r), Some(JournalEvent::SudoCommand { .. })),
                "dropped a successful sudo: {message}"
            );
        }
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

    // --- PAM auth failures (documented format, not lab-verified — see module
    //     doc and crate doc; this VM's sudo has no PAM config to capture against).

    #[test]
    fn pam_auth_failure_for_sudo_names_the_invoker_not_the_dash_u_target() {
        // Documented `pam_unix` format, not a captured line —
        // this crate's lab host has no interactive TTY for a real failed
        // `sudo` attempt (see the module doc and crate doc's Status section).
        // `sudo`'s PAM check authenticates the *invoker's* own password, not
        // the `-u`/default target's, so `user=` here is `omss`, the invoker,
        // same as `logname=`. A fixture with `user=root` (this test's shape
        // before #838) encoded an assumption nobody had captured live, and
        // PAM never actually produces it for `sudo`.
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            (
                "MESSAGE",
                "pam_unix(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 \
                 tty=/dev/pts/2 ruser=omss rhost=  user=omss",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamAuthFailure {
                service: "sudo".into(),
                invoking_user: Some("omss".into()),
                target_user: Some("omss".into()),
            })
        );
    }

    #[test]
    fn pam_auth_failure_for_sudo_via_pam_sss_is_classified_the_same_as_pam_unix() {
        // SSSD-backed sudo (sssd/LDAP-joined host, #881): pam_sss's own
        // auth-failure line was deliberately patched upstream (2009) to mirror
        // pam_unix's exact field layout, specifically so tooling keyed on that
        // layout keeps working — only the module name in the prefix differs.
        let r = record_with(&[
            ("SYSLOG_IDENTIFIER", "sudo"),
            (
                "MESSAGE",
                "pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 \
                 tty=/dev/pts/2 ruser=omss rhost=  user=omss",
            ),
        ]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamAuthFailure {
                service: "sudo".into(),
                invoking_user: Some("omss".into()),
                target_user: Some("omss".into()),
            })
        );
    }

    #[test]
    fn pam_auth_failure_for_su_dash_login_is_folded_into_su() {
        // Review of #838 (Sollykhan, 2026-10-19): `su -`/`su --login` dispatch PAM
        // through the separate `su-l` service (PAM 1.5.3's `/etc/pam.d/su-l`), not
        // `su` — without folding it in, 5 `su -` failures plus a session open gave
        // 0 events, making the most common interactive form of `su` invisible to
        // T1548.003.
        let r = record_with(&[(
            "MESSAGE",
            "pam_unix(su-l:auth): authentication failure; logname=lab uid=1001 euid=0 \
             tty=pts/1 ruser=lab rhost=  user=root",
        )]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamAuthFailure {
                service: "su".into(),
                invoking_user: Some("lab".into()),
                target_user: Some("root".into()),
            })
        );
    }

    #[test]
    fn pam_session_opened_for_sudo_dash_i_is_folded_into_sudo() {
        // Same fold, the other direction: `sudo -i` dispatches PAM through
        // `sudo-i` (PAM 1.5.3's `/etc/pam.d/sudo-i`), not `sudo`.
        let r = record_with(&[(
            "MESSAGE",
            "pam_unix(sudo-i:session): session opened for user root(uid=0) by (uid=1001)",
        )]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamSessionOpened {
                service: "sudo".into(),
                target_user: Some("root".into()),
            })
        );
    }

    #[test]
    fn pam_auth_failure_for_su_to_another_user() {
        let r = record_with(&[(
            "MESSAGE",
            "pam_unix(su:auth): authentication failure; logname=lab uid=1001 euid=0 \
             tty=pts/0 ruser=lab rhost=  user=alice",
        )]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamAuthFailure {
                service: "su".into(),
                invoking_user: Some("lab".into()),
                target_user: Some("alice".into()),
            })
        );
    }

    #[test]
    fn a_nonempty_ruser_does_not_get_mistaken_for_the_target_user() {
        // `extract_field` for "user=" with a leading space must not match inside
        // "ruser=lab" — "r" + "user=" has no space before the embedded "user=".
        let r = record_with(&[(
            "MESSAGE",
            "pam_unix(su:auth): authentication failure; logname=lab uid=1001 euid=0 \
             tty=pts/0 ruser=lab rhost=  user=root",
        )]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamAuthFailure {
                service: "su".into(),
                invoking_user: Some("lab".into()),
                target_user: Some("root".into()),
            })
        );
    }

    #[test]
    fn an_empty_user_field_is_none_not_an_empty_string() {
        // Review of #838 (SherlockOmss, 2026-10-19): `extract_field` used to map
        // `user=` immediately followed by a separator to `Some("")`, not `None` —
        // this `sudo` failure's blank `user=` must fall back to `logname=` (see
        // `auth::to_auth_event`'s `sudo` arm), not report an empty target account.
        let r = record_with(&[(
            "MESSAGE",
            "pam_unix(sudo:auth): authentication failure; logname=lab uid=1000 euid=0 \
             tty=/dev/pts/0 ruser= rhost=  user=",
        )]);
        assert_eq!(
            classify(&r),
            Some(JournalEvent::PamAuthFailure {
                service: "sudo".into(),
                invoking_user: Some("lab".into()),
                target_user: None,
            })
        );
    }

    #[test]
    fn pam_auth_failure_for_sshd_is_not_classified() {
        // sshd's own "Failed password" line already covers this (`SshFailed`);
        // mapping the PAM side too would double-count the same failed login.
        let r = record_with(&[(
            "MESSAGE",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh \
             ruser= rhost=10.0.0.5  user=alice",
        )]);
        assert_eq!(classify(&r), None);
    }

    #[test]
    fn pam_ldap_prefix_is_not_matched_deliberately() {
        // Not covered, format unknown — no source was found documenting
        // pam_ldap's own auth-failure message (if it has one at all), unlike
        // pam_sss's, which is checked against its source above. This pins the
        // current behavior (not matched) as a known gap, not a verified-safe
        // skip; if pam_ldap does emit a failure line shaped like this, this
        // test is locking in a real miss, not evidencing a non-issue (#881,
        // review by SherlockOmss).
        let r = record_with(&[(
            "MESSAGE",
            "pam_ldap(sudo:auth): authentication failure; logname=lab uid=1001 euid=0 \
             tty=pts/0 ruser=lab rhost=  user=lab",
        )]);
        assert_eq!(classify(&r), None);
    }

    #[test]
    fn pam_sss_reports_user_unknown_recognizes_status_ten_for_the_matching_service() {
        assert!(pam_sss_reports_user_unknown(
            "pam_sss(sudo:auth): received for user baduser: 10 (User not known to the \
             underlying authentication module)",
            "sudo",
        ));
    }

    #[test]
    fn pam_sss_reports_user_unknown_is_false_for_a_different_status() {
        // Status 7 (PAM_AUTH_ERR, a real wrong password) must not be read as
        // PAM_USER_UNKNOWN - only the literal "10 (" is the signal.
        assert!(!pam_sss_reports_user_unknown(
            "pam_sss(sudo:auth): received for user omss: 7 (Authentication failure)",
            "sudo",
        ));
    }

    #[test]
    fn pam_sss_reports_user_unknown_is_false_for_a_different_service() {
        // A su-l's "received for user" line must not confirm a pending sudo failure,
        // and vice versa - normalize_pam_service still applies on both sides.
        assert!(!pam_sss_reports_user_unknown(
            "pam_sss(su-l:auth): received for user baduser: 10 (User not known to the \
             underlying authentication module)",
            "sudo",
        ));
        assert!(pam_sss_reports_user_unknown(
            "pam_sss(su-l:auth): received for user baduser: 10 (User not known to the \
             underlying authentication module)",
            "su",
        ));
    }

    #[test]
    fn pam_sss_reports_user_unknown_is_false_for_an_unrelated_line() {
        assert!(!pam_sss_reports_user_unknown(
            "pam_sss(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 \
             tty=/dev/pts/2 ruser=omss rhost=  user=omss",
            "sudo",
        ));
        assert!(!pam_sss_reports_user_unknown(
            "pam_unix(sudo:auth): received for user baduser: 10 (whatever)",
            "sudo",
        ));
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
