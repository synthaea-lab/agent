//! Allowlist classification: turns a [`LogRecord`] into a [`UnifiedLogEvent`],
//! or `None` for everything outside issue #95's three categories. Firehose
//! discipline: the `log stream` predicate (see [`crate::stream`]) already
//! restricts what reaches this code, and this classifier is a second, exact
//! gate — a category not listed here is silently ignored, never shipped.
//!
//! Message formats below are pinned against live captures from this dev
//! machine (macOS 26, 2026-09-22) — see the unit tests, which use verbatim
//! captured messages. Apple does not document these formats; when an OS
//! update changes one, the corresponding test is the tripwire.

use crate::record::{LogRecord, image_basename};

/// One classified unified-log record. Fields are best-effort (`Option`) —
/// a category match with an unextractable field is still reported where the
/// category itself is the signal, and skipped where the field *is* the signal
/// (documented per variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnifiedLogEvent {
    /// A `sudo` invocation with its logged command line — same real-world
    /// format as Linux's (sudo is sudo): `"user : TTY=... ; PWD=... ;
    /// USER=root ; COMMAND=/usr/bin/true"`.
    SudoCommand {
        invoking_user: Option<String>,
        target_user: Option<String>,
        command: Option<String>,
    },
    /// A failed `sudo` authentication: `"user : N incorrect password attempts ;
    /// TTY=... ; USER=root ; COMMAND=..."`.
    SudoFailure {
        invoking_user: Option<String>,
        target_user: Option<String>,
    },
    /// tccd's `AUTHREQ_CTX` — carries the requested service for a message id;
    /// joined with the matching [`UnifiedLogEvent::TccResult`] by
    /// [`crate::tcc::TccJoiner`].
    TccContext { msg_id: String, service: String },
    /// tccd's `AUTHREQ_RESULT` — carries the verdict for a message id.
    TccResult {
        msg_id: String,
        auth_value: u32,
        auth_reason: Option<u32>,
    },
    /// syspolicyd's `GK evaluateScanResult` — a Gatekeeper scan verdict.
    /// `target` is the bundle id when logged, else syspolicyd's opaque path
    /// token (paths are hash-redacted without the private-data profile).
    GatekeeperScan {
        target: String,
        team_id: Option<String>,
        signing_id: Option<String>,
        result_code: u32,
    },
}

/// Classifies one record. `None` means "not one of #95's categories" — the
/// normal case for everything the predicate lets through that isn't an exact
/// message match.
#[must_use]
pub fn classify(record: &LogRecord) -> Option<UnifiedLogEvent> {
    if record.event_type != "logEvent" {
        return None;
    }
    let process = image_basename(&record.process_image_path);

    if process == "sudo" {
        return classify_sudo(&record.message);
    }
    if record.subsystem == "com.apple.TCC" {
        return classify_tcc(&record.message);
    }
    if process == "syspolicyd" {
        return classify_gatekeeper(&record.message);
    }
    None
}

fn classify_sudo(message: &str) -> Option<UnifiedLogEvent> {
    // Both success and failure lines carry "COMMAND="; the failure marker is
    // the "incorrect password attempt(s)" clause. "a password is required"
    // (sudo -n without cached credentials) is a prompt state, not an outcome —
    // deliberately not classified.
    let invoking_user = message
        .trim_start()
        .split_once(" :")
        .map(|(user, _)| user.trim().to_string());
    let target_user = extract_field(message, "USER=");
    if message.contains("incorrect password attempt") {
        return Some(UnifiedLogEvent::SudoFailure {
            invoking_user,
            target_user,
        });
    }
    let command_idx = message.find("COMMAND=")?;
    let command = Some(message[command_idx + "COMMAND=".len()..].trim().to_string());
    if message.contains("a password is required") {
        return None;
    }
    Some(UnifiedLogEvent::SudoCommand {
        invoking_user,
        target_user,
        command,
    })
}

fn classify_tcc(message: &str) -> Option<UnifiedLogEvent> {
    // "AUTHREQ_CTX: msgID=988.7025, function=TCCAccessRequest,
    //  service=kTCCServiceAddressBook, preflight=yes, query=1, ..."
    if message.starts_with("AUTHREQ_CTX:") {
        // Both fields are the join key and the payload — without either, the
        // record is useless, so skip rather than emit an empty shell.
        return Some(UnifiedLogEvent::TccContext {
            msg_id: extract_field(message, "msgID=")?,
            service: extract_field(message, "service=")?,
        });
    }
    // "AUTHREQ_RESULT: msgID=438.631, authValue=0, authReason=12, ..."
    if message.starts_with("AUTHREQ_RESULT:") {
        return Some(UnifiedLogEvent::TccResult {
            msg_id: extract_field(message, "msgID=")?,
            auth_value: extract_field(message, "authValue=")?.parse().ok()?,
            auth_reason: extract_field(message, "authReason=").and_then(|v| v.parse().ok()),
        });
    }
    None
}

fn classify_gatekeeper(message: &str) -> Option<UnifiedLogEvent> {
    // "GK evaluateScanResult: 2, PST: (path: 9417be87be9e9471),
    //  (team: (null)), (id: (null)), (bundle_id: NOT_A_BUNDLE), 0, 0, 1, ..."
    let rest = message.strip_prefix("GK evaluateScanResult: ")?;
    let result_code = rest
        .split_once(',')
        .and_then(|(code, _)| code.trim().parse().ok())?;
    let team_id = extract_paren_field(rest, "(team: ");
    let signing_id = extract_paren_field(rest, "(id: ");
    let bundle_id = extract_paren_field(rest, "(bundle_id: ").filter(|b| b != "NOT_A_BUNDLE");
    let path_token = extract_paren_field(rest, "(path: ");
    // Prefer the human-meaningful identity; fall back to the opaque path
    // token so the event still keys *something* stable for correlation.
    let target = bundle_id
        .or_else(|| signing_id.clone())
        .or(path_token)
        .unwrap_or_else(|| "unknown".to_string());
    Some(UnifiedLogEvent::GatekeeperScan {
        target,
        team_id,
        signing_id,
        result_code,
    })
}

/// Extracts `KEY=value` where the value runs to the next `,`, `;` or
/// whitespace. Returns `None` for an absent key or a literal `(null)`.
fn extract_field(message: &str, key: &str) -> Option<String> {
    let start = message.find(key)? + key.len();
    let rest = &message[start..];
    let end = rest.find([',', ';', ' ', '\n']).unwrap_or(rest.len());
    let value = rest[..end].trim();
    if value.is_empty() || value == "(null)" {
        return None;
    }
    Some(value.to_string())
}

/// Extracts syspolicyd's `"(key: value)"` fields. `(null)` → `None`.
fn extract_paren_field(message: &str, key: &str) -> Option<String> {
    let start = message.find(key)? + key.len();
    let rest = &message[start..];
    let end = rest.find(')')?;
    let value = rest[..end].trim();
    if value.is_empty() || value == "(null" || value == "(null)" {
        return None;
    }
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(process_image_path: &str, subsystem: &str, message: &str) -> LogRecord {
        LogRecord {
            message: message.to_string(),
            subsystem: subsystem.to_string(),
            process_image_path: process_image_path.to_string(),
            pid: Some(427),
            uid: Some(0),
            timestamp_ns: 1_790_068_345_248_383_000,
            event_type: "logEvent".to_string(),
        }
    }

    #[test]
    fn sudo_command_line_classifies_with_users_and_command() {
        // Verbatim (live capture, this machine, 2026-09-22) — modulo the
        // username.
        let r = record(
            "/usr/bin/sudo",
            "",
            "florianamette : TTY=ttys002 ; PWD=/Users/florianamette ; USER=root ; COMMAND=/usr/bin/whoami",
        );
        let Some(UnifiedLogEvent::SudoCommand {
            invoking_user,
            target_user,
            command,
        }) = classify(&r)
        else {
            panic!("must classify as SudoCommand");
        };
        assert_eq!(invoking_user.as_deref(), Some("florianamette"));
        assert_eq!(target_user.as_deref(), Some("root"));
        assert_eq!(command.as_deref(), Some("/usr/bin/whoami"));
    }

    #[test]
    fn sudo_incorrect_password_classifies_as_failure() {
        let r = record(
            "/usr/bin/sudo",
            "",
            "florianamette : 3 incorrect password attempts ; TTY=ttys002 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/whoami",
        );
        assert!(matches!(
            classify(&r),
            Some(UnifiedLogEvent::SudoFailure { invoking_user, target_user })
                if invoking_user.as_deref() == Some("florianamette")
                    && target_user.as_deref() == Some("root")
        ));
    }

    #[test]
    fn sudo_password_prompt_state_is_not_an_outcome() {
        // Verbatim (live capture): `sudo -n` without cached credentials.
        let r = record(
            "/usr/bin/sudo",
            "",
            "florianamette : a password is required ; PWD=/Users/florianamette/code/edr-new ; USER=root ; COMMAND=/usr/bin/true",
        );
        assert_eq!(classify(&r), None);
    }

    #[test]
    fn tcc_context_extracts_msg_id_and_service() {
        // Verbatim (live capture).
        let r = record(
            "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
            "com.apple.TCC",
            "AUTHREQ_CTX: msgID=988.7025, function=TCCAccessRequest, service=kTCCServiceAddressBook, preflight=yes, query=1, client_dict=(null), daemon_dict=<private>",
        );
        assert_eq!(
            classify(&r),
            Some(UnifiedLogEvent::TccContext {
                msg_id: "988.7025".into(),
                service: "kTCCServiceAddressBook".into(),
            })
        );
    }

    #[test]
    fn tcc_result_extracts_verdict() {
        // Verbatim (live capture).
        let r = record(
            "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
            "com.apple.TCC",
            "AUTHREQ_RESULT: msgID=438.631, authValue=0, authReason=12, authVersion=1, desired_auth=0, error=(null),",
        );
        assert_eq!(
            classify(&r),
            Some(UnifiedLogEvent::TccResult {
                msg_id: "438.631".into(),
                auth_value: 0,
                auth_reason: Some(12),
            })
        );
    }

    #[test]
    fn gatekeeper_scan_extracts_raw_code_and_ids() {
        // Verbatim (live capture): unsigned non-bundle — everything null.
        let r = record(
            "/usr/libexec/syspolicyd",
            "com.apple.syspolicy",
            "GK evaluateScanResult: 2, PST: (path: 9417be87be9e9471), (team: (null)), (id: (null)), (bundle_id: NOT_A_BUNDLE), 0, 0, 1, 0, 7, 7, 0",
        );
        let Some(UnifiedLogEvent::GatekeeperScan {
            target,
            team_id,
            signing_id,
            result_code,
        }) = classify(&r)
        else {
            panic!("must classify as GatekeeperScan");
        };
        assert_eq!(result_code, 2);
        assert_eq!(team_id, None);
        assert_eq!(signing_id, None);
        // Falls back to the opaque path token when nothing better is logged.
        assert_eq!(target, "9417be87be9e9471");
    }

    #[test]
    fn gatekeeper_scan_prefers_bundle_identity() {
        let r = record(
            "/usr/libexec/syspolicyd",
            "com.apple.syspolicy",
            "GK evaluateScanResult: 0, PST: (path: ab12cd34), (team: ABCDE12345), (id: com.evil.dropper), (bundle_id: com.evil.dropper), 0, 0, 1, 0, 7, 7, 0",
        );
        let Some(UnifiedLogEvent::GatekeeperScan {
            target,
            team_id,
            signing_id,
            ..
        }) = classify(&r)
        else {
            panic!("must classify as GatekeeperScan");
        };
        assert_eq!(target, "com.evil.dropper");
        assert_eq!(team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(signing_id.as_deref(), Some("com.evil.dropper"));
    }

    #[test]
    fn unlisted_messages_classify_as_none() {
        // The predicate lets tccd's other chatter through the subsystem
        // filter; the classifier is the exact gate.
        let r = record(
            "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
            "com.apple.TCC",
            "send_message_with_reply_sync(): 1 attempts",
        );
        assert_eq!(classify(&r), None);
        let r = record(
            "/usr/libexec/syspolicyd",
            "com.apple.syspolicy",
            "GK performScan: PST: (path: x)",
        );
        assert_eq!(classify(&r), None);
    }

    #[test]
    fn non_log_events_classify_as_none() {
        let mut r = record("/usr/bin/sudo", "", "x : USER=root ; COMMAND=/bin/ls");
        r.event_type = "activityCreateEvent".to_string();
        assert_eq!(classify(&r), None);
    }
}
