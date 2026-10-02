//! MySQL/MariaDB error log: failed logins.
//!
//! ```text
//! MySQL 8:  2026-10-01T12:00:00.123456Z 12 [Note] [MY-010926] [Server] Access denied for user 'root'@'10.0.0.5' (using password: YES)
//! MariaDB:  2026-10-01 12:00:00 12 [Warning] Access denied for user 'root'@'10.0.0.5' (using password: YES)
//! ```
//!
//! The user name is attacker-chosen and the server does not escape it, so it can contain
//! `'`, `@` and spaces. The host cannot contain `'@'`, so the split is on the *last*
//! `'@'` before the fixed ` (using password: ...)` suffix.

use schema::{AuthEvent, AuthKind, AuthOutcome, EventMeta, User};

use crate::{ParseError, clamp};

/// One failed authentication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MysqlLoginFailure {
    /// The line's leading timestamp, as written.
    pub timestamp: String,
    pub user: String,
    pub host: String,
    pub used_password: bool,
    pub truncated: bool,
}

const MARKER: &str = "Access denied for user '";

/// Parses one error-log line. `Ok(None)` is an ordinary line that is not a failed
/// login (most of the log); `Err` is a line that claims to be one and is malformed.
///
/// # Errors
/// [`ParseError`] when the line contains the access-denied marker but not the
/// `'user'@'host' (using password: ...)` shape or a leading timestamp.
pub fn parse_mysql_error_line(line: &str) -> Result<Option<MysqlLoginFailure>, ParseError> {
    let (line, truncated) = clamp(line);
    let Some(at) = line.find(MARKER) else {
        return Ok(None);
    };

    let timestamp = timestamp_prefix(&line[..at]).ok_or(ParseError::MissingField("timestamp"))?;

    let body = &line[at + MARKER.len()..];
    let (identity, used_password) = if let Some(i) = body.strip_suffix(" (using password: YES)") {
        (i, true)
    } else if let Some(i) = body.strip_suffix(" (using password: NO)") {
        (i, false)
    } else {
        // "... to database 'db'" is an authorization failure, not a login failure.
        return if body.contains(" to database ") {
            Ok(None)
        } else {
            Err(ParseError::BadField("password_clause", body.into()))
        };
    };

    let identity = identity
        .strip_suffix('\'')
        .ok_or_else(|| ParseError::BadField("host", identity.into()))?;
    let split = identity
        .rfind("'@'")
        .ok_or_else(|| ParseError::BadField("host", identity.into()))?;

    Ok(Some(MysqlLoginFailure {
        timestamp: timestamp.to_owned(),
        user: identity[..split].to_owned(),
        host: identity[split + 3..].to_owned(),
        used_password,
        truncated,
    }))
}

/// The `comm` of events built from this log. It names the source, not a process: an
/// error-log line carries no pid, so [`to_auth_event`] sets `pid` and `ppid` to 0.
pub const MYSQL_LOG_COMM: &str = "mysql-error-log";

/// A failed login as the shared logon event (ADR-0022 §3, ADR-0005), so the existing
/// brute-force rule (T1110, keyed on target user and source address) covers it.
///
/// `timestamp_ns` is when the agent read the line, not the line's own time: `MariaDB`
/// writes no zone, and a restart's catch-up reads old lines. The source address is
/// the client host when it is an IP; a resolved name or `localhost` leaves it `None`,
/// which the rule keys as "local" (never a fabricated loopback).
#[must_use]
pub fn to_auth_event(failure: &MysqlLoginFailure, timestamp_ns: u64) -> AuthEvent {
    AuthEvent {
        meta: EventMeta {
            pid: 0,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns,
            comm: MYSQL_LOG_COMM.to_owned(),
            container: None,
            process_generation: None,
            parent_process_generation: None,
        },
        outcome: AuthOutcome::Failure,
        kind: AuthKind::LogonFailure,
        target_user: failure.user.clone(),
        target_user_sid: None,
        source_address: failure.host.parse().ok(),
        status_code: Some(
            if failure.used_password {
                "using_password"
            } else {
                "no_password"
            }
            .to_owned(),
        ),
    }
}

/// `2026-10-01T12:00:00.123456Z` or `2026-10-01 12:00:00`: the leading token(s) of
/// `head`, accepted only when they start with a `YYYY-MM-DD` date.
fn timestamp_prefix(head: &str) -> Option<&str> {
    let head = head.trim_start();
    let first_end = head.find(' ').unwrap_or(head.len());
    let first = &head[..first_end];
    let b = first.as_bytes();
    let is_date = b.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit);
    if !is_date {
        return None;
    }
    if first.len() > 10 {
        return Some(first); // ISO 8601 with a 'T'
    }
    // Date and time as two tokens.
    let after = head[first_end..].trim_start_matches(' ');
    let time_len = after.find(' ').unwrap_or(after.len());
    let time = &after[..time_len];
    if time.is_empty() {
        return None;
    }
    Some(&head[..head.len() - after.len() + time_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql8_format() {
        let l = "2026-10-01T12:00:00.123456Z 12 [Note] [MY-010926] [Server] Access denied for user 'root'@'10.0.0.5' (using password: YES)";
        let f = parse_mysql_error_line(l).unwrap().unwrap();
        assert_eq!(f.timestamp, "2026-10-01T12:00:00.123456Z");
        assert_eq!((f.user.as_str(), f.host.as_str()), ("root", "10.0.0.5"));
        assert!(f.used_password);
    }

    #[test]
    fn a_failed_login_becomes_a_logon_failure_with_the_client_ip() {
        let l = "2026-10-01 12:00:00 12 [Warning] Access denied for user 'root'@'10.0.0.5' (using password: YES)";
        let f = parse_mysql_error_line(l).unwrap().unwrap();
        let e = to_auth_event(&f, 42);
        assert_eq!(
            (e.outcome, e.kind),
            (AuthOutcome::Failure, AuthKind::LogonFailure)
        );
        assert_eq!(e.target_user, "root");
        assert_eq!(e.source_address, Some("10.0.0.5".parse().unwrap()));
        assert_eq!((e.meta.pid, e.meta.ppid, e.meta.timestamp_ns), (0, 0, 42));
        assert_eq!(e.meta.comm, MYSQL_LOG_COMM);
    }

    #[test]
    fn a_host_name_is_not_an_address() {
        let l = "2026-10-01 12:00:00 12 [Warning] Access denied for user 'u'@'localhost' (using password: NO)";
        let f = parse_mysql_error_line(l).unwrap().unwrap();
        assert_eq!(to_auth_event(&f, 1).source_address, None);
    }

    #[test]
    fn mariadb_format_and_no_password() {
        let l = "2026-10-01 12:00:00 12 [Warning] Access denied for user 'app'@'localhost' (using password: NO)";
        let f = parse_mysql_error_line(l).unwrap().unwrap();
        assert_eq!(f.timestamp, "2026-10-01 12:00:00");
        assert_eq!((f.user.as_str(), f.host.as_str()), ("app", "localhost"));
        assert!(!f.used_password);
    }

    #[test]
    fn a_hostile_user_name_cannot_shift_the_host() {
        let l = "2026-10-01 12:00:00 12 [Warning] Access denied for user 'a'@'1.2.3.4'@'10.0.0.5' (using password: YES)";
        let f = parse_mysql_error_line(l).unwrap().unwrap();
        assert_eq!(f.user, "a'@'1.2.3.4");
        assert_eq!(f.host, "10.0.0.5");
    }

    #[test]
    fn ordinary_and_authorization_lines_are_not_failures() {
        let ok = "2026-10-01 12:00:00 0 [Note] mysqld: ready for connections.";
        assert_eq!(parse_mysql_error_line(ok), Ok(None));
        let db = "2026-10-01 12:00:00 12 [Warning] Access denied for user 'u'@'h' to database 'x'";
        assert_eq!(parse_mysql_error_line(db), Ok(None));
    }

    #[test]
    fn a_marker_line_that_does_not_fit_is_an_error() {
        let no_ts = "[Warning] Access denied for user 'u'@'h' (using password: YES)";
        assert!(matches!(
            parse_mysql_error_line(no_ts),
            Err(ParseError::MissingField("timestamp"))
        ));
        let odd = "2026-10-01 12:00:00 1 [Warning] Access denied for user 'u'@'h' wat";
        assert!(matches!(
            parse_mysql_error_line(odd),
            Err(ParseError::BadField(..))
        ));
    }
}
