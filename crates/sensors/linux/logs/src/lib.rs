//! # sensor-linux-logs
//!
//! Parsers for the service logs ADR-0022 puts in scope for issue #478 level 2: web
//! **access logs** (Apache `common`/`combined`, nginx `combined`) and the
//! **MySQL/MariaDB error log** (failed logins). Pure functions from one line of text
//! to a typed record, with no I/O, no schema types and no policy.
//!
//! The content of a log line is chosen by whoever sent the request, so every parser
//! here follows the same rules:
//! - fixed presets selected by an explicit kind, never auto-detected and never a
//!   user-supplied pattern;
//! - a tokenizer that understands quoted fields and escapes, not `split(' ')`;
//! - lines longer than [`MAX_LINE_BYTES`] are truncated (and flagged), never buffered
//!   whole;
//! - a line that does not match its preset is an `Err`, so the caller can count and
//!   sample it. Nothing is skipped silently.
//!
//! [`Tailer`] follows one file: a persistable [`Position`], rotation by file identity,
//! bounded memory per line.
//!
//! [`match_request`] and [`to_http_request_event`] turn a parsed access-log line into an
//! `HttpRequest` event when it matches a detection signature; a [`Summarizer`] yields
//! one `HttpSummary` per source per window.
//!
//! **Status:** everything here is pure and tested; nothing writes or sends an event, the
//! agent does (`agent/src/log_sources.rs`). The credential redaction of an event's
//! evidence value is not here either: ADR-0018 puts it at the agent's sink boundary, so
//! the evidence leaves this crate cut but raw.

mod access;
mod budget;
mod health;
mod http;
mod mysql;
mod summary;
mod tail;
mod tokenizer;

pub use access::{AccessFormat, AccessRecord, parse_access_line};
pub use budget::{Dropped, PER_SIGNATURE_PER_WINDOW, SignatureBudget};
pub use health::{MIN_LINES, Misparse, MisparseWatch};
pub use http::{EVIDENCE_MAX_CHARS, HTTP_LOG_COMM, Match, match_request, to_http_request_event};
pub use mysql::{MYSQL_LOG_COMM, MysqlLoginFailure, parse_mysql_error_line, to_auth_event};
pub use summary::{MAX_TRACKED_CLIENTS, Summarizer, TOP_CLIENTS, WINDOW_SECS};
pub use tail::{FileId, PollOutcome, Position, Tailer};

/// Longest line a parser reads; the rest is dropped and the record is flagged
/// `truncated`. Apache's `LimitRequestLine` default is 8190 bytes, so a normal
/// request line fits.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Why a line did not match its preset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("line ended before the field {0:?}")]
    MissingField(&'static str),
    #[error("a quoted or bracketed field is not terminated")]
    Unterminated,
    #[error("field {0:?} is not valid: {1:?}")]
    BadField(&'static str, String),
    #[error("unexpected data after the last field of the format")]
    TrailingData,
    /// The line was longer than [`MAX_LINE_BYTES`], was cut, and the rest does not
    /// parse. Not evidence that the source's format is wrong.
    #[error("line cut at the length cap and no longer parses")]
    Truncated,
}

/// Cuts `line` to at most [`MAX_LINE_BYTES`] on a character boundary, after removing
/// the line terminator. The flag is true when something was dropped.
pub(crate) fn clamp(line: &str) -> (&str, bool) {
    let line = line.trim_end_matches(['\n', '\r']);
    if line.len() <= MAX_LINE_BYTES {
        return (line, false);
    }
    let mut end = MAX_LINE_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    (&line[..end], true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_strips_terminator_and_flags_nothing_when_short() {
        assert_eq!(clamp("abc\r\n"), ("abc", false));
    }

    #[test]
    fn clamp_cuts_on_a_char_boundary() {
        let line = "é".repeat(MAX_LINE_BYTES); // 2 bytes each
        let (cut, truncated) = clamp(&line);
        assert!(truncated);
        assert!(cut.len() <= MAX_LINE_BYTES);
        assert!(cut.chars().all(|c| c == 'é'));
    }
}
