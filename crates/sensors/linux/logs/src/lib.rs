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
//! **Status:** parsing and tailing. Not here yet, by design of the slicing: wiring the
//! sources from `[logs]` into the agent (and persisting each position), signatures,
//! the per-window summary, the schema events and the redaction of what leaves the
//! host (ADR-0018).

mod access;
mod mysql;
mod tail;
mod tokenizer;

pub use access::{AccessFormat, AccessRecord, parse_access_line};
pub use mysql::{MysqlLoginFailure, parse_mysql_error_line};
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
