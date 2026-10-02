//! Web access logs: Apache `common` and `combined`, nginx `combined`.
//!
//! ```text
//! common:   %h %l %u %t "%r" %>s %b
//! combined: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
//! ```
//!
//! nginx's default `combined` is the same layout, so it shares the preset. A site
//! with a custom `LogFormat` (a vhost prefix, JSON, extra fields) fails to parse and
//! is reported by the caller as a misparsing source, never silently mis-read.

use crate::{ParseError, clamp, tokenizer::Cursor};

/// Which preset a source is declared as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessFormat {
    Common,
    Combined,
}

/// One access-log line. Strings are as logged: the request line, referer and user
/// agent are attacker-controlled and unredacted at this layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRecord {
    pub client: String,
    pub user: Option<String>,
    /// As written between the brackets, e.g. `10/Oct/2026:13:55:36 +0000`.
    pub time: String,
    /// The full request line (`GET /a?b=c HTTP/1.1`), possibly garbage for a
    /// request the server could not parse.
    pub request: String,
    pub status: u16,
    pub bytes: Option<u64>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    /// The line was longer than [`crate::MAX_LINE_BYTES`] and cut.
    pub truncated: bool,
}

impl AccessRecord {
    /// The HTTP method, when the request line has the usual `METHOD TARGET ...` shape.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        let mut parts = self.request.split(' ');
        let method = parts.next()?;
        parts.next().map(|_| method)
    }

    /// The request target (path and query), same condition as [`Self::method`].
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.request.split(' ').nth(1)
    }
}

fn dash(s: &str) -> Option<String> {
    (s != "-").then(|| s.to_owned())
}

fn dash_owned(s: String) -> Option<String> {
    (s != "-").then_some(s)
}

/// Parses one line of the given preset.
///
/// # Errors
/// [`ParseError`] when the line does not match the preset; the caller counts it.
pub fn parse_access_line(line: &str, format: AccessFormat) -> Result<AccessRecord, ParseError> {
    let (clamped, truncated) = clamp(line);
    // A line cut at the cap that no longer parses is the cap's doing, not the source's
    // format: reported apart so an over-long request (a probe, or a 414) does not
    // count towards a source being declared misparsing.
    parse_clamped(clamped, truncated, format)
        .map_err(|e| if truncated { ParseError::Truncated } else { e })
}

fn parse_clamped(
    line: &str,
    truncated: bool,
    format: AccessFormat,
) -> Result<AccessRecord, ParseError> {
    let mut c = Cursor::new(line);

    let client = c.word("client")?.to_owned();
    c.word("ident")?; // %l, nearly always "-"; never kept
    let user = dash(c.word("user")?);
    let time = c.bracketed("time")?.to_owned();
    let request = c.quoted("request")?;

    let status_raw = c.word("status")?;
    let status = status_raw
        .parse::<u16>()
        .ok()
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| ParseError::BadField("status", status_raw.into()))?;

    let bytes_raw = c.word("bytes")?;
    let bytes = match bytes_raw {
        "-" => None,
        n => Some(
            n.parse::<u64>()
                .map_err(|_| ParseError::BadField("bytes", n.into()))?,
        ),
    };

    let (referer, user_agent) = match format {
        AccessFormat::Common => (None, None),
        // A truncated line may have lost these; a complete one must have them.
        AccessFormat::Combined if truncated && c.at_end() => (None, None),
        AccessFormat::Combined => {
            let referer = dash_owned(c.quoted("referer")?);
            let user_agent = dash_owned(c.quoted("user_agent")?);
            (referer, user_agent)
        }
    };

    if !truncated && !c.at_end() {
        return Err(ParseError::TrailingData);
    }

    Ok(AccessRecord {
        client,
        user,
        time,
        request,
        status,
        bytes,
        referer,
        user_agent,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMBINED: &str = r#"203.0.113.9 - alice [10/Oct/2026:13:55:36 +0000] "GET /index.php?id=1 HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0 (X11; Linux)""#;

    #[test]
    fn parses_combined() {
        let r = parse_access_line(COMBINED, AccessFormat::Combined).unwrap();
        assert_eq!(r.client, "203.0.113.9");
        assert_eq!(r.user.as_deref(), Some("alice"));
        assert_eq!(r.time, "10/Oct/2026:13:55:36 +0000");
        assert_eq!(r.method(), Some("GET"));
        assert_eq!(r.target(), Some("/index.php?id=1"));
        assert_eq!((r.status, r.bytes), (200, Some(2326)));
        assert_eq!(r.referer.as_deref(), Some("http://example.com/"));
        assert_eq!(r.user_agent.as_deref(), Some("Mozilla/5.0 (X11; Linux)"));
        assert!(!r.truncated);
    }

    #[test]
    fn parses_common_and_dashes() {
        let line = r#"::1 - - [10/Oct/2026:13:55:36 +0000] "HEAD / HTTP/1.0" 304 -"#;
        let r = parse_access_line(line, AccessFormat::Common).unwrap();
        assert_eq!((r.user, r.bytes, r.referer), (None, None, None));
    }

    #[test]
    fn a_quote_in_the_user_agent_does_not_shift_fields() {
        let line = r#"1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 10 "-" "evil\" 999 \"x""#;
        let r = parse_access_line(line, AccessFormat::Combined).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.user_agent.as_deref(), Some(r#"evil" 999 "x"#));
    }

    #[test]
    fn spaces_in_the_request_line_stay_in_the_request() {
        let line = r#"1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /a b c HTTP/1.1" 400 0"#;
        let r = parse_access_line(line, AccessFormat::Common).unwrap();
        assert_eq!(r.request, "GET /a b c HTTP/1.1");
    }

    #[test]
    fn hex_escapes_are_kept_literal() {
        let line = r#"1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /\x22\x00 HTTP/1.1" 400 0"#;
        let r = parse_access_line(line, AccessFormat::Common).unwrap();
        assert_eq!(r.target(), Some(r"/\x22\x00"));
    }

    #[test]
    fn the_unparsed_request_dash_has_no_method() {
        let line = r#"1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "-" 408 -"#;
        let r = parse_access_line(line, AccessFormat::Common).unwrap();
        assert_eq!((r.method(), r.target()), (None, None));
    }

    #[test]
    fn a_custom_format_is_an_error_not_a_misread() {
        // vhost prefix: the client field would be "example.com:80".
        let vhost = format!("example.com:80 {COMBINED}");
        assert!(parse_access_line(&vhost, AccessFormat::Combined).is_err());
        // Common preset on a combined line: trailing fields.
        assert_eq!(
            parse_access_line(COMBINED, AccessFormat::Common),
            Err(ParseError::TrailingData)
        );
        // Combined preset on a common line: missing fields.
        let common = r#"::1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 5"#;
        assert!(matches!(
            parse_access_line(common, AccessFormat::Combined),
            Err(ParseError::MissingField(_))
        ));
    }

    #[test]
    fn rejects_garbage_status_and_unterminated_quotes() {
        let bad_status = r#"1.1.1.1 - - [t] "GET / HTTP/1.1" 999 5"#;
        assert!(matches!(
            parse_access_line(bad_status, AccessFormat::Common),
            Err(ParseError::BadField("status", _))
        ));
        let open = r#"1.1.1.1 - - [t] "GET / HTTP/1.1 200 5"#;
        assert_eq!(
            parse_access_line(open, AccessFormat::Common),
            Err(ParseError::Unterminated)
        );
    }

    #[test]
    fn an_overlong_line_is_cut_and_reported_not_buffered() {
        // The cut lands inside the request line: an error, no panic, no 20 kB buffer.
        let in_request = format!(
            r#"1.2.3.4 - - [t] "GET /{} HTTP/1.1" 200 5"#,
            "a".repeat(20_000)
        );
        assert_eq!(
            parse_access_line(&in_request, AccessFormat::Common),
            Err(ParseError::Truncated)
        );
        // The cut lands inside the user agent: also an error.
        let in_agent = format!(
            r#"1.2.3.4 - - [t] "GET / HTTP/1.1" 200 5 "-" "{}""#,
            "u".repeat(20_000)
        );
        assert!(parse_access_line(&in_agent, AccessFormat::Combined).is_err());
    }

    #[test]
    fn a_truncated_combined_line_that_lost_only_the_tail_still_parses() {
        let head = r#"1.2.3.4 - - [t] "GET / HTTP/1.1" 200 5"#;
        let line = format!("{head}{}", " ".repeat(20_000));
        let r = parse_access_line(&line, AccessFormat::Combined).unwrap();
        assert!(r.truncated);
        assert_eq!(r.user_agent, None);
    }
}
