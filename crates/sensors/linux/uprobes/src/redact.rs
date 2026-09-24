//! Redaction of sensitive data in captured events.
//!
//! This module provides functions to mask sensitive data in TLS captures and shell
//! commands before they are emitted as schema events. Redaction happens in userspace
//! after ring buffer drain, before normalization into schema types.
//!
//! **Patterns redacted:**
//! - HTTP `Authorization:` headers (Bearer tokens, Basic auth)
//! - HTTP `Cookie:` headers (session IDs, auth cookies)
//! - Shell passwords (`--password=`, `-p`, `export FOO=`, `mysql -p`)
//! - Credentials in URLs (`user:pass@host`)
//! - API keys in query strings (`?api_key=`, `?token=`)
//!
//! **Security Note:** Redaction is best-effort pattern matching. Attackers may encode
//! credentials in non-standard ways. This is defense-in-depth, not a security boundary.

/// `(pattern, replacement)` pairs applied to TLS plaintext captures, in order.
///
/// Kept as data (rather than inlined `redact_pattern` calls) so `all_patterns_compile`
/// below walks the exact same list `redact_tls_data` runs — the #251 incident was two
/// patterns here failing `Regex::new` silently, with no test ever having exercised them.
const TLS_PATTERNS: &[(&str, &str)] = &[
    // "Authorization: Bearer ..." or "Authorization: Basic ..."
    (
        r"(?i)authorization:\s*[^\r\n]+",
        "Authorization: [REDACTED]",
    ),
    // "Cookie: session_id=abc123..."
    (r"(?i)cookie:\s*[^\r\n]+", "Cookie: [REDACTED]"),
    // "https://user:password@example.com"
    (
        r"(https?://)([^:@\s]+):([^@\s]+)@",
        "$1[REDACTED]:[REDACTED]@",
    ),
    // "?api_key=abc123", "?token=xyz789", "&key=foo"
    (
        r"[?&](api_key|token|key|apikey|access_token)=[^&\s]+",
        "?$1=[REDACTED]",
    ),
];

/// Redacts sensitive data from TLS plaintext captures (HTTP headers, credentials).
///
/// Replaces matched patterns with `[REDACTED]` markers. Binary data is preserved if
/// no patterns match (non-UTF8 buffers are skipped).
///
/// Example: `b"Authorization: Bearer eyJhbGc..."` becomes
/// `b"Authorization: [REDACTED]"` — pinned by `doc_examples_hold` in this
/// module's tests rather than a doctest: the module is crate-private, so a
/// doctest (which compiles as an external crate) has no path to reach it
/// (issue #276).
pub fn redact_tls_data(mut data: Vec<u8>) -> Vec<u8> {
    // Try to parse as UTF-8 (most HTTP traffic is text-based)
    if let Ok(text) = std::str::from_utf8(&data) {
        let mut redacted = text.to_string();
        for (pattern, replacement) in TLS_PATTERNS {
            redacted = redact_pattern(&redacted, pattern, replacement);
        }
        data = redacted.into_bytes();
    }
    // If not valid UTF-8, return data unchanged (binary protocols like TLS handshake)

    data
}

/// `(pattern, replacement)` pairs applied to shell readline inputs, in order.
///
/// The quote-delimited value patterns (export/`--password`/`-p`/`-u`) use two
/// *independent* optional-quote groups around the value rather than a backreference
/// to the opening quote (`\1`) — this crate's `regex` engine is guaranteed-linear-time
/// and does not support backreferences at all, which is what made these four patterns
/// fail to compile under #251. The replacement text never echoes the value or its
/// quoting back, so an unpaired quote match (e.g. matching a stray trailing `'` that
/// wasn't actually the opening one) has no observable effect beyond this being
/// best-effort redaction, not a parser.
///
/// The `-p` pattern additionally anchors on "not preceded by another `-`"
/// (`(^|[^-])` consumed into the match and echoed back via `$1`, since this engine
/// has no lookbehind): `--password` contains the literal substring `-p`
/// (second dash + "p"), so an unanchored `-p` pattern matches *inside* the
/// `--password=[REDACTED]` this list's own earlier entry just produced — greedily
/// consuming through the `=` and brackets — and clobbers it into `--p[REDACTED]`.
/// Order matters here: this only bites because `--password` runs first.
const READLINE_PATTERNS: &[(&str, &str)] = &[
    // "export FOO=bar", "export FOO='bar'", "export FOO=\"bar\""
    (
        r#"(?i)\b(export\s+\w+)=(['"]?)([^'"\s]+)(['"]?)"#,
        "$1=[REDACTED]",
    ),
    // "--password=foo", "--password='foo'", "--password \"foo\""
    (
        r#"(?i)--password[=\s]+(['"]?)([^'"\s]+)(['"]?)"#,
        "--password=[REDACTED]",
    ),
    // "mysql -pfoo", "mysql -p foo", "mysql -p'foo'" — but not "--password"
    (
        r#"(?i)(^|[^-])-p\s*(['"]?)([^'"\s]+)(['"]?)"#,
        "$1-p[REDACTED]",
    ),
    // "aws_secret_access_key=...", "AWS_SECRET_ACCESS_KEY=..."
    (
        r"(?i)(aws_secret_access_key|aws_session_token)=([^\s]+)",
        "$1=[REDACTED]",
    ),
    // "curl -u user:pass", "curl -u 'user:pass'"
    (r#"-u\s+(['"]?)([^'"\s]+)(['"]?)"#, "-u [REDACTED]"),
];

/// Redacts sensitive data from shell readline inputs (passwords, secrets).
///
/// Replaces matched patterns with `[REDACTED]` markers. Shell commands are always
/// UTF-8 (readline returns strings).
///
/// Example: `export DATABASE_PASSWORD=secret123` becomes
/// `export DATABASE_PASSWORD=[REDACTED]` — pinned by `doc_examples_hold`
/// below, not a doctest (see `redact_tls_data`'s doc for why, issue #276).
pub fn redact_readline_input(mut input: String) -> String {
    for (pattern, replacement) in READLINE_PATTERNS {
        input = redact_pattern(&input, pattern, replacement);
    }
    input
}

/// `(pattern, replacement)` pairs applied to DNS query names, in order — issue
/// #267's "redact sensitive TLDs" requirement. Matches the whole query against
/// each private/internal TLD in turn and, on a hit, blanks everything before
/// that TLD while keeping the TLD itself visible: an internal hostname is
/// sensitive (topology disclosure), but "this process queried something under
/// `.internal`" is exactly the signal DNS tunneling/exfil detection needs to
/// keep. Public DNS (the overwhelming majority of queries) is never touched.
const DNS_PATTERNS: &[(&str, &str)] = &[(
    r"(?i)^.+\.(local|internal|lan|home|corp|intranet)\.?$",
    "[REDACTED].$1",
)];

/// Redacts sensitive TLDs from a DNS query name before it's emitted as a
/// schema event. Public domains pass through unchanged.
///
/// Example: `db01.prod.internal` becomes `[REDACTED].internal` — pinned by
/// `dns_query_redaction_holds` below, not a doctest (see `redact_tls_data`'s
/// doc for why, issue #276).
pub fn redact_dns_query(mut query: String) -> String {
    for (pattern, replacement) in DNS_PATTERNS {
        query = redact_pattern(&query, pattern, replacement);
    }
    query
}

/// Helper: applies a regex pattern replacement.
///
/// Every pattern used by this module is static and covered by `all_patterns_compile`,
/// so a `Regex::new` failure here means a pattern regressed, not bad input. #251 was
/// exactly this: patterns failing to compile and this fallback silently returning the
/// unredacted original with no signal anywhere that redaction had stopped working.
/// Log loudly and fail open (return the original text) rather than panic — dropping a
/// capture event or crashing the sensor over a redaction bug is a worse outcome than a
/// best-effort, non-security-boundary redaction pass being skipped for one pattern.
fn redact_pattern(text: &str, pattern: &str, replacement: &str) -> String {
    match regex::Regex::new(pattern) {
        Ok(re) => re.replace_all(text, replacement).into_owned(),
        Err(err) => {
            tracing::error!(?pattern, error = %err, "redact_pattern: pattern failed to compile");
            text.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_authorization_header() {
        let data =
            b"GET /api HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n"
                .to_vec();
        let redacted = redact_tls_data(data);
        let text = String::from_utf8(redacted).unwrap();
        assert!(text.contains("Authorization: [REDACTED]"));
        assert!(!text.contains("eyJhbGc"));
    }

    #[test]
    fn redacts_cookie_header() {
        let data =
            b"GET /api HTTP/1.1\r\nCookie: session_id=abc123; auth_token=xyz789\r\n".to_vec();
        let redacted = redact_tls_data(data);
        let text = String::from_utf8(redacted).unwrap();
        assert!(text.contains("Cookie: [REDACTED]"));
        assert!(!text.contains("session_id"));
    }

    #[test]
    fn redacts_url_credentials() {
        let data = b"GET https://admin:password123@example.com/api HTTP/1.1\r\n".to_vec();
        let redacted = redact_tls_data(data);
        let text = String::from_utf8(redacted).unwrap();
        assert!(text.contains("https://[REDACTED]:[REDACTED]@example.com"));
        assert!(!text.contains("admin"));
        assert!(!text.contains("password123"));
    }

    #[test]
    fn redacts_api_keys_in_query_string() {
        let data = b"GET /api?api_key=secret123&foo=bar HTTP/1.1\r\n".to_vec();
        let redacted = redact_tls_data(data);
        let text = String::from_utf8(redacted).unwrap();
        assert!(text.contains("?api_key=[REDACTED]"));
        assert!(!text.contains("secret123"));
        assert!(text.contains("foo=bar")); // Non-sensitive params preserved
    }

    #[test]
    fn preserves_binary_data() {
        let data = vec![0xFF, 0xFE, 0xFD, 0xFC]; // Invalid UTF-8
        let redacted = redact_tls_data(data.clone());
        assert_eq!(redacted, data); // Unchanged
    }

    #[test]
    fn redacts_export_statements() {
        let input = "export DATABASE_PASSWORD=secret123".to_string();
        let redacted = redact_readline_input(input);
        assert_eq!(redacted, "export DATABASE_PASSWORD=[REDACTED]");
    }

    #[test]
    fn redacts_export_with_quotes() {
        let input = "export API_KEY='super_secret_key'".to_string();
        let redacted = redact_readline_input(input);
        assert_eq!(redacted, "export API_KEY=[REDACTED]");
    }

    #[test]
    fn redacts_password_flags() {
        let input = "mysql --password=mypassword -h localhost".to_string();
        let redacted = redact_readline_input(input);
        assert!(redacted.contains("--password=[REDACTED]"));
        assert!(!redacted.contains("mypassword"));
        assert!(redacted.contains("localhost")); // Non-sensitive parts preserved
    }

    #[test]
    fn redacts_mysql_p_flag() {
        let input = "mysql -pmypassword -u root".to_string();
        let redacted = redact_readline_input(input);
        assert!(redacted.contains("-p[REDACTED]"));
        assert!(!redacted.contains("mypassword"));
    }

    #[test]
    fn redacts_aws_credentials() {
        let input =
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string();
        let redacted = redact_readline_input(input);
        assert!(redacted.contains("AWS_SECRET_ACCESS_KEY=[REDACTED]"));
        assert!(!redacted.contains("wJalrXUtn"));
    }

    #[test]
    fn redacts_curl_basic_auth() {
        let input = "curl -u admin:password https://api.example.com".to_string();
        let redacted = redact_readline_input(input);
        assert!(redacted.contains("-u [REDACTED]"));
        assert!(!redacted.contains("admin:password"));
    }

    #[test]
    fn preserves_non_sensitive_commands() {
        let input = "ls -la /home/user".to_string();
        let redacted = redact_readline_input(input.clone());
        assert_eq!(redacted, input); // Unchanged
    }

    #[test]
    fn all_patterns_compile() {
        for (pattern, _) in TLS_PATTERNS
            .iter()
            .chain(READLINE_PATTERNS.iter())
            .chain(DNS_PATTERNS.iter())
        {
            assert!(
                regex::Regex::new(pattern).is_ok(),
                "pattern failed to compile: {pattern}"
            );
        }
    }

    #[test]
    fn dns_query_redaction_holds() {
        assert_eq!(
            redact_dns_query("db01.prod.internal".to_string()),
            "[REDACTED].internal"
        );
    }

    #[test]
    fn dns_redacts_every_sensitive_tld() {
        for tld in ["local", "internal", "lan", "home", "corp", "intranet"] {
            let query = format!("host.{tld}");
            let redacted = redact_dns_query(query.clone());
            assert_eq!(redacted, format!("[REDACTED].{tld}"), "tld: {tld}");
        }
    }

    #[test]
    fn dns_preserves_public_domains() {
        let query = "example.com".to_string();
        assert_eq!(redact_dns_query(query.clone()), query);
    }

    #[test]
    fn dns_redaction_is_case_insensitive() {
        assert_eq!(
            redact_dns_query("HOST.LOCAL".to_string()),
            "[REDACTED].LOCAL"
        );
    }

    #[test]
    fn case_insensitive_matching() {
        let input1 = "EXPORT PASSWORD=secret".to_string();
        let input2 = "Export Password=secret".to_string();
        assert!(redact_readline_input(input1).contains("[REDACTED]"));
        assert!(redact_readline_input(input2).contains("[REDACTED]"));
    }

    /// The former doc examples of `redact_tls_data`/`redact_readline_input`,
    /// as the unit test issue #276 asked for — the doctest form could never
    /// compile (crate-private module, no external path).
    #[test]
    fn doc_examples_hold() {
        let data = b"Authorization: Bearer eyJhbGc...".to_vec();
        let redacted = redact_tls_data(data);
        assert!(redacted.starts_with(b"Authorization: [REDACTED]"));

        let input = "export DATABASE_PASSWORD=secret123".to_string();
        let redacted = redact_readline_input(input);
        assert_eq!(redacted, "export DATABASE_PASSWORD=[REDACTED]");
    }
}
