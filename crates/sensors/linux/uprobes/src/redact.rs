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

/// Redacts sensitive data from TLS plaintext captures (HTTP headers, credentials).
///
/// Replaces matched patterns with `[REDACTED]` markers. Binary data is preserved if
/// no patterns match (non-UTF8 buffers are skipped).
///
/// # Examples
///
/// ```
/// let data = b"Authorization: Bearer eyJhbGc...".to_vec();
/// let redacted = redact_tls_data(data);
/// assert!(redacted.starts_with(b"Authorization: [REDACTED]"));
/// ```
pub fn redact_tls_data(mut data: Vec<u8>) -> Vec<u8> {
    // Try to parse as UTF-8 (most HTTP traffic is text-based)
    if let Ok(text) = std::str::from_utf8(&data) {
        let mut redacted = text.to_string();

        // Redact Authorization headers (case-insensitive)
        // Matches: "Authorization: Bearer ..." or "Authorization: Basic ..."
        redacted = redact_pattern(
            &redacted,
            r"(?i)authorization:\s*[^\r\n]+",
            "Authorization: [REDACTED]",
        );

        // Redact Cookie headers
        // Matches: "Cookie: session_id=abc123..."
        redacted = redact_pattern(&redacted, r"(?i)cookie:\s*[^\r\n]+", "Cookie: [REDACTED]");

        // Redact credentials in URLs
        // Matches: "https://user:password@example.com"
        redacted = redact_pattern(
            &redacted,
            r"(https?://)([^:@\s]+):([^@\s]+)@",
            "$1[REDACTED]:[REDACTED]@",
        );

        // Redact API keys in query strings
        // Matches: "?api_key=abc123", "?token=xyz789", "&key=foo"
        redacted = redact_pattern(
            &redacted,
            r"[?&](api_key|token|key|apikey|access_token)=[^&\s]+",
            "?$1=[REDACTED]",
        );

        data = redacted.into_bytes();
    }
    // If not valid UTF-8, return data unchanged (binary protocols like TLS handshake)

    data
}

/// Redacts sensitive data from shell readline inputs (passwords, secrets).
///
/// Replaces matched patterns with `[REDACTED]` markers. Shell commands are always
/// UTF-8 (readline returns strings).
///
/// # Examples
///
/// ```
/// let input = "export DATABASE_PASSWORD=secret123".to_string();
/// let redacted = redact_readline_input(input);
/// assert_eq!(redacted, "export DATABASE_PASSWORD=[REDACTED]");
/// ```
pub fn redact_readline_input(mut input: String) -> String {
    // Redact export statements with secrets
    // Matches: "export FOO=bar", "export FOO='bar'", "export FOO=\"bar\""
    input = redact_pattern(
        &input,
        r#"(?i)\b(export\s+\w+)=(['"]?)([^'"\s]+)\2"#,
        "$1=[REDACTED]",
    );

    // Redact --password= flags
    // Matches: "--password=foo", "--password='foo'", "--password \"foo\""
    input = redact_pattern(
        &input,
        r#"(?i)--password[=\s]+(['"]?)([^'"\s]+)\1"#,
        "--password=[REDACTED]",
    );

    // Redact -p flag for mysql/psql
    // Matches: "mysql -pfoo", "mysql -p foo", "mysql -p'foo'"
    input = redact_pattern(&input, r#"(?i)-p\s*(['"]?)([^'"\s]+)\1"#, "-p[REDACTED]");

    // Redact AWS-style credentials
    // Matches: "aws_secret_access_key=...", "AWS_SECRET_ACCESS_KEY=..."
    input = redact_pattern(
        &input,
        r"(?i)(aws_secret_access_key|aws_session_token)=([^\s]+)",
        "$1=[REDACTED]",
    );

    // Redact curl -u (basic auth)
    // Matches: "curl -u user:pass", "curl -u 'user:pass'"
    input = redact_pattern(&input, r#"-u\s+(['"]?)([^'"\s]+)\1"#, "-u [REDACTED]");

    input
}

/// Helper: applies a regex pattern replacement. Returns original string if regex fails.
fn redact_pattern(text: &str, pattern: &str, replacement: &str) -> String {
    match regex::Regex::new(pattern) {
        Ok(re) => re.replace_all(text, replacement).into_owned(),
        Err(_) => text.to_string(), // Defensive: invalid regex shouldn't break capture
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_authorization_header() {
        let data = b"GET /api HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n".to_vec();
        let redacted = redact_tls_data(data);
        let text = String::from_utf8(redacted).unwrap();
        assert!(text.contains("Authorization: [REDACTED]"));
        assert!(!text.contains("eyJhbGc"));
    }

    #[test]
    fn redacts_cookie_header() {
        let data = b"GET /api HTTP/1.1\r\nCookie: session_id=abc123; auth_token=xyz789\r\n".to_vec();
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
        let input = "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string();
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
    fn case_insensitive_matching() {
        let input1 = "EXPORT PASSWORD=secret".to_string();
        let input2 = "Export Password=secret".to_string();
        assert!(redact_readline_input(input1).contains("[REDACTED]"));
        assert!(redact_readline_input(input2).contains("[REDACTED]"));
    }
}
