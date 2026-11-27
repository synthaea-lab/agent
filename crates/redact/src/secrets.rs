//! Which parameter names carry a secret.

use super::url::percent_decode;

/// Parameter names that are secrets whole. Matched case-insensitively.
pub(super) const SECRET_KEYS: &[&str] = &["sig", "code", "pwd", "pass", "sid", "jwt"];

/// Substrings that mark a parameter name as a secret: `X-Amz-Signature`,
/// `X-Goog-Credential`, `X-Amz-Security-Token`, `access_token`,
/// `client_secret`, `password`, `sessionid`, `PHPSESSID`, …
pub(super) const SECRET_KEY_PARTS: &[&str] = &[
    "signature",
    "token",
    "secret",
    "passw",
    "credential",
    "session",
    "sessid",
    "authoriz",
    "cookie",
    "passphrase",
];

/// Suffixes that mark a parameter name as a secret: `api_key`, `apikey`,
/// `x-api-key`, `oauth_consumer_key`, `AWSAccessKeyId`, `auth`, `oauth`, and
/// SharePoint/OneDrive's `tempauth` bearer token on `download.aspx` links, the
/// most common download source on a managed Windows fleet (#550 review).
pub(super) const SECRET_KEY_SUFFIXES: &[&str] = &["key", "keyid", "auth"];

/// Whether a query parameter name marks its value as a credential. The name is read
/// as written and percent-decoded twice (the web-log matcher's own normalisation), so
/// `pass%77ord` and `%74oken` do not slip past.
/// Returns whether a URL query key identifies a credential.
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    is_secret_name(key) || is_secret_name(&percent_decode(&percent_decode(key)))
}

pub(super) fn is_secret_name(key: &str) -> bool {
    let key = key.trim_end_matches("[]").to_ascii_lowercase();
    SECRET_KEYS.contains(&key.as_str())
        || SECRET_KEY_PARTS.iter().any(|part| key.contains(part))
        || SECRET_KEY_SUFFIXES
            .iter()
            .any(|suffix| key.ends_with(suffix))
}
