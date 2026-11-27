//! Secrets inside a URL: the userinfo part and secret query parameters.

use super::REDACTED;
use super::secrets::is_secret_key;

pub(super) fn url_range(token: &str, offset: usize) -> Option<(usize, usize)> {
    let scheme = token.find("://")?;
    let start = token[..scheme]
        .rfind(['=', '\'', '"', ' ', '\t'])
        .map_or(0, |i| i + 1);
    let mut end = token.len();
    while end > scheme + 3 && matches!(token.as_bytes()[end - 1], b'\'' | b'"' | b',' | b')' | b']')
    {
        end -= 1;
    }
    Some((offset + start, offset + end))
}

/// Returns `url` with its userinfo, fragment, and secret query values replaced
/// by [`REDACTED`]. Anything that isn't a hierarchical URL (`about:internet`,
/// a bare path) keeps everything but a query or fragment it happens to carry.
/// Idempotent, and never panics on arbitrary input.
/// Redacts credentials in URL userinfo, fragments, and secret-named query values.
#[must_use]
pub fn redact_url_secrets(url: &str) -> String {
    // RFC 3986: the fragment starts at the first `#`, the query at the first
    // `?` before it — a `?` inside the fragment is fragment data.
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment)),
        None => (url, None),
    };
    let (base, query) = match before_fragment.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (before_fragment, None),
    };

    let mut out = String::with_capacity(url.len());
    push_without_userinfo(&mut out, base);
    if let Some(query) = query {
        out.push('?');
        push_redacted_query(&mut out, query);
    }
    if let Some(fragment) = fragment {
        out.push('#');
        if !fragment.is_empty() {
            out.push_str(&redacted_keeping_quotes(fragment));
        }
    }
    out
}

/// Pushes `base` (scheme, authority, path) with any `userinfo@` in the
/// authority replaced by [`REDACTED`]. The last `@` ends the userinfo, as in
/// browsers: `https://a@b@host/` has userinfo `a@b`.
pub(super) fn push_without_userinfo(out: &mut String, base: &str) {
    let Some(scheme_end) = base.find("://") else {
        out.push_str(base);
        return;
    };
    let authority_start = scheme_end + "://".len();
    let authority_end = base[authority_start..]
        .find('/')
        .map_or(base.len(), |i| authority_start + i);
    match base[authority_start..authority_end].rfind('@') {
        Some(at) => {
            out.push_str(&base[..authority_start]);
            out.push_str(&redacted_keeping_quotes(
                &base[authority_start..authority_start + at],
            ));
            out.push_str(&base[authority_start + at..]);
        }
        None => out.push_str(base),
    }
}

/// Pushes `query` with the value of every secret-named parameter replaced by
/// [`REDACTED`]. Separators, order, valueless and empty parameters are kept
/// as they were.
/// [`REDACTED`] in place of `value`, keeping every quote character the value held:
/// the leading ones before the token, the rest after it. On a command line those
/// quotes belong to the shell's quoting; dropping one (`token="A"` →
/// `token=REDACTED"`) flips the line's quote parity, so a second pass tokenises
/// differently and redaction stops being idempotent (#843, found by the proptest
/// on CI). A value made only of quotes holds no secret and is kept as is.
pub(super) fn redacted_keeping_quotes(value: &str) -> String {
    let is_quote = |c: char| c == '"' || c == '\'';
    if value.chars().all(is_quote) {
        return value.to_owned();
    }
    let rest = value.trim_start_matches(is_quote);
    let mut out = String::with_capacity(REDACTED.len() + value.len() - rest.len() + 2);
    out.push_str(&value[..value.len() - rest.len()]);
    out.push_str(REDACTED);
    out.extend(rest.chars().filter(|&c| is_quote(c)));
    out
}

pub(super) fn push_redacted_query(out: &mut String, query: &str) {
    for (i, param) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match param.split_once('=') {
            Some((key, value)) if !value.is_empty() && is_secret_key(key) => {
                out.push_str(key);
                out.push('=');
                out.push_str(&redacted_keeping_quotes(value));
            }
            _ => out.push_str(param),
        }
    }
}

/// Percent-decodes `s` (`+` is a space); invalid escapes are kept as written.
pub(super) fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        char::from(b).to_digit(16).map(|d| d as u8)
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
