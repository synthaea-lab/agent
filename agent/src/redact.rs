//! Credential redaction in download-provenance URLs (#440, ADR-0018).
//!
//! `FileQuarantine`'s `origin_url`/`referrer_url` come verbatim from the
//! mark-of-the-web (`HostUrl`/`ReferrerUrl`) or `kMDItemWhereFroms`, and are
//! often bearer credentials: pre-signed S3/GCS/Azure links, OAuth tokens,
//! session ids. [`RedactingSink`] rewrites them before any consumer sees the
//! event, so the spool, `events.jsonl`, the server and the T1204.002 alert
//! message only ever get the redacted form.
//!
//! What goes, unconditionally: the userinfo (`user:pass@`), the fragment
//! (OAuth implicit-flow tokens live there), and the value of every query
//! parameter whose *name* marks it as a secret ([`is_secret_key`]). Names stay,
//! so `X-Amz-Signature=REDACTED` still says "pre-signed S3". Every other
//! parameter is kept: a campaign id or tracking parameter can be the evidence.
//! Redacting *all* query values is reserved for `RedactionPolicy`'s
//! `pii_scrub_enabled`, once policy reaches the agent.
//!
//! Best-effort by design. Known to miss (ADR-0018 lists them):
//! - a secret in the path (`/dl/<token>/x.exe`), including a matrix parameter
//!   (`;jsessionid=`) and `;`-separated query parameters;
//! - a short, host-specific name, too generic to match on its own: Slack's
//!   `t=`, Google Drive's `at=`, Discord's `hm=`, a one-time `?id=`;
//! - the first parameter of an unencoded URL nested in a value
//!   (`?next=https://idp/cb?access_token=…` reads as `next`'s value);
//! - a name whose secret part is itself percent-encoded (`%74oken`). A merely
//!   encoded separator (`Access%5FToken`) is caught, since `token` survives.
//!
//! These URLs are written by browsers and download tools, not crafted to evade:
//! the goal is not storing benign credentials, not winning against an adversary
//! who controls the URL.

// Only the Windows and macOS sensors emit `FileQuarantine`; Linux wires no
// `RedactingSink` until a Linux producer exists (ADR-0018).
#![cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]

use std::sync::Arc;

use schema::{Event, sensor::EventSink};

/// What a redacted value is replaced with. URL-safe, so a redacted URL is
/// still a well-formed URL.
pub(crate) const REDACTED: &str = "REDACTED";

/// Parameter names that are secrets whole. Matched case-insensitively.
const SECRET_KEYS: &[&str] = &["sig", "code", "pwd", "pass", "sid", "jwt"];

/// Substrings that mark a parameter name as a secret: `X-Amz-Signature`,
/// `X-Goog-Credential`, `X-Amz-Security-Token`, `access_token`,
/// `client_secret`, `password`, `sessionid`, `PHPSESSID`, …
const SECRET_KEY_PARTS: &[&str] = &[
    "signature",
    "token",
    "secret",
    "passw",
    "credential",
    "session",
    "sessid",
    "authoriz",
];

/// Suffixes that mark a parameter name as a secret: `api_key`, `apikey`,
/// `x-api-key`, `oauth_consumer_key`, `AWSAccessKeyId`, `auth`, `oauth`, and
/// SharePoint/OneDrive's `tempauth` bearer token on `download.aspx` links, the
/// most common download source on a managed Windows fleet (#550 review).
const SECRET_KEY_SUFFIXES: &[&str] = &["key", "keyid", "auth"];

/// Wraps a sink, redacting credentials in every `FileQuarantine` URL before
/// forwarding (see the module doc). Everything else passes through untouched.
pub(crate) struct RedactingSink<S>(pub(crate) S);

impl<S: EventSink> EventSink for RedactingSink<S> {
    fn on_event(&self, mut event: Event) {
        redact_event(&mut event);
        self.0.on_event(event);
    }
}

/// Puts a [`RedactingSink`] in front of a platform's sensor sink — what
/// `run_windows_sensors`/`run_macos_sensors` share with their sensors.
pub(crate) fn redacting(sink: Box<dyn EventSink>) -> Arc<dyn EventSink> {
    Arc::new(RedactingSink(Arc::<dyn EventSink>::from(sink)))
}

fn redact_event(event: &mut Event) {
    if let Event::FileQuarantine(quarantine) = event {
        for url in [&mut quarantine.origin_url, &mut quarantine.referrer_url]
            .into_iter()
            .flatten()
        {
            *url = redact_url_secrets(url);
        }
    }
}

/// Returns `url` with its userinfo, fragment, and secret query values replaced
/// by [`REDACTED`]. Anything that isn't a hierarchical URL (`about:internet`,
/// a bare path) keeps everything but a query or fragment it happens to carry.
/// Idempotent, and never panics on arbitrary input.
pub(crate) fn redact_url_secrets(url: &str) -> String {
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
            out.push_str(REDACTED);
        }
    }
    out
}

/// Pushes `base` (scheme, authority, path) with any `userinfo@` in the
/// authority replaced by [`REDACTED`]. The last `@` ends the userinfo, as in
/// browsers: `https://a@b@host/` has userinfo `a@b`.
fn push_without_userinfo(out: &mut String, base: &str) {
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
            out.push_str(REDACTED);
            out.push_str(&base[authority_start + at..]);
        }
        None => out.push_str(base),
    }
}

/// Pushes `query` with the value of every secret-named parameter replaced by
/// [`REDACTED`]. Separators, order, valueless and empty parameters are kept
/// as they were.
fn push_redacted_query(out: &mut String, query: &str) {
    for (i, param) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match param.split_once('=') {
            Some((key, value)) if !value.is_empty() && is_secret_key(key) => {
                out.push_str(key);
                out.push('=');
                out.push_str(REDACTED);
            }
            _ => out.push_str(param),
        }
    }
}

/// Whether a query parameter name marks its value as a credential.
fn is_secret_key(key: &str) -> bool {
    let key = key.trim_end_matches("[]").to_ascii_lowercase();
    SECRET_KEYS.contains(&key.as_str())
        || SECRET_KEY_PARTS.iter().any(|part| key.contains(part))
        || SECRET_KEY_SUFFIXES
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn a_presigned_s3_url_keeps_its_shape_and_loses_its_credentials() {
        let url = "https://bucket.s3.amazonaws.com/kit/payload.exe?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                   &X-Amz-Credential=AKIAEXAMPLE%2F20260930%2Fus-east-1%2Fs3%2Faws4_request\
                   &X-Amz-Date=20260930T101500Z&X-Amz-Expires=300\
                   &X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLE\
                   &X-Amz-SignedHeaders=host&X-Amz-Signature=0123abcd&utm_campaign=q3-invoice";
        assert_eq!(
            redact_url_secrets(url),
            "https://bucket.s3.amazonaws.com/kit/payload.exe?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=REDACTED&X-Amz-Date=20260930T101500Z&X-Amz-Expires=300\
             &X-Amz-Security-Token=REDACTED&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=REDACTED&utm_campaign=q3-invoice"
        );
    }

    #[test]
    fn gcs_azure_and_legacy_s3_signatures_are_redacted() {
        for (url, expected) in [
            (
                "https://storage.googleapis.com/b/x.msi?X-Goog-Credential=svc%40p.iam&X-Goog-Signature=beef",
                "https://storage.googleapis.com/b/x.msi?X-Goog-Credential=REDACTED&X-Goog-Signature=REDACTED",
            ),
            (
                "https://acct.blob.core.windows.net/c/x.zip?sv=2022-11-02&se=2026-10-01&sp=r&sig=abc%3D",
                "https://acct.blob.core.windows.net/c/x.zip?sv=2022-11-02&se=2026-10-01&sp=r&sig=REDACTED",
            ),
            (
                "https://b.s3.amazonaws.com/x.exe?AWSAccessKeyId=AKIA&Expires=1&Signature=zz",
                "https://b.s3.amazonaws.com/x.exe?AWSAccessKeyId=REDACTED&Expires=1&Signature=REDACTED",
            ),
        ] {
            assert_eq!(redact_url_secrets(url), expected, "{url}");
        }
    }

    #[test]
    fn oauth_and_session_parameters_are_redacted_case_insensitively() {
        assert_eq!(
            redact_url_secrets(
                "https://h/cb?Access_Token=a&CODE=b&client_secret=c&PHPSESSID=d&api_key=e&x-api-key=f&state=keep"
            ),
            "https://h/cb?Access_Token=REDACTED&CODE=REDACTED&client_secret=REDACTED\
             &PHPSESSID=REDACTED&api_key=REDACTED&x-api-key=REDACTED&state=keep"
        );
    }

    #[test]
    fn a_sharepoint_tempauth_link_loses_its_bearer_token() {
        // #550 review: the most common download source on a managed fleet.
        assert_eq!(
            redact_url_secrets(
                "https://contoso.sharepoint.com/sites/x/_layouts/15/download.aspx\
                 ?UniqueId=0a1b2c3d&Translate=false&tempauth=eyJ0eXAiOiJKV1Qi.v1&ApiVersion=2.0"
            ),
            "https://contoso.sharepoint.com/sites/x/_layouts/15/download.aspx\
             ?UniqueId=0a1b2c3d&Translate=false&tempauth=REDACTED&ApiVersion=2.0"
        );
        assert_eq!(
            redact_url_secrets("https://h/x?auth=a&OAuth=b&author=keep"),
            "https://h/x?auth=REDACTED&OAuth=REDACTED&author=keep"
        );
    }

    #[test]
    fn userinfo_and_fragment_are_always_redacted() {
        assert_eq!(
            redact_url_secrets("https://user:hunter2@host:8443/x.exe#access_token=abc"),
            "https://REDACTED@host:8443/x.exe#REDACTED"
        );
        // The last `@` in the authority ends the userinfo; one in the path is not userinfo.
        assert_eq!(
            redact_url_secrets("ftp://a@b@host/p@th"),
            "ftp://REDACTED@host/p@th"
        );
    }

    #[test]
    fn a_question_mark_inside_the_fragment_is_not_a_query() {
        assert_eq!(
            redact_url_secrets("https://h/x.exe#frag?token=abc"),
            "https://h/x.exe#REDACTED"
        );
    }

    #[test]
    fn urls_without_secrets_are_unchanged() {
        for url in [
            "https://example.test/invoice.exe",
            "https://example.test/dl?id=42&utm_source=mail",
            "about:internet",
            "C:\\Users\\Public\\x.exe",
            "https://h/x?flag&=v&k=&&",
            "https://h/x#",
            "",
        ] {
            assert_eq!(redact_url_secrets(url), url, "{url}");
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let url = "https://u:p@h/x?sig=1&keep=2&token=3#f";
        let once = redact_url_secrets(url);
        assert_eq!(redact_url_secrets(&once), once);
    }

    #[test]
    fn never_panics_on_any_truncation_or_odd_input() {
        // The URL comes from an attacker-writable ADS or xattr: every prefix of
        // a dense URL (multi-byte chars included), plus separator soup.
        let dense = "https://ü:p@h\u{e9}ll\u{f6}/\u{1f600}?sig=\u{e9}&a=b=c&&token#x?y@z";
        for (end, _) in dense.char_indices() {
            let _ = redact_url_secrets(&dense[..end]);
        }
        for odd in [
            "://",
            "://@",
            "?",
            "#",
            "?#",
            "@",
            "a://b@",
            "?=",
            "?&=&",
            "#?@://",
            "\u{0}?\u{0}=\u{0}",
        ] {
            let _ = redact_url_secrets(odd);
        }
    }

    /// Records what reaches the inner sink.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<Event>>);

    impl EventSink for Recorder {
        fn on_event(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn the_sink_redacts_both_quarantine_urls_before_forwarding() {
        let sink = RedactingSink(Recorder::default());
        sink.on_event(Event::FileQuarantine(schema::FileQuarantineEvent {
            origin_url: Some("https://h/x.exe?token=abc".into()),
            referrer_url: Some("https://u:p@h/page".into()),
            ..schema::fixtures::file_quarantine()
        }));
        let events = sink.0.0.lock().unwrap();
        let [Event::FileQuarantine(q)] = events.as_slice() else {
            panic!("expected one FileQuarantine, got {events:?}");
        };
        assert_eq!(
            q.origin_url.as_deref(),
            Some("https://h/x.exe?token=REDACTED")
        );
        assert_eq!(q.referrer_url.as_deref(), Some("https://REDACTED@h/page"));
    }

    #[test]
    fn the_sink_leaves_other_events_untouched() {
        let sink = RedactingSink(Recorder::default());
        let exec = Event::Exec(schema::ExecEvent {
            cmdline: "curl https://h/x?token=abc".into(),
            ..schema::fixtures::exec()
        });
        sink.on_event(exec.clone());
        assert_eq!(*sink.0.0.lock().unwrap(), [exec]);
    }
}
