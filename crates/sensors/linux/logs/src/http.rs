//! Detection signatures over a parsed access-log line, and the event they yield
//! (ADR-0022 §3, §4).
//!
//! A request becomes an event only when it matches one of a small fixed set of
//! signatures. Matching runs on a normalized copy (percent-decoded twice, lower-cased,
//! `/**/` read as a space), because the attacker chooses the encoding; the event is
//! built from the line as logged, reduced:
//! - the path, without its query string;
//! - the query parameter *names*, never their values;
//! - the one value that matched, cut to [`EVIDENCE_MAX_CHARS`], as evidence.
//!
//! **Redaction is not done here.** ADR-0018 puts credential redaction at the agent's
//! sink boundary so no producer carries a second path; the evidence value leaves this
//! crate raw (cut, not redacted) and the agent's `RedactingSink` is what must see it
//! before anything is stored or sent. Nothing in this crate writes or sends an event.
//!
//! These are cheap substring tests, not a WAF: they catch the obvious probes and the
//! common tools, and an attacker who encodes beyond two rounds or splits a marker
//! evades them. What they buy is a case for the correlator when the same host then
//! runs something it should not.

use schema::{EventMeta, HttpEvidence, HttpRequestEvent, HttpSignature, User};

use crate::AccessRecord;

/// Longest evidence value carried, in characters.
pub const EVIDENCE_MAX_CHARS: usize = 128;
/// Most parameter names listed on one event.
const MAX_PARAM_NAMES: usize = 32;
/// Longest parameter name or request path kept, in characters.
const MAX_NAME_CHARS: usize = 64;
const MAX_PATH_CHARS: usize = 512;

/// The `comm` of events built from an access log; names the source, not a process.
pub const HTTP_LOG_COMM: &str = "http-access-log";

const SQLI_MARKERS: &[&str] = &[
    "union select",
    "union all select",
    "' or '",
    "\" or \"",
    "' or 1=1",
    " or 1=1",
    "'or'1'='1",
    "sleep(",
    "benchmark(",
    "waitfor delay",
    "information_schema",
    "xp_cmdshell",
    "load_file(",
    "into outfile",
    "; drop table",
    "extractvalue(",
    "updatexml(",
];

const EXEC_MARKERS: &[&str] = &[
    "base64_decode(",
    "eval(",
    "system(",
    "passthru(",
    "shell_exec(",
    "proc_open(",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "wget http",
    "curl http",
    "uname -a",
];

/// Whole-value commands a webshell's `cmd=` parameter typically carries.
const SHELL_COMMANDS: &[&str] = &["id", "whoami", "ls", "pwd", "ifconfig", "ipconfig"];

/// File names (without extension) of well-known webshells.
const WEBSHELL_STEMS: &[&str] = &[
    "c99",
    "r57",
    "wso",
    "b374k",
    "alfa",
    "webshell",
    "china",
    "chopper",
    "indoxploit",
];

/// User-Agent substrings of scanning and exploitation tools, and the name reported.
const SCANNERS: &[(&str, &str)] = &[
    ("sqlmap", "sqlmap"),
    ("nikto", "nikto"),
    ("masscan", "masscan"),
    ("nmap scripting engine", "nmap"),
    ("wpscan", "wpscan"),
    ("dirbuster", "dirbuster"),
    ("gobuster", "gobuster"),
    ("feroxbuster", "feroxbuster"),
    ("ffuf", "ffuf"),
    ("nuclei", "nuclei"),
    ("acunetix", "acunetix"),
    ("nessus", "nessus"),
    ("openvas", "openvas"),
    ("zgrab", "zgrab"),
    ("havij", "havij"),
    ("w3af", "w3af"),
    ("hydra", "hydra"),
];

/// What a request matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub signature: HttpSignature,
    /// The parameter and its raw value, for the signatures that live in a value.
    pub evidence: Option<(String, String)>,
    pub scanner: Option<&'static str>,
}

/// Percent-decodes `s` (`+` is a space). Invalid escapes are kept as written.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len()
                && hex(bytes[i + 1]).is_some()
                && hex(bytes[i + 2]).is_some() =>
            {
                out.push((hex(bytes[i + 1]).unwrap_or(0) << 4) | hex(bytes[i + 2]).unwrap_or(0));
                i += 3;
            }
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

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decoded twice, lower-cased, inline comments read as spaces, whitespace collapsed.
fn normalize(s: &str) -> String {
    let decoded = percent_decode(&percent_decode(s)).to_lowercase();
    let decoded = decoded.replace("/**/", " ");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Splits `target` into the path and the raw `(name, value)` query parameters.
fn split_target(target: &str) -> (&str, Vec<(&str, &str)>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    (path, params)
}

fn has_traversal(normalized: &str) -> bool {
    normalized.contains("../") || normalized.contains("..\\") || normalized.ends_with("/..")
}

fn file_stem(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.split('.').next().unwrap_or(name)
}

/// The first signature `record` matches, in the order SQL injection, path traversal,
/// webshell-like, scanner user agent: the ones with a value to show come first.
#[must_use]
pub fn match_request(record: &AccessRecord) -> Option<Match> {
    let target = record.target()?;
    let (path, params) = split_target(target);
    let norm_path = normalize(path);

    for (name, value) in &params {
        let v = normalize(value);
        if SQLI_MARKERS.iter().any(|m| v.contains(m)) {
            return Some(evidence_match(HttpSignature::SqlInjection, name, value));
        }
    }
    if has_traversal(&norm_path) {
        return Some(Match {
            signature: HttpSignature::PathTraversal,
            evidence: None,
            scanner: None,
        });
    }
    for (name, value) in &params {
        if has_traversal(&normalize(value)) {
            return Some(evidence_match(HttpSignature::PathTraversal, name, value));
        }
    }
    for (name, value) in &params {
        let v = normalize(value);
        if EXEC_MARKERS.iter().any(|m| v.contains(m)) || SHELL_COMMANDS.contains(&v.as_str()) {
            return Some(evidence_match(HttpSignature::WebshellLike, name, value));
        }
    }
    if (200..300).contains(&record.status) && WEBSHELL_STEMS.contains(&file_stem(&norm_path)) {
        return Some(Match {
            signature: HttpSignature::WebshellLike,
            evidence: None,
            scanner: None,
        });
    }
    let agent = record.user_agent.as_deref().map(str::to_lowercase)?;
    SCANNERS
        .iter()
        .find(|(needle, _)| agent.contains(needle))
        .map(|(_, tool)| Match {
            signature: HttpSignature::ScannerUserAgent,
            evidence: None,
            scanner: Some(tool),
        })
}

fn evidence_match(signature: HttpSignature, name: &str, value: &str) -> Match {
    Match {
        signature,
        evidence: Some((
            truncate_chars(name, MAX_NAME_CHARS),
            truncate_chars(value, EVIDENCE_MAX_CHARS),
        )),
        scanner: None,
    }
}

/// The event for a matched request. `now_ns` is when the agent read the line.
///
/// The evidence value is cut but **not redacted**: see the module doc.
#[must_use]
pub fn to_http_request_event(
    record: &AccessRecord,
    matched: &Match,
    now_ns: u64,
) -> HttpRequestEvent {
    let target = record.target().unwrap_or("");
    let (path, params) = split_target(target);
    HttpRequestEvent {
        meta: EventMeta {
            pid: 0,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: now_ns,
            comm: HTTP_LOG_COMM.to_owned(),
            container: None,
            process_generation: None,
            parent_process_generation: None,
        },
        client: record.client.parse().ok(),
        method: record.method().map(str::to_owned),
        path: truncate_chars(path, MAX_PATH_CHARS),
        param_names: params
            .iter()
            .take(MAX_PARAM_NAMES)
            .map(|(name, _)| truncate_chars(name, MAX_NAME_CHARS))
            .collect(),
        status: record.status,
        signature: matched.signature,
        evidence: matched
            .evidence
            .as_ref()
            .map(|(param, value)| HttpEvidence {
                param: param.clone(),
                value: value.clone(),
            }),
        scanner: matched.scanner.map(str::to_owned),
        truncated: record.truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessFormat, parse_access_line};

    fn rec(target: &str, status: u16, agent: &str) -> AccessRecord {
        let line = format!(
            r#"203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "GET {target} HTTP/1.1" {status} 10 "-" "{agent}""#
        );
        parse_access_line(&line, AccessFormat::Combined).unwrap()
    }

    fn sig(target: &str) -> Option<HttpSignature> {
        match_request(&rec(target, 200, "Mozilla/5.0")).map(|m| m.signature)
    }

    #[test]
    fn ordinary_requests_match_nothing() {
        for t in [
            "/",
            "/index.php?id=42&page=home",
            "/search?q=union+station",
            "/blog/2026/10/how-to-sleep-better",
            "/api/v1/items?filter=a..b",
            "/download?file=report.pdf",
        ] {
            assert_eq!(sig(t), None, "{t}");
        }
    }

    #[test]
    fn sql_injection_in_a_value_is_found_through_encoding_and_comments() {
        assert_eq!(
            sig("/p?id=1%27%20OR%20%271%27=%271"),
            Some(HttpSignature::SqlInjection)
        );
        assert_eq!(
            sig("/p?id=1+UNION+SELECT+1,2,3"),
            Some(HttpSignature::SqlInjection)
        );
        assert_eq!(
            sig("/p?id=1/**/UNION/**/SELECT/**/1"),
            Some(HttpSignature::SqlInjection)
        );
        // Double-encoded.
        assert_eq!(
            sig("/p?id=1%2527%2520or%25201=1"),
            Some(HttpSignature::SqlInjection)
        );
        assert_eq!(
            sig("/p?id=1;SELECT+SLEEP(5)"),
            Some(HttpSignature::SqlInjection)
        );
    }

    #[test]
    fn evidence_is_the_matching_parameter_and_is_cut() {
        let long = format!("/p?ok=1&q=1'+or+'1'='1{}", "x".repeat(500));
        let m = match_request(&rec(&long, 200, "x")).unwrap();
        let (param, value) = m.evidence.unwrap();
        assert_eq!(param, "q");
        assert_eq!(value.chars().count(), EVIDENCE_MAX_CHARS);
    }

    #[test]
    fn traversal_in_the_path_or_a_value() {
        assert_eq!(
            sig("/static/../../etc/passwd"),
            Some(HttpSignature::PathTraversal)
        );
        assert_eq!(
            sig("/static/%2e%2e/%2e%2e/etc/passwd"),
            Some(HttpSignature::PathTraversal)
        );
        let m = match_request(&rec("/view?file=..%2f..%2fetc%2fpasswd", 200, "x")).unwrap();
        assert_eq!(m.signature, HttpSignature::PathTraversal);
        assert_eq!(m.evidence.unwrap().0, "file");
    }

    #[test]
    fn webshell_by_command_value_or_by_name() {
        assert_eq!(
            sig("/up/s.php?cmd=whoami"),
            Some(HttpSignature::WebshellLike)
        );
        assert_eq!(
            sig("/up/s.php?x=base64_decode(abc)"),
            Some(HttpSignature::WebshellLike)
        );
        assert_eq!(sig("/uploads/c99.php"), Some(HttpSignature::WebshellLike));
        // A 404 on a known shell name is a probe that found nothing.
        assert_eq!(match_request(&rec("/uploads/c99.php", 404, "x")), None);
    }

    #[test]
    fn scanner_user_agents_report_the_tool_not_the_string() {
        let m =
            match_request(&rec("/", 404, "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)")).unwrap();
        assert_eq!(m.signature, HttpSignature::ScannerUserAgent);
        assert_eq!(m.scanner, Some("nikto"));
        let m = match_request(&rec("/", 200, "sqlmap/1.7.2#stable (https://sqlmap.org)")).unwrap();
        assert_eq!(m.scanner, Some("sqlmap"));
    }

    #[test]
    fn the_event_keeps_names_and_drops_other_values() {
        let r = rec("/index.php?id=1'+or+'1'='1&token=SECRET&page=2", 200, "x");
        let m = match_request(&r).unwrap();
        let e = to_http_request_event(&r, &m, 9);
        assert_eq!(e.path, "/index.php");
        assert_eq!(e.param_names, ["id", "token", "page"]);
        assert_eq!(e.method.as_deref(), Some("GET"));
        assert_eq!(e.client, Some("203.0.113.9".parse().unwrap()));
        assert_eq!((e.meta.pid, e.meta.ppid, e.meta.timestamp_ns), (0, 0, 9));
        let json = serde_json::to_string(&schema::Event::HttpRequest(e)).unwrap();
        assert!(
            !json.contains("SECRET"),
            "an unmatched value must not leave: {json}"
        );
    }

    #[test]
    fn a_host_name_client_is_not_an_address() {
        let line = r#"www.example.org - - [t] "GET /?q=union+select+1 HTTP/1.1" 200 1 "-" "x""#;
        let r = parse_access_line(line, AccessFormat::Combined).unwrap();
        let m = match_request(&r).unwrap();
        assert_eq!(to_http_request_event(&r, &m, 1).client, None);
    }
}
