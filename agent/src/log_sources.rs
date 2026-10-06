//! Tails the service logs declared in `[logs]` and turns what they say into events
//! (ADR-0022, issue #478 level 2).
//!
//! One thread polls every source once a second. Each source keeps a persisted
//! [`Position`] in a file derived from the alerts path (same convention as
//! `crate::journal_cursor`), so a restart resumes where it stopped.
//!
//! Two kinds of source:
//!
//! - `mysql_error`: a failed login becomes a `schema::AuthEvent` and so feeds the
//!   existing brute-force rule (T1110).
//! - `access_common` / `access_combined`: a request that matches a detection signature
//!   becomes a `schema::HttpRequestEvent` (at most [`sensor_linux_logs::PER_SIGNATURE_PER_WINDOW`]
//!   per signature per window, the rest counted and logged), and every request is counted
//!   in one `schema::HttpSummaryEvent` per 60 s window. Nothing is emitted per ordinary
//!   request (ADR-0022 §3).
//!
//! Every event goes through [`deliver`], the one place it leaves this module: the
//! credential redaction of an `HttpRequest`'s evidence value belongs there (ADR-0018, no
//! second redaction path).
//!
//! No silence alert and no heartbeat: a quiet log is normal on a quiet site (ADR-0022,
//! decision 4). A line that does not parse is counted and sampled in the log, never
//! skipped silently, and a source whose lines mostly fail raises the `LOG-SOURCE` alert.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use config::{LogSourceConfig, LogSourceKind};
use schema::sensor::EventSink as _;
use sensor_linux_logs::{
    AccessFormat, Misparse, MisparseWatch, Position, SignatureBudget, Summarizer, Tailer,
    match_request, parse_access_line, parse_mysql_error_line, to_auth_event, to_http_request_event,
};

use crate::{
    shutdown::{ShutdownPlan, sleep_unless_stopped},
    sink::DetectionSink,
};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Longest stretch of a rejected line copied into the agent's own log.
const SAMPLE_BYTES: usize = 160;

/// Where one source's position is stored: next to the alerts output, keyed by the log's
/// path. FNV-1a, because `DefaultHasher` is not stable across Rust versions and the
/// name must survive an upgrade.
pub(crate) fn position_path_for(alerts: &Path, log: &Path) -> PathBuf {
    let hash = log
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
        });
    alerts.with_extension(format!("logpos-{hash:016x}"))
}

/// The last persisted position, or `None` for an absent, empty or unreadable file:
/// the honest "no prior state" case, not a startup error.
pub(crate) fn read_position(path: &Path) -> Option<Position> {
    Position::decode(&std::fs::read_to_string(path).ok()?)
}

/// Same-directory temp file plus rename, like `journal_cursor::write`: a kill mid-write
/// never leaves a torn position. I/O failures are ignored; a missed persist only means
/// the next restart re-reads a little more.
pub(crate) fn write_position(path: &Path, position: &Position) {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, position.encode()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Health counters for one source. The counts are logged; a source whose lines mostly
/// fail to parse is reported as an alert (see [`poll_source`]), not on the health
/// beacon, whose wire shape the server reads and this slice does not change.
#[derive(Debug, Default)]
struct Stats {
    parse_failures: u64,
    watch: MisparseWatch,
}

/// Counts a line that did not match its declared kind and samples it in the log.
fn note_parse_failure(
    line: &str,
    error: &dyn std::fmt::Display,
    now_ns: u64,
    stats: &mut Stats,
    path: &Path,
) {
    stats.parse_failures += 1;
    stats.watch.record(false, now_ns);
    // First failure, then every thousandth: a custom format would otherwise log once
    // per line. The sample is attacker-controlled text, so it is cut and escaped
    // (`{:?}`), never written raw.
    if stats.parse_failures == 1 || stats.parse_failures.is_multiple_of(1000) {
        let mut end = line.len().min(SAMPLE_BYTES);
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        tracing::warn!(
            log = %path.display(),
            failures = stats.parse_failures,
            error = %error,
            sample = ?&line[..end],
            "log source: line does not match its declared kind"
        );
    }
}

/// One log line of a `mysql_error` source, as the event it yields. `None` for an
/// ordinary line and for one that did not parse (counted and sampled).
fn mysql_line_to_event(
    line: &str,
    now_ns: u64,
    stats: &mut Stats,
    path: &Path,
) -> Option<schema::Event> {
    match parse_mysql_error_line(line) {
        Ok(Some(failure)) => {
            stats.watch.record(true, now_ns);
            Some(schema::Event::Auth(to_auth_event(&failure, now_ns)))
        }
        Ok(None) => None,
        Err(e) => {
            note_parse_failure(line, &e, now_ns, stats, path);
            None
        }
    }
}

/// What an `access_*` source keeps between polls.
struct Access {
    format: AccessFormat,
    summarizer: Summarizer,
    budget: SignatureBudget,
}

impl Access {
    fn new(format: AccessFormat, path: &Path) -> Self {
        Self {
            format,
            summarizer: Summarizer::new(path.display().to_string()),
            budget: SignatureBudget::new(),
        }
    }
}

/// One log line of an `access_*` source. Every parsed request is counted in the window
/// summary; only one that matches a signature, and is within the signature's budget,
/// yields an event. `None` for an ordinary request and for a line that did not parse
/// (counted and sampled).
fn access_line_to_event(
    line: &str,
    now_ns: u64,
    access: &mut Access,
    stats: &mut Stats,
    path: &Path,
) -> Option<schema::Event> {
    match parse_access_line(line, access.format) {
        Ok(record) => {
            stats.watch.record(true, now_ns);
            access.summarizer.observe(&record, now_ns);
            let matched = match_request(&record)?;
            access.budget.allow(matched.signature, now_ns).then(|| {
                schema::Event::HttpRequest(to_http_request_event(&record, &matched, now_ns))
            })
        }
        Err(e) => {
            note_parse_failure(line, &e, now_ns, stats, path);
            None
        }
    }
}

/// Alert id for a source that is read but not understood. Not an ATT&CK technique: a
/// sentinel like the correlator's `BAYES`, since the finding is that a detection source
/// is blind (a custom format, a server wording change), not an attacker behaviour.
const MISPARSE_TECHNIQUE: &str = "LOG-SOURCE";

fn misparse_message(path: &Path, kind: LogSourceKind, m: Misparse) -> String {
    format!(
        "log source {} ({kind:?}): {} of {} lines in the last minute do not match the \
         declared kind: the source is probably misconfigured (a custom format, or a server \
         that words the line differently) and detections from it are blind",
        path.display(),
        m.failed,
        m.parsed.saturating_add(m.failed),
    )
}

struct Source {
    kind: LogSourceKind,
    /// Present for an `access_*` source.
    access: Option<Access>,
    tailer: Tailer,
    position_path: PathBuf,
    last_saved: Option<Position>,
    stats: Stats,
    /// An I/O error was already logged for the current failure streak.
    warned: bool,
}

/// Starts the tail thread for the sources of `sources`, registering it with `shutdown`.
/// Does nothing, and starts no thread, when there are none.
pub(crate) fn spawn(
    sink: Arc<DetectionSink>,
    sources: &[LogSourceConfig],
    alerts: &Path,
    shutdown: &mut ShutdownPlan,
) {
    let mut active = Vec::new();
    for source in sources {
        let access = match source.kind {
            LogSourceKind::MysqlError => None,
            LogSourceKind::AccessCommon => Some(Access::new(AccessFormat::Common, &source.path)),
            LogSourceKind::AccessCombined => {
                Some(Access::new(AccessFormat::Combined, &source.path))
            }
        };
        let position_path = position_path_for(alerts, &source.path);
        let saved = read_position(&position_path);
        active.push(Source {
            kind: source.kind,
            access,
            tailer: Tailer::new(&source.path, saved),
            position_path,
            last_saved: saved,
            stats: Stats::default(),
            warned: false,
        });
    }
    if active.is_empty() {
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("log-sources".into())
        .spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                for source in &mut active {
                    poll_source(source, &sink);
                }
                sleep_unless_stopped(&worker_stop, POLL_INTERVAL);
            }
        })
        .expect("spawning the log sources thread");
    shutdown.register(
        "log-sources",
        move || stop.store(true, Ordering::SeqCst),
        handle,
    );
}

/// The one place an event leaves this module for the sink. ADR-0018's credential
/// redaction of an `HttpRequest`'s evidence value is applied here and nowhere else.
fn deliver(sink: &DetectionSink, mut event: schema::Event) {
    crate::redact::redact_event(&mut event);
    sink.on_event(event);
}

fn poll_source(source: &mut Source, sink: &DetectionSink) {
    let now_ns = schema::time::now_ns();
    let path = source.tailer.path().to_path_buf();
    let mut events = Vec::new();
    // The window's allowance is judged before this poll's lines, and what the window
    // shed is said once, when it ends.
    if let Some(access) = &mut source.access
        && let Some(dropped) = access.budget.tick(now_ns)
    {
        tracing::warn!(
            log = %path.display(),
            dropped = dropped.total(),
            path_traversal = dropped.path_traversal,
            sql_injection = dropped.sql_injection,
            scanner_user_agent = dropped.scanner_user_agent,
            webshell_like = dropped.webshell_like,
            "log source: request events shed over budget (still counted in the window summary)"
        );
    }
    let Source {
        tailer,
        stats,
        access,
        ..
    } = &mut *source;
    let result = tailer.poll(|line| {
        let event = match access {
            Some(access) => access_line_to_event(line, now_ns, access, stats, &path),
            None => mysql_line_to_event(line, now_ns, stats, &path),
        };
        if let Some(event) = event {
            events.push(event);
        }
    });
    if let Some(access) = &mut source.access
        && let Some(summary) = access.summarizer.tick(now_ns)
    {
        events.push(schema::Event::HttpSummary(summary));
    }
    for event in events {
        deliver(sink, event);
    }
    if let Some(m) = source.stats.watch.tick(now_ns) {
        sink.emit(MISPARSE_TECHNIQUE, &misparse_message(&path, source.kind, m));
    }
    match result {
        Ok(outcome) => {
            source.warned = false;
            if outcome.rotations > 0 || outcome.truncations > 0 {
                tracing::info!(
                    log = %path.display(),
                    rotations = outcome.rotations,
                    truncations = outcome.truncations,
                    "log source: file rotated"
                );
            }
        }
        Err(e) if !source.warned => {
            source.warned = true;
            tracing::warn!(log = %path.display(), error = %e, "log source: cannot read, retrying");
        }
        Err(_) => {}
    }
    if let Some(position) = source.tailer.position()
        && source.last_saved != Some(position)
    {
        write_position(&source.position_path, &position);
        source.last_saved = Some(position);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAIL: &str = "2026-10-01 12:00:00 12 [Warning] Access denied for user 'root'@'10.0.0.5' (using password: YES)";

    #[test]
    fn a_failed_login_line_yields_an_auth_event() {
        let mut stats = Stats::default();
        let event = mysql_line_to_event(FAIL, 7, &mut stats, Path::new("/var/log/mysql/error.log"));
        let Some(schema::Event::Auth(auth)) = event else {
            panic!("expected an Auth event, got {event:?}");
        };
        assert_eq!(auth.target_user, "root");
        assert_eq!(auth.meta.timestamp_ns, 7);
        assert_eq!(stats.parse_failures, 0);
    }

    #[test]
    fn an_ordinary_line_is_ignored_and_a_broken_one_is_counted() {
        let mut stats = Stats::default();
        let p = Path::new("/x");
        assert!(
            mysql_line_to_event("2026-10-01 12:00:00 0 [Note] ready", 1, &mut stats, p).is_none()
        );
        assert_eq!(stats.parse_failures, 0);
        let broken = "[Warning] Access denied for user 'u'@'h' (using password: YES)";
        assert!(mysql_line_to_event(broken, 1, &mut stats, p).is_none());
        assert_eq!(stats.parse_failures, 1);
    }

    #[test]
    fn a_source_whose_login_lines_all_fail_to_parse_is_flagged_once() {
        const SEC: u64 = 1_000_000_000;
        let mut stats = Stats::default();
        let p = Path::new("/var/log/mysql/error.log");
        let broken = "[Warning] Access denied for user 'u'@'h' wat";
        for _ in 0..20 {
            assert!(mysql_line_to_event(broken, 10 * SEC, &mut stats, p).is_none());
        }
        let m = stats.watch.tick(70 * SEC).expect("20 of 20 failed");
        assert_eq!((m.parsed, m.failed), (0, 20));
        let text = misparse_message(p, LogSourceKind::MysqlError, m);
        assert!(text.contains("20 of 20") && text.contains("/var/log/mysql/error.log"));
        // Ordinary lines the parser ignores on purpose say nothing about the format.
        let ok_line = "2026-10-01 12:00:00 0 [Note] ready for connections";
        for _ in 0..50 {
            mysql_line_to_event(ok_line, 80 * SEC, &mut stats, p);
        }
        assert_eq!(stats.watch.tick(140 * SEC), None);
    }

    #[test]
    fn position_files_are_stable_per_log_path_and_distinct_between_logs() {
        let alerts = Path::new("/var/lib/synthaea/alerts.ndjson");
        let a = position_path_for(alerts, Path::new("/var/log/mysql/error.log"));
        let b = position_path_for(alerts, Path::new("/var/log/mysql/other.log"));
        assert_eq!(
            a,
            position_path_for(alerts, Path::new("/var/log/mysql/error.log"))
        );
        assert_ne!(a, b);
        assert_eq!(a.parent(), alerts.parent());
    }

    #[test]
    fn a_position_survives_a_write_and_a_read() {
        let dir = std::env::temp_dir().join(format!("log-pos-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alerts.logpos-0");
        assert_eq!(read_position(&path), None);
        let p = Position::decode("v1 - - 123").unwrap();
        write_position(&path, &p);
        assert_eq!(read_position(&path), Some(p));
        std::fs::write(&path, "garbage").unwrap();
        assert_eq!(read_position(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    const SEC: u64 = 1_000_000_000;
    const NGINX: &str = "/var/log/nginx/access.log";

    fn access_line(target: &str, status: u16, agent: &str) -> String {
        format!(
            r#"203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "GET {target} HTTP/1.1" {status} 10 "-" "{agent}""#
        )
    }

    fn access() -> (Access, Stats) {
        (
            Access::new(AccessFormat::Combined, Path::new(NGINX)),
            Stats::default(),
        )
    }

    #[test]
    fn a_request_that_matches_a_signature_yields_an_event_and_an_ordinary_one_does_not() {
        let (mut acc, mut stats) = access();
        let p = Path::new(NGINX);
        let hit = access_line("/a.php?id=1%20union%20select%201", 200, "curl/8");
        let Some(schema::Event::HttpRequest(e)) =
            access_line_to_event(&hit, 7, &mut acc, &mut stats, p)
        else {
            panic!("expected an HttpRequest event");
        };
        assert_eq!(e.signature, schema::HttpSignature::SqlInjection);
        assert_eq!(e.path, "/a.php");
        assert_eq!(e.meta.timestamp_ns, 7);

        let ordinary = access_line("/index.html", 200, "Mozilla/5.0");
        assert!(access_line_to_event(&ordinary, 8, &mut acc, &mut stats, p).is_none());
        assert_eq!(stats.parse_failures, 0);
    }

    #[test]
    fn every_parsed_request_reaches_the_window_summary_matched_or_not() {
        let (mut acc, mut stats) = access();
        let p = Path::new(NGINX);
        access_line_to_event(&access_line("/", 200, "x"), SEC, &mut acc, &mut stats, p);
        access_line_to_event(
            &access_line("/missing", 404, "x"),
            SEC,
            &mut acc,
            &mut stats,
            p,
        );
        access_line_to_event(
            &access_line("/a?q=../../etc/passwd", 200, "x"),
            SEC,
            &mut acc,
            &mut stats,
            p,
        );
        let summary = acc
            .summarizer
            .tick(62 * SEC)
            .expect("a full window with requests");
        assert_eq!(summary.requests, 3);
        assert_eq!(summary.status_4xx, 1);
        assert_eq!(summary.source, NGINX);
    }

    #[test]
    fn a_flood_of_one_signature_is_shed_but_still_counted_and_does_not_hide_another() {
        let (mut acc, mut stats) = access();
        let p = Path::new(NGINX);
        let sqli = access_line("/a?id=1%20union%20select%201", 200, "x");
        let mut emitted = 0;
        for _ in 0..100 {
            if access_line_to_event(&sqli, SEC, &mut acc, &mut stats, p).is_some() {
                emitted += 1;
            }
        }
        assert_eq!(emitted, sensor_linux_logs::PER_SIGNATURE_PER_WINDOW);
        let shell = access_line("/uploads/c99.php", 200, "x");
        assert!(access_line_to_event(&shell, SEC, &mut acc, &mut stats, p).is_some());
        let summary = acc.summarizer.tick(62 * SEC).unwrap();
        assert_eq!(summary.requests, 101, "shed events are still counted");
        assert_eq!(acc.budget.tick(62 * SEC).unwrap().sql_injection, 70);
    }

    #[test]
    fn a_line_that_is_not_an_access_line_is_counted_and_feeds_the_misparse_watch() {
        let (mut acc, mut stats) = access();
        let p = Path::new(NGINX);
        for _ in 0..20 {
            assert!(
                access_line_to_event("not an access log line", 10 * SEC, &mut acc, &mut stats, p)
                    .is_none()
            );
        }
        assert_eq!(stats.parse_failures, 20);
        let m = stats.watch.tick(70 * SEC).expect("20 of 20 failed");
        assert_eq!((m.parsed, m.failed), (0, 20));
        assert!(
            acc.summarizer.tick(70 * SEC).is_none(),
            "no request, no summary"
        );
    }

    /// Runs one access-log line through `poll_source` into a real `DetectionSink` and
    /// returns what reached the raw event log (`events.jsonl`). This is the path an
    /// `HttpRequest` takes in the agent, so it pins that [`deliver`] really is the one
    /// choke point where the evidence is redacted (ADR-0018), not a convention.
    fn raw_events_after_polling(name: &str, request_target: &str) -> String {
        let dir = std::env::temp_dir().join(format!("log-sources-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("access.log");
        // The tailer starts at the end of a log that already exists; this one does not
        // yet, so the first poll reads it from the top.
        let mut source = Source {
            kind: LogSourceKind::AccessCombined,
            access: Some(Access::new(AccessFormat::Combined, &log)),
            tailer: Tailer::new(&log, None),
            position_path: dir.join("position"),
            last_saved: None,
            stats: Stats::default(),
            warned: false,
        };
        std::fs::write(
            &log,
            format!("{}\n", access_line(request_target, 200, "curl/8")),
        )
        .unwrap();
        let sink = DetectionSink::new(
            rules::RuleState::new(),
            &dir.join("alerts.ndjson"),
            Some(&dir.join("events.jsonl")),
            None,
            None,
            &dir.join("content"),
            &dir.join("ml-registry"),
        )
        .unwrap();

        poll_source(&mut source, &sink);

        // The raw event log is written by the enrichment worker, not the caller: wait.
        let events = dir.join("events.jsonl");
        for _ in 0..200 {
            let text = std::fs::read_to_string(&events).unwrap_or_default();
            if text.contains("/a.php") {
                let _ = std::fs::remove_dir_all(&dir);
                return text;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no http_request event in the raw log within 10 s");
    }

    #[test]
    fn a_secret_in_the_matched_parameter_never_reaches_the_event_log() {
        let events = raw_events_after_polling(
            "secret-param",
            "/a.php?token=s3cr3t-9f2a%20union%20select%201",
        );
        assert!(
            !events.contains("s3cr3t"),
            "the credential must not leave the host: {events}"
        );
        assert!(events.contains("REDACTED"), "{events}");
        assert!(
            events.contains("token"),
            "the parameter name stays, the finding is still readable: {events}"
        );
    }

    #[test]
    fn the_evidence_of_an_ordinary_parameter_still_reaches_the_event_log() {
        let events = raw_events_after_polling("plain-param", "/a.php?id=1%20union%20select%201");
        assert!(events.contains("union"), "the evidence is kept: {events}");
        assert!(
            !events.contains("REDACTED"),
            "nothing to redact on `id`: {events}"
        );
    }
}
