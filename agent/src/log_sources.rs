//! Tails the service logs declared in `[logs]` and turns what they say into events
//! (ADR-0022, issue #478 level 2).
//!
//! One thread polls every source once a second. Each source keeps a persisted
//! [`Position`] in a file derived from the alerts path (same convention as
//! `crate::journal_cursor`), so a restart resumes where it stopped.
//!
//! **Active today:** `mysql_error`, whose failed logins become `schema::AuthEvent`s and
//! so feed the existing brute-force rule (T1110). The `access_*` kinds are accepted by
//! the configuration but not read yet: they need the `HttpRequest` event and the
//! redaction of what leaves the host, which are separate changes. Declaring one logs a
//! warning rather than silently doing nothing.
//!
//! No silence alert and no heartbeat: a quiet log is normal on a quiet site (ADR-0022,
//! decision 4). A line that does not parse is counted and sampled in the log, never
//! skipped silently; the "misparsing" health event is a follow-up.

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
    Misparse, MisparseWatch, Position, Tailer, parse_mysql_error_line, to_auth_event,
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
            stats.parse_failures += 1;
            stats.watch.record(false, now_ns);
            // First failure, then every thousandth: a custom format would otherwise
            // log once per line. The sample is attacker-controlled text, so it is
            // cut and escaped (`{:?}`), never written raw.
            if stats.parse_failures == 1 || stats.parse_failures.is_multiple_of(1000) {
                let mut end = line.len().min(SAMPLE_BYTES);
                while !line.is_char_boundary(end) {
                    end -= 1;
                }
                tracing::warn!(
                    log = %path.display(),
                    failures = stats.parse_failures,
                    error = %e,
                    sample = ?&line[..end],
                    "log source: line does not match its declared kind"
                );
            }
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
    tailer: Tailer,
    position_path: PathBuf,
    last_saved: Option<Position>,
    stats: Stats,
    /// An I/O error was already logged for the current failure streak.
    warned: bool,
}

/// Starts the tail thread for the `mysql_error` sources of `sources`, registering it
/// with `shutdown`. Does nothing, and starts no thread, when none is active.
pub(crate) fn spawn(
    sink: Arc<DetectionSink>,
    sources: &[LogSourceConfig],
    alerts: &Path,
    shutdown: &mut ShutdownPlan,
) {
    let mut active = Vec::new();
    for source in sources {
        match source.kind {
            LogSourceKind::MysqlError => {
                let position_path = position_path_for(alerts, &source.path);
                let saved = read_position(&position_path);
                active.push(Source {
                    kind: source.kind,
                    tailer: Tailer::new(&source.path, saved),
                    position_path,
                    last_saved: saved,
                    stats: Stats::default(),
                    warned: false,
                });
            }
            LogSourceKind::AccessCommon | LogSourceKind::AccessCombined => {
                tracing::warn!(
                    log = %source.path.display(),
                    "log source: access logs are declared but not read yet (needs the HttpRequest event)"
                );
            }
        }
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

fn poll_source(source: &mut Source, sink: &DetectionSink) {
    let now_ns = schema::time::now_ns();
    let path = source.tailer.path().to_path_buf();
    let mut events = Vec::new();
    let result = source.tailer.poll(|line| {
        if let Some(event) = mysql_line_to_event(line, now_ns, &mut source.stats, &path) {
            events.push(event);
        }
    });
    for event in events {
        sink.on_event(event);
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
}
