//! Progress-backed heartbeat (#102): a background thread periodically writes
//! the sensor pipeline's live event counter to a small file next to the
//! alerts output, which the watchdog polls to detect a hung agent. Unlike a
//! bare "I'm still scheduled" timer, this only advances when
//! [`crate::sink::DetectionSink::on_event`] completes end-to-end for a real
//! event — a wedged sensor thread, a poisoned lock, or a stalled drain loop
//! all stop it, exactly the failure mode a plain process-alive (`try_wait`)
//! check misses (the endpoint looks protected while collecting nothing).
//!
//! File-based rather than a socket/named pipe or `crates/ipc`: cross-platform
//! for free (no `cfg(windows)`/`cfg(unix)` split anywhere in this path), and
//! `watchdog` has no dependency on `agent`'s or `schema`'s types to decode a
//! richer protocol with — a plain advancing counter is all liveness needs.
//! `crates/ipc`'s richer protocol (agent status, recent detections, policy
//! version) remains the right tool for the UI/CLI control channel it's
//! designed for; this is a narrower, purpose-built mechanism for one signal.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How often the writer thread samples the counter and rewrites the file.
/// Independent of the watchdog's own `--heartbeat-interval-secs` (its poll
/// cadence) — this just needs to be frequent enough that the watchdog's
/// coarser polling always sees fresh data, not tuned per deployment.
pub(crate) const WRITE_INTERVAL: Duration = Duration::from_secs(2);

/// Derives the heartbeat file path from the alerts output path — the two
/// always travel together, so no separate CLI flag or install-time wiring is
/// needed. **Must stay in sync with `watchdog::paths::heartbeat_path_for`**,
/// which computes the same transform independently (the two crates share no
/// dependency to hang a single implementation off of, and `watchdog` cannot
/// depend on this binary-only `agent` crate to reuse it directly).
pub(crate) fn heartbeat_path_for(alerts: &Path) -> PathBuf {
    alerts.with_extension("heartbeat")
}

/// Starts the writer thread (detached — it runs until the process exits, no
/// shutdown handshake needed: the file simply stops advancing). `counter` is
/// the same `Arc` [`crate::sink::DetectionSink`] increments per event
/// (`DetectionSink::progress_handle`).
pub(crate) fn start(path: PathBuf, counter: Arc<AtomicU64>, interval: Duration) {
    std::thread::Builder::new()
        .name("heartbeat".into())
        .spawn(move || {
            loop {
                write_once(&path, counter.load(Ordering::Relaxed));
                std::thread::sleep(interval);
            }
        })
        .expect("spawning the heartbeat writer thread");
}

/// Writes `count` to `path` via a same-directory temp file + rename, so a
/// concurrent reader (the watchdog) never observes a torn/partial write.
fn write_once(path: &Path, count: u64) {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, count.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_path_is_derived_from_alerts() {
        assert_eq!(
            heartbeat_path_for(Path::new("/var/lib/synthaea/alerts.ndjson")),
            PathBuf::from("/var/lib/synthaea/alerts.heartbeat")
        );
    }

    #[test]
    fn heartbeat_path_handles_an_extensionless_alerts_path() {
        assert_eq!(
            heartbeat_path_for(Path::new("/var/lib/synthaea/alerts")),
            PathBuf::from("/var/lib/synthaea/alerts.heartbeat")
        );
    }

    #[test]
    fn writer_thread_advances_the_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "heartbeat-test-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        let counter = Arc::new(AtomicU64::new(0));
        start(
            path.clone(),
            Arc::clone(&counter),
            Duration::from_millis(20),
        );
        counter.store(42, Ordering::Relaxed);

        let mut seen = None;
        for _ in 0..100 {
            if let Ok(content) = std::fs::read_to_string(&path)
                && let Ok(n) = content.trim().parse::<u64>()
            {
                seen = Some(n);
                if n == 42 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(seen, Some(42));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn writer_never_leaves_a_torn_file_visible() {
        // Every observed state of the file is a value the counter actually
        // held — the temp-file-then-rename means a concurrent reader can
        // only ever see a complete write, never a partial one.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "heartbeat-torn-test-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        let counter = Arc::new(AtomicU64::new(0));
        start(path.clone(), Arc::clone(&counter), Duration::from_millis(5));
        for i in 1..=50u64 {
            counter.store(i, Ordering::Relaxed);
            if let Ok(content) = std::fs::read_to_string(&path) {
                let trimmed = content.trim();
                assert!(
                    trimmed.is_empty() || trimmed.parse::<u64>().is_ok(),
                    "torn read: {trimmed:?}"
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::remove_file(&path).ok();
    }
}
