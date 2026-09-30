//! The budgeted scan queue: one worker thread behind a bounded channel, so scanning
//! never blocks the event path. Overflow drops the request and counts it.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use crate::{RuleSet, YaraMatch};

/// Queue capacity: a burst of file writes beyond this sheds scan requests (counted).
const QUEUE_CAP: usize = 512;
/// Settle delay before scanning: a FileOpen-for-write event fires at open time, and
/// the interesting content usually lands milliseconds later.
const SETTLE: Duration = Duration::from_millis(200);

/// One scan result delivered to the callback.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub path: PathBuf,
    /// Matching rules, with metadata (non-empty by construction — clean scans are
    /// not delivered).
    pub matches: Vec<YaraMatch>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScanStats {
    pub scanned: u64,
    pub dropped: u64,
}

/// Owns the worker thread. Dropping the queue stops the worker after the backlog.
pub struct ScanQueue {
    tx: mpsc::SyncSender<(PathBuf, Instant)>,
    scanned: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl ScanQueue {
    /// Starts the worker. `on_match` runs on the worker thread for every scan with
    /// at least one matching rule.
    ///
    /// # Panics
    ///
    /// Panics when the OS refuses to spawn the worker thread — at agent startup,
    /// on a host that cannot spawn one thread, there is nothing to degrade to.
    pub fn start(rules: RuleSet, on_match: impl Fn(ScanOutcome) + Send + 'static) -> Self {
        let (tx, rx) = mpsc::sync_channel::<(PathBuf, Instant)>(QUEUE_CAP);
        let scanned = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let scanned_w = scanned.clone();
        std::thread::Builder::new()
            .name("yara-scan".into())
            .spawn(move || {
                while let Ok((path, ready_at)) = rx.recv() {
                    // The settle deadline was stamped at ENQUEUE time — under a
                    // backlog the wait overlaps with earlier scans instead of
                    // adding 200ms of dead time per item (review finding: the
                    // per-item sleep capped throughput at 5 scans/second).
                    let now = Instant::now();
                    if ready_at > now {
                        std::thread::sleep(ready_at - now);
                    }
                    match rules.scan_file(&path) {
                        Ok(matches) if !matches.is_empty() => {
                            scanned_w.fetch_add(1, Ordering::Relaxed);
                            on_match(ScanOutcome { path, matches });
                        }
                        Ok(_) => {
                            scanned_w.fetch_add(1, Ordering::Relaxed);
                        }
                        // Vanished files are the normal case for droppers that
                        // delete their payload; anything else is logged, not fatal.
                        Err(e) => tracing::debug!(error = %e, "yara: scan skipped"),
                    }
                }
            })
            .expect("spawning the yara worker thread");
        Self {
            tx,
            scanned,
            dropped,
        }
    }

    /// Enqueues a path for scanning; sheds (and counts) when the queue is full.
    pub fn enqueue(&self, path: PathBuf) {
        let ready_at = Instant::now() + SETTLE;
        if self.tx.try_send((path, ready_at)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn stats(&self) -> ScanStats {
        ScanStats {
            scanned: self.scanned.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn queue_scans_and_reports_matches_only() {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(
                br#"
rule q {
    meta:
        severity = "high"
        technique = "T1105"
        falsepositives = "none known"
    strings:
        $m = "QUEUE-MARKER"
    condition:
        $m
}
"#
                .as_slice(),
            )
            .unwrap();
        let rules = RuleSet::from_compiled(compiler.build()).unwrap();
        let hits: Arc<Mutex<Vec<ScanOutcome>>> = Arc::new(Mutex::new(Vec::new()));
        let hits_w = hits.clone();
        let queue = ScanQueue::start(rules, move |o| hits_w.lock().unwrap().push(o));

        let dir = std::env::temp_dir();
        let hit = dir.join(format!("yara-q-hit-{}", std::process::id()));
        let miss = dir.join(format!("yara-q-miss-{}", std::process::id()));
        std::fs::write(&hit, b"xx QUEUE-MARKER xx").unwrap();
        std::fs::write(&miss, b"benign").unwrap();
        queue.enqueue(hit.clone());
        queue.enqueue(miss);

        // Two scans with a 200ms settle each — wait generously.
        for _ in 0..100 {
            if queue.stats().scanned >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let hits = hits.lock().unwrap();
        assert_eq!(hits.len(), 1, "only the matching file is delivered");
        assert_eq!(hits[0].path, hit);
        assert_eq!(hits[0].matches.len(), 1);
        assert_eq!(hits[0].matches[0].identifier, "q");
    }
}
