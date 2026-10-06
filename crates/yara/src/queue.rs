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

use crate::{RuleSet, YaraMatch, access::Requester};

/// Queue capacity: a burst of file writes beyond this sheds scan requests (counted).
const QUEUE_CAP: usize = 512;
/// Settle delay before scanning: a FileOpen-for-write event fires at open time, and
/// the interesting content usually lands milliseconds later.
const SETTLE: Duration = Duration::from_millis(200);

/// Who caused a scan request: the process behind the file write that queued it.
/// Scanning is deliberately decoupled from that process (the settle delay below),
/// so the identity has to travel with the request for a match to be attributed.
/// The fields mirror the correlator's entity join `(ppid, comm)` plus the parent's
/// incarnation (issues #614, #592).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanContext {
    pub ppid: u32,
    pub comm: String,
    /// The incarnation of the parent `ppid` names, when the sensor stamped one
    /// (`EventMeta::parent_process_generation`): without it a recycled parent pid
    /// would let a match join the previous parent's entity.
    pub parent_generation: Option<u64>,
    /// Timestamp of the triggering event: the clock the entity's other findings
    /// use, not the later scan time, so dedup windows compare like with like.
    pub timestamp_ns: u64,
    /// The user behind the request (#594). The path is whatever the process named, even
    /// when the kernel refused the open, and the agent reads with `CAP_DAC_READ_SEARCH`:
    /// the file is scanned only if this user could read it themselves. `None` where the
    /// platform has no uid, which scans as before.
    pub requester: Option<Requester>,
}

/// One scan result delivered to the callback.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub path: PathBuf,
    /// The process that wrote the file, when the request carried one
    /// ([`ScanQueue::enqueue_for`]).
    pub context: Option<ScanContext>,
    /// Matching rules, with metadata (non-empty by construction — clean scans are
    /// not delivered).
    pub matches: Vec<YaraMatch>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScanStats {
    /// Scans fully handled: the match callback, when there was a match, has returned.
    pub scanned: u64,
    pub dropped: u64,
}

struct ScanRequest {
    path: PathBuf,
    ready_at: Instant,
    context: Option<ScanContext>,
}

/// Owns the worker thread. Dropping the queue stops the worker after the backlog.
pub struct ScanQueue {
    tx: mpsc::SyncSender<ScanRequest>,
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
        let (tx, rx) = mpsc::sync_channel::<ScanRequest>(QUEUE_CAP);
        let scanned = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let scanned_w = scanned.clone();
        std::thread::Builder::new()
            .name("yara-scan".into())
            .spawn(move || {
                while let Ok(ScanRequest {
                    path,
                    ready_at,
                    context,
                }) = rx.recv()
                {
                    // The settle deadline was stamped at ENQUEUE time — under a
                    // backlog the wait overlaps with earlier scans instead of
                    // adding 200ms of dead time per item (review finding: the
                    // per-item sleep capped throughput at 5 scans/second).
                    let now = Instant::now();
                    if ready_at > now {
                        std::thread::sleep(ready_at - now);
                    }
                    let scanned = match context.as_ref().and_then(|c| c.requester) {
                        Some(requester) => rules.scan_file_as(&path, requester),
                        None => rules.scan_file(&path),
                    };
                    match scanned {
                        Ok(matches) if !matches.is_empty() => {
                            on_match(ScanOutcome {
                                path,
                                context,
                                matches,
                            });
                            // Counted only once the callback has returned: `scanned`
                            // means "fully handled", so a caller that waits on it (a
                            // test, an orderly shutdown) never sees a match that the
                            // callback has not yet delivered.
                            scanned_w.fetch_add(1, Ordering::Relaxed);
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
        self.send(path, None);
    }

    /// [`Self::enqueue`] carrying the process behind the write, so a match comes
    /// back attributed to it ([`ScanOutcome::context`]).
    pub fn enqueue_for(&self, path: PathBuf, context: ScanContext) {
        self.send(path, Some(context));
    }

    fn send(&self, path: PathBuf, context: Option<ScanContext>) {
        let request = ScanRequest {
            path,
            ready_at: Instant::now() + SETTLE,
            context,
        };
        if self.tx.try_send(request).is_err() {
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
        assert_eq!(hits[0].context, None, "a plain enqueue carries no context");
    }

    #[test]
    fn a_match_comes_back_attributed_to_the_process_that_queued_the_scan() {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(
                br#"
rule ctx {
    meta:
        severity = "high"
        technique = "T1105"
        falsepositives = "none known"
    strings:
        $m = "CONTEXT-MARKER"
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

        let path = std::env::temp_dir().join(format!("yara-q-ctx-{}", std::process::id()));
        std::fs::write(&path, b"CONTEXT-MARKER").unwrap();
        let context = ScanContext {
            ppid: 42,
            comm: "dropper".into(),
            parent_generation: Some(3),
            timestamp_ns: 7,
            requester: None,
        };
        queue.enqueue_for(path, context.clone());

        for _ in 0..100 {
            if queue.stats().scanned >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let hits = hits.lock().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].context, Some(context));
    }

    #[cfg(unix)]
    #[test]
    fn a_scan_queued_for_a_user_who_cannot_read_the_file_finds_nothing() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(
                br#"
rule as_user_q {
    meta:
        severity = "high"
        technique = "T1105"
        falsepositives = "none known"
    strings:
        $m = "AS-USER-QUEUE-MARKER"
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

        let path = std::env::temp_dir().join(format!("yara-q-as-{}", std::process::id()));
        std::fs::write(&path, b"AS-USER-QUEUE-MARKER").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        queue.enqueue_for(
            path.clone(),
            ScanContext {
                ppid: 1,
                comm: "stranger".into(),
                parent_generation: None,
                timestamp_ns: 1,
                requester: Some(Requester {
                    uid: 4_000_000,
                    gid: 4_000_000,
                }),
            },
        );

        for _ in 0..100 {
            if queue.stats().scanned >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(queue.stats().scanned, 1, "the request was handled");
        assert!(hits.lock().unwrap().is_empty(), "but nothing was read");
        let _ = std::fs::remove_file(&path);
    }
}
