//! The enrichment + event-log worker — keeping hashing and signature verification
//! off the sensor's drain thread (issue #126).
//!
//! `DetectionSink::on_event` runs synchronously on the thread that drains the
//! kernel ring buffer / ETW session. Enrichment on a cache miss does a streaming
//! SHA-256 plus a signature verification (file reads + crypto), and misses cluster
//! (a software rollout, first boot, an attacker unpacking many payloads). Paid on
//! the capture thread, that stall is unbounded in aggregate and the kernel drops
//! telemetry once its buffer fills — the one thing an EDR must not do.
//!
//! So enrichment and the (high-volume) raw-event logging move here, behind a bounded
//! channel: the drain thread runs the in-memory detection engines and hands the
//! event off with a non-blocking `try_send`. No on-device engine consumes the hash
//! or signature synchronously (rules/Sigma/correlator all work on cmdline, lineage,
//! paths, and ports), so nothing detection-relevant waits on this. Overflow sheds
//! and counts, like `yara::ScanQueue` — the loss is a logged/enriched record under
//! extreme load, never a dropped detection and never stalled capture.
//!
//! [`EnrichQueue::flush`] (issue #341) gives `kill_loudness`'s shutdown path a
//! bounded way to wait for this backlog before the process exits — the backlog is
//! normally sub-millisecond, but a signal can land in the same instant an event
//! was captured, and without this the event is already lost downstream of a
//! successful `enqueue`, before it ever reaches `events.jsonl`. Bounded, not
//! unconditional: #71's kill-loudness deliberately hard-exits rather than run a
//! full clean shutdown, so a compromised or wedged process can't use its own
//! teardown path to outlast a termination signal — `flush`'s caller-supplied
//! timeout preserves that: the worst case is the same immediate exit as before,
//! just after a short, fixed wait instead of none.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use enrich::Enricher;
use schema::Event;

/// Queue depth: a burst of events beyond this sheds enrichment/logging (counted).
/// Sized so a normal exec rate has ample headroom and only a pathological burst
/// (mass process creation) reaches the cap.
const QUEUE_CAP: usize = 4_096;

/// What travels over the channel: a real event, or a shutdown-time marker (see
/// [`EnrichQueue::flush`]) that carries nothing but a place to signal "everything
/// enqueued before me has been processed."
enum QueueItem {
    // Boxed: `Event`'s largest variant otherwise sets every channel slot's size,
    // multiplied by `QUEUE_CAP` — `Flush` doesn't need anywhere near that much room.
    Event(Box<Event>),
    // Only `kill_loudness` (Linux-gated) flushes today — the shutdown path on
    // the other platforms doesn't exist yet, not a reason to lose the variant.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Flush(mpsc::Sender<()>),
}

/// Owns the worker thread. Dropping the queue stops the worker after the backlog
/// drains.
#[derive(Clone)]
pub(crate) struct EnrichQueue {
    tx: mpsc::SyncSender<QueueItem>,
    dropped: Arc<AtomicU64>,
}

impl EnrichQueue {
    /// Starts the worker. It enriches each event (exec images only) and hands the
    /// finished event to `on_enriched` — which the sink wires to the raw event log.
    /// The [`Enricher`] is owned exclusively by the worker, so its cache needs no
    /// lock and a long hash never blocks another thread.
    pub(crate) fn start(
        mut enricher: Enricher,
        on_enriched: impl Fn(Event) + Send + 'static,
    ) -> Self {
        let (tx, rx) = mpsc::sync_channel::<QueueItem>(QUEUE_CAP);
        let dropped = Arc::new(AtomicU64::new(0));
        std::thread::Builder::new()
            .name("enrich".into())
            .spawn(move || {
                while let Ok(item) = rx.recv() {
                    match item {
                        QueueItem::Event(mut event) => {
                            enrich_event(&mut enricher, &mut event);
                            on_enriched(*event);
                        }
                        // Nothing to do but signal back — arriving here at all means
                        // every `Event` sent before it has already been enriched and
                        // handed to `on_enriched`, since this is a single-consumer
                        // FIFO channel. The receiver going away (flush() timed out
                        // and stopped waiting) makes `send` fail — fine, nobody's
                        // listening any more.
                        QueueItem::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .expect("spawning the enrichment worker thread");
        Self { tx, dropped }
    }

    /// Hands an event to the worker; sheds (and counts) when the queue is full so
    /// the caller — the capture thread — never blocks.
    pub(crate) fn enqueue(&self, event: Event) {
        if self.tx.try_send(QueueItem::Event(Box::new(event))).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Events shed because the queue was full — observable loss, for the agent's
    /// own health telemetry (bounded state loses information by design; the count
    /// keeps it visible). Read by the health beacon (#134); exercised by tests today.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Best-effort shutdown drain (issue #341): waits up to `timeout` for every
    /// event already enqueued to finish enrichment and reach `on_enriched`, so a
    /// signal landing right after an event was captured doesn't lose it downstream
    /// of an already-successful `enqueue`.
    ///
    /// Works by sending a marker behind whatever is already queued and waiting for
    /// the worker to reach it — since the channel is single-consumer FIFO, the
    /// worker reaching the marker means it already processed everything ahead of
    /// it. Enqueueing the marker itself uses `try_send` in a short retry loop
    /// rather than a blocking `send`, so a queue that's *completely full* still
    /// respects `timeout` instead of a plain `send` potentially blocking the whole
    /// budget away on the enqueue step alone.
    ///
    /// Returns `false` on a timeout (queue too full to accept the marker in time,
    /// or the worker didn't reach it in time) or if the worker thread is gone —
    /// the caller's own bounded budget is what actually protects it against this
    /// never resolving, not this function's internals.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (done_tx, done_rx) = mpsc::channel();
        loop {
            match self.tx.try_send(QueueItem::Flush(done_tx.clone())) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Disconnected(_)) => return false,
                Err(mpsc::TrySendError::Full(_)) => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return false;
                    };
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        done_rx.recv_timeout(remaining).is_ok()
    }
}

impl crate::health::DroppedCounter for EnrichQueue {
    fn dropped(&self) -> u64 {
        EnrichQueue::dropped(self)
    }
}

/// Fills an exec event's hash + signature from the enricher. A cache hit is a
/// metadata stat; a miss is one bounded hash + one offline signature check. Runs on
/// the worker, never the capture thread.
fn enrich_event(enricher: &mut Enricher, event: &mut Event) {
    if let Event::Exec(e) = event
        && !e.image_path.is_empty()
        && e.sha256.is_none()
    {
        let enrichment = enricher.enrich(std::path::Path::new(&e.image_path));
        e.sha256 = enrichment.sha256;
        e.signature = Some(enrichment.signature);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use schema::{Event, EventMeta, ExecEvent};

    use super::*;

    fn exec(image_path: &str) -> Event {
        Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 1,
                comm: "t".into(),
                ..schema::fixtures::meta()
            },
            image_path: image_path.to_string(),
            ..schema::fixtures::exec()
        })
    }

    #[test]
    fn worker_enriches_exec_and_delivers_it() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("enrich-queue-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();

        let out: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let out_w = out.clone();
        let queue = EnrichQueue::start(Enricher::new(), move |e| out_w.lock().unwrap().push(e));
        queue.enqueue(exec(&path.to_string_lossy()));

        // Wait for the worker to deliver.
        for _ in 0..100 {
            if !out.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let delivered = out.lock().unwrap();
        assert_eq!(delivered.len(), 1);
        let Event::Exec(e) = &delivered[0] else {
            panic!("expected exec")
        };
        // SHA-256("abc") — the worker filled it off the enqueue thread.
        assert_eq!(
            e.sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert!(e.signature.is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn overflow_sheds_and_counts_instead_of_blocking() {
        // A worker that blocks until released, so the queue fills.
        let gate = Arc::new(Mutex::new(()));
        let held = gate.lock().unwrap();
        let gate_worker = gate.clone();
        let queue = EnrichQueue::start(Enricher::new(), move |_| {
            let _wait = gate_worker.lock().unwrap();
        });
        // First send is accepted (worker takes it, then blocks); fill the buffer and
        // then some. try_send must never block — the loop returning proves it.
        for _ in 0..(QUEUE_CAP + 200) {
            queue.enqueue(exec("/nonexistent/x"));
        }
        assert!(queue.dropped() > 0, "a full queue must shed, not block");
        drop(held); // release the worker so it can exit cleanly
    }

    #[test]
    fn flush_waits_for_already_enqueued_events_to_finish() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("enrich-queue-flush-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();

        let out: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let out_w = out.clone();
        // Slows the worker down (not to zero — flush must still finish inside its
        // own budget) so a flush racing an in-flight enrichment is exercised, not
        // just the trivially-already-empty case.
        let queue = EnrichQueue::start(Enricher::new(), move |e| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            out_w.lock().unwrap().push(e);
        });
        for _ in 0..5 {
            queue.enqueue(exec(&path.to_string_lossy()));
        }

        assert!(
            queue.flush(Duration::from_secs(2)),
            "flush must report success once every prior event is drained"
        );
        assert_eq!(
            out.lock().unwrap().len(),
            5,
            "every event enqueued before flush() must have been processed by the time it returns"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn flush_times_out_rather_than_waiting_forever_on_a_wedged_worker() {
        // A worker that never returns — flush must still respect its deadline.
        let gate = Arc::new(Mutex::new(()));
        let held = gate.lock().unwrap();
        let gate_worker = gate.clone();
        let queue = EnrichQueue::start(Enricher::new(), move |_| {
            let _wait = gate_worker.lock().unwrap();
        });
        queue.enqueue(exec("/nonexistent/x"));

        let start = Instant::now();
        let flushed = queue.flush(Duration::from_millis(100));
        assert!(!flushed, "a wedged worker must make flush() report failure");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "flush() must not wait past its own timeout"
        );
        drop(held); // release the worker so it can exit cleanly
    }
}
