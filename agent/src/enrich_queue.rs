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

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};

use enrich::Enricher;
use schema::Event;

/// Queue depth: a burst of events beyond this sheds enrichment/logging (counted).
/// Sized so a normal exec rate has ample headroom and only a pathological burst
/// (mass process creation) reaches the cap.
const QUEUE_CAP: usize = 4_096;

/// Owns the worker thread. Dropping the queue stops the worker after the backlog
/// drains.
#[derive(Clone)]
pub(crate) struct EnrichQueue {
    tx: mpsc::SyncSender<Event>,
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
        let (tx, rx) = mpsc::sync_channel::<Event>(QUEUE_CAP);
        let dropped = Arc::new(AtomicU64::new(0));
        std::thread::Builder::new()
            .name("enrich".into())
            .spawn(move || {
                while let Ok(mut event) = rx.recv() {
                    enrich_event(&mut enricher, &mut event);
                    on_enriched(event);
                }
            })
            .expect("spawning the enrichment worker thread");
        Self { tx, dropped }
    }

    /// Hands an event to the worker; sheds (and counts) when the queue is full so
    /// the caller — the capture thread — never blocks.
    pub(crate) fn enqueue(&self, event: Event) {
        if self.tx.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Events shed because the queue was full — observable loss, for the agent's
    /// own health telemetry (bounded state loses information by design; the count
    /// keeps it visible). Read by the health beacon (#134); exercised by tests today.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
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

    use schema::{Event, EventMeta, ExecEvent, User};

    use super::*;

    fn exec(image_path: &str) -> Event {
        Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 1,
                ppid: 0,
                user: User::Unknown,
                timestamp_ns: 0,
                comm: "t".into(),
                container: None,
            },
            image_path: image_path.to_string(),
            cmdline: String::new(),
            argv: vec![],
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
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
}
