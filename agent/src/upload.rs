//! Store-and-forward upload (#24): the `store::EventSpool` → `transport` wiring.
//!
//! The binary is the composition point (CLAUDE.md's dependency direction:
//! `transport` and `store` may not know each other) — this module owns the
//! spool the sink appends to, adapts it to `transport::EventDrain`'s two-phase
//! drain/ack/skip contract, and runs the upload loop on its own thread.
//! Everything here is opt-in behind `run --server <url>`: without a server,
//! nothing is spooled and the agent behaves exactly as before.

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use store::EventSpool;
use transport::{EventDrain, EventUploader, TransportClient, TransportConfig, UploadLoop};

/// On-disk cap for the spool. Beyond it the spool sheds oldest and counts
/// (`store::EventSpool`'s own policy) — visible in the health beacon as
/// `spool_dropped`, never a blocked capture path.
const SPOOL_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// How long the upload loop sleeps when the spool is empty. Uploads are
/// batched and latency-tolerant by design (store-and-forward); detection is
/// entirely local, so nothing time-critical rides on this.
const UPLOAD_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Adapts the spool to `transport`'s [`EventDrain`]: `drain` re-delivers the
/// in-flight segment until [`EventDrain::ack`] (at-least-once), `skip`
/// discards a poison segment the server permanently rejects.
struct SpoolDrain(Arc<Mutex<EventSpool>>);

impl EventDrain for SpoolDrain {
    fn drain(&mut self) -> std::io::Result<Vec<schema::Event>> {
        self.0.lock().unwrap().drain_oldest()
    }

    fn ack(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().ack().map(|_| ())
    }

    fn skip(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().skip().map(|_| ())
    }
}

/// What `run` keeps after starting the upload pipeline: the spool handle the
/// sink appends to (and health reads), and a client for the health beacon's
/// heartbeat POSTs. The upload thread itself needs no handle — like the
/// health-beacon thread, it stops when the process exits (see
/// `commands::linux::cmd_run`'s note on graceful shutdown).
pub(crate) struct TransportHandle {
    pub(crate) spool: Arc<Mutex<EventSpool>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    // heartbeat wiring is Linux-first (#25 precedent)
    pub(crate) client: Arc<TransportClient>,
}

/// Opens the spool (next to the alerts file — the same "derived, no separate
/// flag" convention as `quarantine/` and the heartbeat file) and starts the
/// upload thread against `server_url`.
pub(crate) fn start(server_url: &str, alerts: &Path) -> anyhow::Result<TransportHandle> {
    let dir = alerts.with_file_name("spool");
    let spool = Arc::new(Mutex::new(EventSpool::open(&dir, SPOOL_MAX_BYTES)?));

    // Two clients on one config: `EventUploader` consumes its client, and the
    // health beacon needs one of its own for heartbeats.
    let config = TransportConfig::new(server_url);
    let upload_client = TransportClient::new(config.clone())
        .map_err(|e| anyhow::anyhow!("transport client: {e}"))?;
    let heartbeat_client = Arc::new(
        TransportClient::new(config).map_err(|e| anyhow::anyhow!("transport client: {e}"))?,
    );

    let uploader = EventUploader::new(upload_client, SpoolDrain(Arc::clone(&spool)));
    let mut upload_loop = UploadLoop::new(uploader, UPLOAD_POLL_INTERVAL);
    std::thread::Builder::new()
        .name("transport-upload".into())
        .spawn(move || upload_loop.run())
        .expect("spawning the transport upload thread");

    Ok(TransportHandle {
        spool,
        client: heartbeat_client,
    })
}

/// The health beacon's view of the spool (`spool_bytes`/`spool_dropped` in
/// #134's beacon) — replaces `health::NoopSpoolStats` when transport is on.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // health collector is Linux-first (#25 precedent)
pub(crate) struct SpoolHealth(pub(crate) Arc<Mutex<EventSpool>>);

impl crate::health::SpoolStatsSource for SpoolHealth {
    fn spool_bytes(&self) -> u64 {
        self.0.lock().unwrap().stats().bytes
    }

    fn spool_dropped(&self) -> u64 {
        self.0.lock().unwrap().stats().dropped_records
    }
}

#[cfg(test)]
mod tests {
    use schema::{Event, ExecEvent};

    use super::*;

    fn spool(name: &str) -> Arc<Mutex<EventSpool>> {
        let dir = std::env::temp_dir().join(format!("agent-upload-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(Mutex::new(EventSpool::open(&dir, u64::MAX).unwrap()))
    }

    fn exec(cmdline: &str) -> Event {
        Event::Exec(ExecEvent {
            cmdline: cmdline.into(),
            ..schema::fixtures::exec()
        })
    }

    /// The at-least-once property the whole wiring exists for: a drain that is
    /// never ack'd (crash, network outage) re-delivers the same events; only
    /// ack makes them gone.
    #[test]
    fn unacked_drain_redelivers_acked_drain_deletes() {
        let spool = spool("redeliver");
        spool.lock().unwrap().push(&exec("curl evil.test")).unwrap();
        let mut drain = SpoolDrain(Arc::clone(&spool));

        let first = drain.drain().unwrap();
        assert_eq!(first.len(), 1);
        // No ack — the "upload failed" path. The same segment comes back.
        let again = drain.drain().unwrap();
        assert_eq!(again, first, "un-acked events must re-deliver, not vanish");

        drain.ack().unwrap();
        assert!(drain.drain().unwrap().is_empty(), "acked events are gone");
    }

    /// The poison escape hatch: skip discards without upload so one rejected
    /// segment cannot block newer telemetry.
    #[test]
    fn skipped_segment_is_discarded_and_newer_data_flows() {
        let spool = spool("skip");
        spool.lock().unwrap().push(&exec("poison")).unwrap();
        let mut drain = SpoolDrain(Arc::clone(&spool));
        assert_eq!(drain.drain().unwrap().len(), 1);
        drain.skip().unwrap();

        spool.lock().unwrap().push(&exec("fresh")).unwrap();
        let next = drain.drain().unwrap();
        assert_eq!(next.len(), 1);
        let Event::Exec(e) = &next[0] else {
            panic!("expected exec");
        };
        assert_eq!(e.cmdline, "fresh");
    }
}
