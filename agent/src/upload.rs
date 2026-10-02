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
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use store::EventSpool;
use transport::{EventDrain, EventUploader, TransportClient, TransportConfig, UploadLoop};

use crate::shutdown::ShutdownPlan;

/// The spool's on-disk cap in bytes, from `storage.spool_max_mb` (mebibytes, as the
/// configuration documents; 4096 by default). Beyond it the spool sheds oldest and
/// counts (`store::EventSpool`'s own policy) — visible in the health beacon as
/// `spool_dropped`, never a blocked capture path. Saturates instead of wrapping, and
/// the configuration already rejects 0 at load, so the cap is never 0.
///
/// Until #604 this was a hard-coded 64 MiB and the configured value was never read.
pub(crate) fn spool_cap_bytes(spool_max_mb: u64) -> u64 {
    spool_max_mb.saturating_mul(1024 * 1024)
}

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
/// heartbeat POSTs, plus the upload thread's stop flag and join handle so a
/// graceful shutdown (#316) can end it with one last drain. Platforms that do
/// not shut down gracefully yet just let the thread die with the process —
/// safe, the spool redelivers.
pub(crate) struct TransportHandle {
    pub(crate) spool: Arc<Mutex<EventSpool>>,
    // Read by the health beacon, which macOS doesn't wire yet (#317).
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub(crate) client: Arc<TransportClient>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // graceful shutdown is Linux-first
    upload_stop: Arc<AtomicBool>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    upload_thread: JoinHandle<()>,
}

impl TransportHandle {
    /// Registers the upload thread with `plan`: stopping it makes the loop
    /// exit its poll/backoff sleep and attempt the final spool drain.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn register_shutdown(self, plan: &mut ShutdownPlan) {
        let stop = self.upload_stop;
        plan.register(
            "transport-upload",
            move || stop.store(true, Ordering::SeqCst),
            self.upload_thread,
        );
    }
}

/// Opens the spool (next to the alerts file — the same "derived, no separate
/// flag" convention as `quarantine/` and the heartbeat file) and starts the
/// upload thread against `server_url`.
pub(crate) fn start(
    server_url: &str,
    alerts: &Path,
    spool_max_bytes: u64,
) -> anyhow::Result<TransportHandle> {
    let dir = alerts.with_file_name("spool");
    let spool = Arc::new(Mutex::new(EventSpool::open(&dir, spool_max_bytes)?));

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
    let upload_stop = upload_loop.stop_handle();
    let upload_thread = std::thread::Builder::new()
        .name("transport-upload".into())
        .spawn(move || upload_loop.run())
        .expect("spawning the transport upload thread");

    Ok(TransportHandle {
        spool,
        client: heartbeat_client,
        upload_stop,
        upload_thread,
    })
}

/// The health beacon's view of the spool (`spool_bytes`/`spool_dropped` in
/// #134's beacon) — replaces `health::NoopSpoolStats` when transport is on.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))] // no health beacon on macOS yet (#317)
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

    #[test]
    fn the_spool_cap_follows_the_configured_mebibytes() {
        assert_eq!(spool_cap_bytes(1), 1024 * 1024);
        assert_eq!(spool_cap_bytes(64), 64 * 1024 * 1024);
        // The documented default, 4096 MiB, is 4 GiB: not the old hard-coded 64 MiB.
        assert_eq!(spool_cap_bytes(4096), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn an_absurd_configured_value_saturates_instead_of_wrapping() {
        assert_eq!(spool_cap_bytes(u64::MAX), u64::MAX);
        assert!(spool_cap_bytes(u64::MAX / 2) > spool_cap_bytes(4096));
    }

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
