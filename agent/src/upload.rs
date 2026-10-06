//! Store-and-forward upload (#24): the `store::EventSpool` → `transport` wiring.
//!
//! The binary is the composition point (CLAUDE.md's dependency direction:
//! `transport` and `store` may not know each other) — this module owns the
//! spool the sink appends to, adapts it to `transport::EventDrain`'s two-phase
//! drain/ack/skip contract, and runs the upload loop on its own thread.
//! Everything here is opt-in behind `run --server <url>`: without a server,
//! nothing is spooled and the agent behaves exactly as before.

use std::{
    fmt::Write as _,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use store::EventSpool;
use transport::{
    DetectionDrain, DetectionUploader, EventDrain, EventUploader, QueuedDetection, TransportClient,
    TransportConfig, UploadLoop,
};

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

struct DetectionSpoolDrain(Arc<Mutex<EventSpool>>);

impl DetectionDrain for DetectionSpoolDrain {
    fn drain(&mut self) -> std::io::Result<Vec<QueuedDetection>> {
        self.0.lock().unwrap().drain_oldest()
    }

    fn ack(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().ack().map(|_| ())
    }

    fn skip(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().skip().map(|_| ())
    }
}

/// Creates the retry identity and persists it atomically with the detection.
/// A recovered segment carries the same identity after a crash.
pub(crate) fn persist_detection(
    spool: &Mutex<EventSpool>,
    detection: schema::detection::Detection,
) -> std::io::Result<()> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to String");
    }
    let key = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    spool
        .lock()
        .unwrap()
        .push(&QueuedDetection { key, detection })
}

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
    pub(crate) detection_spool: Arc<Mutex<EventSpool>>,
    // Read by the health beacon, which macOS doesn't wire yet (#317).
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub(crate) client: Arc<TransportClient>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // graceful shutdown is Linux-first
    upload_stop: Arc<AtomicBool>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    upload_thread: JoinHandle<()>,
    detection_upload_stop: Arc<AtomicBool>,
    detection_upload_thread: JoinHandle<()>,
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
        plan.register(
            "detection-upload",
            move || self.detection_upload_stop.store(true, Ordering::SeqCst),
            self.detection_upload_thread,
        );
    }
}

/// The control plane `run` uploads to: its URL and, for one on a private CA, the PEM
/// bundle that is the only trust root (`--ca-cert`, else `server.ca_cert`; #658).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlPlane<'a> {
    pub(crate) url: &'a str,
    pub(crate) ca_cert: Option<&'a Path>,
}

impl ControlPlane<'_> {
    fn transport_config(&self) -> TransportConfig {
        let config = TransportConfig::new(self.url);
        match self.ca_cert {
            Some(ca_cert) => config.with_ca_cert(ca_cert.to_path_buf()),
            None => config,
        }
    }
}

/// Opens the spool (next to the alerts file — the same "derived, no separate
/// flag" convention as `quarantine/` and the heartbeat file) and starts the
/// upload thread against `server_url`.
///
/// `spool_max_bytes` caps **each** of the two spools (events, and the detection
/// spool beside it), so the worst case on disk is twice `storage.spool_max_mb`.
pub(crate) fn start(
    control_plane: &ControlPlane<'_>,
    alerts: &Path,
    spool_max_bytes: u64,
) -> anyhow::Result<TransportHandle> {
    let dir = alerts.with_file_name("spool");
    let spool = Arc::new(Mutex::new(EventSpool::open(&dir, spool_max_bytes)?));
    let detection_dir = alerts.with_file_name("detection-spool");
    let detection_spool = Arc::new(Mutex::new(EventSpool::open_with_segment_records(
        &detection_dir,
        spool_max_bytes,
        1,
    )?));

    // Two clients on one config: `EventUploader` consumes its client, and the
    // health beacon needs one of its own for heartbeats.
    let config = control_plane.transport_config();
    let upload_client = TransportClient::new(config.clone())
        .map_err(|e| anyhow::anyhow!("transport client: {e}"))?;
    let detection_client = TransportClient::new(config.clone())
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

    let detection_uploader = DetectionUploader::new(
        detection_client,
        DetectionSpoolDrain(Arc::clone(&detection_spool)),
    );
    let mut detection_loop = UploadLoop::new(detection_uploader, UPLOAD_POLL_INTERVAL);
    let detection_upload_stop = detection_loop.stop_handle();
    let detection_upload_thread = std::thread::Builder::new()
        .name("detection-upload".into())
        .spawn(move || detection_loop.run())
        .expect("spawning the detection upload thread");

    Ok(TransportHandle {
        spool,
        detection_spool,
        client: heartbeat_client,
        upload_stop,
        upload_thread,
        detection_upload_stop,
        detection_upload_thread,
    })
}

/// The health beacon's view of the spool (`spool_bytes`/`spool_dropped` in
/// #134's beacon) — replaces `health::NoopSpoolStats` when transport is on.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))] // no health beacon on macOS yet (#317)
pub(crate) struct SpoolHealth {
    pub(crate) events: Arc<Mutex<EventSpool>>,
    pub(crate) detections: Arc<Mutex<EventSpool>>,
}

impl crate::health::SpoolStatsSource for SpoolHealth {
    fn spool_bytes(&self) -> u64 {
        self.events.lock().unwrap().stats().bytes + self.detections.lock().unwrap().stats().bytes
    }

    fn spool_dropped(&self) -> u64 {
        self.events.lock().unwrap().stats().dropped_records
            + self.detections.lock().unwrap().stats().dropped_records
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_configured_ca_reaches_the_transport_config() {
        let ca = Path::new("/etc/synthaea/certs/ca.pem");
        let pinned = ControlPlane {
            url: "https://cp.example",
            ca_cert: Some(ca),
        };
        assert_eq!(pinned.transport_config().ca_cert_path.as_deref(), Some(ca));
        let default = ControlPlane {
            url: "https://cp.example",
            ca_cert: None,
        };
        assert_eq!(default.transport_config().ca_cert_path, None);
    }

    use schema::{
        Event, ExecEvent,
        detection::{Detection, DetectionSource, Severity},
    };

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

    #[test]
    fn detection_retry_key_survives_spool_reopen_until_ack() {
        let dir =
            std::env::temp_dir().join(format!("agent-detection-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let detection = Detection {
            timestamp_ns: 1_700_000_000_000_000_000,
            severity: Severity::High,
            title: "rule hit".into(),
            source: DetectionSource::Rule {
                rule_id: "T1059".into(),
            },
            score: None,
            attributions: Vec::new(),
            techniques: vec!["T1059".into()],
            events: vec![exec("test")],
        };
        let spool = Mutex::new(EventSpool::open(&dir, u64::MAX).unwrap());
        persist_detection(&spool, detection.clone()).unwrap();
        // The persisted record, including its key, is recovered after a crash
        // that happened between drain and acknowledgement.
        let mut first = spool.into_inner().unwrap();
        let original: Vec<QueuedDetection> = first.drain_oldest().unwrap();
        assert_eq!(original.len(), 1);
        assert_eq!(original[0].detection, detection);
        assert_eq!(original[0].key.len(), 36);
        drop(first);
        let mut reopened = EventSpool::open(&dir, u64::MAX).unwrap();
        let retry: Vec<QueuedDetection> = reopened.drain_oldest().unwrap();
        assert_eq!(retry, original);
        assert!(reopened.ack().unwrap());
        let empty: Vec<QueuedDetection> = reopened.drain_oldest().unwrap();
        assert!(empty.is_empty());
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
