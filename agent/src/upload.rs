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
    path::{Path, PathBuf},
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

/// The control plane `run` uploads to: its URL, for one on a private CA the PEM bundle that
/// is the only trust root (#658), and for one that requires mTLS the client certificate and
/// key it presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlPlane<'a> {
    pub(crate) url: &'a str,
    pub(crate) ca_cert: Option<&'a Path>,
    /// `(certificate, key)`, both PEM.
    pub(crate) client_cert: Option<(&'a Path, &'a Path)>,
    /// `server.offline_fallback`: whether a failure to set the upload up (an unreadable
    /// client certificate, a missing CA) lets `run` start without it (see
    /// [`start_or_disable`]) or stops it.
    pub(crate) offline_fallback: bool,
}

impl ControlPlane<'_> {
    fn transport_config(&self) -> TransportConfig {
        let mut config = TransportConfig::new(self.url);
        if let Some(ca_cert) = self.ca_cert {
            config = config.with_ca_cert(ca_cert.to_path_buf());
        }
        if let Some((cert, key)) = self.client_cert {
            config = config.with_client_cert(cert.to_path_buf(), key.to_path_buf());
        }
        config
    }
}

/// Where `run` uploads, resolved from the command line and `agent.toml` and owned, so the
/// borrowed [`ControlPlane`] can be taken from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunTarget {
    url: String,
    ca_cert: Option<PathBuf>,
    client_cert: Option<(PathBuf, PathBuf)>,
    offline_fallback: bool,
}

impl RunTarget {
    /// The borrowed form `start` takes.
    pub(crate) fn control_plane(&self) -> ControlPlane<'_> {
        ControlPlane {
            url: &self.url,
            ca_cert: self.ca_cert.as_deref(),
            client_cert: self
                .client_cert
                .as_ref()
                .map(|(cert, key)| (cert.as_path(), key.as_path())),
            offline_fallback: self.offline_fallback,
        }
    }
}

/// Picks what `agent run` uploads to (#658), or `None` for a standalone agent.
///
/// - `--standalone`: nothing is uploaded, whatever the config says.
/// - `--server` given: exactly that server. It never receives the client certificate from
///   `agent.toml` (the same rule as `apply-content-manifest`: a certificate is a credential
///   and is not handed to a server the operator named by hand); `--cert`/`--key` present one
///   explicitly.
/// - Neither: this install's own control plane, `server.control_plane_url`, with the
///   configured `mtls_cert`/`mtls_key` pair (`--cert`/`--key` override it).
///
/// The CA is a trust anchor and not a credential, so `--ca-cert`, else `server.ca_cert`,
/// applies to either server.
pub(crate) fn resolve_run_target(
    server: Option<String>,
    standalone: bool,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    configured: &config::ServerConfig,
) -> Option<RunTarget> {
    if standalone {
        return None;
    }
    let ca_cert = crate::content::resolve_ca_cert(ca_cert, configured);
    let flagged = cert.zip(key);
    let offline_fallback = configured.offline_fallback;
    Some(match server {
        Some(url) => RunTarget {
            url,
            ca_cert,
            client_cert: flagged,
            offline_fallback,
        },
        None => RunTarget {
            url: configured.control_plane_url.clone(),
            ca_cert,
            offline_fallback,
            client_cert: Some(
                flagged
                    .unwrap_or_else(|| (configured.mtls_cert.clone(), configured.mtls_key.clone())),
            ),
        },
    })
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

/// What [`start_or_disable`] came to.
pub(crate) enum UploadStart {
    /// The spool and the upload threads are running.
    Running(TransportHandle),
    /// Upload could not be set up and the agent runs without it: why. The caller says so
    /// loudly (an alert and the journal); the detection side is untouched.
    Disabled(String),
}

/// [`start`], with the failure policy of `server.offline_fallback`.
///
/// Setting the upload up fails for reasons that are configuration and not the network: an
/// unreadable or passphrase-protected client key, a missing CA bundle, a spool directory
/// that cannot be opened. If that stopped `run`, an agent without its certificates would
/// detect nothing at all (a day-0 install from `bootstrap/` loops on restart forever), and
/// the watchdog, which only sees that the heartbeat never advances, would roll back and ban
/// a release that is otherwise healthy (ADR-0015 probation). So with `offline_fallback`
/// (the default) the agent keeps detecting locally and reports that it is not uploading;
/// with it off, the failure stays fatal, as ADR-0013 describes.
///
/// # Errors
///
/// The error of [`start`] when `offline_fallback` is off.
pub(crate) fn start_or_disable(
    control_plane: &ControlPlane<'_>,
    alerts: &Path,
    spool_max_bytes: u64,
) -> anyhow::Result<UploadStart> {
    match start(control_plane, alerts, spool_max_bytes) {
        Ok(handle) => Ok(UploadStart::Running(handle)),
        Err(error) if control_plane.offline_fallback => Ok(UploadStart::Disabled(format!(
            "not uploading to {}: {error:#}",
            control_plane.url
        ))),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use schema::{
        Event, ExecEvent,
        detection::{Detection, DetectionSource, Severity},
    };

    use super::*;

    #[test]
    fn the_ca_and_the_client_certificate_reach_the_transport_config() {
        let ca = Path::new("/etc/synthaea/certs/ca.pem");
        let (cert, key) = (
            Path::new("/etc/synthaea/certs/client.crt"),
            Path::new("/etc/synthaea/certs/client.key"),
        );
        let full = ControlPlane {
            url: "https://cp.example",
            ca_cert: Some(ca),
            client_cert: Some((cert, key)),
            offline_fallback: true,
        }
        .transport_config();
        assert_eq!(full.ca_cert_path.as_deref(), Some(ca));
        assert_eq!(full.client_cert_path.as_deref(), Some(cert));
        assert_eq!(full.client_key_path.as_deref(), Some(key));

        let bare = ControlPlane {
            url: "https://cp.example",
            ca_cert: None,
            client_cert: None,
            offline_fallback: true,
        }
        .transport_config();
        assert_eq!(bare.ca_cert_path, None);
        assert!(!bare.has_client_cert());
    }

    fn configured() -> config::ServerConfig {
        config::ServerConfig {
            control_plane_url: "https://cp.example".to_string(),
            mtls_cert: PathBuf::from("/etc/synthaea/certs/client.crt"),
            mtls_key: PathBuf::from("/etc/synthaea/certs/client.key"),
            mtls_passphrase: config::SecretRef::Invalid(String::new()),
            ca_cert: Some(PathBuf::from("/etc/synthaea/certs/ca.pem")),
            offline_fallback: true,
        }
    }

    fn pair(cert: &str, key: &str) -> Option<(PathBuf, PathBuf)> {
        Some((PathBuf::from(cert), PathBuf::from(key)))
    }

    #[test]
    fn with_no_flags_run_uploads_to_the_configured_control_plane_with_its_certificates() {
        let target = resolve_run_target(None, false, None, None, None, &configured()).unwrap();
        assert_eq!(target.url, "https://cp.example");
        assert_eq!(
            target.client_cert,
            pair(
                "/etc/synthaea/certs/client.crt",
                "/etc/synthaea/certs/client.key"
            )
        );
        assert_eq!(
            target.ca_cert,
            Some(PathBuf::from("/etc/synthaea/certs/ca.pem"))
        );
    }

    #[test]
    fn standalone_uploads_nothing_whatever_the_config_says() {
        assert_eq!(
            resolve_run_target(None, true, None, None, None, &configured()),
            None
        );
    }

    #[test]
    fn a_server_named_by_hand_never_receives_the_configured_client_certificate() {
        let target = resolve_run_target(
            Some("http://127.0.0.1:8080".into()),
            false,
            None,
            None,
            None,
            &configured(),
        )
        .unwrap();
        assert_eq!(target.url, "http://127.0.0.1:8080");
        assert_eq!(target.client_cert, None);
        // The CA is a trust anchor, not a credential: it still applies.
        assert_eq!(
            target.ca_cert,
            Some(PathBuf::from("/etc/synthaea/certs/ca.pem"))
        );
    }

    #[test]
    fn explicit_certificate_flags_win_for_either_server() {
        let flags = (
            Some(PathBuf::from("/lab/c.crt")),
            Some(PathBuf::from("/lab/c.key")),
        );
        let named = resolve_run_target(
            Some("https://lab".into()),
            false,
            flags.0.clone(),
            flags.1.clone(),
            None,
            &configured(),
        )
        .unwrap();
        assert_eq!(named.client_cert, pair("/lab/c.crt", "/lab/c.key"));
        let own = resolve_run_target(None, false, flags.0, flags.1, None, &configured()).unwrap();
        assert_eq!(own.client_cert, pair("/lab/c.crt", "/lab/c.key"));
    }

    #[test]
    fn the_ca_flag_wins_over_the_configured_ca() {
        let target = resolve_run_target(
            None,
            false,
            None,
            None,
            Some(PathBuf::from("/lab/ca.pem")),
            &configured(),
        )
        .unwrap();
        assert_eq!(target.ca_cert, Some(PathBuf::from("/lab/ca.pem")));
    }

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

    /// A control plane whose client certificate does not exist: setting the upload up fails.
    fn control_plane_with_a_missing_certificate(offline_fallback: bool) -> ControlPlane<'static> {
        ControlPlane {
            url: "https://cp.example",
            ca_cert: None,
            client_cert: Some((
                Path::new("/nonexistent/client.crt"),
                Path::new("/nonexistent/client.key"),
            )),
            offline_fallback,
        }
    }

    #[test]
    fn a_missing_client_certificate_disables_the_upload_when_offline_fallback_is_on() {
        let dir = std::env::temp_dir().join(format!("agent-upload-degrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let started = start_or_disable(
            &control_plane_with_a_missing_certificate(true),
            &dir.join("alerts.ndjson"),
            1 << 20,
        )
        .expect("with offline_fallback the agent still starts");

        let UploadStart::Disabled(reason) = started else {
            panic!("upload cannot be running without its certificate");
        };
        assert!(reason.contains("https://cp.example"), "{reason}");
        assert!(
            reason.contains("client.crt"),
            "the cause is named: {reason}"
        );
    }

    #[test]
    fn a_missing_client_certificate_stops_the_agent_when_offline_fallback_is_off() {
        let dir = std::env::temp_dir().join(format!("agent-upload-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let result = start_or_disable(
            &control_plane_with_a_missing_certificate(false),
            &dir.join("alerts.ndjson"),
            1 << 20,
        );

        assert!(result.is_err(), "offline_fallback = false keeps it fatal");
    }

    #[test]
    fn offline_fallback_comes_from_the_configuration_for_either_server() {
        let mut server = configured();
        server.offline_fallback = false;
        for named in [None, Some("https://lab".to_string())] {
            let target = resolve_run_target(named, false, None, None, None, &server).unwrap();
            assert!(!target.control_plane().offline_fallback);
        }
        server.offline_fallback = true;
        let target = resolve_run_target(None, false, None, None, None, &server).unwrap();
        assert!(target.control_plane().offline_fallback);
    }
}
