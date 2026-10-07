//! The Windows sensor: ETW providers (Kernel-Process, Kernel-Network, Kernel-File)
//! normalized into schema events. Migrated from the old iteration; the provider
//! wiring and its lab-earned notes (`TcpClient` emits no eid=42 — 2026-08-25; PID
//! recycling; orphan named sessions) carry over, the audit findings are fixed here.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender},
    },
};

use ferrisetw::trace::UserTrace;
use schema::{
    ContainerContext, EventMeta,
    sensor::{Capabilities, EventSink, Sensor, SensorError},
};

use crate::{
    amsi, budget, etw_sessions, hcs,
    long_path::{self, LongPathCache},
    normalize,
    pid_cache::PidCache,
    providers::{
        ALL_PROVIDERS, amsi_provider, dns_provider, dotnet_provider, file_provider, ldap_provider,
        network_provider, powershell_provider, process_provider, registry_provider, smb_provider,
        wmi_provider,
    },
    silo::{self, SiloDirectory},
    winapi,
    zone_identifier::{self, MarkQueue, QuarantineDedup},
};

/// Cap for the pid cache. A live host rarely runs more than a few hundred
/// processes; this leaves generous headroom (spawn storms, bursts of short-lived
/// helpers) while bounding memory if `ProcessEnd` events are lost — a documented
/// ETW behavior under buffer pressure, not a theoretical one.
const PID_CACHE_CAP: usize = 16_384;

/// Short-named directories are a small, stable set per host (#489); this is a
/// backstop, not a working-set size.
const LONG_PATH_CACHE_CAP: usize = 4_096;

/// The records of one `Zone.Identifier` write arrive within milliseconds
/// (lab, 2026-09-23); 5s absorbs ETW buffer-flush jitter without merging a
/// genuine re-download of the same path.
const QUARANTINE_DEDUP_WINDOW_NS: u64 = 5_000_000_000;
/// Distinct files marked within one window — a download burst, not a steady
/// state; past it a mark is reported without being deduplicated.
const QUARANTINE_DEDUP_CAP: usize = 1_024;
/// Marks waiting for the read-back worker (#439). A write yields 2-3 records
/// and downloads come at human or script rate, so 256 absorbs a burst of ~100
/// downloads behind one slow read; past it a mark is dropped and counted.
const MARK_QUEUE_CAPACITY: usize = 256;
/// LDAP searches reported per process per window (#364). SharpHound-style
/// collection runs hundreds of searches; the burst rule needs well under
/// this to fire, the cap only bounds a runaway client.
const LDAP_PER_PID_LIMIT: u32 = 128;
const LDAP_PER_PID_WINDOW_NS: u64 = 10_000_000_000;
/// Silos waiting for a container lookup (#371). A full queue loses nothing:
/// the pass already queued probes every container not yet mapped.
const SILO_REQUEST_CAPACITY: usize = 16;

/// Stops an orphaned ETW session. Named sessions are kernel objects that outlive
/// the creating process: after a `taskkill /f` or crash the session stays Running
/// and any restart fails with `AlreadyExist` — without this cleanup the agent
/// could never restart after an unclean shutdown, defeating the watchdog.
fn stop_orphaned_session(name: &str) {
    let out = std::process::Command::new("logman")
        .args(["stop", name, "-ets"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            tracing::info!(
                session = name,
                "orphaned ETW session stopped before startup"
            );
        }
        Ok(_) => {} // no such session — nominal on a clean start
        Err(e) => tracing::warn!(error = %e, "logman unavailable — ETW orphan cleanup skipped"),
    }
}

/// Stops every ETW session we could have orphaned (issue #408), not just the
/// one from the most recent unclean shutdown. The previous mechanism persisted
/// a single session name to a state file and only ever cleaned that one up — a
/// *second* consecutive unclean shutdown overwrote the file before the first
/// orphan was ever stopped, and it accumulated forever (each one a kernel
/// session that keeps costing ETW resources and, per #408's lab observation,
/// may leave a freshly started session receiving zero events).
///
/// Enumerates `logman query -ets` and stops every session matching our fixed
/// `wtrace-` prefix (`normalize::random_session_name`) — no persisted state
/// needed, and it catches every orphan regardless of how many unclean shutdowns
/// preceded this start. See `normalize::parse_orphaned_sessions` for the pure,
/// tested parsing logic.
///
/// Single-instance assumption (Jean's #408 review, non-blocking): this stops
/// every live `wtrace-` session, not just ones this install actually orphaned
/// — correct only as long as at most one agent runs per host. Two instances
/// overlapping even briefly (a watchdog restart racing a slow shutdown, a
/// future Windows self-update swap, a manual `agent run` while the service is
/// up) would have the new instance silently blind the old one's still-live
/// session, which then trips the old instance's own silence watchdog
/// ([`liveness_watch`]). `sensor-windows-etw` depends only on `schema`
/// (workspace dependency rules), so it has no way to ask the agent/watchdog
/// whether another instance is already running — that check, if ever needed,
/// belongs a layer up, not here.
///
/// Also best-effort removes the pre-#408 state file (`synthaea-etw-session`,
/// see the old `session_state_path`) so a host upgraded from that version
/// doesn't keep it around forever — the new mechanism doesn't use it.
fn stop_all_orphaned_sessions() {
    let _ = std::fs::remove_file(std::env::temp_dir().join("synthaea-etw-session"));

    let out = std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output();
    // A failed `logman` (access denied, ETW service trouble) prints no session
    // table, so without the status check it parses as "no orphans" and cleanup is
    // silently skipped — orphans accumulate, which is exactly #408 (same class as
    // the failed-`wevtutil`-reads-as-empty bug in #391).
    match out {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for name in normalize::parse_orphaned_sessions(&stdout) {
                stop_orphaned_session(&name);
            }
        }
        Ok(o) => tracing::warn!(
            status = %o.status,
            stderr = %String::from_utf8_lossy(&o.stderr).trim(),
            "logman query -ets failed — ETW orphan enumeration skipped"
        ),
        Err(e) => tracing::warn!(error = %e, "logman unavailable — ETW orphan enumeration skipped"),
    }
}

/// Stops the session a failed `start_and_process` left behind (#408, see
/// `normalize::start_or_stop_session`). "Not found" is nominal: the failure may
/// have come before `StartTrace` created anything.
fn stop_session_after_failed_start(session: &str) {
    match ferrisetw::trace::stop_trace_by_name(session) {
        Ok(()) => tracing::warn!(
            session,
            "ETW start failed; stopped the session it had created"
        ),
        Err(e) => {
            tracing::debug!(session, error = ?e, "no session to stop after a failed ETW start");
        }
    }
}

/// The liveness error's diagnosis (#408): is our silent session still listed by
/// `logman query -ets` (running but blind) or gone (stopped from outside)? And
/// which foreign sessions enable our providers: a real-time one nobody consumes
/// blinds every real-time consumer on the host (lab, 2026-10-01), so naming it
/// is what the operator needs to act.
fn silent_session_diagnosis(session: &str) -> String {
    let output = std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    let state = normalize::describe_silent_session(session, output.as_deref());

    let sessions = etw_sessions::running_sessions();
    let enablements: Vec<normalize::ProviderEnablement> =
        etw_sessions::provider_enablements(&ALL_PROVIDERS)
            .into_iter()
            .filter_map(|(provider, logger_id, level, match_any_keyword)| {
                let (_, stats) = sessions.iter().find(|(id, _)| *id == logger_id)?;
                Some(normalize::ProviderEnablement {
                    provider,
                    session: stats.name.clone(),
                    level,
                    match_any_keyword,
                })
            })
            .collect();
    let stats: Vec<normalize::SessionStats> = sessions.into_iter().map(|(_, s)| s).collect();
    state + &normalize::describe_foreign_sessions(session, &enablements, &stats)
}

// ── Shared state between provider callbacks ──────────────────────────────────

pub(crate) struct SharedState {
    /// pid → full image path; populated by seed + `ProcessStart`, pruned on
    /// `ProcessEnd` (PID recycling), bounded as a backstop (see [`PidCache`]).
    pub(crate) pids: Mutex<PidCache>,
    /// F-5: live device→drive map, refreshed on normalization misses.
    pub(crate) volumes: Mutex<HashMap<String, String>>,
    /// #489: short-form directory → long form, so one file has one path.
    pub(crate) long_paths: Mutex<LongPathCache>,
    /// F-7: Connect/Send dedup.
    pub(crate) dedup: Mutex<normalize::ConnectDedup>,
    /// #365/#439: `Zone.Identifier` writes, queued for the read-back worker
    /// (which owns the one-`FileQuarantine`-per-write dedup).
    pub(crate) marks: MarkQueue,
    /// F-2: events observed — the silence watchdog reads this.
    pub(crate) events_seen: AtomicU64,
    /// AMSI volume gate (#282): dedup + per-process budget.
    pub(crate) amsi: Mutex<amsi::AmsiGate>,
    /// LDAP search budget (#364): per process, no dedup (the burst rule
    /// counts distinct searches).
    pub(crate) ldap: Mutex<budget::PidBudget>,
    /// #371: server silo → container, shared with the lookup thread.
    pub(crate) silos: Arc<Mutex<SiloDirectory>>,
    /// Silos the lookup thread should name.
    silo_requests: SyncSender<u32>,
    /// The liveness canary file: the run loop touches it every heartbeat, which
    /// MUST produce a Kernel-File event (our pid is tracked) — so sensor liveness
    /// is deterministic instead of traffic-dependent (a quiet host produces no
    /// guaranteed events in 30s; review finding on #100). Canary events are
    /// filtered from emission below.
    pub(crate) canary_path: String,
}

impl SharedState {
    /// The identity of the process an event is about: its token user (F-3)
    /// and its container (#371).
    pub(crate) fn meta(&self, pid: u32, ppid: u32, comm: String, timestamp_ns: u64) -> EventMeta {
        EventMeta {
            pid,
            ppid,
            // F-3: real token identity; Unknown when the process is gone/protected.
            user: winapi::read_process_user(pid),
            timestamp_ns,
            comm,
            container: self.container_of(pid, timestamp_ns),
            process_generation: None,
            parent_process_generation: None,
        }
    }

    /// `None` for a host process and for a pid whose silo was never read.
    fn container_of(&self, pid: u32, now_ns: u64) -> Option<ContainerContext> {
        let silo = self
            .pids
            .lock()
            .unwrap()
            .silo(pid)
            .filter(|&silo| silo != 0)?;
        let (context, ask) = self.silos.lock().unwrap().lookup(silo, now_ns);
        if ask {
            let _ = self.silo_requests.try_send(silo);
        }
        Some(context)
    }

    pub(crate) fn normalize_path(&self, raw: &str) -> String {
        let dos = self.to_dos_path(raw);
        long_path::expand(&dos, &self.long_paths, winapi::long_path_name)
    }

    fn to_dos_path(&self, raw: &str) -> String {
        let normalized = normalize::normalize_nt_path(raw, &self.volumes.lock().unwrap());
        if normalized.starts_with(r"\Device\") {
            // Unknown device: refresh the map once (a newly mounted volume) and retry.
            let fresh = winapi::build_volume_map();
            let mut volumes = self.volumes.lock().unwrap();
            *volumes = fresh;
            return normalize::normalize_nt_path(raw, &volumes);
        }
        normalized
    }

    pub(crate) fn comm_for(&self, pid: u32) -> Option<String> {
        let cached = {
            let mut pids = self.pids.lock().unwrap();
            pids.get(pid).map(str::to_owned)
        };
        let path = match cached {
            Some(p) => p,
            None => {
                // ETW race: ConnectEvent before the ExecEvent populated the store.
                let resolved = winapi::resolve_pid_live(pid)?;
                let silo = winapi::read_server_silo_id(pid);
                self.pids
                    .lock()
                    .unwrap()
                    .insert(pid, resolved.clone(), silo);
                resolved
            }
        };
        Some(basename(&path))
    }
}

pub(crate) fn basename(path: &str) -> String {
    path.rsplit('\\').next().unwrap_or(path).to_string()
}

/// Starts the `Zone.Identifier` read-back worker (#439). It exits by itself
/// once every [`MarkQueue`] sender is gone, i.e. when the trace's callbacks and
/// this run's [`SharedState`] are dropped, so it is not joined.
fn spawn_mark_reader(
    marks: std::sync::mpsc::Receiver<zone_identifier::MarkWrite>,
    sink: Arc<dyn EventSink>,
) -> Result<(), SensorError> {
    std::thread::Builder::new()
        .name("zone-identifier-reader".into())
        .spawn(move || {
            zone_identifier::run_mark_reader(
                &marks,
                zone_identifier::read_stream,
                QuarantineDedup::new(QUARANTINE_DEDUP_WINDOW_NS, QUARANTINE_DEDUP_CAP),
                |event| sink.on_event(event),
            );
        })
        .map(drop)
        .map_err(|e| -> SensorError { format!("Zone.Identifier reader thread: {e}").into() })
}

/// Starts the container lookup worker (#371). Like the mark reader, it exits
/// by itself once this run's [`SharedState`] (the only request sender) is
/// dropped.
fn spawn_silo_resolver(
    requests: Receiver<u32>,
    directory: Arc<Mutex<SiloDirectory>>,
) -> Result<(), SensorError> {
    std::thread::Builder::new()
        .name("silo-resolver".into())
        .spawn(move || {
            silo::run_resolver(&requests, &directory, &hcs::Hcs::default(), probe_silo);
        })
        .map(drop)
        .map_err(|e| -> SensorError { format!("silo resolver thread: {e}").into() })
}

/// The silo of `pid` if it still runs `image` (the Host Compute Service's view
/// of it); see [`silo::match_containers`] for why the image is checked.
fn probe_silo(pid: u32, image: &str) -> Option<u32> {
    let live = winapi::resolve_pid_live(pid)?;
    if !basename(&live).eq_ignore_ascii_case(&basename(image)) {
        return None;
    }
    winapi::read_server_silo_id(pid)
}

/// Seeds the pid store before the trace: already-running processes resolve from
/// the very first `ConnectEvent`, and parent lineage/exclusions apply to them.
fn seed_pid_store(state: &SharedState) {
    let mut pids = state.pids.lock().unwrap();
    for (pid, name) in winapi::snapshot_processes() {
        pids.insert(pid, name, winapi::read_server_silo_id(pid));
    }
    tracing::info!(processes = pids.len(), "pid store seeded");
}

/// F-2: a freshly randomized session name for this run — anti-fingerprinting of
/// the session *name*, see `normalize::random_session_name`. Caller is
/// responsible for orphan cleanup first (`stop_all_orphaned_sessions`); no state
/// is persisted between runs, unlike the old per-name file (issue #408).
fn new_session_name() -> String {
    normalize::random_session_name(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id(),
    )
}

/// F-2: the silence watchdog, made deterministic by a canary: every heartbeat the
/// loop touches our own temp file, which MUST produce a Kernel-File event (our pid
/// is tracked and create-dispositions pass the filter). A healthy-but-idle host
/// therefore still advances the counter — only a trace actually stopped out from
/// under us (logman by an attacker) freezes it, and that is a loud sensor error
/// the watchdog restarts.
fn liveness_watch(
    stop: &AtomicBool,
    state: &SharedState,
    canary_file: &std::path::Path,
    session: &str,
) -> Result<(), SensorError> {
    let mut last_seen = state.events_seen.load(Ordering::Relaxed);
    let mut silent_intervals = 0u32;
    while !stop.load(Ordering::SeqCst) {
        let _ = std::fs::write(canary_file, b"synthaea liveness canary");
        std::thread::sleep(std::time::Duration::from_millis(2_000));
        let seen = state.events_seen.load(Ordering::Relaxed);
        if seen == last_seen {
            silent_intervals += 1;
            // 15 × 2s = 30s with zero events despite the canary writes.
            if silent_intervals >= 15 {
                return Err(format!(
                    "sensor produced no events for 30s despite liveness canary \
                     writes: {}",
                    silent_session_diagnosis(session)
                )
                .into());
            }
        } else {
            silent_intervals = 0;
            last_seen = seen;
        }
    }
    Ok(())
}

// ── The sensor ───────────────────────────────────────────────────────────────

/// The Windows ETW sensor: owns the trace session and consumer thread, and
/// implements `schema::sensor::Sensor` (see the crate doc for provider coverage).
pub struct WindowsSensor {
    stop: Arc<AtomicBool>,
}

impl WindowsSensor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shared stop flag for a ctrlc handler on another thread.
    #[must_use]
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }
}

impl Default for WindowsSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for WindowsSensor {
    fn name(&self) -> &str {
        "windows-etw"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            exec_events: true,
            file_events: true,
            connect_events: true,
            user_attribution: true, // F-3: token SID + integrity level
            parent_lineage: true,   // parent path/comm resolved at exec time
            // ETW (this sensor) only covers Kernel-Process/File/Network — it
            // doesn't emit logon/auth events. That's `sensor-windows-eventlog`'s
            // job (#94, Security 4624/4625/4648/4672 via wevtutil polling).
            auth_events: false,
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        self.stop.store(false, Ordering::SeqCst);
        let sink: Arc<dyn EventSink> = Arc::from(sink);

        let canary_file =
            std::env::temp_dir().join(format!("synthaea-canary-{}", std::process::id()));
        let (marks, mark_rx) = MarkQueue::bounded(MARK_QUEUE_CAPACITY);
        spawn_mark_reader(mark_rx, Arc::clone(&sink))?;
        let silos = Arc::new(Mutex::new(SiloDirectory::new()));
        let (silo_requests, silo_rx) = std::sync::mpsc::sync_channel(SILO_REQUEST_CAPACITY);
        spawn_silo_resolver(silo_rx, Arc::clone(&silos))?;
        let state = Arc::new(SharedState {
            pids: Mutex::new(PidCache::new(PID_CACHE_CAP)),
            volumes: Mutex::new(winapi::build_volume_map()),
            long_paths: Mutex::new(LongPathCache::new(LONG_PATH_CACHE_CAP)),
            dedup: Mutex::new(normalize::ConnectDedup::new(60_000_000_000)),
            marks,
            events_seen: AtomicU64::new(0),
            amsi: Mutex::new(amsi::AmsiGate::default()),
            ldap: Mutex::new(budget::PidBudget::new(
                "ldap",
                LDAP_PER_PID_LIMIT,
                LDAP_PER_PID_WINDOW_NS,
            )),
            silos,
            silo_requests,
            canary_path: canary_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        });

        seed_pid_store(&state);

        stop_all_orphaned_sessions();
        let session = new_session_name();

        let builder = UserTrace::new()
            .named(session.clone())
            .enable(process_provider(sink.clone(), state.clone()))
            .enable(network_provider(sink.clone(), state.clone()))
            .enable(file_provider(sink.clone(), state.clone()))
            .enable(dns_provider(sink.clone(), state.clone()))
            .enable(registry_provider(sink.clone(), state.clone()))
            .enable(powershell_provider(sink.clone(), state.clone()))
            .enable(wmi_provider(sink.clone(), state.clone()))
            .enable(dotnet_provider(sink.clone(), state.clone()))
            .enable(smb_provider(sink.clone(), state.clone()))
            .enable(amsi_provider(sink.clone(), state.clone()))
            .enable(ldap_provider(sink, state.clone()));
        let trace = normalize::start_or_stop_session(
            &session,
            || builder.start_and_process(),
            stop_session_after_failed_start,
        )
        .map_err(|e| -> SensorError { format!("ETW startup error: {e:?}").into() })?;

        let result = liveness_watch(&self.stop, &state, &canary_file, &session);

        let _ = trace.stop();
        let _ = std::fs::remove_file(&canary_file);
        result
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}
