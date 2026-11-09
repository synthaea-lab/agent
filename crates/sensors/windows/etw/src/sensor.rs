//! The Windows sensor: ETW providers (Kernel-Process, Kernel-Network, Kernel-File)
//! normalized into schema events. Migrated from the old iteration; the provider
//! wiring and its lab-earned notes (`TcpClient` emits no eid=42 — 2026-08-25; PID
//! recycling; orphan named sessions) carry over, the audit findings are fixed here.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{Receiver, SyncSender},
};

use ferrisetw::trace::UserTrace;
use schema::{
    ContainerContext, EventMeta,
    sensor::{Capabilities, EventSink, Sensor, SensorError},
};

use crate::{
    amsi,
    bits::BitsJobs,
    budget, cross_process, etw_sessions, hcs, normalize,
    path_normalizer::PathNormalizer,
    pid_cache::PidCache,
    providers::{
        ALL_PROVIDERS, amsi_provider, audit_api_provider, bits_provider, dns_provider,
        dotnet_provider, file_provider, ldap_provider, network_provider, ntlm_provider,
        powershell_provider, process_provider, registry_provider, smb_provider, wmi_provider,
    },
    silo::{self, SiloDirectory},
    sync::LockExt,
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
/// Silos waiting for a container lookup (<https://github.com/synthaea-lab/agent/issues/39>). A full queue loses nothing:
/// the pass already queued maps every pending silo, and a dropped request is
/// asked again on that silo's next event.
const SILO_REQUEST_CAPACITY: usize = 16;
/// An identical NTLM authentication (direction, account, target, address, version) is
/// reported once per this window (#364): most come from pid 4, so there is no per-process
/// budget.
const NTLM_DEDUP_WINDOW_NS: u64 = 60_000_000_000;
/// One remote thread is reported per (creator, owner) pair per window (<https://github.com/synthaea-lab/agent/issues/41>): an injector
/// that starts many threads in one target is one fact, and #715 found no dominant pair on
/// an idle host, so the window only bounds a repeat.
const REMOTE_THREAD_DEDUP_WINDOW_NS: u64 = 60_000_000_000;
/// Remote threads reported per creating process per window (<https://github.com/synthaea-lab/agent/issues/41>): one process starting
/// threads in many targets (a debugger attaching widely, a spray) is capped, counted.
const REMOTE_THREAD_PER_PID_LIMIT: u32 = 32;
const REMOTE_THREAD_PER_PID_WINDOW_NS: u64 = 10_000_000_000;
/// An identical open of LSASS (caller, access mask, status) is reported once per window
/// (<https://github.com/synthaea-lab/agent/issues/41>): security products and the service host re-open it on a schedule.
const LSASS_OPEN_DEDUP_WINDOW_NS: u64 = 60_000_000_000;

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
/// Enumerates `logman query -ets` and stops every session matching our session
/// prefix ([`EtwNames::session_prefix`], `normalize::random_session_name`) — no persisted state
/// needed, and it catches every orphan regardless of how many unclean shutdowns
/// preceded this start. See `normalize::parse_orphaned_sessions` for the pure,
/// tested parsing logic.
///
/// Single-instance assumption (Jean's #408 review, non-blocking): this stops
/// every live session under the prefix, not just ones this install actually orphaned
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
fn stop_all_orphaned_sessions(prefix: &str) {
    let _ = std::fs::remove_file(std::env::temp_dir().join("synthaea-etw-session"));
    match etw_sessions::running_sessions() {
        Ok(snapshot) => {
            tracing::info!(
                source = "QueryAllTracesW",
                "ETW orphan enumeration succeeded"
            );
            let sessions: Vec<normalize::SessionStats> = snapshot
                .entries
                .into_iter()
                .map(|(_, stats)| stats)
                .collect();
            let selected = normalize::select_orphaned_sessions(
                &sessions,
                prefix,
                etw_sessions::MAX_SESSIONS,
                snapshot.possibly_truncated,
            );
            for name in selected.names {
                stop_orphaned_session(&name);
            }
            if selected.possibly_truncated {
                tracing::warn!(
                    limit = etw_sessions::MAX_SESSIONS,
                    "QueryAllTracesW returned a full session list; checking logman for orphans beyond it"
                );
                stop_orphans_via_logman(prefix);
            }
        }
        Err(status) => {
            tracing::warn!(
                status,
                "QueryAllTracesW failed; falling back to logman for ETW orphan enumeration"
            );
            stop_orphans_via_logman(prefix);
        }
    }
}

/// Enumerates `logman query -ets` and stops every session under `prefix` in it. Used when
/// `QueryAllTracesW` fails, and when its list is full and may hide some (a session
/// the native pass already stopped is "not found" here, which is nominal).
fn stop_orphans_via_logman(prefix: &str) {
    let out = std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            tracing::info!(
                source = "logman",
                "ETW orphan enumeration succeeded via fallback"
            );
            let stdout = String::from_utf8_lossy(&o.stdout);
            for name in normalize::parse_orphaned_sessions(&stdout, prefix) {
                stop_orphaned_session(&name);
            }
        }
        Ok(o) => tracing::warn!(
            status = %o.status,
            stderr = %String::from_utf8_lossy(&o.stderr).trim(),
            "logman query -ets fallback failed — ETW orphan enumeration skipped"
        ),
        Err(e) => {
            tracing::warn!(error = %e, "logman unavailable — ETW orphan enumeration skipped");
        }
    }
}

/// `logman query -ets` output, `None` when it cannot be run or fails.
fn logman_listing() -> Option<String> {
    std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
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
fn silent_session_diagnosis(session: &str, prefix: &str) -> String {
    let (sessions, state) = match etw_sessions::running_sessions() {
        Ok(snapshot) => {
            if snapshot.possibly_truncated {
                tracing::warn!(
                    limit = etw_sessions::MAX_SESSIONS,
                    "QueryAllTracesW session list may be truncated during blind-session diagnosis"
                );
            }
            tracing::info!(
                source = "QueryAllTracesW",
                "ETW blind-session diagnosis enumerated sessions"
            );
            let sessions = snapshot.entries;
            let names: Vec<&str> = sessions
                .iter()
                .map(|(_, stats)| stats.name.as_str())
                .collect();
            let state =
                if normalize::listing_is_conclusive(snapshot.possibly_truncated, &names, session) {
                    normalize::describe_silent_session(session, prefix, Some(&names.join("\n")))
                } else {
                    // A full list without our session: it may be one of those not
                    // returned, so "stopped from outside" would be a guess. Ask logman;
                    // if that fails too, the state is unknown.
                    normalize::describe_silent_session(session, prefix, logman_listing().as_deref())
                };
            (sessions, state)
        }
        Err(status) => {
            tracing::warn!(
                status,
                "QueryAllTracesW failed during blind-session diagnosis; falling back to logman"
            );
            let output = logman_listing();
            let state = normalize::describe_silent_session(session, prefix, output.as_deref());
            (Vec::new(), state)
        }
    };
    let own_losses = sessions
        .iter()
        .find(|(_, stats)| stats.name == session)
        .map(|(_, stats)| normalize::describe_session_losses(stats))
        .unwrap_or_else(|| "loss counters unavailable".to_string());
    let state = format!("{state}; own session ETW losses: {own_losses}");

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
    /// F-5 + #489: device→drive map and short→long directory cache, so one
    /// file has one path.
    paths: PathNormalizer,
    /// F-7: Connect/Send dedup.
    pub(crate) dedup: Mutex<normalize::ConnectDedup>,
    /// #365/#439: `Zone.Identifier` writes, queued for the read-back worker
    /// (which owns the one-`FileQuarantine`-per-write dedup).
    pub(crate) marks: MarkQueue,
    /// #284: BITS jobs in flight, between their file-added record and their
    /// last one.
    pub(crate) bits: Mutex<BitsJobs>,
    /// F-2: events observed — the silence watchdog reads this.
    pub(crate) events_seen: AtomicU64,
    /// AMSI volume gate (#282): dedup + per-process budget.
    pub(crate) amsi: Mutex<amsi::AmsiGate>,
    /// LDAP search budget (#364): per process, no dedup (the burst rule
    /// counts distinct searches).
    pub(crate) ldap: Mutex<budget::PidBudget>,
    /// <https://github.com/synthaea-lab/agent/issues/39>: server silo → container, shared with the lookup thread.
    pub(crate) silos: Arc<Mutex<SiloDirectory>>,
    /// Silos the lookup thread should name.
    silo_requests: SyncSender<u32>,
    /// NTLM dedup (#364): one event per (direction, account, target,
    /// address, version) per minute.
    pub(crate) ntlm: Mutex<budget::KeyDedup>,
    /// <https://github.com/synthaea-lab/agent/issues/41>: which cross-process thread starts are a new process's initial thread.
    pub(crate) threads: Mutex<cross_process::ThreadOrigins>,
    /// <https://github.com/synthaea-lab/agent/issues/41>: remote threads, one per (creator, owner) per minute.
    pub(crate) remote_threads: Mutex<budget::KeyDedup>,
    /// <https://github.com/synthaea-lab/agent/issues/41>: remote threads, per creating process.
    pub(crate) remote_thread_budget: Mutex<budget::PidBudget>,
    /// <https://github.com/synthaea-lab/agent/issues/41>: LSASS's pid, 0 until found. Only ever a process
    /// `cross_process::is_system_lsass` confirmed.
    pub(crate) lsass: cross_process::LsassTracker,
    /// <https://github.com/synthaea-lab/agent/issues/41>: opens of LSASS, one per (caller, mask, status) per minute.
    pub(crate) lsass_opens: Mutex<budget::KeyDedup>,
    /// `%SystemRoot%` (`C:\Windows`), where LSASS's image is looked for.
    pub(crate) system_root: String,
    /// The liveness canary file: the run loop touches it every heartbeat, which
    /// MUST produce a Kernel-File event (our pid is tracked) — so sensor liveness
    /// is deterministic instead of traffic-dependent (a quiet host produces no
    /// guaranteed events in 30s; review finding on #100). Canary events are
    /// filtered from emission below.
    pub(crate) canary_path: String,
}

impl SharedState {
    /// The identity of the process an event is about: its token user (F-3),
    /// its container (<https://github.com/synthaea-lab/agent/issues/39>) and the incarnation stamps of it and its parent
    /// (#725), as the pid store recorded them. `ppid` 0 (an event that names no parent) has no stamp.
    pub(crate) fn meta(&self, pid: u32, ppid: u32, comm: String, timestamp_ns: u64) -> EventMeta {
        let (process_generation, parent_process_generation) = {
            let pids = self.pids.lock_or_recover();
            let parent = if ppid == 0 {
                None
            } else {
                pids.generation(ppid)
            };
            (pids.generation(pid), parent)
        };
        EventMeta {
            pid,
            ppid,
            // F-3: real token identity; Unknown when the process is gone/protected.
            user: winapi::read_process_user(pid),
            timestamp_ns,
            comm,
            container: self.container_of(pid, timestamp_ns),
            process_generation,
            parent_process_generation,
        }
    }

    /// `None` for a host process and for a pid whose silo was never read.
    fn container_of(&self, pid: u32, now_ns: u64) -> Option<ContainerContext> {
        let silo = self
            .pids
            .lock_or_recover()
            .silo(pid)
            .filter(|&silo| silo != 0)?;
        let mut silos = self.silos.lock_or_recover();
        let (context, ask) = silos.lookup(silo, now_ns);
        if ask && self.silo_requests.try_send(silo).is_err() {
            silos.request_dropped(silo);
        }
        Some(context)
    }

    pub(crate) fn normalize_path(&self, raw: &str) -> String {
        self.paths.normalize(raw)
    }

    pub(crate) fn comm_for(&self, pid: u32) -> Option<String> {
        let cached = {
            let mut pids = self.pids.lock_or_recover();
            pids.get(pid).map(str::to_owned)
        };
        let path = match cached {
            Some(p) => p,
            None => {
                // ETW race: ConnectEvent before the ExecEvent populated the store.
                let resolved = winapi::resolve_pid_live(pid)?;
                let generation = winapi::read_process_sequence_number(pid);
                let silo = winapi::read_server_silo_id(pid);
                self.pids
                    .lock_or_recover()
                    .insert(pid, resolved.clone(), generation, silo);
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

/// Starts the container lookup worker (<https://github.com/synthaea-lab/agent/issues/39>). Like the mark reader, it exits
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
    let mut pids = state.pids.lock_or_recover();
    for winapi::ProcessEntry { pid, name, .. } in winapi::snapshot_processes() {
        pids.insert(
            pid,
            name,
            winapi::read_process_sequence_number(pid),
            winapi::read_server_silo_id(pid),
        );
    }
    tracing::info!(processes = pids.len(), "pid store seeded");
}

/// <https://github.com/synthaea-lab/agent/issues/41>: the pid of the system's LSASS among the running processes, found by name and
/// confirmed by `cross_process::is_system_lsass` (its full image path, session 0, wininit
/// as its parent), so neither an `lsass.exe` started from elsewhere nor a copy of the real
/// file started by hand is taken for it. Called at start and when the tracked LSASS ends.
/// 0 when none is found: opens of LSASS are then not reported until a `ProcessStart` of
/// the real one (a reboot) sets it.
pub(crate) fn find_lsass(state: &SharedState) -> u32 {
    let processes = winapi::snapshot_processes();
    let found = processes
        .iter()
        .filter(|entry| entry.name.eq_ignore_ascii_case("lsass.exe"))
        .find(|entry| {
            let Some(image_path) = winapi::resolve_pid_live(entry.pid) else {
                return false;
            };
            let parent_image_path = winapi::resolve_pid_live(entry.parent_pid);
            let claim = cross_process::LsassClaim {
                image_path: &image_path,
                session_id: winapi::process_session_id(entry.pid),
                parent_image_path: parent_image_path.as_deref(),
            };
            cross_process::is_system_lsass(&claim, &state.system_root)
        })
        .map(|entry| entry.pid);
    match found {
        Some(pid) => tracing::info!(pid, "LSASS found: opens of it are watched"),
        None => tracing::warn!(
            system_root = %state.system_root,
            "system LSASS not found: opens of it are not reported"
        ),
    }
    found.unwrap_or(0)
}

/// F-2: a freshly randomized session name for this run — anti-fingerprinting of
/// the session *name*, see `normalize::random_session_name`. Caller is
/// responsible for orphan cleanup first (`stop_all_orphaned_sessions`); no state
/// is persisted between runs, unlike the old per-name file (issue #408).
fn new_session_name(prefix: &str) -> String {
    normalize::random_session_name(
        prefix,
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
    prefix: &str,
) -> Result<(), SensorError> {
    let mut last_seen = state.events_seen.load(Ordering::Relaxed);
    let mut silent_intervals = 0u32;
    while !stop.load(Ordering::SeqCst) {
        let _ = std::fs::write(canary_file, b"liveness canary");
        std::thread::sleep(std::time::Duration::from_millis(2_000));
        let seen = state.events_seen.load(Ordering::Relaxed);
        if seen == last_seen {
            silent_intervals += 1;
            // 15 × 2s = 30s with zero events despite the canary writes.
            if silent_intervals >= 15 {
                return Err(format!(
                    "sensor produced no events for 30s despite liveness canary \
                     writes: {}",
                    silent_session_diagnosis(session, prefix)
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

/// The names the sensor leaves on the host, chosen by the agent (#596): this
/// crate depends only on `schema`, so it cannot read the agent's identity
/// constants itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwNames {
    /// Prefix of every session name; a random suffix follows it per start.
    /// Startup stops every running session under it as an orphan (#408), so it
    /// must stay the same from one start to the next on a host.
    pub session_prefix: String,
    /// Prefix of the liveness canary file in the temp directory; the process
    /// id follows it.
    pub canary_prefix: String,
}

/// The Windows ETW sensor: owns the trace session and consumer thread, and
/// implements `schema::sensor::Sensor` (see the crate doc for provider coverage).
pub struct WindowsSensor {
    stop: Arc<AtomicBool>,
    names: EtwNames,
}

impl WindowsSensor {
    #[must_use]
    pub fn new(names: EtwNames) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            names,
        }
    }

    /// Shared stop flag for a ctrlc handler on another thread.
    #[must_use]
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
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

        let canary_file = std::env::temp_dir().join(format!(
            "{}{}",
            self.names.canary_prefix,
            std::process::id()
        ));
        let (marks, mark_rx) = MarkQueue::bounded(MARK_QUEUE_CAPACITY);
        spawn_mark_reader(mark_rx, Arc::clone(&sink))?;
        let silos = Arc::new(Mutex::new(SiloDirectory::new()));
        let (silo_requests, silo_rx) = std::sync::mpsc::sync_channel(SILO_REQUEST_CAPACITY);
        spawn_silo_resolver(silo_rx, Arc::clone(&silos))?;
        let state = Arc::new(SharedState {
            pids: Mutex::new(PidCache::new(PID_CACHE_CAP)),
            paths: PathNormalizer::new(
                winapi::build_volume_map,
                winapi::long_path_name,
                LONG_PATH_CACHE_CAP,
            ),
            dedup: Mutex::new(normalize::ConnectDedup::new(60_000_000_000)),
            marks,
            bits: Mutex::new(BitsJobs::default()),
            events_seen: AtomicU64::new(0),
            amsi: Mutex::new(amsi::AmsiGate::default()),
            ldap: Mutex::new(budget::PidBudget::new(
                "ldap",
                LDAP_PER_PID_LIMIT,
                LDAP_PER_PID_WINDOW_NS,
            )),
            silos,
            silo_requests,
            ntlm: Mutex::new(budget::KeyDedup::new("ntlm", NTLM_DEDUP_WINDOW_NS)),
            threads: Mutex::new(cross_process::ThreadOrigins::default()),
            remote_threads: Mutex::new(budget::KeyDedup::new(
                "remote-thread",
                REMOTE_THREAD_DEDUP_WINDOW_NS,
            )),
            remote_thread_budget: Mutex::new(budget::PidBudget::new(
                "remote-thread",
                REMOTE_THREAD_PER_PID_LIMIT,
                REMOTE_THREAD_PER_PID_WINDOW_NS,
            )),
            lsass: cross_process::LsassTracker::default(),
            lsass_opens: Mutex::new(budget::KeyDedup::new(
                "lsass-open",
                LSASS_OPEN_DEDUP_WINDOW_NS,
            )),
            system_root: std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
            canary_path: canary_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        });

        seed_pid_store(&state);
        state.lsass.set(find_lsass(&state));

        let prefix = self.names.session_prefix.as_str();
        stop_all_orphaned_sessions(prefix);
        let session = new_session_name(prefix);

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
            .enable(bits_provider(sink.clone(), state.clone()))
            .enable(ldap_provider(sink.clone(), state.clone()))
            .enable(ntlm_provider(sink.clone(), state.clone()))
            .enable(audit_api_provider(sink, state.clone()));
        let trace = normalize::start_or_stop_session(
            &session,
            || builder.start_and_process(),
            stop_session_after_failed_start,
        )
        .map_err(|e| -> SensorError { format!("ETW startup error: {e:?}").into() })?;

        let result = liveness_watch(&self.stop, &state, &canary_file, &session, prefix);

        let _ = trace.stop();
        let _ = std::fs::remove_file(&canary_file);
        result
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}
