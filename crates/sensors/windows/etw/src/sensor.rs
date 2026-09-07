//! The Windows sensor: ETW providers (Kernel-Process, Kernel-Network, Kernel-File)
//! normalized into schema events. Migrated from the old iteration; the provider
//! wiring and its lab-earned notes (`TcpClient` emits no eid=42 — 2026-08-25; PID
//! recycling; orphan named sessions) carry over, the audit findings are fixed here.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use ferrisetw::trace::UserTrace;
use schema::{
    EventMeta,
    sensor::{Capabilities, EventSink, Sensor, SensorError},
};

use crate::providers::{
    dns_provider, file_provider, network_provider, powershell_provider, process_provider,
    registry_provider, wmi_provider,
};
use crate::{normalize, winapi};

/// Where the previous session's randomized name is persisted, so orphan cleanup
/// after a crash still works despite F-2's name randomization.
fn session_state_path() -> std::path::PathBuf {
    std::env::temp_dir().join("synthaea-etw-session")
}

/// Stops an orphaned ETW session, if one exists. Named sessions are kernel objects
/// that outlive the creating process: after a `taskkill /f` or crash the session
/// stays Running and any restart fails with `AlreadyExist` — without this cleanup the
/// agent could never restart after an unclean shutdown, defeating the watchdog.
fn stop_orphaned_session(name: &str) {
    let out = std::process::Command::new("logman")
        .args(["stop", name, "-ets"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            log::info!("orphaned ETW session {name} stopped before startup");
        }
        Ok(_) => {} // no such session — nominal on a clean start
        Err(e) => log::warn!("logman unavailable ({e}) — ETW orphan cleanup skipped"),
    }
}

// ── Shared state between provider callbacks ──────────────────────────────────

pub(crate) struct SharedState {
    /// pid → full image path; populated by seed + `ProcessStart`, pruned on
    /// `ProcessEnd` (PID recycling).
    pub(crate) pids: Mutex<HashMap<u32, String>>,
    /// F-5: live device→drive map, refreshed on normalization misses.
    pub(crate) volumes: Mutex<HashMap<String, String>>,
    /// F-7: Connect/Send dedup.
    pub(crate) dedup: Mutex<normalize::ConnectDedup>,
    /// F-2: events observed — the silence watchdog reads this.
    pub(crate) events_seen: AtomicU64,
    /// The liveness canary file: the run loop touches it every heartbeat, which
    /// MUST produce a Kernel-File event (our pid is tracked) — so sensor liveness
    /// is deterministic instead of traffic-dependent (a quiet host produces no
    /// guaranteed events in 30s; review finding on #100). Canary events are
    /// filtered from emission below.
    pub(crate) canary_path: String,
}

impl SharedState {
    pub(crate) fn normalize_path(&self, raw: &str) -> String {
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
            let pids = self.pids.lock().unwrap();
            pids.get(&pid).cloned()
        };
        let path = match cached {
            Some(p) => p,
            None => {
                // ETW race: ConnectEvent before the ExecEvent populated the store.
                let resolved = winapi::resolve_pid_live(pid)?;
                self.pids.lock().unwrap().insert(pid, resolved.clone());
                resolved
            }
        };
        Some(basename(&path))
    }
}

pub(crate) fn basename(path: &str) -> String {
    path.rsplit('\\').next().unwrap_or(path).to_string()
}

pub(crate) fn meta(pid: u32, ppid: u32, comm: String, timestamp_ns: u64) -> EventMeta {
    EventMeta {
        pid,
        ppid,
        // F-3: real token identity; Unknown when the process is gone/protected.
        user: winapi::read_process_user(pid),
        timestamp_ns,
        comm,
    }
}

/// Seeds the pid store before the trace: already-running processes resolve from
/// the very first `ConnectEvent`, and parent lineage/exclusions apply to them.
fn seed_pid_store(state: &SharedState) {
    let mut pids = state.pids.lock().unwrap();
    for (pid, name) in winapi::snapshot_processes() {
        pids.insert(pid, name);
    }
    log::info!("pid store seeded: {} existing processes", pids.len());
}

/// F-2: randomized session name; the previous name is persisted so orphan cleanup
/// survives both crashes AND the randomization.
fn rotate_session_name(state_path: &std::path::Path) -> String {
    if let Ok(previous) = std::fs::read_to_string(state_path) {
        let previous = previous.trim();
        if !previous.is_empty() {
            stop_orphaned_session(previous);
        }
    }
    let session = normalize::random_session_name(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id(),
    );
    let _ = std::fs::write(state_path, &session);
    session
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
                     writes (session {session}) — trace stopped or tampered"
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
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        self.stop.store(false, Ordering::SeqCst);
        let sink: Arc<dyn EventSink> = Arc::from(sink);

        let canary_file =
            std::env::temp_dir().join(format!("synthaea-canary-{}", std::process::id()));
        let state = Arc::new(SharedState {
            pids: Mutex::new(HashMap::new()),
            volumes: Mutex::new(winapi::build_volume_map()),
            dedup: Mutex::new(normalize::ConnectDedup::new(60_000_000_000)),
            events_seen: AtomicU64::new(0),
            canary_path: canary_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        });

        seed_pid_store(&state);

        let state_path = session_state_path();
        let session = rotate_session_name(&state_path);

        let trace = UserTrace::new()
            .named(session.clone())
            .enable(process_provider(sink.clone(), state.clone()))
            .enable(network_provider(sink.clone(), state.clone()))
            .enable(file_provider(sink.clone(), state.clone()))
            .enable(dns_provider(sink.clone(), state.clone()))
            .enable(registry_provider(sink.clone(), state.clone()))
            .enable(powershell_provider(sink.clone(), state.clone()))
            .enable(wmi_provider(sink, state.clone()))
            .start_and_process()
            .map_err(|e| -> SensorError { format!("ETW startup error: {e:?}").into() })?;

        let result = liveness_watch(&self.stop, &state, &canary_file, &session);

        let _ = trace.stop();
        let _ = std::fs::remove_file(&canary_file);
        if result.is_ok() {
            let _ = std::fs::remove_file(&state_path);
        }
        result
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}
