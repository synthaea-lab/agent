//! The Windows sensor: ETW providers (Kernel-Process, Kernel-Network, Kernel-File)
//! normalized into schema events. Migrated from the old iteration; the provider
//! wiring and its lab-earned notes (TcpClient emits no eid=42 — 2026-08-25; PID
//! recycling; orphan named sessions) carry over, the audit findings are fixed here.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use ferrisetw::{
    EventRecord, parser::Parser, provider::Provider, schema_locator::SchemaLocator,
    trace::UserTrace,
};
use schema::{
    ConnectEvent, Event, EventMeta, ExecEvent, FileOpenEvent,
    sensor::{Capabilities, EventSink, Sensor, SensorError},
};

use crate::{normalize, winapi};

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";

/// Where the previous session's randomized name is persisted, so orphan cleanup
/// after a crash still works despite F-2's name randomization.
fn session_state_path() -> std::path::PathBuf {
    std::env::temp_dir().join("synthaea-etw-session")
}

/// Stops an orphaned ETW session, if one exists. Named sessions are kernel objects
/// that outlive the creating process: after a `taskkill /f` or crash the session
/// stays Running and any restart fails with AlreadyExist — without this cleanup the
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

struct SharedState {
    /// pid → full image path; populated by seed + ProcessStart, pruned on
    /// ProcessEnd (PID recycling).
    pids: Mutex<HashMap<u32, String>>,
    /// F-5: live device→drive map, refreshed on normalization misses.
    volumes: Mutex<HashMap<String, String>>,
    /// F-7: Connect/Send dedup.
    dedup: Mutex<normalize::ConnectDedup>,
    /// F-2: events observed — the silence watchdog reads this.
    events_seen: AtomicU64,
    /// The liveness canary file: the run loop touches it every heartbeat, which
    /// MUST produce a Kernel-File event (our pid is tracked) — so sensor liveness
    /// is deterministic instead of traffic-dependent (a quiet host produces no
    /// guaranteed events in 30s; review finding on #100). Canary events are
    /// filtered from emission below.
    canary_path: String,
}

impl SharedState {
    fn normalize_path(&self, raw: &str) -> String {
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

    fn comm_for(&self, pid: u32) -> Option<String> {
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

fn basename(path: &str) -> String {
    path.rsplit('\\').next().unwrap_or(path).to_string()
}

fn meta(pid: u32, ppid: u32, comm: String, timestamp_ns: u64) -> EventMeta {
    EventMeta {
        pid,
        ppid,
        // F-3: real token identity; Unknown when the process is gone/protected.
        user: winapi::read_process_user(pid),
        timestamp_ns,
        comm,
    }
}

// ── Providers ────────────────────────────────────────────────────────────────

fn process_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        // 1=ProcessStart (new spawn → ExecEvent), 2=ProcessEnd (prune the store —
        // PID recycling), 3=ProcessDCStart (rundown of already-running processes →
        // store only, not a spawn).
        if eid != 1 && eid != 2 && eid != 3 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);

        if eid == 2 {
            if pid != 0 {
                state.pids.lock().unwrap().remove(&pid);
            }
            return;
        }

        let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
        let raw_image: String = parser
            .try_parse("ImageName")
            .unwrap_or_else(|_| String::from("<unknown>"));
        let image_path = state.normalize_path(&raw_image);
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());

        // Never store "<unknown>": a cache hit on it would suppress live lookups.
        if image_path != "<unknown>" {
            state.pids.lock().unwrap().insert(pid, image_path.clone());
        }
        if eid == 3 {
            return; // rundown: store populated, nothing else to do
        }

        // Lineage at exec time (schema parent fields): the parent is usually alive
        // and already in the store.
        let parent_image_path = state.pids.lock().unwrap().get(&ppid).cloned();
        let parent_comm = parent_image_path.as_deref().map(basename);

        // F-1: the REAL command line from the target's PEB, unbounded (F-4);
        // fall back to the image path only when the read fails — never a
        // placeholder pretending to be arguments.
        let cmdline = winapi::read_process_cmdline(pid).unwrap_or_else(|| image_path.clone());

        let comm = basename(&image_path);
        sink.on_event(Event::Exec(ExecEvent {
            meta: meta(pid, ppid, comm, timestamp_ns),
            image_path,
            cmdline,
            argv: vec![], // Windows has a flat command line; consumers fall back
            parent_comm,
            parent_image_path,
            sha256: None, // filled by the agent's enrichment stage
            signature: None,
        }));
    };
    Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_callback(callback)
        .build()
}

fn network_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        // v4: 42=TcpIpConnect, 12=TcpIpSend (TcpClient emits no 42 — lab
        // 2026-08-25). v6 counterparts (F-7): 58=connect, 26=send. Recv excluded:
        // would double-count on the receiver side.
        let is_v6 = eid == 58 || eid == 26;
        if eid != 42 && eid != 12 && !is_v6 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        let pid: u32 = parser.try_parse("PID").unwrap_or(0);
        let dport = parser.try_parse::<u16>("dport").unwrap_or(0).swap_bytes();
        let sport = parser.try_parse::<u16>("sport").unwrap_or(0).swap_bytes();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());

        let daddr: std::net::IpAddr = if is_v6 {
            let raw: Vec<u8> = parser.try_parse("daddr").unwrap_or_default();
            let Ok(bytes) = <[u8; 16]>::try_from(raw) else {
                return;
            };
            std::net::IpAddr::V6(bytes.into())
        } else {
            let raw: u32 = parser.try_parse("daddr").unwrap_or(0);
            if raw == 0 {
                return;
            }
            // ETW stores the v4 address in memory order — to_ne_bytes preserves it.
            std::net::IpAddr::V4(raw.to_ne_bytes().into())
        };

        // F-7: one logical connection = one event — flow-keyed (sport included) so
        // parallel connections stay distinct and chatty flows never re-emit.
        if state
            .dedup
            .lock()
            .unwrap()
            .is_duplicate(pid, sport, daddr, dport, timestamp_ns)
        {
            return;
        }

        let Some(comm) = state.comm_for(pid) else {
            return;
        };
        sink.on_event(Event::Connect(ConnectEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            daddr,
            dport,
        }));
    };
    Provider::by_guid(KERNEL_NETWORK_GUID)
        .add_callback(callback)
        .build()
}

fn file_provider(sink: Arc<dyn EventSink>, state: Arc<SharedState>) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let eid = record.event_id();
        // 12=NameCreate; 30=CreateNewFile (F-6 partial — delete/rename semantics
        // need schema variants and land with #82/#39).
        if eid != 12 && eid != 30 {
            return;
        }
        state.events_seen.fetch_add(1, Ordering::Relaxed);
        let Ok(schema_def) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema_def);
        // PID from the ETW header — the event fires in the caller's thread context.
        let pid = record.process_id();
        let timestamp_ns = normalize::filetime_to_ns(record.raw_timestamp());

        // Tracked PIDs only: discards pure kernel ops and untracked churn (the
        // volume filter the old sensor validated in the lab).
        let Some(comm) = ({
            let pids = state.pids.lock().unwrap();
            pids.get(&pid).map(|p| basename(p))
        }) else {
            return;
        };

        let flags = if eid == 30 {
            0o101 // CreateNewFile: create+write by definition
        } else {
            // NameCreate: disposition in the high byte of CreateOptions.
            let create_options: u32 = parser.try_parse("CreateOptions").unwrap_or(0x0100_0000);
            normalize::disposition_to_flags((create_options >> 24) & 0xFF)
        };
        if flags == 0 {
            return; // read-only open — of no interest for detection
        }

        let raw_path: String = parser.try_parse("FileName").unwrap_or_default();
        if raw_path.is_empty() {
            return;
        }
        let path = state.normalize_path(&raw_path);
        // The liveness canary proves the trace is alive; it is not telemetry.
        if path.ends_with(&state.canary_path) {
            return;
        }
        sink.on_event(Event::FileOpen(FileOpenEvent {
            meta: meta(pid, 0, comm, timestamp_ns),
            path,
            flags,
        }));
    };
    Provider::by_guid(KERNEL_FILE_GUID)
        .add_callback(callback)
        .build()
}

// ── The sensor ───────────────────────────────────────────────────────────────

pub struct WindowsSensor {
    stop: Arc<AtomicBool>,
}

impl WindowsSensor {
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Shared stop flag for a ctrlc handler on another thread.
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

        // Seed before the trace: already-running processes resolve from the very
        // first ConnectEvent, and parent lineage/exclusions apply to them.
        {
            let mut pids = state.pids.lock().unwrap();
            for (pid, name) in winapi::snapshot_processes() {
                pids.insert(pid, name);
            }
            log::info!("pid store seeded: {} existing processes", pids.len());
        }

        // F-2: randomized session name; the previous name is persisted so orphan
        // cleanup survives both crashes AND the randomization.
        let state_path = session_state_path();
        if let Ok(previous) = std::fs::read_to_string(&state_path) {
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
        let _ = std::fs::write(&state_path, &session);

        let trace = UserTrace::new()
            .named(session.clone())
            .enable(process_provider(sink.clone(), state.clone()))
            .enable(network_provider(sink.clone(), state.clone()))
            .enable(file_provider(sink, state.clone()))
            .start_and_process()
            .map_err(|e| -> SensorError { format!("ETW startup error: {e:?}").into() })?;

        // F-2: the silence watchdog, made deterministic by a canary: every
        // heartbeat the loop touches our own temp file, which MUST produce a
        // Kernel-File event (our pid is tracked and create-dispositions pass the
        // filter). A healthy-but-idle host therefore still advances the counter —
        // only a trace actually stopped out from under us (logman by an attacker)
        // freezes it, and that is a loud sensor error the watchdog restarts.
        let mut last_seen = state.events_seen.load(Ordering::Relaxed);
        let mut silent_intervals = 0u32;
        while !self.stop.load(Ordering::SeqCst) {
            let _ = std::fs::write(&canary_file, b"synthaea liveness canary");
            std::thread::sleep(std::time::Duration::from_millis(2_000));
            let seen = state.events_seen.load(Ordering::Relaxed);
            if seen == last_seen {
                silent_intervals += 1;
                // 15 × 2s = 30s with zero events despite the canary writes.
                if silent_intervals >= 15 {
                    let _ = trace.stop();
                    let _ = std::fs::remove_file(&canary_file);
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

        let _ = trace.stop();
        let _ = std::fs::remove_file(&canary_file);
        let _ = std::fs::remove_file(&state_path);
        Ok(())
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}
