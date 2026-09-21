//! `wevtutil`-polling implementation of the persistence detections plus the
//! logon/session events (see the crate doc for why polling rather than
//! `EvtSubscribe`/ETW). Three independent threads, one per channel/event group,
//! each following the same pattern as the other sensors in this workspace:
//! remember the last `EventRecordID` seen, poll for anything newer, normalize
//! into a `schema::Event`, hand it to the sink.

use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use schema::{
    AuthEvent, AuthKind, AuthOutcome, Event, EventMeta, FLAG_PERSISTENCE_ACCOUNT_ARTIFACT,
    FLAG_PERSISTENCE_ARTIFACT, FLAG_PERSISTENCE_TASK_ARTIFACT, FileOpenEvent, User,
    sensor::{Capabilities, EventSink, Sensor, SensorError},
};

use crate::xml::{self, AccountCreatedEvent, LogonEvent, ScheduledTaskEvent, ServiceInstallEvent};

/// All channels are polled on the same cadence — persistence detection and
/// logon-event normalization both have no sub-second stakes (the underlying
/// Windows event already exists by the time a poll tick could see it), so one
/// constant covers all three threads.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The audit subcategory event 4698 depends on, referenced by GUID rather than
/// name: `auditpol` matches subcategory names against the OS's **localized**
/// label, not the canonical English one — confirmed failing with Win32 error 87 on
/// a French-language lab VM using the English name. The GUID is stable regardless
/// of the OS language (Microsoft's documented approach for scripting `auditpol`).
const SCHEDULED_TASK_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE9227-69AE-11D9-BED3-505054503030}";

/// "Logon" audit subcategory (covers 4624, 4625, and 4648) — GUID form for the
/// same locale-independence reason as
/// [`SCHEDULED_TASK_AUDIT_SUBCATEGORY_GUID`]. Taken from Microsoft's published
/// subcategory GUID list; **not yet re-confirmed against this project's own lab
/// VM** the way the 4698 GUID was. Enabling it here is belt-and-suspenders, not
/// the primary path: unlike "Other Object Access Events", "Logon" is part of
/// Windows' out-of-the-box default audit policy, so a failure here should not
/// be read as urgently as an `enable_scheduled_task_audit` failure would be.
const LOGON_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE9215-69AE-11D9-BED3-505054503030}";

/// "Special Logon" audit subcategory (covers 4672) — same caveats as
/// [`LOGON_AUDIT_SUBCATEGORY_GUID`].
const SPECIAL_LOGON_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE921B-69AE-11D9-BED3-505054503030}";

/// "User Account Management" audit subcategory (covers 4720/4722/4724/4738/...) —
/// GUID form for the same locale-independence reason as the other GUIDs above.
/// Published by Microsoft's subcategory GUID list; **not yet re-confirmed against
/// this project's own lab VM** the way the 4698 GUID was. Unlike "Other Object
/// Access Events" (needed for 4698), User Account Management is part of Windows'
/// out-of-the-box default audit policy on both Client and Server SKUs — a failure
/// to enable here is expected to be rare and non-blocking.
const USER_ACCOUNT_MGMT_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE9235-69AE-11D9-BED3-505054503030}";

/// The "Microsoft-Windows-Security-Auditing" provider that writes 4624/4625/
/// 4648/4672 runs inside the LSA subsystem process, not the account's own
/// process — see [`LogonEvent`]'s doc. `EventMeta::comm` names that reporting
/// process rather than leaving it blank.
const LSASS_COMM: &str = "lsass.exe";

fn wevtutil(args: &[&str]) -> String {
    match Command::new("wevtutil").args(args).output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(e) => {
            log::warn!("wevtutil invocation failed ({e}); args={args:?}");
            String::new()
        }
    }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ── Event 7045 — service install (T1543.003) ─────────────────────────────────

/// `EventRecordID` of the newest 7045 event already in the System log at startup —
/// only services installed *after* the sensor starts are reported, matching the
/// other sensors in this workspace (none of them replay history).
fn last_known_record_id_7045() -> u64 {
    let xml_out = wevtutil(&[
        "qe",
        "System",
        "/c:1",
        "/rd:true",
        "/f:xml",
        "/q:*[System[(EventID=7045)]]",
    ]);
    xml::split_event_blocks(&xml_out)
        .first()
        .and_then(|block| xml::parse_service_install_block(block))
        .map(|e| e.record_id)
        .unwrap_or(0)
}

/// New 7045 events since `since_record_id` (exclusive), oldest to newest.
fn new_service_install_events(since_record_id: u64) -> Vec<ServiceInstallEvent> {
    let query = format!("*[System[(EventID=7045) and (EventRecordID>{since_record_id})]]");
    let query_arg = format!("/q:{query}");
    let xml_out = wevtutil(&["qe", "System", "/rd:false", "/f:xml", query_arg.as_str()]);
    xml::split_event_blocks(&xml_out)
        .into_iter()
        .filter_map(xml::parse_service_install_block)
        .collect()
}

fn poll_service_installs(
    sink: Arc<dyn EventSink>,
    stop: Arc<AtomicBool>,
    counters: Arc<EventLogCounters>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_id = last_known_record_id_7045();
        log::info!("service-install poll started (last known EventRecordID: {last_id})");
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(POLL_INTERVAL);
            for install in new_service_install_events(last_id) {
                last_id = last_id.max(install.record_id);
                if install.service_name.is_empty() || install.image_path.is_empty() {
                    continue;
                }
                let event = FileOpenEvent {
                    meta: EventMeta {
                        pid: install.pid,
                        ppid: 0,
                        user: User::Unknown,
                        timestamp_ns: now_ns(),
                        comm: install.service_name,
                        container: None, // Windows: no container support
                    },
                    path: install.image_path,
                    flags: FLAG_PERSISTENCE_ARTIFACT,
                };
                counters.service_installs.fetch_add(1, Ordering::Relaxed);
                sink.on_event(Event::FileOpen(event));
            }
        }
        log::info!("service-install poll stopped");
    })
}

// ── Event 4698 — scheduled task creation (T1053.005) ─────────────────────────

/// Best-effort, non-blocking: if `auditpol` fails (insufficient rights despite
/// being admin, a GPO overriding it, the command missing...), this is logged and
/// the sensor keeps going — a problem in this one sub-feature must never take down
/// the rest of the sensor. Still required even though reading is done via
/// `wevtutil` rather than a live ETW subscription: without this subcategory
/// active, Windows simply never writes the 4698 event, regardless of how it is
/// read afterward.
fn enable_scheduled_task_audit() -> bool {
    let subcategory_arg = format!("/subcategory:{SCHEDULED_TASK_AUDIT_SUBCATEGORY_GUID}");
    let output = Command::new("auditpol")
        .args([
            "/set",
            subcategory_arg.as_str(),
            "/success:enable",
            "/failure:enable",
        ])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            log::info!("\"Other Object Access Events\" audit enabled (event 4698)");
            true
        }
        Ok(o) => {
            log::warn!(
                "auditpol failed (code {:?}) — scheduled task persistence detection (T1053.005) \
                 may not receive any 4698 events until this audit subcategory is enabled \
                 manually: auditpol /set /subcategory:{SCHEDULED_TASK_AUDIT_SUBCATEGORY_GUID} \
                 /success:enable /failure:enable. stderr: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            log::warn!(
                "could not run auditpol ({e}) — scheduled task persistence detection (T1053.005) \
                 may stay silent until the audit is enabled manually (see command above)"
            );
            false
        }
    }
}

fn last_known_record_id_4698() -> u64 {
    let xml_out = wevtutil(&[
        "qe",
        "Security",
        "/c:1",
        "/rd:true",
        "/f:xml",
        "/q:*[System[(EventID=4698)]]",
    ]);
    xml::split_event_blocks(&xml_out)
        .first()
        .and_then(|block| xml::parse_scheduled_task_block(block))
        .map(|e| e.record_id)
        .unwrap_or(0)
}

fn new_scheduled_task_events(since_record_id: u64) -> Vec<ScheduledTaskEvent> {
    let query = format!("*[System[(EventID=4698) and (EventRecordID>{since_record_id})]]");
    let query_arg = format!("/q:{query}");
    let xml_out = wevtutil(&["qe", "Security", "/rd:false", "/f:xml", query_arg.as_str()]);
    xml::split_event_blocks(&xml_out)
        .into_iter()
        .filter_map(xml::parse_scheduled_task_block)
        .collect()
}

fn poll_scheduled_tasks(
    sink: Arc<dyn EventSink>,
    stop: Arc<AtomicBool>,
    counters: Arc<EventLogCounters>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_id = last_known_record_id_4698();
        log::info!("scheduled-task poll started (last known EventRecordID: {last_id})");
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(POLL_INTERVAL);
            for task in new_scheduled_task_events(last_id) {
                last_id = last_id.max(task.record_id);
                if task.task_name.is_empty() {
                    continue;
                }
                let Some(action_path) = xml::task_action_path(&task.task_content) else {
                    continue;
                };
                let event = FileOpenEvent {
                    meta: EventMeta {
                        pid: task.pid,
                        ppid: 0,
                        user: User::Unknown,
                        timestamp_ns: now_ns(),
                        comm: xml::task_leaf_name(&task.task_name),
                        container: None, // Windows: no container support
                    },
                    path: action_path,
                    flags: FLAG_PERSISTENCE_TASK_ARTIFACT,
                };
                counters.scheduled_tasks.fetch_add(1, Ordering::Relaxed);
                sink.on_event(Event::FileOpen(event));
            }
        }
        log::info!("scheduled-task poll stopped");
    })
}

// ── Events 4624/4625/4648/4672 — logon/session (#94) ─────────────────────────

/// Best-effort, non-blocking — same rationale as [`enable_scheduled_task_audit`],
/// except a failure here is expected to be rarer: "Logon" and "Special Logon"
/// are both enabled by Windows' default audit policy out of the box, so this
/// call is reinforcement against a hardened/custom policy that turned them off,
/// not the primary enablement path.
fn enable_logon_audit() {
    for (label, guid) in [
        ("Logon", LOGON_AUDIT_SUBCATEGORY_GUID),
        ("Special Logon", SPECIAL_LOGON_AUDIT_SUBCATEGORY_GUID),
    ] {
        let subcategory_arg = format!("/subcategory:{guid}");
        let output = Command::new("auditpol")
            .args([
                "/set",
                subcategory_arg.as_str(),
                "/success:enable",
                "/failure:enable",
            ])
            .output();
        match output {
            Ok(o) if o.status.success() => log::info!("\"{label}\" audit enabled"),
            Ok(o) => log::warn!(
                "auditpol failed enabling \"{label}\" audit (code {:?}) — logon-event coverage \
                 may be incomplete until this audit subcategory is confirmed enabled: auditpol \
                 /set /subcategory:{guid} /success:enable /failure:enable. stderr: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => log::warn!(
                "could not run auditpol ({e}) — logon-event coverage may be incomplete until \
                 the \"{label}\" audit is confirmed enabled (see command above)"
            ),
        }
    }
}

fn last_known_record_id_logon() -> u64 {
    let xml_out = wevtutil(&[
        "qe",
        "Security",
        "/c:1",
        "/rd:true",
        "/f:xml",
        "/q:*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672)]]",
    ]);
    xml::split_event_blocks(&xml_out)
        .first()
        .and_then(|block| xml::parse_logon_block(block))
        .map(|e| e.record_id)
        .unwrap_or(0)
}

/// New 4624/4625/4648/4672 events since `since_record_id` (exclusive), oldest to
/// newest — one query across all four IDs (they share the Security channel's
/// single `EventRecordID` sequence), rather than four separate polls hammering
/// the same channel.
fn new_logon_events(since_record_id: u64) -> Vec<LogonEvent> {
    let query = format!(
        "*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672) and \
         (EventRecordID>{since_record_id})]]"
    );
    let query_arg = format!("/q:{query}");
    let xml_out = wevtutil(&["qe", "Security", "/rd:false", "/f:xml", query_arg.as_str()]);
    xml::split_event_blocks(&xml_out)
        .into_iter()
        .filter_map(xml::parse_logon_block)
        .collect()
}

/// Maps a parsed [`LogonEvent`] to the normalized [`Event::Auth`], or `None`
/// when the event carries no usable account identity (a shape this module does
/// not yet understand — skip rather than report a hollow event).
fn to_auth_event(logon: &LogonEvent) -> Option<Event> {
    let (kind, outcome) = match logon.event_id {
        4624 => (AuthKind::Logon, AuthOutcome::Success),
        4625 => (AuthKind::LogonFailure, AuthOutcome::Failure),
        // 4648 fires when explicit credentials are used to attempt a logon; it
        // carries no pass/fail status of its own (whether the attempt actually
        // succeeded is a separate 4624/4625), so it is reported as `Success`
        // meaning "the explicit-credential attempt was observed", not "and it
        // succeeded".
        4648 => (AuthKind::ExplicitCredentials, AuthOutcome::Success),
        // 4672 only fires for a logon that already succeeded.
        4672 => (AuthKind::PrivilegedSession, AuthOutcome::Success),
        _ => return None,
    };

    // 4672 has no Target* fields — the Subject *is* the account granted the
    // special privileges (see `LogonEvent`'s doc).
    let (target_user, target_user_sid) = if logon.event_id == 4672 {
        (
            logon.subject_user_name.clone(),
            logon.subject_user_sid.clone(),
        )
    } else {
        (
            logon.target_user_name.clone(),
            logon.target_user_sid.clone(),
        )
    };
    let target_user = target_user?;

    let source_address = logon.ip_address.as_deref().and_then(|s| s.parse().ok());
    let status_code = match (&logon.status, &logon.sub_status) {
        (Some(status), Some(sub)) => Some(format!("{status}/{sub}")),
        (Some(status), None) => Some(status.clone()),
        (None, Some(sub)) => Some(sub.clone()),
        (None, None) => None,
    };
    let user = match &logon.subject_user_sid {
        Some(sid) => User::Windows {
            sid: sid.clone(),
            integrity_level: None,
        },
        None => User::Unknown,
    };

    Some(Event::Auth(AuthEvent {
        meta: EventMeta {
            pid: logon.pid,
            ppid: 0,
            user,
            timestamp_ns: now_ns(),
            comm: LSASS_COMM.to_string(),
            container: None, // Windows: no container support
        },
        outcome,
        kind,
        target_user,
        target_user_sid,
        source_address,
        status_code,
    }))
}

fn poll_logon_events(
    sink: Arc<dyn EventSink>,
    stop: Arc<AtomicBool>,
    counters: Arc<EventLogCounters>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_id = last_known_record_id_logon();
        log::info!("logon poll started (last known EventRecordID: {last_id})");
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(POLL_INTERVAL);
            for logon in new_logon_events(last_id) {
                last_id = last_id.max(logon.record_id);
                if let Some(event) = to_auth_event(&logon) {
                    counters.logon_events.fetch_add(1, Ordering::Relaxed);
                    sink.on_event(event);
                }
            }
        }
        log::info!("logon poll stopped");
    })
}

// ── Event 4720 — account creation (T1136.001) ────────────────────────────────

/// Same rationale as [`enable_scheduled_task_audit`], less critical: User Account
/// Management is part of Windows' out-of-the-box default audit policy on both
/// Client and Server SKUs, so a failure here should not be read as urgently as an
/// `enable_scheduled_task_audit` failure would be. Belt-and-suspenders regardless
/// — enable it explicitly so we do not silently miss 4720s on a hardened VM that
/// disabled the default policy.
fn enable_account_creation_audit() -> bool {
    let subcategory_arg = format!("/subcategory:{USER_ACCOUNT_MGMT_AUDIT_SUBCATEGORY_GUID}");
    let output = Command::new("auditpol")
        .args([
            "/set",
            subcategory_arg.as_str(),
            "/success:enable",
            "/failure:enable",
        ])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            log::info!("\"User Account Management\" audit enabled (event 4720)");
            true
        }
        Ok(o) => {
            log::warn!(
                "auditpol failed (code {:?}) — account-creation persistence detection \
                 (T1136.001) may not receive any 4720 events until this audit \
                 subcategory is enabled manually: auditpol /set \
                 /subcategory:{USER_ACCOUNT_MGMT_AUDIT_SUBCATEGORY_GUID} \
                 /success:enable /failure:enable. stderr: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            log::warn!(
                "could not run auditpol ({e}) — account-creation persistence detection \
                 (T1136.001) may stay silent until the audit is enabled manually \
                 (see command above)"
            );
            false
        }
    }
}

fn last_known_record_id_4720() -> u64 {
    let xml_out = wevtutil(&[
        "qe",
        "Security",
        "/c:1",
        "/rd:true",
        "/f:xml",
        "/q:*[System[(EventID=4720)]]",
    ]);
    xml::split_event_blocks(&xml_out)
        .first()
        .and_then(|block| xml::parse_account_created_block(block))
        .map(|e| e.record_id)
        .unwrap_or(0)
}

fn new_account_created_events(since_record_id: u64) -> Vec<AccountCreatedEvent> {
    let query = format!("*[System[(EventID=4720) and (EventRecordID>{since_record_id})]]");
    let query_arg = format!("/q:{query}");
    let xml_out = wevtutil(&["qe", "Security", "/rd:false", "/f:xml", query_arg.as_str()]);
    xml::split_event_blocks(&xml_out)
        .into_iter()
        .filter_map(xml::parse_account_created_block)
        .collect()
}

fn poll_account_creations(
    sink: Arc<dyn EventSink>,
    stop: Arc<AtomicBool>,
    counters: Arc<EventLogCounters>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_id = last_known_record_id_4720();
        log::info!("account-creation poll started (last known EventRecordID: {last_id})");
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(POLL_INTERVAL);
            for account in new_account_created_events(last_id) {
                last_id = last_id.max(account.record_id);
                // A 4720 without a target user name is not usable — the alert
                // message quotes this as `comm`. Skip (same tolerance rule as
                // the scheduled-task/service-install pollers).
                let Some(target_name) = account.target_user_name else {
                    continue;
                };
                // TargetSid is preferred as `path` (the persistence artifact's
                // canonical identifier — survives an account rename). Falling
                // back to the leaf name reproduced as a placeholder path keeps
                // the alert well-formed if the SID is missing on some future
                // Windows shape rather than dropping the event outright.
                let sid = account
                    .target_user_sid
                    .unwrap_or_else(|| format!("(unknown-sid:{target_name})"));
                let event = FileOpenEvent {
                    meta: EventMeta {
                        pid: account.pid,
                        ppid: 0,
                        user: User::Unknown,
                        timestamp_ns: now_ns(),
                        comm: target_name,
                        container: None, // Windows: no container support
                    },
                    path: sid,
                    flags: FLAG_PERSISTENCE_ACCOUNT_ARTIFACT,
                };
                counters.account_creations.fetch_add(1, Ordering::Relaxed);
                sink.on_event(Event::FileOpen(event));
            }
        }
        log::info!("account-creation poll stopped");
    })
}

// ── Policy-configurable allowlist and volume counters (#94) ─────────────────
//
// `sensor-*` crates may depend only on `schema` (`tools/check-deps.py`), so
// this sensor cannot read `policy::EventLogPolicy` itself — the agent binary
// (unrestricted deps) reads that type and converts it into this crate's own
// `EventLogConfig` when constructing the sensor. See
// `docs/adr/0006-eventlog-channel-allowlist-and-volume-counters.md`.

/// Which of this sensor's three independent poll targets are active. A
/// disabled group is never even queried — not filtered after the fact — so a
/// host that, say, disables logon-event polling pays no `wevtutil` cost for it
/// either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLogConfig {
    /// Event 7045 (T1543.003 — service install persistence).
    pub service_installs_enabled: bool,
    /// Event 4698 (T1053.005 — scheduled task persistence).
    pub scheduled_tasks_enabled: bool,
    /// Event 4720 (T1136.001 — local account creation persistence).
    pub account_creations_enabled: bool,
    /// Events 4624/4625/4648/4672 (logon/session, #94).
    pub logon_events_enabled: bool,
}

impl Default for EventLogConfig {
    /// Every group enabled — this crate's behavior before `EventLogConfig`
    /// existed.
    fn default() -> Self {
        Self {
            service_installs_enabled: true,
            scheduled_tasks_enabled: true,
            account_creations_enabled: true,
            logon_events_enabled: true,
        }
    }
}

/// Per-group event counts, incremented once per event actually normalized and
/// handed to the sink (not per raw `wevtutil` XML block — a block skipped for
/// missing/unusable fields is not "volume", it is noise this sensor already
/// filtered out). Plain `Relaxed` atomics: independent monotonic counts, never
/// used to synchronize anything else. A handle from
/// [`EventLogSensor::counters`] can be read from any thread while `run` is
/// updating it — e.g. a future diagnostics/health surface (none exists in
/// this workspace yet; this type is what such a surface would read).
#[derive(Debug, Default)]
pub struct EventLogCounters {
    pub service_installs: AtomicU64,
    pub scheduled_tasks: AtomicU64,
    pub account_creations: AtomicU64,
    pub logon_events: AtomicU64,
}

// ── The sensor ────────────────────────────────────────────────────────────────

pub struct EventLogSensor {
    stop: Arc<AtomicBool>,
    config: EventLogConfig,
    counters: Arc<EventLogCounters>,
}

impl EventLogSensor {
    /// Every poll target enabled — equivalent to
    /// `Self::with_config(EventLogConfig::default())`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EventLogConfig::default())
    }

    #[must_use]
    pub fn with_config(config: EventLogConfig) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            config,
            counters: Arc::new(EventLogCounters::default()),
        }
    }

    /// Shared stop flag, so a ctrlc handler (or another sensor's failure) can
    /// signal this sensor to wind down from outside its own thread.
    #[must_use]
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Handle to this sensor's live volume counters — cloning the `Arc` is
    /// cheap and safe to read from any thread while `run` is active.
    #[must_use]
    pub fn counters(&self) -> Arc<EventLogCounters> {
        Arc::clone(&self.counters)
    }
}

impl Default for EventLogSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for EventLogSensor {
    fn name(&self) -> &str {
        "windows-eventlog"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            file_events: self.config.service_installs_enabled
                || self.config.scheduled_tasks_enabled
                || self.config.account_creations_enabled,
            auth_events: self.config.logon_events_enabled,
            ..Capabilities::default()
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        self.stop.store(false, Ordering::SeqCst);
        let sink: Arc<dyn EventSink> = Arc::from(sink);

        let mut handles = Vec::new();

        if self.config.service_installs_enabled {
            handles.push(poll_service_installs(
                Arc::clone(&sink),
                Arc::clone(&self.stop),
                Arc::clone(&self.counters),
            ));
        }
        if self.config.scheduled_tasks_enabled {
            enable_scheduled_task_audit();
            handles.push(poll_scheduled_tasks(
                Arc::clone(&sink),
                Arc::clone(&self.stop),
                Arc::clone(&self.counters),
            ));
        }
        if self.config.account_creations_enabled {
            enable_account_creation_audit();
            handles.push(poll_account_creations(
                Arc::clone(&sink),
                Arc::clone(&self.stop),
                Arc::clone(&self.counters),
            ));
        }
        if self.config.logon_events_enabled {
            enable_logon_audit();
            handles.push(poll_logon_events(
                Arc::clone(&sink),
                Arc::clone(&self.stop),
                Arc::clone(&self.counters),
            ));
        }

        while !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }

        for handle in handles {
            let _ = handle.join();
        }
        Ok(())
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn default_config_enables_every_poll_target() {
        let config = EventLogConfig::default();
        assert!(config.service_installs_enabled);
        assert!(config.scheduled_tasks_enabled);
        assert!(config.account_creations_enabled);
        assert!(config.logon_events_enabled);
    }

    #[test]
    fn capabilities_reflect_disabled_groups() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            service_installs_enabled: false,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
        });
        let caps = sensor.capabilities();
        assert!(!caps.file_events);
        assert!(!caps.auth_events);
    }

    #[test]
    fn capabilities_stay_true_if_any_file_group_enabled() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            service_installs_enabled: true,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
        });
        assert!(sensor.capabilities().file_events);
    }

    #[test]
    fn counters_start_at_zero() {
        let sensor = EventLogSensor::new();
        let counters = sensor.counters();
        assert_eq!(counters.service_installs.load(Ordering::Relaxed), 0);
        assert_eq!(counters.scheduled_tasks.load(Ordering::Relaxed), 0);
        assert_eq!(counters.account_creations.load(Ordering::Relaxed), 0);
        assert_eq!(counters.logon_events.load(Ordering::Relaxed), 0);
    }
}
