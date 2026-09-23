//! `wevtutil`-polling implementation of the persistence detections plus the
//! logon/session events (see the crate doc for why polling rather than
//! `EvtSubscribe`/ETW). One independent poll thread per enabled
//! [`PollTarget`] — the shared pipeline (cursor, query, normalize, count,
//! sink) exists once; each target contributes only its query, parser, and
//! normalization.

use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use schema::{
    AuthEvent, AuthKind, AuthOutcome, Event, EventMeta, FLAG_APPLICATION_BLOCKED,
    FLAG_PERSISTENCE_ACCOUNT_ARTIFACT, FLAG_PERSISTENCE_ARTIFACT, FLAG_PERSISTENCE_TASK_ARTIFACT,
    FileOpenEvent, User,
    sensor::{Capabilities, EventSink, Sensor, SensorError},
    time::now_ns,
};

use crate::xml::{self, LogonEvent};

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
            tracing::warn!(error = %e, ?args, "wevtutil invocation failed");
            String::new()
        }
    }
}

// ── The shared poll pipeline ─────────────────────────────────────────────────
//
// Every target below is the same machine: remember the newest `EventRecordID`
// already in the channel at startup — only events written *after* the sensor
// starts are reported, matching the other sensors in this workspace (none of
// them replay history) — then poll for anything newer, normalize each parsed
// block into a `schema::Event`, count it, hand it to the sink. Only the
// query, the parser, and the normalization differ per target, so those live
// in a [`PollTarget`] and the machine exists once.

/// What [`PollTarget::parse_block`] yields for one `<Event>` XML block.
/// `None`: not even parseable. `Some((record_id, None))`: parsed but skipped
/// as unusable. `Some((record_id, Some(event)))`: a normalized event.
type ParsedBlock = Option<(u64, Option<Event>)>;

/// One poll target: a channel + `EventID` filter, and how its raw XML blocks
/// become normalized events.
struct PollTarget {
    /// Names the poll thread in logs.
    label: &'static str,
    /// `wevtutil` channel (`System` / `Security`).
    channel: &'static str,
    /// The `EventID=...` predicate, without the surrounding `*[System[...]]`.
    id_filter: &'static str,
    /// Which volume counter this target increments.
    counter: fn(&EventLogCounters) -> &AtomicU64,
    /// Parses one `<Event>` XML block — see [`ParsedBlock`] for the three
    /// outcomes. An unparseable block does not advance the record cursor; a
    /// parsed-but-unusable one advances it without counting (a block missing
    /// required fields is noise the sensor filtered out, not volume).
    parse_block: fn(&str) -> ParsedBlock,
    /// `auditpol` enablement to run once before polling starts, for targets
    /// whose audit subcategory may be off (see each target's enable fn doc).
    enable_audit: Option<fn()>,
}

/// `EventRecordID` of the newest matching event already in the channel.
fn last_known_record_id(target: &PollTarget) -> u64 {
    let query = format!("/q:*[System[({})]]", target.id_filter);
    let xml_out = wevtutil(&[
        "qe",
        target.channel,
        "/c:1",
        "/rd:true",
        "/f:xml",
        query.as_str(),
    ]);
    xml::split_event_blocks(&xml_out)
        .first()
        .and_then(|block| (target.parse_block)(block))
        .map(|(record_id, _)| record_id)
        .unwrap_or(0)
}

/// Parsed blocks newer than `since_record_id` (exclusive), oldest to newest.
fn new_blocks(target: &PollTarget, since_record_id: u64) -> Vec<(u64, Option<Event>)> {
    let query = format!(
        "/q:*[System[({}) and (EventRecordID>{since_record_id})]]",
        target.id_filter
    );
    let xml_out = wevtutil(&["qe", target.channel, "/rd:false", "/f:xml", query.as_str()]);
    xml::split_event_blocks(&xml_out)
        .into_iter()
        .filter_map(|block| (target.parse_block)(block))
        .collect()
}

fn poll(
    target: &'static PollTarget,
    sink: Arc<dyn EventSink>,
    stop: Arc<AtomicBool>,
    counters: Arc<EventLogCounters>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_id = last_known_record_id(target);
        tracing::info!(
            target = target.label,
            last_record_id = last_id,
            "poll started"
        );
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(POLL_INTERVAL);
            for (record_id, event) in new_blocks(target, last_id) {
                last_id = last_id.max(record_id);
                if let Some(event) = event {
                    (target.counter)(&counters).fetch_add(1, Ordering::Relaxed);
                    sink.on_event(event);
                }
            }
        }
        tracing::info!(target = target.label, "poll stopped");
    })
}

/// The meta shape shared by the three persistence-artifact targets, which all
/// reuse [`FileOpenEvent`] (see ADR-0004) rather than defining event types of
/// their own.
fn persistence_file_open(pid: u32, comm: String, path: String, flags: u32) -> Event {
    Event::FileOpen(FileOpenEvent {
        meta: EventMeta {
            pid,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: now_ns(),
            comm,
            container: None, // Windows: no container support
        },
        path,
        flags,
    })
}

/// Runs `auditpol /set /subcategory:<guid>` — best-effort and non-blocking: if
/// it fails (insufficient rights despite being admin, a GPO overriding it, the
/// command missing...), the failure is logged with `consequence` (what
/// coverage the operator loses until they enable the subcategory manually) and
/// the sensor keeps going — a problem in one sub-feature must never take down
/// the rest of the sensor.
fn enable_audit_subcategory(label: &str, guid: &str, consequence: &str) {
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
        Ok(o) if o.status.success() => {
            tracing::info!(audit = label, "audit subcategory enabled");
        }
        Ok(o) => tracing::warn!(
            audit = label,
            code = ?o.status.code(),
            stderr = %String::from_utf8_lossy(&o.stderr).trim(),
            "auditpol failed — {consequence}: enable manually with auditpol /set \
             /subcategory:{guid} /success:enable /failure:enable"
        ),
        Err(e) => tracing::warn!(
            audit = label,
            error = %e,
            "could not run auditpol — {consequence}: enable manually with auditpol /set \
             /subcategory:{guid} /success:enable /failure:enable"
        ),
    }
}

// ── Event 7045 — service install (T1543.003) ─────────────────────────────────

/// A 7045 without a service name or image path is unusable — the alert quotes
/// them as `comm`/`path`. Skip, advancing the cursor.
fn normalize_service_install(block: &str) -> ParsedBlock {
    let install = xml::parse_service_install_block(block)?;
    let record_id = install.record_id;
    if install.service_name.is_empty() || install.image_path.is_empty() {
        return Some((record_id, None));
    }
    let event = persistence_file_open(
        install.pid,
        install.service_name,
        install.image_path,
        FLAG_PERSISTENCE_ARTIFACT,
    );
    Some((record_id, Some(event)))
}

static SERVICE_INSTALLS: PollTarget = PollTarget {
    label: "service-install",
    channel: "System",
    id_filter: "EventID=7045",
    counter: |c| &c.service_installs,
    parse_block: normalize_service_install,
    // 7045 lands in the System log unconditionally — nothing to enable.
    enable_audit: None,
};

// ── Event 4698 — scheduled task creation (T1053.005) ─────────────────────────

/// Audit enablement is still required even though reading is done via
/// `wevtutil` rather than a live ETW subscription: without the subcategory
/// active, Windows simply never writes the 4698 event, regardless of how it is
/// read afterward. Unlike the logon/account subcategories, "Other Object
/// Access Events" is NOT in Windows' default audit policy — this call is the
/// primary enablement path, and its failure warning deserves urgency.
fn enable_scheduled_task_audit() {
    enable_audit_subcategory(
        "Other Object Access Events (event 4698)",
        SCHEDULED_TASK_AUDIT_SUBCATEGORY_GUID,
        "scheduled task persistence detection (T1053.005) will not receive any 4698 events",
    );
}

/// Same tolerance rule as [`normalize_service_install`]; additionally skips a
/// task whose XML content yields no action path to report.
fn normalize_scheduled_task(block: &str) -> ParsedBlock {
    let task = xml::parse_scheduled_task_block(block)?;
    let record_id = task.record_id;
    if task.task_name.is_empty() {
        return Some((record_id, None));
    }
    let Some(action_path) = xml::task_action_path(&task.task_content) else {
        return Some((record_id, None));
    };
    let event = persistence_file_open(
        task.pid,
        xml::task_leaf_name(&task.task_name),
        action_path,
        FLAG_PERSISTENCE_TASK_ARTIFACT,
    );
    Some((record_id, Some(event)))
}

static SCHEDULED_TASKS: PollTarget = PollTarget {
    label: "scheduled-task",
    channel: "Security",
    id_filter: "EventID=4698",
    counter: |c| &c.scheduled_tasks,
    parse_block: normalize_scheduled_task,
    enable_audit: Some(enable_scheduled_task_audit),
};

// ── Events 4624/4625/4648/4672 — logon/session (#94) ─────────────────────────

/// Reinforcement, not primary enablement: "Logon" and "Special Logon" are both
/// in Windows' default audit policy out of the box, so this guards against a
/// hardened/custom policy that turned them off — a failure here is less urgent
/// than [`enable_scheduled_task_audit`]'s.
fn enable_logon_audit() {
    for (label, guid) in [
        ("Logon", LOGON_AUDIT_SUBCATEGORY_GUID),
        ("Special Logon", SPECIAL_LOGON_AUDIT_SUBCATEGORY_GUID),
    ] {
        enable_audit_subcategory(label, guid, "logon-event coverage may be incomplete");
    }
}

fn normalize_logon(block: &str) -> ParsedBlock {
    let logon = xml::parse_logon_block(block)?;
    Some((logon.record_id, to_auth_event(&logon)))
}

static LOGON_EVENTS: PollTarget = PollTarget {
    label: "logon",
    channel: "Security",
    // One query across all four IDs (they share the Security channel's single
    // `EventRecordID` sequence), rather than four separate polls hammering the
    // same channel.
    id_filter: "EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672",
    counter: |c| &c.logon_events,
    parse_block: normalize_logon,
    enable_audit: Some(enable_logon_audit),
};

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

// ── Event 4720 — account creation (T1136.001) ────────────────────────────────

/// Belt-and-suspenders like [`enable_logon_audit`]: "User Account Management"
/// is part of Windows' out-of-the-box default audit policy on both Client and
/// Server SKUs, so this only matters on a hardened VM that disabled the
/// default policy.
fn enable_account_creation_audit() {
    enable_audit_subcategory(
        "User Account Management (event 4720)",
        USER_ACCOUNT_MGMT_AUDIT_SUBCATEGORY_GUID,
        "account-creation persistence detection (T1136.001) will not receive any 4720 events",
    );
}

/// A 4720 without a target user name is not usable — the alert message quotes
/// it as `comm`. Skip, advancing the cursor.
fn normalize_account_created(block: &str) -> ParsedBlock {
    let account = xml::parse_account_created_block(block)?;
    let record_id = account.record_id;
    let Some(target_name) = account.target_user_name else {
        return Some((record_id, None));
    };
    // TargetSid is preferred as `path` (the persistence artifact's canonical
    // identifier — survives an account rename). Falling back to the leaf name
    // reproduced as a placeholder path keeps the alert well-formed if the SID
    // is missing on some future Windows shape rather than dropping the event
    // outright.
    let sid = account
        .target_user_sid
        .unwrap_or_else(|| format!("(unknown-sid:{target_name})"));
    let event = persistence_file_open(
        account.pid,
        target_name,
        sid,
        FLAG_PERSISTENCE_ACCOUNT_ARTIFACT,
    );
    Some((record_id, Some(event)))
}

static ACCOUNT_CREATIONS: PollTarget = PollTarget {
    label: "account-creation",
    channel: "Security",
    id_filter: "EventID=4720",
    counter: |c| &c.account_creations,
    parse_block: normalize_account_created,
    enable_audit: Some(enable_account_creation_audit),
};

// ── Event 8004 — `AppLocker` EXE/DLL block (Microsoft-Windows-AppLocker/EXE and DLL) ───
//
// `AppLocker`'s operational channel is **enabled by default** on modern Windows
// SKUs that ship `AppLocker`: unlike 4698, no `auditpol` toggle is involved
// (`AppLocker` is a policy-configured feature, not an audit subcategory). If the
// channel is disabled by group policy on a given host, `wevtutil qe` simply
// returns nothing and this poll thread stays idle — the failure mode is a
// coverage gap, not a crash.

/// Filename-only leaf of an `AppLocker` `FilePath`, which is upper-cased and
/// backslash-separated (e.g. `%OSDRIVE%\USERS\X\DOWNLOADS\POWERSHELL.EXE`).
/// Returns the trailing segment lowercased for `comm`.
fn applocker_leaf_name(path: &str) -> String {
    path.rsplit(&['\\', '/'][..])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// An 8004 without a `FilePath` cannot carry a persistence artifact — nothing
/// to hand to the sink. Skip, advancing the cursor.
fn normalize_applocker_block(block: &str) -> ParsedBlock {
    let ev = xml::parse_applocker_block(block)?;
    let record_id = ev.record_id;
    if ev.file_path.is_empty() {
        return Some((record_id, None));
    }
    let comm = applocker_leaf_name(&ev.file_path);
    let event = persistence_file_open(
        ev.target_process_id,
        comm,
        ev.file_path,
        FLAG_APPLICATION_BLOCKED,
    );
    Some((record_id, Some(event)))
}

static APPLOCKER_BLOCKS: PollTarget = PollTarget {
    label: "applocker-block",
    channel: "Microsoft-Windows-AppLocker/EXE and DLL",
    id_filter: "EventID=8004",
    counter: |c| &c.applocker_blocks,
    parse_block: normalize_applocker_block,
    // No audit-subcategory toggle: `AppLocker`'s channel is on when `AppLocker` is
    // configured on the host, off otherwise. Enabling it here would need
    // `wevtutil sl <channel> /e:true`, which is best done by the operator's
    // deployment (a disabled channel is a policy decision, not an oversight
    // the sensor should override on its own).
    enable_audit: None,
};

// ── Event 106 — TaskScheduler Operational "task registered" ─────────────────
//
// The `Microsoft-Windows-TaskScheduler/Operational` channel is **enabled by
// default** on all supported Windows SKUs (Task Scheduler being a core service)
// — no `auditpol` interaction, complementing the Security 4698 path whose
// `enable_scheduled_task_audit` may fail on a hardened host. When both channels
// are up, they double-fire on the same event: the deduplication happens at the
// rules layer (schema flag differentiation), not here.

/// A 106 without a `TaskName` is unusable — the alert quotes it as
/// `comm`/`path`. Skip, advancing the cursor.
fn normalize_task_scheduler_op_registered(block: &str) -> ParsedBlock {
    let ev = xml::parse_task_scheduler_op_registered_block(block)?;
    let record_id = ev.record_id;
    if ev.task_name.is_empty() {
        return Some((record_id, None));
    }
    // Operational 106 carries no serialized task XML (unlike 4698), so no
    // action path is available — the task name is the only artifact. Feed it
    // as both `comm` (leaf) and `path` (full path form Task Scheduler uses,
    // `\Folder\TaskName`) to keep the FileOpenEvent shape well-formed.
    let comm = xml::task_leaf_name(&ev.task_name);
    let event = persistence_file_open(ev.pid, comm, ev.task_name, FLAG_PERSISTENCE_TASK_ARTIFACT);
    Some((record_id, Some(event)))
}

static TASK_SCHEDULER_OP: PollTarget = PollTarget {
    label: "task-scheduler-op",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    id_filter: "EventID=106",
    counter: |c| &c.task_scheduler_op,
    parse_block: normalize_task_scheduler_op_registered,
    // Operational channel, always on — nothing to enable.
    enable_audit: None,
};

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
    /// Event 4698 (T1053.005 — scheduled task persistence). Reads the Security
    /// channel; requires `Other Object Access Events` audit enabled.
    pub scheduled_tasks_enabled: bool,
    /// Event 4720 (T1136.001 — local account creation persistence).
    pub account_creations_enabled: bool,
    /// Events 4624/4625/4648/4672 (logon/session, #94).
    pub logon_events_enabled: bool,
    /// Event 8004 (T1562.001-adjacent — `AppLocker` EXE/DLL block).
    /// `Microsoft-Windows-AppLocker/EXE and DLL` operational channel.
    pub applocker_blocks_enabled: bool,
    /// Event 106 (T1053.005 — scheduled task registered via the
    /// `Microsoft-Windows-TaskScheduler/Operational` channel; always-on
    /// complement to the 4698 path).
    pub task_scheduler_op_enabled: bool,
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
            applocker_blocks_enabled: true,
            task_scheduler_op_enabled: true,
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
    pub applocker_blocks: AtomicU64,
    pub task_scheduler_op: AtomicU64,
}

// ── The sensor ────────────────────────────────────────────────────────────────

/// The Windows Event Log poller: spawns one `wevtutil`-based poll loop per
/// enabled target (see the crate doc) and implements `schema::sensor::Sensor`.
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
                || self.config.account_creations_enabled
                || self.config.applocker_blocks_enabled
                || self.config.task_scheduler_op_enabled,
            auth_events: self.config.logon_events_enabled,
            ..Capabilities::default()
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        self.stop.store(false, Ordering::SeqCst);
        let sink: Arc<dyn EventSink> = Arc::from(sink);

        let mut handles = Vec::new();

        let targets = [
            (self.config.service_installs_enabled, &SERVICE_INSTALLS),
            (self.config.scheduled_tasks_enabled, &SCHEDULED_TASKS),
            (self.config.account_creations_enabled, &ACCOUNT_CREATIONS),
            (self.config.logon_events_enabled, &LOGON_EVENTS),
            (self.config.applocker_blocks_enabled, &APPLOCKER_BLOCKS),
            (self.config.task_scheduler_op_enabled, &TASK_SCHEDULER_OP),
        ];
        for (enabled, target) in targets {
            if !enabled {
                continue;
            }
            if let Some(enable_audit) = target.enable_audit {
                enable_audit();
            }
            handles.push(poll(
                target,
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
        assert!(config.applocker_blocks_enabled);
        assert!(config.task_scheduler_op_enabled);
    }

    #[test]
    fn capabilities_reflect_disabled_groups() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            service_installs_enabled: false,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
            applocker_blocks_enabled: false,
            task_scheduler_op_enabled: false,
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
            applocker_blocks_enabled: false,
            task_scheduler_op_enabled: false,
        });
        assert!(sensor.capabilities().file_events);
    }

    #[test]
    fn applocker_alone_still_sets_file_events() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            service_installs_enabled: false,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
            applocker_blocks_enabled: true,
            task_scheduler_op_enabled: false,
        });
        assert!(sensor.capabilities().file_events);
    }

    #[test]
    fn task_scheduler_op_alone_still_sets_file_events() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            service_installs_enabled: false,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
            applocker_blocks_enabled: false,
            task_scheduler_op_enabled: true,
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
        assert_eq!(counters.applocker_blocks.load(Ordering::Relaxed), 0);
        assert_eq!(counters.task_scheduler_op.load(Ordering::Relaxed), 0);
    }
}
