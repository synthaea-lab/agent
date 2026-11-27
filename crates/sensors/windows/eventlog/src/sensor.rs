//! The Windows-gated sensor: one poll thread per enabled [`PollTarget`] over `EvtQuery`
//! (`query.rs`), or one `EvtSubscribe` subscription per target (`subscribe.rs`). The shared
//! pipeline (cursor, query, normalize, count, sink) exists once; each target contributes its
//! query, parser and normalization.

use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};

use crate::{
    error::EventQueryError,
    query::{Direction, query_events},
    targets::{
        BlockOutcome,
        applocker::normalize_applocker_block,
        defender::normalize_defender_block,
        kerberos::normalize_kerberos_delegation_failure_block,
        log_cleared::normalize_log_cleared_block,
        logon::normalize_logon,
        persistence::{
            normalize_account_created, normalize_scheduled_task, normalize_scheduled_task_update,
            normalize_service_install, normalize_task_scheduler_op_registered,
        },
        session::{normalize_rdp_connection_block, normalize_session_lifecycle_block},
        wdac::normalize_wdac_block,
    },
};

/// The poll cadence of every target: none has sub-second stakes, since the event
/// already exists by the time a tick could see it.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The audit subcategory events 4698 and 4702 depend on (lab, 2026-09-22: 4702 needs
/// nothing more). Referenced by GUID because `auditpol` matches names against the
/// localized label: the English name fails with Win32 error 87 on a French VM.
const SCHEDULED_TASK_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE9227-69AE-11D9-BED3-505054503030}";

/// "Logon" audit subcategory (4624, 4625, 4648), by GUID as above. From Microsoft's
/// published list, not lab-confirmed like the 4698 GUID. It is on in the default audit
/// policy, so enabling it is belt-and-suspenders and a failure is less urgent than an
/// `enable_scheduled_task_audit` one.
const LOGON_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE9215-69AE-11D9-BED3-505054503030}";

/// "Special Logon" audit subcategory (covers 4672) — same caveats as
/// [`LOGON_AUDIT_SUBCATEGORY_GUID`].
const SPECIAL_LOGON_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE921B-69AE-11D9-BED3-505054503030}";

/// "User Account Management" audit subcategory (4720 and the other account events), by
/// GUID as above, from Microsoft's published list and not lab-confirmed. On in the
/// default audit policy of Client and Server SKUs, so a failure to enable is rare and
/// non-blocking.
const USER_ACCOUNT_MGMT_AUDIT_SUBCATEGORY_GUID: &str = "{0CCE9235-69AE-11D9-BED3-505054503030}";

// ── The shared poll pipeline ─────────────────────────────────────────────────
//
// Every target is the same machine: remember the newest `EventRecordID` in the
// channel at startup (no sensor replays history), then poll for anything newer,
// normalize each parsed block, count it and hand it to the sink.

/// One poll target: a channel + `EventID` filter, and how its raw XML blocks
/// become normalized events. Reused as-is by the push-based `subscribe`
/// transport (`subscribe.rs`) — same channel, same filter, same parser: only
/// the delivery mechanism differs between the two transports.
pub(crate) struct PollTarget {
    /// Names the poll thread in logs.
    pub(crate) label: &'static str,
    /// Names this target's silence heartbeat (`cli health`, T1562 alerts) —
    /// see [`EventLogSensor::liveness`].
    heartbeat: &'static str,
    /// Event Log channel (`System` / `Security`).
    pub(crate) channel: &'static str,
    /// The `EventID=...` predicate, without the surrounding `*[System[...]]`.
    pub(crate) id_filter: &'static str,
    /// Which volume counter this target increments.
    pub(crate) counter: fn(&EventLogCounters) -> &AtomicU64,
    /// Parses one `<Event>` XML block into a [`BlockOutcome`].
    pub(crate) parse_block: fn(&str) -> BlockOutcome,
    /// `auditpol` enablement to run once before polling starts, for targets
    /// whose audit subcategory may be off (see each target's enable fn doc).
    pub(crate) enable_audit: Option<fn()>,
    /// Which [`EventLogConfig`] switch gates this target. Carried by the
    /// target itself so adding one is a single entry in [`TARGETS`], with no
    /// parallel array to keep in step (several targets may share a switch).
    enabled: fn(&EventLogConfig) -> bool,
}

/// `EventRecordID` of the newest matching event already in the channel.
fn last_known_record_id(target: &PollTarget) -> Result<u64, EventQueryError> {
    let blocks = query_events(
        target.channel,
        &target_xpath(target, None),
        Direction::Reverse,
        Some(1),
    )?;
    Ok(blocks
        .first()
        .and_then(|block| (target.parse_block)(block).record_id())
        .unwrap_or(0))
}

/// Blocks newer than `since_record_id` (exclusive), oldest to newest.
fn new_blocks(
    target: &PollTarget,
    since_record_id: u64,
) -> Result<Vec<BlockOutcome>, EventQueryError> {
    let blocks = query_events(
        target.channel,
        &target_xpath(target, Some(since_record_id)),
        Direction::Forward,
        None,
    )?;
    Ok(blocks
        .iter()
        .map(|block| (target.parse_block)(block))
        .collect())
}

/// The `XPath` query of `target`, restricted to records after `since_record_id` if given. The
/// `Subscribe` transport wraps `id_filter` the same way.
fn target_xpath(target: &PollTarget, since_record_id: Option<u64>) -> String {
    match since_record_id {
        Some(since) => format!(
            "*[System[({}) and (EventRecordID>{since})]]",
            target.id_filter
        ),
        None => format!("*[System[({})]]", target.id_filter),
    }
}

/// One poll tick: establishes the startup cursor if there is none yet,
/// otherwise forwards everything newer than it. Returns the new cursor.
fn poll_once(
    target: &PollTarget,
    cursor: Option<u64>,
    sink: &dyn EventSink,
    counters: &EventLogCounters,
) -> Result<u64, EventQueryError> {
    let Some(since) = cursor else {
        return last_known_record_id(target);
    };
    let mut newest = since;
    for outcome in new_blocks(target, since)? {
        match outcome {
            BlockOutcome::Unparseable => {}
            BlockOutcome::Filtered { record_id } => newest = newest.max(record_id),
            BlockOutcome::Event { record_id, event } => {
                newest = newest.max(record_id);
                (target.counter)(counters).fetch_add(1, Ordering::Relaxed);
                sink.on_event(event);
            }
        }
    }
    Ok(newest)
}

/// Runs one target's poll loop on its own thread. `liveness` is incremented
/// once per tick that succeeded — events found or not — and never on a failed
/// one (see [`EventLogSensor::liveness`]).
fn poll(
    target: &'static PollTarget,
    sink: Arc<dyn EventSink>,
    stop: Arc<AtomicBool>,
    counters: Arc<EventLogCounters>,
    liveness: Arc<AtomicU64>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // `None` until the startup cursor is read. A channel unreadable at
        // startup must not fall back to record 0 — that would replay its whole
        // history the moment it becomes readable — so the cursor read is
        // retried every tick instead.
        let mut cursor: Option<u64> = None;
        // Warn once per failure streak, not every `POLL_INTERVAL`.
        let mut failing = false;
        tracing::info!(target = target.label, "poll started");
        while !stop.load(Ordering::SeqCst) {
            match poll_once(target, cursor, sink.as_ref(), &counters) {
                Ok(newest) => {
                    if cursor.is_none() {
                        tracing::info!(
                            target = target.label,
                            last_record_id = newest,
                            "poll cursor established"
                        );
                    }
                    cursor = Some(newest);
                    liveness.fetch_add(1, Ordering::Relaxed);
                    if failing {
                        tracing::info!(target = target.label, "poll recovered");
                        failing = false;
                    }
                }
                Err(error) => {
                    if !failing {
                        tracing::warn!(
                            target = target.label,
                            channel = target.channel,
                            %error,
                            "poll failed — this channel reports nothing until it recovers, \
                             and its silence heartbeat stops"
                        );
                        failing = true;
                    }
                }
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        tracing::info!(target = target.label, "poll stopped");
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

static SERVICE_INSTALLS: PollTarget = PollTarget {
    label: "service-install",
    heartbeat: "windows-eventlog:service-install",
    channel: "System",
    id_filter: "EventID=7045",
    counter: |c| &c.service_installs,
    parse_block: normalize_service_install,
    // 7045 lands in the System log unconditionally — nothing to enable.
    enable_audit: None,
    enabled: |c| c.service_installs_enabled,
};

// ── Event 4698 — scheduled task creation (T1053.005) ─────────────────────────

/// Without this subcategory Windows never writes 4698/4702, however they are read.
/// "Other Object Access Events" is not in the default audit policy, so this call is
/// the primary enablement path and its failure warning deserves urgency.
fn enable_scheduled_task_audit() {
    enable_audit_subcategory(
        "Other Object Access Events (events 4698/4702)",
        SCHEDULED_TASK_AUDIT_SUBCATEGORY_GUID,
        "scheduled task persistence detection (T1053.005) will not receive any 4698/4702 \
         events",
    );
}

static SCHEDULED_TASKS: PollTarget = PollTarget {
    label: "scheduled-task",
    heartbeat: "windows-eventlog:scheduled-task",
    channel: "Security",
    id_filter: "EventID=4698",
    counter: |c| &c.scheduled_tasks,
    parse_block: normalize_scheduled_task,
    enable_audit: Some(enable_scheduled_task_audit),
    enabled: |c| c.scheduled_tasks_enabled,
};

/// Own target rather than `EventID=4698 or EventID=4702` on [`SCHEDULED_TASKS`]:
/// the two parse a differently named content field, and a separate volume counter
/// keeps 4702's (much noisier) churn observable on its own. Gated by the same
/// `scheduled_tasks_enabled` toggle — same technique, same audit subcategory.
static SCHEDULED_TASK_UPDATES: PollTarget = PollTarget {
    label: "scheduled-task-update",
    heartbeat: "windows-eventlog:scheduled-task-update",
    channel: "Security",
    id_filter: "EventID=4702",
    counter: |c| &c.scheduled_task_updates,
    parse_block: normalize_scheduled_task_update,
    // Same subcategory as 4698 — already enabled by `SCHEDULED_TASKS`.
    enable_audit: None,
    enabled: |c| c.scheduled_tasks_enabled,
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

static LOGON_EVENTS: PollTarget = PollTarget {
    label: "logon",
    heartbeat: "windows-eventlog:logon",
    channel: "Security",
    // One query across all four IDs (they share the Security channel's single
    // `EventRecordID` sequence), rather than four separate polls hammering the
    // same channel.
    id_filter: "EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672",
    counter: |c| &c.logon_events,
    parse_block: normalize_logon,
    enable_audit: Some(enable_logon_audit),
    enabled: |c| c.logon_events_enabled,
};

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

static ACCOUNT_CREATIONS: PollTarget = PollTarget {
    label: "account-creation",
    heartbeat: "windows-eventlog:account-creation",
    channel: "Security",
    id_filter: "EventID=4720",
    counter: |c| &c.account_creations,
    parse_block: normalize_account_created,
    enable_audit: Some(enable_account_creation_audit),
    enabled: |c| c.account_creations_enabled,
};

static APPLOCKER_BLOCKS: PollTarget = PollTarget {
    label: "applocker-block",
    heartbeat: "windows-eventlog:applocker-block",
    channel: "Microsoft-Windows-AppLocker/EXE and DLL",
    id_filter: "EventID=8003 or EventID=8004",
    counter: |c| &c.applocker_blocks,
    parse_block: normalize_applocker_block,
    // No audit-subcategory toggle: `AppLocker`'s channel is on when `AppLocker` is
    // configured on the host, off otherwise. Enabling it here would need
    // `wevtutil sl <channel> /e:true`, which is best done by the operator's
    // deployment (a disabled channel is a policy decision, not an oversight
    // the sensor should override on its own).
    enable_audit: None,
    enabled: |c| c.applocker_blocks_enabled,
};

static APPLOCKER_MSI_SCRIPT: PollTarget = PollTarget {
    label: "applocker-msi-script",
    heartbeat: "windows-eventlog:applocker-msi-script",
    channel: "Microsoft-Windows-AppLocker/MSI and Script",
    id_filter: "EventID=8006 or EventID=8007",
    counter: |c| &c.applocker_blocks,
    parse_block: normalize_applocker_block,
    enable_audit: None,
    enabled: |c| c.applocker_blocks_enabled,
};

static APPLOCKER_PACKAGED_EXECUTION: PollTarget = PollTarget {
    label: "applocker-packaged-execution",
    heartbeat: "windows-eventlog:applocker-packaged-execution",
    channel: "Microsoft-Windows-AppLocker/Packaged app-Execution",
    id_filter: "EventID=8021 or EventID=8022",
    counter: |c| &c.applocker_blocks,
    parse_block: normalize_applocker_block,
    enable_audit: None,
    enabled: |c| c.applocker_blocks_enabled,
};

static APPLOCKER_PACKAGED_DEPLOYMENT: PollTarget = PollTarget {
    label: "applocker-packaged-deployment",
    heartbeat: "windows-eventlog:applocker-packaged-deployment",
    channel: "Microsoft-Windows-AppLocker/Packaged app-Deployment",
    id_filter: "EventID=8024 or EventID=8025",
    counter: |c| &c.applocker_blocks,
    parse_block: normalize_applocker_block,
    enable_audit: None,
    enabled: |c| c.applocker_blocks_enabled,
};

static TASK_SCHEDULER_OP: PollTarget = PollTarget {
    label: "task-scheduler-op",
    heartbeat: "windows-eventlog:task-scheduler-op",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    id_filter: "EventID=106",
    counter: |c| &c.task_scheduler_op,
    parse_block: normalize_task_scheduler_op_registered,
    // Off by default (Task Scheduler history). Not enabled here: like
    // `AppLocker`'s channel, that is the operator's call (#786).
    enable_audit: None,
    enabled: |c| c.task_scheduler_op_enabled,
};

static DEFENDER_OP: PollTarget = PollTarget {
    label: "defender",
    heartbeat: "windows-eventlog:defender",
    channel: "Microsoft-Windows-Windows Defender/Operational",
    id_filter: "EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5010 \
                or EventID=5012",
    counter: |c| &c.defender,
    parse_block: normalize_defender_block,
    // On by default; a disabled channel is the operator's policy decision, not
    // something the sensor overrides (same stance as `AppLocker`).
    enable_audit: None,
    enabled: |c| c.defender_enabled,
};

static WDAC_OP: PollTarget = PollTarget {
    label: "wdac",
    heartbeat: "windows-eventlog:wdac",
    channel: "Microsoft-Windows-CodeIntegrity/Operational",
    id_filter: "EventID=3076 or EventID=3077",
    counter: |c| &c.wdac,
    parse_block: normalize_wdac_block,
    // The channel is on by default; 3076/3077 only exist once a WDAC policy
    // does. No audit toggle, nothing for the sensor to enable.
    enable_audit: None,
    enabled: |c| c.wdac_enabled,
};

// ── Terminal Services sessions, log clears, Kerberos delegation failures ────
//
// Normalization lives in `targets::{session, log_cleared, kerberos}`.

/// `LocalSessionManager` also writes an RPC trace (59) for every session
/// capability query: 1 444 of 1 588 records on the 2026-10-05 host. The
/// filter names the four lifecycle ids so none of that is ever read.
static SESSION_LIFECYCLE: PollTarget = PollTarget {
    label: "session-lifecycle",
    heartbeat: "windows-eventlog:session-lifecycle",
    channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    id_filter: "EventID=21 or EventID=23 or EventID=24 or EventID=25",
    counter: |c| &c.session_lifecycle,
    parse_block: normalize_session_lifecycle_block,
    enable_audit: None,
    enabled: |c| c.terminal_sessions_enabled,
};

static RDP_CONNECTIONS: PollTarget = PollTarget {
    label: "rdp-connection",
    heartbeat: "windows-eventlog:rdp-connection",
    channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    id_filter: "EventID=1149",
    counter: |c| &c.rdp_connections,
    parse_block: normalize_rdp_connection_block,
    enable_audit: None,
    enabled: |c| c.terminal_sessions_enabled,
};

static SECURITY_LOG_CLEARS: PollTarget = PollTarget {
    label: "security-log-cleared",
    heartbeat: "windows-eventlog:security-log-cleared",
    channel: "Security",
    id_filter: "EventID=1102",
    counter: |c| &c.log_clears,
    parse_block: normalize_log_cleared_block,
    enable_audit: None,
    enabled: |c| c.log_clears_enabled,
};

/// Event ids are per provider and the System log mixes dozens of them, so the
/// filter names the Event Log service's own.
static LOG_FILE_CLEARS: PollTarget = PollTarget {
    label: "log-file-cleared",
    heartbeat: "windows-eventlog:log-file-cleared",
    channel: "System",
    id_filter: "Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=104",
    counter: |c| &c.log_clears,
    parse_block: normalize_log_cleared_block,
    enable_audit: None,
    enabled: |c| c.log_clears_enabled,
};

static KERBEROS_DELEGATION_FAILURES: PollTarget = PollTarget {
    label: "kerberos-delegation-failure",
    heartbeat: "windows-eventlog:kerberos-delegation-failure",
    channel: "Microsoft-Windows-Kerberos/Operational",
    id_filter: "EventID=201 or EventID=202",
    counter: |c| &c.kerberos_delegation_failures,
    parse_block: normalize_kerberos_delegation_failure_block,
    enable_audit: None,
    enabled: |c| c.kerberos_delegation_failures_enabled,
};

// ── Policy-configurable allowlist and volume counters ────────────────────────
//
// Sensor crates depend only on `schema` (`tools/check-deps.py`), so the agent
// converts `policy::EventLogPolicy` into this crate's own `EventLogConfig`.

/// Which transport delivers Event Log records. Both produce identical events
/// through the same [`PollTarget`] parsers and update the same
/// [`EventLogCounters`].
///
/// [`Polling`](EventLogTransport::Polling) is the default: it adds up to
/// `POLL_INTERVAL` of latency but registers no callback with the OS.
/// [`Subscribe`](EventLogTransport::Subscribe) removes the latency and is opted
/// into host by host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLogTransport {
    /// Default `EvtQuery` poll loop, one thread per enabled target.
    Polling,
    /// `EvtSubscribe`-based push delivery via a Windows callback, one
    /// subscription per enabled target.
    Subscribe,
}

impl Default for EventLogTransport {
    /// [`Polling`](EventLogTransport::Polling): the transport changes only when
    /// an operator says so.
    fn default() -> Self {
        Self::Polling
    }
}

/// Which of this sensor's independently toggled targets are active, and which
/// transport delivers them. A disabled target is never queried, so it costs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLogConfig {
    /// Which transport delivers channel events; see [`EventLogTransport`].
    pub transport: EventLogTransport,
    /// Event 7045 (T1543.003 — service install persistence).
    pub service_installs_enabled: bool,
    /// Events 4698 and 4702 (T1053.005 — scheduled task creation and
    /// update). Reads the Security channel; requires `Other Object Access
    /// Events` audit enabled.
    pub scheduled_tasks_enabled: bool,
    /// Event 4720 (T1136.001 — local account creation persistence).
    pub account_creations_enabled: bool,
    /// Events 4624/4625/4648/4672 (logon/session).
    pub logon_events_enabled: bool,
    /// Audit and enforced `AppLocker` decisions from EXE/DLL, MSI/Script,
    /// Packaged app-Execution, and Packaged app-Deployment, reported as
    /// `PolicyDenialEvent`.
    pub applocker_blocks_enabled: bool,
    /// Event 106 (T1053.005 — scheduled task registered via the
    /// `Microsoft-Windows-TaskScheduler/Operational` channel; complements the
    /// 4698 path where Task Scheduler history is enabled, which it is not by
    /// default).
    pub task_scheduler_op_enabled: bool,
    /// Defender Operational: 1116/1117 verdicts and the 5001/5007/5010/5012
    /// tamper traces, reported as `DefenderEvent`.
    pub defender_enabled: bool,
    /// WDAC 3076/3077 on the `CodeIntegrity` Operational channel, reported as
    /// `PolicyDenialEvent` with `POLICY_MECHANISM_WDAC`.
    pub wdac_enabled: bool,
    /// Terminal Services session lifecycle (`LocalSessionManager` 21/23/24/25)
    /// and RDP authentications (`RemoteConnectionManager` 1149), reported as
    /// `SessionEvent`. Console sessions included.
    pub terminal_sessions_enabled: bool,
    /// Security 1102 and System 104, an event log cleared by any means,
    /// reported as `LogClearedEvent`. Both channels are always on.
    pub log_clears_enabled: bool,
    /// Events 201/202 on `Microsoft-Windows-Kerberos/Operational` (unconstrained
    /// delegation and TGT session-key-export denials), reported as
    /// `KerberosDelegationFailureEvent`. That channel is off on a clean install
    /// and this crate does not enable it; [`warn_about_disabled_channels`]
    /// reports it.
    pub kerberos_delegation_failures_enabled: bool,
}

/// Every poll target. Adding one = one entry here: its switch, heartbeat name
/// and liveness counter all follow from it.
static TARGETS: &[&PollTarget] = &[
    &SERVICE_INSTALLS,
    &SCHEDULED_TASKS,
    &SCHEDULED_TASK_UPDATES,
    &ACCOUNT_CREATIONS,
    &LOGON_EVENTS,
    &APPLOCKER_BLOCKS,
    &APPLOCKER_MSI_SCRIPT,
    &APPLOCKER_PACKAGED_EXECUTION,
    &APPLOCKER_PACKAGED_DEPLOYMENT,
    &TASK_SCHEDULER_OP,
    &DEFENDER_OP,
    &WDAC_OP,
    &SESSION_LIFECYCLE,
    &RDP_CONNECTIONS,
    &SECURITY_LOG_CLEARS,
    &LOG_FILE_CLEARS,
    &KERBEROS_DELEGATION_FAILURES,
];

impl Default for EventLogConfig {
    /// Every group enabled.
    fn default() -> Self {
        Self {
            transport: EventLogTransport::default(),
            service_installs_enabled: true,
            scheduled_tasks_enabled: true,
            account_creations_enabled: true,
            logon_events_enabled: true,
            applocker_blocks_enabled: true,
            task_scheduler_op_enabled: true,
            defender_enabled: true,
            wdac_enabled: true,
            terminal_sessions_enabled: true,
            log_clears_enabled: true,
            kerberos_delegation_failures_enabled: true,
        }
    }
}

/// Per-group event counts, incremented once per event normalized and handed to
/// the sink (a skipped block is not volume). Independent `Relaxed` counters,
/// readable from any thread through [`EventLogSensor::counters`] while `run`
/// updates them.
#[derive(Debug, Default)]
pub struct EventLogCounters {
    /// System 7045.
    pub service_installs: AtomicU64,
    /// Security 4698.
    pub scheduled_tasks: AtomicU64,
    /// Security 4702, counted apart from 4698 because it is much noisier.
    pub scheduled_task_updates: AtomicU64,
    /// Security 4720.
    pub account_creations: AtomicU64,
    /// Security 4624, 4625, 4648 and 4672 together.
    pub logon_events: AtomicU64,
    /// `AppLocker` decisions from its four channels together: EXE and DLL (8003, 8004), MSI and
    /// Script (8006, 8007), Packaged app-Execution (8021, 8022) and Packaged app-Deployment
    /// (8024, 8025).
    pub applocker_blocks: AtomicU64,
    /// `Microsoft-Windows-TaskScheduler/Operational` 106.
    pub task_scheduler_op: AtomicU64,
    /// Defender Operational 1116, 1117, 5001, 5007, 5010 and 5012 together.
    pub defender: AtomicU64,
    /// `Microsoft-Windows-CodeIntegrity/Operational` 3076 and 3077 together.
    pub wdac: AtomicU64,
    /// `LocalSessionManager` 21, 23, 24 and 25 together.
    pub session_lifecycle: AtomicU64,
    /// `RemoteConnectionManager` 1149.
    pub rdp_connections: AtomicU64,
    /// Security 1102 and System 104 together.
    pub log_clears: AtomicU64,
    /// `Microsoft-Windows-Kerberos/Operational` 201 and 202 together.
    pub kerberos_delegation_failures: AtomicU64,
    /// Channels found disabled at start-up for an enabled target: each
    /// is polled or subscribed like any other but cannot deliver an event.
    pub disabled_channels: AtomicU64,
}

/// One warning per enabled target channel that is switched off. A disabled
/// channel answers a query with no events and no error, so without this the
/// target looks like a quiet, healthy one and its liveness counter keeps moving.
/// Checked once per channel (several targets share `Security`), at start-up only:
/// a channel switched off while the agent runs is not caught here.
fn warn_about_disabled_channels(config: &EventLogConfig, counters: &EventLogCounters) {
    let mut checked: Vec<&str> = Vec::new();
    for target in TARGETS {
        if !(target.enabled)(config) || checked.contains(&target.channel) {
            continue;
        }
        checked.push(target.channel);
        if crate::channel::is_enabled(target.channel) != Some(false) {
            continue;
        }
        counters.disabled_channels.fetch_add(1, Ordering::Relaxed);
        let targets: Vec<&str> = TARGETS
            .iter()
            .filter(|t| t.channel == target.channel && (t.enabled)(config))
            .map(|t| t.label)
            .collect();
        tracing::warn!(
            channel = target.channel,
            targets = ?targets,
            "event log channel is disabled: these targets will see no events until an              operator enables it (wevtutil sl \"<channel>\" /e:true)"
        );
    }
}

// ── The sensor ────────────────────────────────────────────────────────────────

/// The Windows Event Log sensor: one poll loop or subscription per enabled
/// target, implementing `schema::sensor::Sensor`.
pub struct EventLogSensor {
    stop: Arc<AtomicBool>,
    config: EventLogConfig,
    counters: Arc<EventLogCounters>,
    /// One per [`TARGETS`] entry, same order — see [`Self::liveness`].
    liveness: Vec<Arc<AtomicU64>>,
}

impl EventLogSensor {
    /// Every poll target enabled — equivalent to
    /// `Self::with_config(EventLogConfig::default())`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EventLogConfig::default())
    }

    /// A sensor polling the targets `config` enables, with fresh counters and liveness stamps.
    #[must_use]
    pub fn with_config(config: EventLogConfig) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            config,
            counters: Arc::new(EventLogCounters::default()),
            liveness: TARGETS
                .iter()
                .map(|_| Arc::new(AtomicU64::new(0)))
                .collect(),
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

    /// One liveness counter per **enabled** poll target, named for a silence
    /// monitor (`windows-eventlog:<target>`). Each is incremented once per poll
    /// tick whose query succeeded, events or not: a quiet channel stays live, a
    /// refused one goes dark. Per target so a healthy System poll cannot mask a
    /// silent Security channel. A disabled target is omitted.
    ///
    /// Empty under [`EventLogTransport::Subscribe`]: a push subscription has no
    /// tick, so a counter would stay still on a quiet channel and raise a false
    /// T1562 on a healthy target.
    #[must_use]
    pub fn liveness(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        if self.config.transport == EventLogTransport::Subscribe {
            return Vec::new();
        }
        TARGETS
            .iter()
            .zip(&self.liveness)
            .filter(|(target, _)| (target.enabled)(&self.config))
            .map(|(target, counter)| (target.heartbeat, Arc::clone(counter)))
            .collect()
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
                || self.config.task_scheduler_op_enabled,
            // `AppLocker` (8003/8004) is deliberately absent: it emits
            // `PolicyDenialEvent`, not `FileOpenEvent` (#427), and
            // `Capabilities` has no policy-denial field yet — same as the
            // Linux audit sensor's `SELinux` AVC path.
            auth_events: self.config.logon_events_enabled,
            ..Capabilities::default()
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        self.stop.store(false, Ordering::SeqCst);
        let sink: Arc<dyn EventSink> = Arc::from(sink);

        // Audit enablement decides whether events are written at all, so it
        // runs once up front whatever the transport.
        for target in TARGETS {
            if !(target.enabled)(&self.config) {
                continue;
            }
            if let Some(enable_audit) = target.enable_audit {
                enable_audit();
            }
        }
        warn_about_disabled_channels(&self.config, &self.counters);

        // Declared before `subscriptions` so the subscriptions drop first.
        let mut poll_handles: Vec<std::thread::JoinHandle<()>> = Vec::new();
        #[cfg(windows)]
        let mut subscriptions: Vec<crate::subscribe::SubscriptionHandle> = Vec::new();

        match self.config.transport {
            EventLogTransport::Polling => {
                for (target, liveness) in TARGETS.iter().zip(&self.liveness) {
                    if !(target.enabled)(&self.config) {
                        continue;
                    }
                    poll_handles.push(poll(
                        target,
                        Arc::clone(&sink),
                        Arc::clone(&self.stop),
                        Arc::clone(&self.counters),
                        Arc::clone(liveness),
                    ));
                }
            }
            EventLogTransport::Subscribe => {
                #[cfg(windows)]
                {
                    let mut enabled = 0_usize;
                    for target in TARGETS {
                        if !(target.enabled)(&self.config) {
                            continue;
                        }
                        enabled += 1;
                        // `None` (logged inside `subscribe`) degrades this
                        // channel only.
                        if let Some(handle) = crate::subscribe::subscribe(
                            target,
                            Arc::clone(&sink),
                            Arc::clone(&self.counters),
                            Arc::clone(&self.stop),
                        ) {
                            subscriptions.push(handle);
                        }
                    }
                    // One line that tells a degraded Subscribe transport from a
                    // healthy one; each failure is logged inside `subscribe`.
                    tracing::info!(
                        established = subscriptions.len(),
                        enabled,
                        "event log subscriptions registered"
                    );
                }
            }
        }

        // Subscriptions deliver on OS callback threads; both transports just wait
        // for stop here.
        while !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }

        for handle in poll_handles {
            let _ = handle.join();
        }
        // `subscriptions` drops here, closing each `EvtSubscribe` handle.
        Ok(())
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod config_tests {
    use std::sync::atomic::Ordering;

    use schema::sensor::Sensor;

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
        assert!(config.defender_enabled);
        assert!(config.wdac_enabled);
        assert!(config.terminal_sessions_enabled);
        assert!(config.log_clears_enabled);
    }

    #[test]
    fn default_transport_is_polling() {
        // An upgrade must not change the delivery mechanism of any host.
        assert_eq!(
            EventLogConfig::default().transport,
            EventLogTransport::Polling
        );
    }

    #[test]
    fn subscribe_transport_selectable() {
        let cfg = EventLogConfig {
            transport: EventLogTransport::Subscribe,
            ..Default::default()
        };
        assert_eq!(cfg.transport, EventLogTransport::Subscribe);
        // Toggling transport does not touch the per-channel enable flags.
        assert!(cfg.service_installs_enabled);
        assert!(cfg.logon_events_enabled);
    }

    #[test]
    fn capabilities_reflect_disabled_groups() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            transport: EventLogTransport::default(),
            service_installs_enabled: false,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
            applocker_blocks_enabled: false,
            task_scheduler_op_enabled: false,
            defender_enabled: false,
            wdac_enabled: false,
            terminal_sessions_enabled: false,
            log_clears_enabled: false,
            kerberos_delegation_failures_enabled: false,
        });
        let caps = sensor.capabilities();
        assert!(!caps.file_events);
        assert!(!caps.auth_events);
    }

    #[test]
    fn capabilities_stay_true_if_any_file_group_enabled() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            transport: EventLogTransport::default(),
            service_installs_enabled: true,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
            applocker_blocks_enabled: false,
            task_scheduler_op_enabled: false,
            defender_enabled: false,
            wdac_enabled: false,
            terminal_sessions_enabled: false,
            log_clears_enabled: false,
            kerberos_delegation_failures_enabled: false,
        });
        assert!(sensor.capabilities().file_events);
    }

    #[test]
    fn applocker_alone_no_longer_sets_file_events() {
        // #427: `AppLocker` verdicts are `PolicyDenialEvent`s now, not
        // `FileOpenEvent`s — declaring `file_events` would be a false claim.
        let sensor = EventLogSensor::with_config(EventLogConfig {
            service_installs_enabled: false,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
            applocker_blocks_enabled: true,
            task_scheduler_op_enabled: false,
            defender_enabled: false,
            wdac_enabled: false,
            terminal_sessions_enabled: false,
            log_clears_enabled: false,
            kerberos_delegation_failures_enabled: false,
            transport: EventLogTransport::default(),
        });
        assert!(!sensor.capabilities().file_events);
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
            defender_enabled: false,
            wdac_enabled: false,
            terminal_sessions_enabled: false,
            log_clears_enabled: false,
            kerberos_delegation_failures_enabled: false,
            transport: EventLogTransport::default(),
        });
        assert!(sensor.capabilities().file_events);
    }

    #[test]
    fn counters_start_at_zero() {
        let sensor = EventLogSensor::new();
        let counters = sensor.counters();
        assert_eq!(counters.service_installs.load(Ordering::Relaxed), 0);
        assert_eq!(counters.scheduled_tasks.load(Ordering::Relaxed), 0);
        assert_eq!(counters.scheduled_task_updates.load(Ordering::Relaxed), 0);
        assert_eq!(counters.account_creations.load(Ordering::Relaxed), 0);
        assert_eq!(counters.logon_events.load(Ordering::Relaxed), 0);
        assert_eq!(counters.applocker_blocks.load(Ordering::Relaxed), 0);
        assert_eq!(counters.task_scheduler_op.load(Ordering::Relaxed), 0);
        assert_eq!(counters.defender.load(Ordering::Relaxed), 0);
        assert_eq!(counters.wdac.load(Ordering::Relaxed), 0);
        assert_eq!(counters.session_lifecycle.load(Ordering::Relaxed), 0);
        assert_eq!(counters.rdp_connections.load(Ordering::Relaxed), 0);
        assert_eq!(counters.log_clears.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn liveness_covers_every_target_by_default_with_distinct_names() {
        let names: Vec<_> = EventLogSensor::new()
            .liveness()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            [
                "windows-eventlog:service-install",
                "windows-eventlog:scheduled-task",
                "windows-eventlog:scheduled-task-update",
                "windows-eventlog:account-creation",
                "windows-eventlog:logon",
                "windows-eventlog:applocker-block",
                "windows-eventlog:applocker-msi-script",
                "windows-eventlog:applocker-packaged-execution",
                "windows-eventlog:applocker-packaged-deployment",
                "windows-eventlog:task-scheduler-op",
                "windows-eventlog:defender",
                "windows-eventlog:wdac",
                "windows-eventlog:session-lifecycle",
                "windows-eventlog:rdp-connection",
                "windows-eventlog:security-log-cleared",
                "windows-eventlog:log-file-cleared",
                "windows-eventlog:kerberos-delegation-failure",
            ]
        );
    }

    #[test]
    fn liveness_omits_disabled_targets() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            service_installs_enabled: false,
            scheduled_tasks_enabled: true,
            account_creations_enabled: false,
            logon_events_enabled: true,
            applocker_blocks_enabled: false,
            task_scheduler_op_enabled: false,
            defender_enabled: false,
            wdac_enabled: false,
            terminal_sessions_enabled: false,
            log_clears_enabled: false,
            kerberos_delegation_failures_enabled: false,
            transport: EventLogTransport::Polling,
        });
        let names: Vec<_> = sensor.liveness().into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "windows-eventlog:scheduled-task",
                "windows-eventlog:scheduled-task-update",
                "windows-eventlog:logon"
            ]
        );
    }

    #[test]
    fn subscribe_transport_exposes_no_liveness_counters() {
        let sensor = EventLogSensor::with_config(EventLogConfig {
            transport: EventLogTransport::Subscribe,
            ..EventLogConfig::default()
        });
        assert!(
            sensor.liveness().is_empty(),
            "a push subscription has no poll tick: watching it would raise false T1562"
        );
    }

    #[test]
    fn every_target_has_a_distinct_heartbeat_name() {
        let mut names: Vec<_> = TARGETS.iter().map(|t| t.heartbeat).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TARGETS.len(), "two targets share a heartbeat");
        assert!(names.iter().all(|n| n.starts_with("windows-eventlog:")));
    }

    #[test]
    fn liveness_handles_share_the_sensor_counters() {
        let sensor = EventLogSensor::new();
        let (_, first) = &sensor.liveness()[0];
        first.fetch_add(1, Ordering::Relaxed);
        assert_eq!(sensor.liveness()[0].1.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod query_tests {
    use std::{process::Command, sync::atomic::Ordering};

    use schema::Event;

    use super::*;
    use crate::{
        query::{Direction, query_events},
        targets::BlockOutcome,
        xml::{self},
    };

    /// Writes one Application event whose only insertion string is `text`, from an
    /// unregistered source: no admin rights needed.
    fn write_application_event(text: &str) {
        use windows_sys::Win32::System::EventLog::{
            DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW, ReportEventW,
        };
        let source: Vec<u16> = TEST_SOURCE
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let strings = [wide.as_ptr()];
        // SAFETY: `source` is a NUL-terminated UTF-16 string alive for the call; a null server
        // name is the local host.
        let log = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
        assert!(!log.is_null(), "RegisterEventSourceW failed");
        // SAFETY: `log` is the handle opened above; `strings` holds one pointer to a
        // NUL-terminated UTF-16 string alive for the call; no SID, no raw data.
        let ok = unsafe {
            ReportEventW(
                log,
                EVENTLOG_INFORMATION_TYPE,
                0,
                1126,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        };
        // SAFETY: `log` was opened above and is closed once, here.
        unsafe { DeregisterEventSource(log) };
        assert_ne!(ok, 0, "ReportEventW failed");
    }

    const TEST_SOURCE: &str = "Synthaea-test-1126";

    fn record_ids(blocks: &[String]) -> Vec<u64> {
        blocks
            .iter()
            .filter_map(|b| {
                xml::extract_between(b, "<EventRecordID>", "</EventRecordID>")?
                    .parse()
                    .ok()
            })
            .collect()
    }

    /// #1126: the polling transport read `wevtutil`'s stdout, which is in the ANSI code page,
    /// so a name that page cannot hold (Cyrillic or CJK on a Windows-1252 host) reached the
    /// rules as `?`s, and two such accounts as one string. Read through `EvtQuery`, the event's
    /// text comes back as written, whatever the host's code page.
    #[test]
    fn a_non_ascii_name_is_read_back_from_the_channel_as_written() {
        let text = format!("Système Дмитрий 山田太郎 andrè {}", std::process::id());
        write_application_event(&text);
        let query = format!("*[System[Provider[@Name='{TEST_SOURCE}'] and (EventID=1126)]]");
        let blocks = query_events("Application", &query, Direction::Reverse, Some(20))
            .expect("the Application channel is readable unelevated");
        assert!(
            blocks.iter().any(|block| block.contains(&text)),
            "the event was not read back intact: {blocks:?}"
        );
        assert!(blocks.iter().all(|block| !block.contains('\u{FFFD}')));
    }

    /// The logon path from a block as `EvtRender` gives it: a non-ASCII account name reaches
    /// the `AuthEvent` intact, and two names that differ by one accented letter stay two users
    /// (both were `andr\u{FFFD}` before #1126).
    #[test]
    fn a_non_ascii_account_name_reaches_the_auth_event_intact() {
        let user_of = |name: &str| {
            let block = format!(
                "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
                 <EventID>4624</EventID><TimeCreated SystemTime='2026-11-05T10:00:00.0000000Z'/>\
                 <EventRecordID>7</EventRecordID><Execution ProcessID='836' ThreadID='1'/>\
                 </System><EventData><Data Name='TargetUserSid'>S-1-5-21-1-2-3-1001</Data>\
                 <Data Name='TargetUserName'>{name}</Data><Data Name='LogonType'>2</Data>\
                 </EventData></Event>"
            );
            match normalize_logon(&block) {
                BlockOutcome::Event {
                    record_id: 7,
                    event: Event::Auth(auth),
                } => auth.target_user,
                other => panic!("{name}: {other:?}"),
            }
        };
        for name in ["Système", "Дмитрий", "山田太郎"] {
            assert_eq!(user_of(name), name);
        }
        assert_ne!(user_of("andré"), user_of("andrè"));
    }

    /// The `EvtQuery` read picks the records `wevtutil` picked, newest first with a limit and
    /// oldest first after a cursor, so swapping the transport moves no poll cursor.
    #[test]
    fn the_query_reads_the_records_wevtutil_reads() {
        let out = Command::new("wevtutil")
            .args(["qe", "System", "/c:5", "/rd:true", "/f:xml"])
            .output()
            .expect("wevtutil runs");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let wevtutil_blocks: Vec<String> = xml::split_event_blocks(&text)
            .into_iter()
            .map(str::to_string)
            .collect();

        let newest = query_events("System", "*", Direction::Reverse, Some(5)).expect("System");
        let newest = record_ids(&newest);
        assert_eq!(newest.len(), 5);
        assert_eq!(newest, record_ids(&wevtutil_blocks));

        let query = format!(
            "*[System[(EventRecordID>{}) and (EventRecordID<={})]]",
            newest[4], newest[0]
        );
        let forward = query_events("System", &query, Direction::Forward, None).expect("System");
        let mut expected = newest[..4].to_vec();
        expected.reverse();
        assert_eq!(record_ids(&forward), expected);
    }

    #[test]
    fn a_query_matching_nothing_is_a_success_with_no_events() {
        let blocks = query_events(
            "System",
            "*[System[(EventID=99999)]]",
            Direction::Reverse,
            Some(1),
        )
        .expect("an empty result is not a failure");
        assert!(blocks.is_empty());
    }

    /// #388: a refused or misspelt channel must not look like a quiet one.
    #[test]
    fn a_failing_query_is_an_error_not_an_empty_result() {
        let err = query_events("Synthaea-No-Such-Channel", "*", Direction::Reverse, Some(1))
            .expect_err("an unknown channel must not look like a quiet one");
        assert!(err.to_string().contains("Win32 error"), "{err}");
    }

    #[test]
    fn a_malformed_query_is_an_error() {
        let err = query_events("System", "*[System[(EventID=", Direction::Forward, None)
            .expect_err("a malformed XPath fails every poll, so it must be an error");
        assert!(err.to_string().contains("Win32 error"), "{err}");
    }

    #[test]
    fn the_session_channels_exist_unelevated_and_accept_their_filters() {
        // A misspelt channel would fail every poll and silence the target
        // for good; unit tests on XML strings cannot see it.
        for target in [&SESSION_LIFECYCLE, &RDP_CONNECTIONS] {
            last_known_record_id(target)
                .unwrap_or_else(|e| panic!("{} on {}: {e}", target.label, target.channel));
        }
    }

    /// The 104 filter is the only one naming a provider: a malformed `XPath`
    /// there would fail every poll. System is readable unelevated; Security
    /// (1102) is not, and its filter is a plain id.
    #[test]
    fn the_log_file_cleared_filter_is_accepted_on_the_system_log() {
        last_known_record_id(&LOG_FILE_CLEARS).expect("System 104 query");
    }

    /// #786: what the start-up check reports does not depend on the host. Each
    /// disabled channel counts once, however many targets read it.
    #[test]
    fn each_disabled_target_channel_is_counted_once() {
        let config = EventLogConfig::default();
        let mut channels: Vec<&str> = TARGETS
            .iter()
            .filter(|t| (t.enabled)(&config))
            .map(|t| t.channel)
            .collect();
        channels.sort_unstable();
        channels.dedup();
        let disabled = channels
            .iter()
            .filter(|c| crate::channel::is_enabled(c) == Some(false))
            .count() as u64;

        let counters = EventLogCounters::default();
        warn_about_disabled_channels(&config, &counters);
        assert_eq!(counters.disabled_channels.load(Ordering::Relaxed), disabled);
    }

    /// #786: a disabled channel answers a query with exit 0 and no events, the
    /// same as a quiet one. That is why the poll loop cannot tell them apart and
    /// the start-up check above exists. Ignored: it needs a channel that is off
    /// on this host (Task Scheduler history is, on a default client install).
    #[test]
    #[ignore = "needs Microsoft-Windows-TaskScheduler/Operational disabled on this host"]
    fn a_disabled_channel_looks_like_a_quiet_one_to_a_query() {
        assert_eq!(
            crate::channel::is_enabled(TASK_SCHEDULER_OP.channel),
            Some(false),
            "precondition: Task Scheduler history is off here"
        );
        let blocks = query_events(TASK_SCHEDULER_OP.channel, "*", Direction::Reverse, Some(1))
            .expect("a disabled channel is not a failing query");
        assert!(blocks.is_empty());
    }
}

#[cfg(test)]
mod scheduled_task_tests {
    use std::path::Path;

    use schema::{Event, FLAG_PERSISTENCE_TASK_ARTIFACT, FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT};

    use super::*;
    use crate::{
        targets::{BlockOutcome, persistence::normalize_task_registered_from},
        xml::{self},
    };

    /// Minimal 4698 block: only the fields `parse_scheduled_task_block` reads.
    fn block_4698(task_content_escaped: &str) -> String {
        format!(
            "<Event><System><EventID>4698</EventID><EventRecordID>42</EventRecordID></System><EventData><Data Name='TaskName'>\\HiddenTask</Data><Data Name='TaskContent'>{task_content_escaped}</Data><Data Name='ClientProcessId'>1234</Data></EventData></Event>"
        )
    }

    #[test]
    fn task_with_no_readable_action_is_still_reported() {
        let block = block_4698(
            "&lt;Task&gt;&lt;Actions&gt;&lt;ComHandler/&gt;&lt;/Actions&gt;&lt;/Task&gt;",
        );
        let BlockOutcome::Event {
            record_id: 42,
            event: Event::FileOpen(event),
        } = normalize_scheduled_task(&block)
        else {
            panic!("a 4698 must never be dropped (#422)");
        };
        assert_eq!(event.path, xml::TASK_ACTION_UNKNOWN);
        assert_eq!(
            event.flags,
            FLAG_PERSISTENCE_TASK_ARTIFACT | schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN
        );
        assert_eq!(event.meta.comm, "HiddenTask");
        assert_eq!(event.meta.pid, 1234);
    }

    #[test]
    fn task_with_several_actions_reports_all_of_them() {
        let block = block_4698(
            "&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;a.exe&lt;/Command&gt;&lt;/Exec&gt;&lt;ComHandler&gt;&lt;ClassId&gt;{X}&lt;/ClassId&gt;&lt;/ComHandler&gt;&lt;/Actions&gt;",
        );
        let BlockOutcome::Event {
            record_id: 42,
            event: Event::FileOpen(event),
        } = normalize_scheduled_task(&block)
        else {
            panic!("expected a FileOpen event");
        };
        assert_eq!(event.path, "a.exe | com:{X}");
        assert_eq!(event.flags, FLAG_PERSISTENCE_TASK_ARTIFACT);
    }

    /// Minimal 4702 block: same fields as [`block_4698`], content in `TaskContentNew`.
    fn block_4702(task_content_escaped: &str) -> String {
        format!(
            "<Event><System><EventID>4702</EventID><EventRecordID>43</EventRecordID></System><EventData><Data Name='TaskName'>\\BackupTask</Data><Data Name='TaskContentNew'>{task_content_escaped}</Data><Data Name='ClientProcessId'>1234</Data></EventData></Event>"
        )
    }

    #[test]
    fn task_update_reports_every_action_not_only_the_first() {
        let block = block_4702(
            "&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;C:\\legit\\backup.exe&lt;/Command&gt;&lt;/Exec&gt;&lt;Exec&gt;&lt;Command&gt;C:\\Users\\Public\\evil.exe&lt;/Command&gt;&lt;/Exec&gt;&lt;/Actions&gt;",
        );
        let BlockOutcome::Event {
            record_id: 43,
            event: Event::FileOpen(event),
        } = normalize_scheduled_task_update(&block)
        else {
            panic!("expected a FileOpen event");
        };
        assert_eq!(
            event.path,
            r"C:\legit\backup.exe | C:\Users\Public\evil.exe"
        );
        assert_eq!(event.flags, FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT);
        assert_eq!(event.meta.comm, "BackupTask");
    }

    #[test]
    fn task_update_with_no_readable_action_is_still_reported() {
        let block = block_4702(
            "&lt;Task&gt;&lt;Actions&gt;&lt;ComHandler/&gt;&lt;/Actions&gt;&lt;/Task&gt;",
        );
        let BlockOutcome::Event {
            record_id: 43,
            event: Event::FileOpen(event),
        } = normalize_scheduled_task_update(&block)
        else {
            panic!("an unreadable 4702 must be reported, not dropped");
        };
        assert_eq!(event.path, xml::TASK_ACTION_UNKNOWN);
        assert_eq!(
            event.flags,
            FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT | schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN
        );
    }

    /// Minimal TaskScheduler/Operational 106 block for task `task_name`.
    fn block_106(task_name: &str) -> String {
        format!(
            "<Event><System><EventID>106</EventID><EventRecordID>44</EventRecordID><Execution ProcessID='2124' ThreadID='1'/></System><EventData><Data Name='TaskName'>{task_name}</Data><Data Name='UserContext'>LAB\\victim</Data></EventData></Event>"
        )
    }

    /// Writes `content` as Task Scheduler does: UTF-16LE with a BOM.
    fn write_task_file(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().expect("has a parent")).expect("mkdir");
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(content.encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(path, bytes).expect("write task file");
    }

    #[test]
    fn task_registration_106_reports_the_actions_read_back_from_the_task_file() {
        let tasks = tempfile::tempdir().expect("tempdir");
        write_task_file(
            &tasks.path().join("Folder").join("EvilTask"),
            r"<Task><Actions><Exec><Command>C:\Users\Public\evil.exe</Command><Arguments>-q</Arguments></Exec></Actions></Task>",
        );
        let block = block_106(r"\Folder\EvilTask");
        let BlockOutcome::Event {
            record_id: 44,
            event: Event::FileOpen(event),
        } = normalize_task_registered_from(&block, Some(tasks.path()))
        else {
            panic!("expected a FileOpen event");
        };
        assert_eq!(event.path, r"C:\Users\Public\evil.exe -q");
        assert_eq!(event.flags, FLAG_PERSISTENCE_TASK_ARTIFACT);
        assert_eq!(event.meta.comm, "EvilTask");
    }

    #[test]
    fn task_registration_106_never_reports_the_task_name_as_an_action_path() {
        // Regression (#422): with no readable definition (task already deleted,
        // or an unsafe name) the path was the task name, printed as an executable.
        let tasks = tempfile::tempdir().expect("tempdir");
        for name in [r"\GoneTask", r"\..\outside"] {
            let block = block_106(name);
            let BlockOutcome::Event {
                record_id: 44,
                event: Event::FileOpen(event),
            } = normalize_task_registered_from(&block, Some(tasks.path()))
            else {
                panic!("a 106 must be reported, not dropped: {name}");
            };
            assert_eq!(event.path, xml::TASK_ACTION_UNKNOWN, "{name}");
            assert_eq!(
                event.flags,
                FLAG_PERSISTENCE_TASK_ARTIFACT | schema::FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN
            );
        }
    }

    #[test]
    fn task_registration_106_over_the_size_cap_is_not_parsed() {
        let tasks = tempfile::tempdir().expect("tempdir");
        let padding = " ".repeat(usize::try_from(xml::MAX_TASK_DEFINITION_BYTES).unwrap());
        write_task_file(
            &tasks.path().join("Huge"),
            &format!(
                "<Task><Actions><Exec><Command>a.exe</Command></Exec></Actions>{padding}</Task>"
            ),
        );
        let BlockOutcome::Event {
            record_id: 44,
            event: Event::FileOpen(event),
        } = normalize_task_registered_from(&block_106(r"\Huge"), Some(tasks.path()))
        else {
            panic!("expected a FileOpen event");
        };
        assert_eq!(event.path, xml::TASK_ACTION_UNKNOWN);
    }
}

#[cfg(test)]
mod applocker_tests {

    use schema::{Event, POLICY_MECHANISM_APPLOCKER, PolicyDenialEvent, User};

    use super::*;
    use crate::targets::BlockOutcome;

    fn applocker_block(event_id: u32) -> String {
        format!(
            "<Event><System><EventID>{event_id}</EventID><EventRecordID>7</EventRecordID><Execution ProcessID='4242' ThreadID='1'/></System>\
            <UserData><RuleAndFileData><PolicyName>EXE</PolicyName>\
            <TargetUser>S-1-5-21-1-2-3-1001</TargetUser><TargetProcessId>42</TargetProcessId>\
            <FilePath>%OSDRIVE%\\USERS\\X\\EVIL.EXE</FilePath></RuleAndFileData></UserData></Event>"
        )
    }

    fn policy_denial(event_id: u32) -> PolicyDenialEvent {
        match normalize_applocker_block(&applocker_block(event_id)) {
            BlockOutcome::Event {
                record_id: 7,
                event: Event::PolicyDenial(denial),
            } => denial,
            other => panic!("expected a PolicyDenial event, got {other:?}"),
        }
    }

    fn applocker_decision_xml(event_id: u32, channel: &str, policy_name: &str) -> String {
        let object = if policy_name == "APPX" {
            "<PackageLength>14</PackageLength><Package>Contoso.Reader</Package>"
        } else if policy_name == "SCRIPT" {
            "<FilePathLength>18</FilePathLength><FilePath>C:\\Users\\X\\RUN.PS1</FilePath>"
        } else {
            "<FilePathLength>22</FilePathLength><FilePath>C:\\Users\\X\\INSTALL.MSI</FilePath>"
        };
        let policy_length = policy_name.len();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-AppLocker' Guid='{{cbda4dbf-8d5d-4f69-9578-be14aa540d22}}'/><EventID Qualifiers='0'>{event_id}</EventID><Version>0</Version><Level>2</Level><TimeCreated SystemTime='2026-10-01T12:00:00.0000000Z'/><EventRecordID>991</EventRecordID><Correlation/><Execution ProcessID=\"4242\" ThreadID=\"8\"/><Channel>{channel}</Channel><Computer>HOST</Computer><Security UserID='S-1-5-21-1-2-3-1001'/></System><UserData><RuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'><PolicyNameLength>{policy_length}</PolicyNameLength><PolicyName>{policy_name}</PolicyName><RuleId>{{00000000-0000-0000-0000-000000000000}}</RuleId><RuleNameLength>4</RuleNameLength><RuleName>Rule</RuleName><RuleSddlLength>1</RuleSddlLength><RuleSddl>-</RuleSddl><TargetUser>S-1-5-21-1-2-3-1001</TargetUser><TargetProcessId>7777</TargetProcessId>{object}<FqbnLength>1</FqbnLength><Fqbn>-</Fqbn></RuleAndFileData></UserData></Event>"
        )
    }

    #[test]
    fn applocker_other_channels_reuse_policy_denial_and_ignore_localized_channel_text() {
        for (event_id, channel, policy_name, enforced, action) in [
            (
                8006,
                "Microsoft-Windows-AppLocker/MSI et Script",
                "MSI",
                false,
                "execute",
            ),
            (
                8007,
                "Microsoft-Windows-AppLocker/MSI et Script",
                "MSI",
                true,
                "execute",
            ),
            (
                8006,
                "Microsoft-Windows-AppLocker/MSI et Script",
                "SCRIPT",
                false,
                "execute",
            ),
            (
                8007,
                "Microsoft-Windows-AppLocker/MSI et Script",
                "SCRIPT",
                true,
                "execute",
            ),
            (
                8021,
                "Microsoft-Windows-AppLocker/Packaged app-Execution",
                "APPX",
                false,
                "execute",
            ),
            (
                8022,
                "Microsoft-Windows-AppLocker/Packaged app-Execution",
                "APPX",
                true,
                "execute",
            ),
            (
                8024,
                "Microsoft-Windows-AppLocker/Packaged app-Deployment",
                "APPX",
                false,
                "install",
            ),
            (
                8025,
                "Microsoft-Windows-AppLocker/Packaged app-Deployment",
                "APPX",
                true,
                "install",
            ),
        ] {
            let block = applocker_decision_xml(event_id, channel, policy_name);
            let BlockOutcome::Event {
                record_id: 991,
                event: Event::PolicyDenial(denial),
            } = normalize_applocker_block(&block)
            else {
                panic!("event {event_id} should reuse PolicyDenial");
            };
            assert_eq!(denial.mechanism, POLICY_MECHANISM_APPLOCKER);
            assert_eq!(denial.enforced, enforced, "event id {event_id}");
            assert_eq!(denial.object_class.as_deref(), Some(policy_name));
            assert_eq!(
                denial.action.as_deref(),
                Some(action),
                "event id {event_id}"
            );
            assert_eq!(denial.meta.pid, 4242, "event id {event_id}");
            assert_eq!(
                denial.object_path.as_deref(),
                Some(if policy_name == "APPX" {
                    "Contoso.Reader"
                } else if policy_name == "SCRIPT" {
                    "C:\\Users\\X\\RUN.PS1"
                } else {
                    "C:\\Users\\X\\INSTALL.MSI"
                }),
                "event id {event_id}"
            );
        }
    }

    #[test]
    fn applocker_allow_events_and_unrecognized_ids_are_skipped() {
        for event_id in [8005, 8020, 8023, 8035, 8028, 8029, 8999] {
            let outcome = normalize_applocker_block(&applocker_decision_xml(
                event_id,
                "localized channel name",
                "APPX",
            ));
            assert_eq!(
                outcome,
                BlockOutcome::Filtered { record_id: 991 },
                "event id {event_id} is not a denial"
            );
        }
    }

    #[test]
    fn applocker_8004_is_an_enforced_policy_denial() {
        let denial = policy_denial(8004);
        assert_eq!(denial.mechanism, POLICY_MECHANISM_APPLOCKER);
        assert!(denial.enforced);
        assert_eq!(denial.object_class.as_deref(), Some("EXE"));
        assert_eq!(denial.action.as_deref(), Some("execute"));
        let path = denial.object_path.expect("object_path");
        assert!(
            !path.starts_with('%'),
            "path variable left unexpanded: {path}"
        );
        assert!(path.ends_with("\\USERS\\X\\EVIL.EXE"), "{path}");
        // The launcher (Execution ProcessID), not the image's TargetProcessId.
        assert_eq!(denial.meta.pid, 4242);
        assert!(
            denial.meta.comm.is_empty(),
            "comm must not name the refused image: {}",
            denial.meta.comm
        );
        assert_eq!(
            denial.meta.user,
            User::Windows {
                sid: "S-1-5-21-1-2-3-1001".into(),
                integrity_level: None,
            }
        );
    }

    #[test]
    fn applocker_prefers_full_file_path_over_the_expanded_variable_path() {
        // Trimmed from the real 8003 captured in the lab (#427, see xml/records/applocker.rs).
        let block = "<Event><System><EventID>8003</EventID><EventRecordID>24</EventRecordID></System>\
            <UserData><RuleAndFileData><PolicyName>EXE</PolicyName>\
            <TargetUser>S-1-5-21-1-2-3-1001</TargetUser><TargetProcessId>7092</TargetProcessId>\
            <FilePath>%OSDRIVE%\\USERS\\PUBLIC\\TEST8003.EXE</FilePath>\
            <FullFilePath>C:\\Users\\Public\\test8003.exe</FullFilePath>\
            </RuleAndFileData></UserData></Event>";
        let outcome = normalize_applocker_block(block);
        let BlockOutcome::Event {
            event: Event::PolicyDenial(denial),
            ..
        } = outcome
        else {
            panic!("expected a PolicyDenial event, got {outcome:?}");
        };
        assert!(!denial.enforced);
        assert_eq!(
            denial.object_path.as_deref(),
            Some("C:\\Users\\Public\\test8003.exe")
        );
    }

    #[test]
    fn a_real_8004_is_an_enforced_denial_of_its_full_file_path() {
        // Trimmed from the real 8004 captured in the lab (#529, see xml/records/applocker.rs).
        let block = "<Event><System><EventID>8004</EventID><EventRecordID>29</EventRecordID><Execution ProcessID='7764' ThreadID='8072'/></System>\
            <UserData><RuleAndFileData><PolicyName>EXE</PolicyName>\
            <TargetUser>S-1-5-21-1-2-3-1001</TargetUser><TargetProcessId>9184</TargetProcessId>\
            <FilePath>%OSDRIVE%\\USERS\\PUBLIC\\TEST8004.EXE</FilePath>\
            <FileHashLength>0</FileHashLength><FileHash></FileHash><Fqbn>-</Fqbn>\
            <FullFilePath>C:\\Users\\Public\\test8004.exe</FullFilePath>\
            </RuleAndFileData></UserData></Event>";
        let outcome = normalize_applocker_block(block);
        let BlockOutcome::Event {
            record_id: 29,
            event: Event::PolicyDenial(denial),
        } = outcome
        else {
            panic!("expected a PolicyDenial event, got {outcome:?}");
        };
        assert!(denial.enforced);
        assert_eq!(
            denial.object_path.as_deref(),
            Some("C:\\Users\\Public\\test8004.exe")
        );
        assert_eq!(denial.meta.pid, 7764);
    }

    #[test]
    fn applocker_8003_is_an_audit_mode_policy_denial() {
        let denial = policy_denial(8003);
        assert_eq!(denial.mechanism, POLICY_MECHANISM_APPLOCKER);
        assert!(!denial.enforced);
    }

    #[test]
    fn applocker_unknown_event_id_is_skipped_but_advances_the_cursor() {
        assert_eq!(
            normalize_applocker_block(&applocker_block(8002)),
            BlockOutcome::Filtered { record_id: 7 }
        );
    }

    #[test]
    fn applocker_without_file_path_is_skipped() {
        let block = "<Event><System><EventID>8004</EventID><EventRecordID>9</EventRecordID></System>\
            <UserData><RuleAndFileData><PolicyName>EXE</PolicyName></RuleAndFileData></UserData></Event>";
        assert_eq!(
            normalize_applocker_block(block),
            BlockOutcome::Filtered { record_id: 9 }
        );
    }
}

#[cfg(test)]
mod defender_wdac_tests {

    use schema::{
        DefenderEvent, DefenderEventKind, Event, POLICY_MECHANISM_WDAC, PolicyDenialEvent,
    };

    use super::*;
    use crate::targets::{BlockOutcome, defender::DEFENDER_PATH_MAX_CHARS};

    fn defender_block(event_id: u32, data: &str) -> String {
        format!(
            "<Event><System><EventID>{event_id}</EventID><EventRecordID>31</EventRecordID></System><EventData>{data}</EventData></Event>"
        )
    }

    fn defender_event(block: &str) -> DefenderEvent {
        match normalize_defender_block(block) {
            BlockOutcome::Event {
                record_id: 31,
                event: Event::Defender(e),
            } => e,
            other => panic!("expected a DefenderEvent, got {other:?}"),
        }
    }

    fn skipped(block: &str) -> bool {
        matches!(
            normalize_defender_block(block),
            BlockOutcome::Filtered { record_id: 31 }
        )
    }

    const DETECTION: &str = "<Data Name='Detection ID'>{AAAA}</Data><Data Name='Threat Name'>Trojan:Win32/Lab.A</Data><Data Name='Severity ID'>5</Data><Data Name='Category ID'>8</Data><Data Name='Process Name'>Unknown</Data><Data Name='Detection User'>LAB\\alice</Data><Data Name='Path'>file:_C:\\Users\\Public\\x.exe</Data><Data Name='Action ID'>9</Data>";

    #[test]
    fn a_detection_keeps_ids_and_drops_the_action_of_a_non_remediation() {
        let e = defender_event(&defender_block(1116, DETECTION));
        assert_eq!(e.kind, DefenderEventKind::Detection);
        assert_eq!(e.threat_name.as_deref(), Some("Trojan:Win32/Lab.A"));
        assert_eq!((e.severity_id, e.category_id), (Some(5), Some(8)));
        assert_eq!(
            e.action_id, None,
            "1116 carries `Action ID` 9 = not applicable"
        );
        assert_eq!(e.user.as_deref(), Some(r"LAB\alice"));
        assert_eq!(e.process_name, None);
        assert_eq!(e.meta.pid, 0);
        let r = defender_event(&defender_block(1117, &DETECTION.replace(">9<", ">3<")));
        assert_eq!(r.kind, DefenderEventKind::Remediation);
        assert_eq!(r.action_id, Some(3));
    }

    #[test]
    fn a_command_line_detection_path_is_cut() {
        let long = "x".repeat(DEFENDER_PATH_MAX_CHARS * 3);
        let data = format!(
            "<Data Name='Threat Name'>HackTool:Win32/Lab.B</Data><Data Name='Path'>CmdLine:_{long}</Data>"
        );
        let e = defender_event(&defender_block(1116, &data));
        assert_eq!(e.path.unwrap().chars().count(), DEFENDER_PATH_MAX_CHARS);
    }

    #[test]
    fn a_detection_without_a_threat_name_is_skipped() {
        assert!(skipped(&defender_block(
            1116,
            "<Data Name='Severity ID'>4</Data>"
        )));
    }

    #[test]
    fn protection_turned_off_uses_fixed_english_labels() {
        for (id, label) in [
            (5001, "real-time protection"),
            (5010, "spyware scanning"),
            (5012, "virus scanning"),
        ] {
            let e = defender_event(&defender_block(
                id,
                "<Data Name='Product Name'>Antivirus Microsoft Defender</Data>",
            ));
            assert_eq!(e.kind, DefenderEventKind::ProtectionDisabled, "{id}");
            assert_eq!(e.setting.as_deref(), Some(label), "{id}");
        }
    }

    #[test]
    fn an_exclusion_added_keeps_path_and_value() {
        let data = r"<Data Name='Old Value'></Data><Data Name='New Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0</Data>";
        let e = defender_event(&defender_block(5007, data));
        assert_eq!(e.kind, DefenderEventKind::ConfigChanged);
        assert_eq!(
            e.setting.as_deref(),
            Some(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public")
        );
        assert_eq!((e.old_value, e.new_value.as_deref()), (None, Some("0x0")));
    }

    #[test]
    fn an_exclusion_removed_is_reported_from_the_old_side() {
        let data = r"<Data Name='Old Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\.zip = 0x0</Data><Data Name='New Value'></Data>";
        let e = defender_event(&defender_block(5007, data));
        assert_eq!(
            e.setting.as_deref(),
            Some(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\.zip")
        );
        assert_eq!((e.old_value.as_deref(), e.new_value), (Some("0x0"), None));
    }

    #[test]
    fn a_protection_switch_change_carries_both_values() {
        let data = r"<Data Name='Old Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x0</Data><Data Name='New Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1</Data>";
        let e = defender_event(&defender_block(5007, data));
        assert!(e.setting.unwrap().ends_with(r"\DisableRealtimeMonitoring"));
        assert_eq!(
            (e.old_value.as_deref(), e.new_value.as_deref()),
            (Some("0x0"), Some("0x1"))
        );
    }

    #[test]
    fn the_5007_start_up_flood_is_filtered_out() {
        // The values that were 40 % of the lab host's whole channel.
        for noise in [
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\IsServiceRunning = 0x1",
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Diagnostics\InitializingComponentProgress = LoadingEngine",
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash = 0x8FF20051",
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\ServiceStartStates = 0x1",
        ] {
            let data =
                format!("<Data Name='Old Value'></Data><Data Name='New Value'>{noise}</Data>");
            assert!(skipped(&defender_block(5007, &data)), "{noise}");
        }
    }

    #[test]
    fn a_5007_without_any_value_is_skipped_and_unknown_ids_too() {
        assert!(skipped(&defender_block(5007, "")));
        assert!(skipped(&defender_block(1234, DETECTION)));
    }

    // ── WDAC ────────────────────────────────────────────────────────────────

    fn wdac_block(event_id: u32, data: &str) -> String {
        format!(
            "<Event><System><EventID>{event_id}</EventID><EventRecordID>8</EventRecordID></System><EventData>{data}</EventData></Event>"
        )
    }

    const WDAC_DATA: &str = r"<Data Name='File Name'>\Device\HarddiskVolume3\Users\Public\x.dll</Data><Data Name='Process Name'>\Device\HarddiskVolume3\Windows\System32\rundll32.exe</Data><Data Name='SI Signing Scenario'>1</Data>";

    fn wdac_denial(event_id: u32, data: &str) -> PolicyDenialEvent {
        match normalize_wdac_block(&wdac_block(event_id, data)) {
            BlockOutcome::Event {
                event: Event::PolicyDenial(e),
                ..
            } => e,
            other => panic!("expected a PolicyDenialEvent, got {other:?}"),
        }
    }

    #[test]
    fn wdac_3077_is_an_enforced_denial_and_3076_an_audit_one() {
        let blocked = wdac_denial(3077, WDAC_DATA);
        assert_eq!(blocked.mechanism, POLICY_MECHANISM_WDAC);
        assert!(blocked.enforced);
        assert_eq!(
            blocked.object_path.as_deref(),
            Some(r"\Device\HarddiskVolume3\Users\Public\x.dll")
        );
        assert_eq!(
            blocked.subject_context.as_deref(),
            Some(r"\Device\HarddiskVolume3\Windows\System32\rundll32.exe")
        );
        assert_eq!(blocked.object_class.as_deref(), Some("user-mode"));
        assert_eq!(blocked.action.as_deref(), Some("load"));
        assert!(!wdac_denial(3076, WDAC_DATA).enforced);
    }

    #[test]
    fn wdac_kernel_scenario_and_unknown_scenario() {
        let kernel = wdac_denial(3077, &WDAC_DATA.replace(">1<", ">0<"));
        assert_eq!(kernel.object_class.as_deref(), Some("kernel-mode"));
        let unknown = wdac_denial(3077, &WDAC_DATA.replace(">1<", ">7<"));
        assert_eq!(unknown.object_class, None);
    }

    #[test]
    fn wdac_without_a_file_name_or_with_another_id_is_skipped() {
        assert!(matches!(
            normalize_wdac_block(&wdac_block(
                3077,
                "<Data Name='SI Signing Scenario'>1</Data>"
            )),
            BlockOutcome::Filtered { record_id: 8 }
        ));
        // 3033 (a DLL failed a signing level) is Chrome noise: not subscribed,
        // and refused here if the filter ever let one through.
        assert!(matches!(
            normalize_wdac_block(&wdac_block(3033, WDAC_DATA)),
            BlockOutcome::Filtered { record_id: 8 }
        ));
    }

    #[test]
    fn the_new_targets_are_wired_with_their_filters() {
        assert_eq!(
            DEFENDER_OP.channel,
            "Microsoft-Windows-Windows Defender/Operational"
        );
        for id in ["1116", "1117", "5001", "5007", "5010", "5012"] {
            assert!(
                DEFENDER_OP.id_filter.contains(&format!("EventID={id}")),
                "{id}"
            );
        }
        assert_eq!(
            WDAC_OP.channel,
            "Microsoft-Windows-CodeIntegrity/Operational"
        );
        assert!(!WDAC_OP.id_filter.contains("3033"));
        assert!(TARGETS.iter().any(|t| t.label == "defender"));
        assert!(TARGETS.iter().any(|t| t.label == "wdac"));
    }
}

#[cfg(test)]
mod target_wiring_tests {

    use super::*;

    #[test]
    fn session_targets_poll_only_the_lifecycle_ids() {
        assert!(!SESSION_LIFECYCLE.id_filter.contains("59"));
        assert!(!SESSION_LIFECYCLE.id_filter.contains("EventID=22"));
        assert_eq!(RDP_CONNECTIONS.id_filter, "EventID=1149");
    }
}

#[cfg(test)]
mod subscribe_tests {
    use std::{
        cell::RefCell,
        io,
        sync::{Arc, Once, atomic::AtomicBool},
    };

    use schema::{Event, sensor::EventSink};

    use super::*;
    use crate::targets::BlockOutcome;

    struct NullSink;

    impl EventSink for NullSink {
        fn on_event(&self, _event: Event) {}
    }

    std::thread_local! {
        static CAPTURED_LOGS: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    }

    /// Writes into the calling thread's [`captured_logs`] buffer, or nowhere when
    /// that thread is not capturing.
    struct ThreadCapture;

    impl io::Write for ThreadCapture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            CAPTURED_LOGS.with_borrow_mut(|captured| {
                if let Some(captured) = captured {
                    captured.extend_from_slice(buf);
                }
            });
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Runs `f` and returns what it logged through `tracing` on the calling thread.
    ///
    /// One process-wide subscriber, installed once, that routes each thread's output
    /// to that thread's own buffer — not `tracing::subscriber::with_default` (the
    /// `rules` tests' #876/#885 flake): while a scoped subscriber is the only live
    /// dispatcher, `tracing-core` (0.1.36) computes a callsite's cached interest from
    /// the default of whichever thread registers it, so a parallel test reaching the
    /// same log line first, with no subscriber of its own, caches it as "never" for
    /// the whole process and the capturing test reads nothing. A global default is
    /// every thread's default, so no registration order can disable a callsite.
    fn captured_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(|| ThreadCapture)
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other test in this binary sets a global subscriber");
        });
        CAPTURED_LOGS.with_borrow_mut(|captured| *captured = Some(Vec::new()));
        let result = f();
        let captured = CAPTURED_LOGS
            .with_borrow_mut(Option::take)
            .unwrap_or_default();
        (result, String::from_utf8_lossy(&captured).into_owned())
    }

    /// Subscribes to `target` with `tracing` captured; returns whether the
    /// subscription registered and every line logged meanwhile.
    fn subscribe_capturing_logs(target: &'static PollTarget) -> (bool, String) {
        let (handle, logs) = captured_logs(|| {
            crate::subscribe::subscribe(
                target,
                Arc::new(NullSink),
                Arc::new(EventLogCounters::default()),
                Arc::new(AtomicBool::new(false)),
            )
        });
        (handle.is_some(), logs)
    }

    #[test]
    fn captured_logs_sees_a_callsite_another_thread_registered_first() {
        // The #876/#885 race made deterministic: under `with_default`, the spawned
        // thread (no subscriber of its own) registers the callsite as "never" and the
        // capturing thread's own call is then filtered out before dispatch.
        fn probe() {
            tracing::warn!("captured-logs probe");
        }
        let ((), logs) = captured_logs(|| {
            std::thread::spawn(probe).join().expect("probe thread");
            probe();
        });
        assert_eq!(
            logs.matches("captured-logs probe").count(),
            1,
            "exactly this thread's line, not zero and not the other thread's too: {logs}"
        );
    }

    fn target_on(channel: &'static str) -> PollTarget {
        PollTarget {
            label: "subscribe-test",
            heartbeat: "windows-eventlog:subscribe-test",
            channel,
            // An ID no provider emits: the subscription registers, nothing fires.
            id_filter: "EventID=65000",
            counter: |c| &c.service_installs,
            parse_block: |_| BlockOutcome::Unparseable,
            enable_audit: None,
            enabled: |_| true,
        }
    }

    static READABLE: std::sync::LazyLock<PollTarget> =
        std::sync::LazyLock::new(|| target_on("Application"));
    static MISSING: std::sync::LazyLock<PollTarget> =
        std::sync::LazyLock::new(|| target_on("Synthaea-No-Such-Channel/Operational"));

    #[test]
    fn an_established_subscription_is_logged() {
        // Regression (#423): a live Subscribe run could only be proven by the
        // absence of poll lines. `Application` is readable without elevation.
        let (registered, logs) = subscribe_capturing_logs(&READABLE);
        assert!(
            registered,
            "EvtSubscribe on Application should register: {logs}"
        );
        assert!(logs.contains("subscription established"), "{logs}");
        assert!(logs.contains("channel=\"Application\""), "{logs}");
    }

    #[test]
    fn a_failed_subscription_is_not_logged_as_established() {
        let (registered, logs) = subscribe_capturing_logs(&MISSING);
        assert!(!registered);
        assert!(logs.contains("EvtSubscribe failed to register"), "{logs}");
        assert!(!logs.contains("subscription established"), "{logs}");
    }
}
