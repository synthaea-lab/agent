//! The agent's report on itself.

use super::*;

/// Health status of a single sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorHealth {
    /// Sensor name (e.g. "linux-ebpf", "windows-etw").
    pub name: String,
    /// Cumulative pulse count since agent start (heartbeat counter).
    pub pulse_count: u64,
    /// Whether the sensor is currently considered silent (no pulses in deadline).
    pub silent: bool,
}

/// Periodic agent health beacon — self-diagnostics emitted to the control plane.
///
/// Emitted at a fixed cadence (default 30s) so the server can detect silent agents
/// (an agent that stops beaconing is as suspicious as one that stops sending events).
/// Does not carry event payloads — only aggregate counters and status flags.
///
/// Note: Unlike telemetry events, `HealthBeacon` has no `EventMeta` (no originating
/// process). Consumers must handle this variant specially in pattern matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthBeacon {
    /// Nanoseconds since the UNIX epoch.
    pub timestamp_ns: u64,
    /// Agent version string (e.g. "0.1.0").
    pub agent_version: String,
    /// Health status of each loaded sensor.
    pub sensors: Vec<SensorHealth>,
    /// Total bytes currently in the event spool (upload backlog).
    pub spool_bytes: u64,
    /// Cumulative records dropped from spool due to byte cap.
    pub spool_dropped: u64,
    /// Cumulative events dropped from enrichment queue (backpressure).
    pub enrich_dropped: u64,
    /// Cumulative executed images the fleet's common set called rare whose evidence reached
    /// a process belief (issue #76). Absent in a beacon from an older agent: zero.
    #[serde(default)]
    pub rarity_applied: u64,
    /// Cumulative executions the rarity evidence could not judge: no snapshot, one covering
    /// too few hosts, or no usable hash. A high count with no applied one says why rarity is
    /// silent. Absent in a beacon from an older agent: zero.
    #[serde(default)]
    pub rarity_withheld: u64,
    /// Cumulative rare images whose evidence found no belief to land on (the correlator had
    /// evicted or never created it): the loss, counted. Absent in an older beacon: zero.
    #[serde(default)]
    pub rarity_unapplied: u64,
    /// How many times the watchdog has respawned the agent since the watchdog started (the
    /// watchdog tells the agent at spawn). Zero when the agent is not run under a watchdog, and
    /// in a beacon from an older agent (issue #863).
    #[serde(default)]
    pub watchdog_restarts: u64,
    /// Cumulative tamper-class alerts raised since the agent started: a sensor confirmed silent,
    /// a shipped binary or its signed manifest that no longer verifies, plus the self-protection
    /// events the watchdog reported (service definition drift, a binary that no longer matches its
    /// pinned hash). Absent in a beacon from an older agent: zero (issue #863).
    #[serde(default)]
    pub tamper_events: u64,
    /// Cumulative entries of the Linux parent-image cache the cap dropped while their process was
    /// still alive: the loss, a later child of such a process carries no `parent_image_path`
    /// (issue #783). Zero on other platforms and in a beacon from an older agent (issue #863).
    #[serde(default)]
    pub parent_image_evicted_live: u64,
    /// Cumulative entries the cap dropped whose process had already exited: nothing lost, counted
    /// to show how full the cache runs. Zero on other platforms and in an older beacon.
    #[serde(default)]
    pub parent_image_evicted_dead: u64,
    /// Indicators in force in the on-device IOC set right now (#60): a gauge, not a total. Zero
    /// when no feed is loaded, and in a beacon from an older agent.
    #[serde(default)]
    pub ioc_indicators: u64,
    /// Cumulative IOC matches that raised a finding since the agent started. Zero in a beacon
    /// from an older agent.
    #[serde(default)]
    pub ioc_findings: u64,
    /// Cumulative IOC matches the per-indicator cooldown absorbed: a high count against few
    /// findings is one indicator seen again and again. Zero in an older beacon.
    #[serde(default)]
    pub ioc_cooled_down: u64,
    /// Cumulative IOC matches skipped as the agent's own traffic to its control plane, made by
    /// the agent process itself (<https://github.com/synthaea-lab/agent/issues/47>): a non-zero count is a feed that lists the control
    /// plane. Zero in an older beacon.
    #[serde(default)]
    pub ioc_own_skipped: u64,
    /// The same, made by a second process on the agent's executable (`apply-content-manifest`)
    /// to the control plane. Kept apart because it is the case worth a look. Zero in an older
    /// beacon.
    #[serde(default)]
    pub ioc_sibling_skipped: u64,
    /// Cumulative alerts that could not be written to `alerts.ndjson` (a full disk, a
    /// serialization failure) since the agent started: the audit trail's loss, counted. The
    /// alert still reached stderr and `cli detections`. Zero in an older beacon (#167).
    #[serde(default)]
    pub alerts_dropped: u64,
    /// Cumulative events the Linux eBPF probes lost to a full ring buffer, summed over every ring
    /// (#304, #335): telemetry that never left the kernel. The per-ring breakdown is in the
    /// agent's log. Zero on other platforms and in a beacon from an older agent.
    #[serde(default)]
    pub ring_dropped: u64,
    /// The part of `ring_dropped` lost from the exec ring: process starts the rules never saw,
    /// whose children also get no `parent_image_path` from them. Zero on other platforms and in an
    /// older beacon.
    #[serde(default)]
    pub exec_ring_dropped: u64,
    /// Cumulative entries the Windows ETW sensor's pid cache dropped at its cap: a later event of
    /// such a process misses its image path (issue #178). Zero on other platforms and in a
    /// beacon from an older agent.
    #[serde(default)]
    pub etw_pid_cache_evicted: u64,
    /// Cumulative entries the Windows ETW sensor's silo directory dropped at its cap: a container
    /// event is named again by a lookup. Zero on other platforms and in an older beacon.
    #[serde(default)]
    pub etw_silo_evicted: u64,
    /// Cumulative `Zone.Identifier` marks the Windows ETW read-back queue dropped: each one is a
    /// lost `FileQuarantine`. Zero on other platforms and in an older beacon.
    #[serde(default)]
    pub etw_marks_dropped: u64,
    /// Cumulative quarantine paths reported without dedup because the dedup map was full: a
    /// possible duplicate, never a lost mark. Zero on other platforms and in an older beacon.
    #[serde(default)]
    pub etw_quarantine_unremembered: u64,
    /// Cumulative registry value writes the Windows ETW sensor reported with their key
    /// unresolved ([`RegistryKey::Unresolved`]): the key was opened relative to one opened
    /// before the session, or the key table had dropped it (#91). Zero on other platforms and
    /// in an older beacon.
    #[serde(default)]
    pub etw_registry_unresolved_writes: u64,
    /// Cumulative key objects the Windows ETW sensor's registry key table dropped at its cap or
    /// at one process's share of it: a later write through one is reported unresolved. Zero on
    /// other platforms and in an older beacon.
    #[serde(default)]
    pub etw_registry_keys_evicted: u64,
    /// Cumulative registry key names the Windows ETW sensor cut to its length bound. Zero on
    /// other platforms and in an older beacon.
    #[serde(default)]
    pub etw_registry_names_truncated: u64,
}
