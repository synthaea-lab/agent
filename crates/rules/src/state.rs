//! Correlation rules: [`RuleState`] keeps a sliding history (pid→comm, recent writes,
//! per-window counters) and consults it on every event. Each rule stays a dedicated
//! method, with its calibration constants next to it.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
};

use schema::{
    AuthEvent, AuthKind, AuthOutcome, BitsJobEvent, BitsJobState, ConnectEvent, DnsQueryEvent,
    Event, ExecEvent, FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN, FileDeleteEvent, FileOpenEvent,
    FileQuarantineEvent, FileRenameEvent, FileWriteEvent, ListenPortEvent, MemfdCreateEvent,
    NetworkFlowEvent, O_CREAT, POLICY_MECHANISM_APPLOCKER, POLICY_MECHANISM_SELINUX,
    POLICY_MECHANISM_WDAC, PolicyDenialEvent, SessionEvent, SessionState, User,
    detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    credfiles::{self, CredFile},
    egressdomain::{self, DomainClass},
    exclusions::{
        AGENT_CHILD_EXCLUSIONS, APK_STAGING_FILE_PREFIX, ARCHIVE_EGRESS_WINDOW_NS,
        ARCHIVE_READ_WINDOW_NS, ARCHIVE_STAGED_BYTES, ARCHIVE_SUFFIXES, AUTH_FAILURE_THRESHOLD,
        AUTH_FAILURE_WINDOW_NS, BEACON_THRESHOLD, BEACON_WINDOW_NS, BITS_EXEC_WINDOW_NS, BROWSERS,
        BURST_WRITE_BYTES_THRESHOLD, COMPRESSION_DRIVER_COMMS, COMPRESSION_SUFFIXES,
        COMPRESSOR_COMMS, CREATE_UNLINK_HISTORY_PER_PID, CREATE_UNLINK_PAIR_WINDOW_NS,
        CREATE_UNLINK_PID_CAP, CREDENTIAL_READ_ALERT_WINDOW_NS, DNS_CLASS_WINDOW_NS,
        DOWNLOAD_EXEC_WINDOW_NS, DOWNLOADER_COMMS, EGRESS_BYTES_THRESHOLD,
        EGRESS_CLASSED_BYTES_THRESHOLD, EGRESS_DOMAIN_BROWSER_COMMS, EGRESS_WINDOW_NS,
        IN_PLACE_EDIT_COMMS, LOLBIN_LEGIT_PARENTS, LOLBINS, MAILDIR_FLAG_LETTERS,
        MEMFD_EXEC_WINDOW_NS, PACKAGE_MANAGER_COMMS, PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES,
        POLICY_DENIAL_ALERT_CAP, POLICY_DENIAL_SUBJECT_CAP, QUARANTINE_EXEC_WINDOW_NS,
        RANSOMWARE_EXCLUDED_PATH_PREFIXES, RANSOMWARE_LOOP_CHILD_MAX, RANSOMWARE_RENAME_THRESHOLD,
        RANSOMWARE_RENAME_WINDOW_NS, SCAN_SPREAD_THRESHOLD, SCAN_SPREAD_WINDOW_NS,
        SCAN_VERTICAL_THRESHOLD, SCAN_VERTICAL_WINDOW_NS, SELF_SPAWN_EXCLUSIONS,
        SELF_SPAWN_PARENT_EXCLUSIONS, SELF_SPAWN_SCRIPT_HOSTS, SELF_SPAWN_THRESHOLD,
        SELF_SPAWN_TRUSTED_THRESHOLD, SELF_SPAWN_WINDOW_NS, SELINUX_POLICY_TOOL_COMMS,
        SERVICE_COMM_PREFIXES, SERVICE_COMMS, SHELL_COMMS, STAGING_PID_CAP, STAGING_READ_DIRS,
        STAGING_READ_FILES, STAGING_WINDOW_NS, STAGING_WRITE_FILES, STANDARD_PORTS,
        SUSPECT_CHILDREN_WIN, SUSPECT_PARENTS_WIN, TASK_REGISTRATION_DEDUP_WINDOW_NS,
        TOUCHED_FILES_PER_PID, TOUCHED_FILES_PID_CAP,
    },
    has_write_intent,
    logon::{LogonBaseline, Observation},
    rdp::RdpSuccessAfterFailures,
    session::SessionHijack,
    signature_gate::SignatureGatedAlert,
    sliding::{FlowPortDedup, SlidingCounter, SlidingDistinct, SlidingSum},
    staging::{self, StagingDir, StagingReads},
    sudo::SudoSuccessAfterFailures,
};

/// One (comm, daddr) EGRESS-VOLUME entry: the bytes sent inside the window and when
/// the last alert fired (one alert per window, as `SlidingCounter::try_alert`).
#[derive(Default)]
struct EgressVolume {
    sum: SlidingSum,
    last_alert_ns: Option<u64>,
    /// The last EGRESS-DOMAIN alert for this entry, kept apart from `last_alert_ns` so that
    /// one finding does not hide the other.
    last_class_alert_ns: Option<u64>,
}

/// A storage or paste service a pid resolved, and the address its lookup returned
/// (EGRESS-DOMAIN). Keyed by (pid, address) in `RuleState::dns_class`.
struct DnsClassSighting {
    generation: Option<u64>,
    class: DomainClass,
    /// The name the process asked for, kept for the alert message.
    domain: String,
    timestamp_ns: u64,
}

/// The archive a pid has open for writing (ARCHIVE-EXFIL).
struct ArchiveWriter {
    generation: Option<u64>,
    path: String,
    bytes: u64,
}

/// A staged archive a pid has read (ARCHIVE-EXFIL).
struct ArchiveReader {
    generation: Option<u64>,
    path: String,
    read_ns: u64,
    alerted: bool,
}

/// False only when both generation stamps exist and differ: the same rule as
/// [`PidFact::current`], a pid reused by another process must not inherit a fact.
fn same_incarnation(recorded: Option<u64>, wanted: Option<u64>) -> bool {
    !matches!((recorded, wanted), (Some(a), Some(b)) if a != b)
}

/// True when `path` ends in one of [`ARCHIVE_SUFFIXES`] (case-insensitive).
fn is_archive_name(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ARCHIVE_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// True for an address a remote party can be at: not loopback, private, link-local,
/// multicast, unspecified, or an IPv4 broadcast/unique-local equivalent.
fn is_public_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // 100.64.0.0/10, carrier-grade NAT (also Tailscale): an overlay, not the internet
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7 unique-local, fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

struct RecentWrite {
    pid: u32,
    comm: String,
    timestamp_ns: u64,
}

/// A download-provenance mark, as [`RuleState::on_file_quarantine`] saw it.
struct RecentQuarantine {
    timestamp_ns: u64,
    agent: Option<String>,
    origin_url: Option<String>,
    /// Set by the first exec that alerted: one alert per mark, not per run.
    alerted: bool,
}

/// A file a BITS job downloads, as [`RuleState::on_bits_job`] saw it.
struct RecentBitsDownload {
    /// The job's latest file-added or completion time: the exec window runs
    /// from when the file is actually there.
    timestamp_ns: u64,
    /// The job that armed this path.
    job_id: String,
    /// That job completed: the file is on disk, and no cancellation of
    /// another job (or a late one of this job) removes it.
    on_disk: bool,
    client_pid: u32,
    client_comm: String,
    job_title: String,
    url: String,
    /// Set by the first exec that alerted: one alert per download, not per run.
    alerted: bool,
}

/// A mark-of-the-web removal (`FileDelete` of a `:Zone.Identifier` stream), as
/// [`RuleState::on_file_delete`] saw it.
struct MotwRemoval {
    timestamp_ns: u64,
    pid: u32,
    comm: String,
    /// Set by the first exec that alerted: one alert per removal, not per run.
    alerted: bool,
}

struct ReportedTaskRegistration {
    timestamp_ns: u64,
    /// The reported action list, `None` for an unknown-action report (its path
    /// is only the sensor's placeholder).
    actions: Option<String>,
}

/// What the rules remember about a pid, and for which incarnation of it.
///
/// The kernel recycles pids, and the schema has no exit event, so a cache keyed on
/// the pid alone hands a new process the name or image path of the one that held the
/// number before it (#519). `generation` is the sensor's stamp for the incarnation
/// the fact was recorded for ([`schema::EventMeta::process_generation`]); a lookup
/// that names a different one misses. `None` on either side means "cannot tell" and
/// reads as a match: an entry seeded at startup, or an event from a platform with no
/// stamp (macOS), behaves exactly as before.
#[derive(Debug, Clone)]
pub(crate) struct PidFact {
    generation: Option<u64>,
    pub(crate) value: String,
}

impl PidFact {
    fn new(generation: Option<u64>, value: String) -> Self {
        Self { generation, value }
    }

    /// A fact read from `/proc` or an external table at startup: no stamp to compare.
    fn seeded(value: String) -> Self {
        Self::new(None, value)
    }

    /// The value cached for `pid`, unless it was recorded for another incarnation
    /// than `generation`.
    fn current(map: &BoundedMap<u32, Self>, pid: u32, generation: Option<u64>) -> Option<&str> {
        let fact = map.peek(&pid)?;
        match (fact.generation, generation) {
            (Some(recorded), Some(wanted)) if recorded != wanted => None,
            _ => Some(fact.value.as_str()),
        }
    }
}

/// `known_policy_denials`' key: (mechanism, subject context, object context, object
/// class, action). Named so clippy's `type_complexity` lint doesn't flag the field
/// declaration.
type PolicyDenialKey = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// One subject type's alert budget for `check_policy_denial_drift` (#840).
#[derive(Default)]
struct PolicyDenialBudget {
    /// Event time (`meta.timestamp_ns`) at which this subject's current window began; `None` until
    /// its first new shape, so the window is anchored on that shape and not on the epoch.
    window_start_ns: Option<u64>,
    /// New-shape alerts raised in the window.
    alerts: u64,
    /// New shapes shed in the window: the warning that the cap was hit is logged when this is 0.
    shed: u64,
}

/// The permission set of an AVC denial in canonical form for the dedup key: whitespace-separated
/// permissions, sorted and deduplicated, so `read write`, `write read` and `read  write` are one
/// shape. The wire value (`PolicyDenialEvent::action`) stays as the kernel wrote it.
fn normalized_permissions(action: &str) -> String {
    let mut permissions: Vec<&str> = action.split_whitespace().collect();
    permissions.sort_unstable();
    permissions.dedup();
    permissions.join(" ")
}

/// Sliding history needed by the correlation rules:
/// - T1105 (Ingress Tool Transfer): a path recently written by `curl`/`wget` is
///   executed shortly after. Correlated by path + time window rather than by a strict
///   parent/child process link — more robust to the various invocation forms
///   (`curl -o x && x`, `sh -c 'wget -O x; x'`, where `x` is not necessarily a direct
///   child of `curl`/`wget`).
/// - T1059 (suspicious process lineage): a shell interpreter executed directly by a
///   web server process — classic indicator of a web shell / RCE.
pub struct RuleState {
    /// pid → comm of the last exec seen for this pid, to recover the parent's comm
    /// (T1059) with a simple `ppid` lookup without having to walk the process tree in
    /// userspace. LRU-bounded (`store::BoundedMap`) — a long-lived agent must not
    /// grow this without limit. `pub(crate)` for the `seed_from_proc` test.
    pub(crate) pid_comm: BoundedMap<u32, PidFact>,
    /// pid → kernel-reported `image_path` of the last exec seen for this pid. The
    /// only race-free source of "which binary is this pid" for rename-time
    /// exclusions: `FileRenameEvent::executable_path` is read from `/proc/<pid>/exe`
    /// after the event crossed the ring buffer, so a short-lived process (real
    /// `sed -i.bak`, or an encryptor that exits right after its renames) is already
    /// gone and it reads `None` (#513 review). LRU-bounded like `pid_comm`.
    pid_image_path: BoundedMap<u32, PidFact>,
    /// path → info about the last write by a known downloader (T1105). LRU-bounded:
    /// downloader writes are rare, but a hostile loop must not grow agent memory.
    recent_writes: BoundedMap<String, RecentWrite>,
    /// case-folded path → its latest download-provenance mark (T1204.002,
    /// #365). LRU-bounded like `recent_writes`: a burst of downloads, or a
    /// hostile loop writing marks, must not grow agent memory.
    recent_quarantines: BoundedMap<String, RecentQuarantine>,
    /// case-folded local path → the BITS job downloading it (T1197, #284).
    /// LRU-bounded like `recent_quarantines`.
    recent_bits_downloads: BoundedMap<String, RecentBitsDownload>,
    /// case-folded host path → its latest mark-of-the-web removal (T1553.005,
    /// #442). LRU-bounded: `Unblock-File` over a whole module tree removes
    /// hundreds of marks at once.
    recent_motw_removals: BoundedMap<String, MotwRemoval>,
    /// (ppid, comm) → sliding counter for SELF-SPAWN (T1059 Windows). LRU-bounded.
    self_spawn: BoundedMap<(u32, String), SlidingCounter>,
    /// (comm, daddr, dport) → sliding counter for BEACON (T1071 Windows). LRU-bounded.
    beacon: BoundedMap<(String, String, u16), SlidingCounter>,
    /// Same key as `beacon` → which local ports have already counted toward it —
    /// only consulted by [`Self::on_network_flow`] (a poll-based source, see
    /// [`FlowPortDedup`]'s doc); `on_connect`'s discrete syscall trace needs no
    /// dedup, each `ConnectEvent` already is one real connection attempt.
    beacon_flow_dedup: BoundedMap<(String, String, u16), FlowPortDedup>,
    /// (pid, daddr) → distinct destination ports, for SCAN-VERTICAL (T1046, #378).
    /// LRU-bounded.
    scan_vertical: BoundedMap<(u32, IpAddr), SlidingDistinct<u16>>,
    /// Lineage → the discovery commands it ran inside the window, for RECON-BURST
    /// (T1057/T1082/T1016/T1087, #378). LRU-bounded.
    recon_burst: BoundedMap<crate::recon::Lineage, crate::recon::ReconWindow>,
    /// pid → the lineage its children belong to, for each one-shot shell wrapper
    /// (`sh -c`, `cmd /c`) seen running. LRU-bounded.
    recon_wrappers: BoundedMap<u32, crate::recon::Wrapper>,
    /// (comm, daddr, dport, `local_port`) → the `bytes_sent` of the last poll of that
    /// flow, for EGRESS-VOLUME (T1041/T1048, #380). Conntrack counters are cumulative
    /// per flow, so only the difference between two polls is new volume. LRU-bounded.
    egress_flow_last: BoundedMap<(String, IpAddr, u16, u16), u64>,
    /// (comm, daddr) → bytes sent inside the sliding window, for EGRESS-VOLUME. The
    /// key leaves the port out on purpose: an exfiltration split over many connections
    /// to one host is the shape to catch. LRU-bounded.
    egress_volume: BoundedMap<(String, IpAddr), EgressVolume>,
    /// (pid, address) → the storage or paste service that pid resolved to that address, for
    /// EGRESS-DOMAIN (T1567, #380). Only a lookup of a listed service is recorded, so the
    /// history grows with those, not with all DNS; LRU-bounded like every other table.
    dns_class: BoundedMap<(u32, IpAddr), DnsClassSighting>,
    /// pid → the archive it opened for writing and the bytes it has written since, for
    /// ARCHIVE-EXFIL (T1560/T1041, #380). `FileWriteEvent` carries no path, so the bytes
    /// are everything the pid writes (any fd): an archiver's output dominates them, a
    /// chatty process that also opens a `.gz` would overcount (a stated gap). LRU-bounded.
    archive_writers: BoundedMap<u32, ArchiveWriter>,
    /// Path of a staged archive → when it crossed [`ARCHIVE_STAGED_BYTES`]. LRU-bounded.
    staged_archives: BoundedMap<String, u64>,
    /// pid → the staged archive it read, until it connects out. LRU-bounded.
    archive_readers: BoundedMap<u32, ArchiveReader>,
    /// pid → the distinct user-data files it opened for reading, for STAGING-DIR (T1074.001,
    /// #380). LRU-bounded by [`STAGING_PID_CAP`].
    staging_reads: BoundedMap<u32, StagingReads>,
    /// (pid, directory) → the distinct files the pid created there, for STAGING-DIR. Only
    /// staging directories are recorded (see [`staging::staging_dir`]). LRU-bounded by
    /// [`STAGING_PID_CAP`].
    staging_dirs: BoundedMap<(u32, String), StagingDir>,
    /// pid → the lineage it was exec'd under, for the rules that see a process later
    /// (SSH-FANOUT reads it on the process's connects). LRU-bounded.
    exec_lineage: BoundedMap<u32, crate::recon::ExecLineage>,
    /// Lineage → distinct SSH destinations, for SSH-FANOUT (T1021.004, #378). LRU-bounded.
    ssh_fanout: BoundedMap<crate::recon::Lineage, SlidingDistinct<IpAddr>>,
    /// Lineage → distinct security-software discovery commands, for SECURITY-DISCOVERY
    /// (T1518.001, #378). LRU-bounded.
    security_discovery: BoundedMap<crate::recon::Lineage, SlidingDistinct<&'static str>>,
    /// Lineage → distinct services it stopped, for SERVICE-STOP-BURST (T1489, #381).
    /// LRU-bounded.
    service_stop: BoundedMap<crate::recon::Lineage, SlidingDistinct<String>>,
    /// (pid, dport) → sliding distinct-destination counter for SCAN-SPREAD
    /// (T1046/T1210, issue #465). LRU-bounded.
    scan_spread: BoundedMap<(u32, u16), SlidingDistinct<IpAddr>>,
    /// (`local_addr`, `local_port`) → seen, for LISTENER-DRIFT (issue #92, T1571).
    /// [`Self::seed_listen_ports`] pre-fills this from one startup snapshot so
    /// every service already listening when the agent attaches is the baseline,
    /// not noise — the same "seed from the world as it already is" principle as
    /// [`Self::seed_from_proc`]/`seed_pid_comm`. LRU-bounded: the realistic
    /// listener space is a few dozen, not unbounded, but a hostile loop binding
    /// many ports must not grow this without limit either.
    known_listeners: BoundedMap<(IpAddr, u16), ()>,
    /// (mechanism, subject context, object context, object class) → seen, for
    /// POLICY-DENIAL-DRIFT (issue #774, T1562-adjacent). Same "first new shape
    /// wins, the routine repeat doesn't" principle as `known_listeners` above:
    /// a `SELinux`-Enforcing host denies constantly as part of normal
    /// operation, so alerting on every `PolicyDenial` would be unusable — a
    /// *new* (subject, object, class) triple appearing is the signal. No
    /// startup-baseline seeding (unlike listeners, there's no enumerable
    /// "current state" of past denials to snapshot at agent start) — the
    /// first run is cold by design. LRU-bounded like every other stateful
    /// rule.
    ///
    /// Includes the requested permission (`action`, #813, recovered by
    /// `sensor-linux-audit`'s AVC parser): without it, a routine `getattr` denial on a
    /// subject/object/class triple would silence a later, more interesting
    /// `read`/`write`/`open` denial on that exact same triple. The set is normalised in
    /// the key ([`normalized_permissions`]: sorted, deduplicated), so only a different
    /// set is a new shape, not a different order.
    ///
    /// The key is per mechanism (#796). `SELinux`: `scontext`/`tcontext` give each denial a
    /// rich, domain-specific triple. AppLocker/WDAC `PolicyDenialEvent`s carry no object
    /// context, and `AppLocker` no subject either, so keying them like `SELinux` would collapse
    /// to `object_class` (5 collections for `AppLocker`, 2 signing scenarios for WDAC): the first
    /// blocked `.exe` would alert and every other one after it would not. They key on the
    /// file instead: `AppLocker` (collection, path), WDAC (loading process, path, scenario),
    /// with paths and process lowercased because Windows paths are case-insensitive and
    /// `AppLocker` reports one file as `C:\Users\x\EVIL.EXE` (`FullFilePath`) or
    /// `C:\USERS\X\EVIL.EXE` (an expanded `FilePath`).
    known_policy_denials: BoundedMap<PolicyDenialKey, ()>,
    /// Subject type (`user:role:type`, `None` for a denial with no subject context) → the new-shape
    /// alerts `check_policy_denial_drift` has raised for it in its current budget window, against
    /// [`POLICY_DENIAL_ALERT_CAP`] (#812, per subject since #840): `known_policy_denials` bounds
    /// what the rule remembers, not what it alerts, so a flood of distinct shapes could otherwise
    /// emit one alert per shape. One budget per subject, so a noisy domain (`httpd_t` probing 512
    /// types) cannot spend another's. LRU-bounded by [`POLICY_DENIAL_SUBJECT_CAP`]; a subject
    /// forgotten by eviction starts a fresh budget (counted, logged).
    policy_denial_budgets: BoundedMap<Option<String>, PolicyDenialBudget>,
    /// `policy_denial_budgets.evicted()` last reported, so each rise is logged once.
    policy_denial_budget_evictions_reported: u64,
    /// New-shape events shed by [`POLICY_DENIAL_ALERT_CAP`] over the whole run, all subjects — counted
    /// instead of silent (#812). A shed shape is *not* remembered in
    /// `known_policy_denials`, so it is still new when it comes back: it can alert in a
    /// later budget window, and every event for it while the budget is spent counts
    /// again (this counts events, not distinct shapes).
    policy_denial_alerts_shed: u64,
    /// `known_policy_denials.evicted()` last reported, so each rise is logged once
    /// (#812): otherwise `known_policy_denials` evicting its oldest eighth at
    /// `COUNTER_CAP` (never a full clear — only the evicted entries can re-alert) and a
    /// shape re-alerting is silent loss (CLAUDE.md: counted, observable shedding).
    policy_denial_evictions_reported: u64,
    /// (target user, source) → sliding failure counter for T1110 (AUTH-BURST).
    /// LRU-bounded like every other counter: a spray across many fabricated
    /// usernames must not grow this without limit.
    auth_failures: BoundedMap<(String, String), SlidingCounter>,
    /// The accounts seen logging on, for FIRST-SEEN-LOGON (T1078, #376). LRU-bounded.
    logon_baseline: LogonBaseline,
    /// RDP authentication successes joined to the failures from the same address,
    /// by event time (T1021.001, #285); see the `rdp` module.
    rdp_success: RdpSuccessAfterFailures,
    /// Local privilege-escalation successes (`sudo`/`su`) joined to the
    /// authentication failures for the same account, by event time (#381,
    /// T1548.003 for `sudo` / T1110.001 for `su`) — "same account" means the
    /// same invoker uid for `sudo`, the same target name for `su`; see the
    /// `sudo` module's own doc for why they differ.
    sudo_success: SudoSuccessAfterFailures,
    /// (pid, kind of credential file) → the last alert, for CREDENTIAL-READ (T1003.008,
    /// T1552, #377): one alert per window, not one per open. LRU-bounded like every other
    /// counter.
    credential_reads: BoundedMap<(u32, CredFile), SlidingCounter>,
    /// pid → sliding counter for RANSOMWARE-RENAME (T1486, issue #262): renames by
    /// this pid where `new_path` is `old_path` plus an appended suffix. LRU-bounded:
    /// a hostile process renaming under many different pids (unusual, but not
    /// impossible) must not grow this without limit either.
    ransomware_rename: BoundedMap<u32, SlidingCounter>,
    /// Distinct LDAP searches per process for the enumeration-sweep rule
    /// (T1087.002, #364).
    ldap_burst: crate::ldap::LdapBurst,
    /// ppid → the same counter, for the shell-loop shape (`for f in *; do mv "$f"
    /// "$f.locked"; done`, `find … -exec mv {} {}.x \;`): each rename runs in its own
    /// short-lived `mv` pid, so the per-pid counter never climbs, but every child
    /// shares the loop's shell as `ppid`. Real Linux ransomware ships this way, so the
    /// per-pid counter alone would miss it (issue #262 review, old-dov). LRU-bounded.
    /// `ppid <= 1` (unknown/init) is never keyed here — see `check_mass_rename_pattern`.
    ransomware_rename_by_ppid: BoundedMap<u32, SlidingCounter>,
    /// pid → (timestamp, path) of the recent write-intent creations (`O_CREAT`) seen
    /// for it, newest last: the "new file" half of the write-new-then-unlink T1486
    /// shape (#512 part B). `FileWriteEvent` carries only an fd, so the correlation is
    /// between this creation and a later `FileDeleteEvent`, both of which carry paths.
    /// Bounded by [`CREATE_UNLINK_PID_CAP`] pids x [`CREATE_UNLINK_HISTORY_PER_PID`].
    recent_creates: BoundedMap<u32, VecDeque<(u64, String)>>,
    /// pid → (timestamp, path) of unlinks that found no creation to pair with yet.
    /// The kernel always creates `X.suffix` before unlinking `X`, but userspace drains
    /// the open and delete ring buffers independently, so the delete can be processed
    /// first (the same ordering hazard as `pending_proc_fd_exec`, #503); the creation
    /// then pairs with it on arrival. Same bounds as `recent_creates`.
    pending_unlinks: BoundedMap<u32, VecDeque<(u64, String)>>,
    /// pid → the newest renames and deletions seen for it (oldest first): the damage
    /// manifest of a ransomware detection (issue #82), read through [`Self::touched_files`].
    /// Bounded by [`TOUCHED_FILES_PID_CAP`] pids x [`TOUCHED_FILES_PER_PID`] events.
    touched_files: BoundedMap<u32, VecDeque<Event>>,
    /// pid → sliding counter of write-new-then-unlink pairs (T1486, #512 part B).
    ransomware_unlink: BoundedMap<u32, SlidingCounter>,
    /// pid → sliding sum of `FileWriteEvent::bytes_requested` (issue #82): the
    /// write-volume half of a second, independent T1486 corroboration signal —
    /// heavy write volume alongside a rename burst, regardless of whether the
    /// rename shape itself matched `check_mass_rename_pattern`'s prefix-preserving
    /// pattern. LRU-bounded.
    write_volume: BoundedMap<u32, SlidingSum>,
    /// pid → sliding counter of renames, any shape — the rename half of the
    /// write-volume corroboration signal above. Deliberately separate from
    /// `ransomware_rename`: that counter only records prefix-preserving renames
    /// (`check_mass_rename_pattern`'s shape), this one counts every rename, so a
    /// pid that renames heavily without preserving the original name still
    /// contributes here.
    rename_count: BoundedMap<u32, SlidingCounter>,
    /// Task leaf name → last reported T1053.005 registration, so one registration
    /// seen on both Security 4698 and TaskScheduler/Operational 106 alerts once
    /// (#422). LRU-bounded like the counters.
    task_registrations: BoundedMap<String, ReportedTaskRegistration>,
    /// Disconnected sessions and the client each was left from, for the
    /// T1563.002 reconnect check (#285).
    session_hijack: SessionHijack,
    /// The agent's own pid, for [`Self::check_self_spawn`]'s narrow exclusion of
    /// its own known children (issue #403). `None` until [`Self::seed_own_pid`] is
    /// called — `sensor-*` crates stay `schema`-only (`tools/check-deps.py`), so
    /// this cannot be discovered from inside a sensor and must be seeded by the
    /// agent binary, same caller responsibility as `seed_pid_comm`.
    own_pid: Option<u32>,
    /// Library directories the host's `ld.so.conf` declares, as `/`-terminated trust
    /// prefixes, on top of the built-in baseline (T1574.006, #363). Empty until
    /// [`Self::seed_ld_trust_from_system`] runs — the rule then falls back to the
    /// baseline alone, which only costs false positives on vendor directories.
    ld_trust_extra: Vec<String>,
    /// pid → the most recent `(timestamp, fd)` pairs of `MemfdCreateEvent`s seen
    /// for it (T1620, issues #497/#510): the evidence [`Self::check_memfd_exec`]
    /// requires before treating an exec via `/proc/(self|<pid>)/fd/<n>` as a
    /// memfd-exec, since that path shape alone (unlike `/dev/fd/<n>` + a
    /// `memfd:`-prefixed `comm`) is not reliable evidence on its own — see that
    /// method's doc. The exec's `<n>` must equal one of these fds. A process can
    /// legitimately hold several memfds, so this keeps up to
    /// [`MEMFD_CREATES_PER_PID`] (oldest dropped) rather than only the latest.
    /// LRU-bounded like `pid_comm`, same key space.
    recent_memfd_creates: BoundedMap<u32, Vec<(u64, i32)>>,
    /// pid → a `/proc/.../fd/<n>` exec seen with no corroborating
    /// `MemfdCreateEvent` yet (#503 review): held instead of dropped, since
    /// the creation may still arrive after the exec despite always preceding
    /// it at the kernel's own timestamp — two ring buffers drained
    /// independently don't guarantee delivery order. [`Self::on_memfd_create`]
    /// checks this and fires retroactively. LRU-bounded like `pid_comm`, same
    /// key space.
    pending_proc_fd_exec: BoundedMap<u32, PendingProcFdExec>,
}

/// See [`RuleState::pending_proc_fd_exec`].
struct PendingProcFdExec {
    path: String,
    /// The `<n>` of the `/proc/.../fd/<n>` path: the descriptor the exec ran.
    fd: i32,
    comm: String,
    timestamp_ns: u64,
}

/// Memfd creations remembered per pid (see `RuleState::recent_memfd_creates`). A real
/// fileless-exec process creates one or two; a process making more than this inside
/// the correlation window is not something a longer list would catch better.
const MEMFD_CREATES_PER_PID: usize = 8;
/// Same bound as the correlator's entity table: the realistic live-pid space.
const PID_COMM_CAP: usize = 65_536;
/// Counter/write-history bounds — one logical entity per key, far fewer than pids.
pub(crate) const COUNTER_CAP: usize = 16_384;
const RECENT_WRITES_CAP: usize = 4_096;

impl Default for RuleState {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pid_comm: BoundedMap::new(PID_COMM_CAP),
            pid_image_path: BoundedMap::new(PID_COMM_CAP),
            recent_writes: BoundedMap::new(RECENT_WRITES_CAP),
            recent_quarantines: BoundedMap::new(RECENT_WRITES_CAP),
            recent_bits_downloads: BoundedMap::new(RECENT_WRITES_CAP),
            recent_motw_removals: BoundedMap::new(RECENT_WRITES_CAP),
            self_spawn: BoundedMap::new(COUNTER_CAP),
            ldap_burst: crate::ldap::LdapBurst::new(),
            beacon: BoundedMap::new(COUNTER_CAP),
            beacon_flow_dedup: BoundedMap::new(COUNTER_CAP),
            egress_flow_last: BoundedMap::new(COUNTER_CAP),
            egress_volume: BoundedMap::new(COUNTER_CAP),
            dns_class: BoundedMap::new(COUNTER_CAP),
            archive_writers: BoundedMap::new(COUNTER_CAP),
            staged_archives: BoundedMap::new(COUNTER_CAP),
            archive_readers: BoundedMap::new(COUNTER_CAP),
            staging_reads: BoundedMap::new(STAGING_PID_CAP),
            staging_dirs: BoundedMap::new(STAGING_PID_CAP),
            scan_spread: BoundedMap::new(COUNTER_CAP),
            scan_vertical: BoundedMap::new(COUNTER_CAP),
            recon_burst: BoundedMap::new(COUNTER_CAP),
            recon_wrappers: BoundedMap::new(COUNTER_CAP),
            exec_lineage: BoundedMap::new(PID_COMM_CAP),
            ssh_fanout: BoundedMap::new(COUNTER_CAP),
            security_discovery: BoundedMap::new(COUNTER_CAP),
            service_stop: BoundedMap::new(COUNTER_CAP),
            known_listeners: BoundedMap::new(COUNTER_CAP),
            known_policy_denials: BoundedMap::new(COUNTER_CAP),
            policy_denial_budgets: BoundedMap::new(POLICY_DENIAL_SUBJECT_CAP),
            policy_denial_budget_evictions_reported: 0,
            policy_denial_alerts_shed: 0,
            policy_denial_evictions_reported: 0,
            auth_failures: BoundedMap::new(COUNTER_CAP),
            logon_baseline: LogonBaseline::new(),
            rdp_success: RdpSuccessAfterFailures::new(),
            sudo_success: SudoSuccessAfterFailures::new(),
            recent_creates: BoundedMap::new(CREATE_UNLINK_PID_CAP),
            pending_unlinks: BoundedMap::new(CREATE_UNLINK_PID_CAP),
            touched_files: BoundedMap::new(TOUCHED_FILES_PID_CAP),
            ransomware_unlink: BoundedMap::new(COUNTER_CAP),
            credential_reads: BoundedMap::new(COUNTER_CAP),
            ransomware_rename: BoundedMap::new(COUNTER_CAP),
            ransomware_rename_by_ppid: BoundedMap::new(COUNTER_CAP),
            write_volume: BoundedMap::new(COUNTER_CAP),
            rename_count: BoundedMap::new(COUNTER_CAP),
            task_registrations: BoundedMap::new(COUNTER_CAP),
            session_hijack: SessionHijack::new(),
            own_pid: None,
            ld_trust_extra: Vec::new(),
            recent_memfd_creates: BoundedMap::new(PID_COMM_CAP),
            pending_proc_fd_exec: BoundedMap::new(PID_COMM_CAP),
        }
    }

    /// Seeds the agent's own pid (issue #403), so [`Self::check_self_spawn`] can
    /// narrowly exclude its own known children (`AGENT_CHILD_EXCLUSIONS`) instead
    /// of alerting on the Event Log sensor's `wevtutil`/`auditpol` poll loop. Not a
    /// blanket "ignore every child of this pid": the exclusion still requires the
    /// child's image to live at a trusted system path, since `ppid` alone is
    /// spoofable. Call once at startup, same as `seed_pid_comm`/`seed_listen_ports`.
    pub fn seed_own_pid(&mut self, pid: u32) {
        self.own_pid = Some(pid);
    }

    /// Loads the host's dynamic-linker trust set from `/etc/ld.so.conf` (`include`s
    /// followed) for the `LD_PRELOAD`/`LD_AUDIT` hijack rule (T1574.006, #363), so a vendor
    /// library directory registered with `ldconfig` (`/opt/<app>/lib`) is not mistaken
    /// for a planted preload. Linux-only in practice: elsewhere the file does not
    /// exist and this is a no-op. Best-effort, same caller responsibility as
    /// [`Self::seed_from_proc`]: call once at startup; an unreadable file only means the
    /// rule judges against the built-in baseline.
    pub fn seed_ld_trust_from_system(&mut self) {
        self.seed_ld_trust_dirs(crate::ld_trust::collect_ld_dirs(
            std::path::Path::new(crate::ld_trust::LD_SO_CONF),
            &crate::ld_trust::read_file,
            &crate::ld_trust::list_dir,
        ));
    }

    /// Replaces the extra trusted directories (already normalized, `/`-terminated).
    /// The seam [`Self::seed_ld_trust_from_system`] goes through; exposed for callers
    /// and tests that supply their own list.
    pub fn seed_ld_trust_dirs(&mut self, dirs: Vec<String>) {
        self.ld_trust_extra = dirs;
    }

    /// Pre-fills the LISTENER-DRIFT baseline from the agent's own startup
    /// snapshot — without this, every service already listening when the agent
    /// attaches (sshd, nginx started by systemd at boot) would look exactly like
    /// a freshly planted backdoor listener on the very first poll after startup.
    /// Same principle, same caller responsibility, as [`Self::seed_from_proc`].
    pub fn seed_listen_ports(&mut self, ports: impl IntoIterator<Item = (IpAddr, u16)>) {
        for key in ports {
            self.known_listeners.insert(key, ());
        }
    }

    /// Pre-fills `pid_comm` from an external table (pid → comm) — the Windows
    /// equivalent of `seed_from_proc` for systems without /proc. To be called once at
    /// startup with the list of already-running processes, so that the parent-side
    /// exclusions (SELF-SPAWN, T1059) also apply to processes started before the agent
    /// (e.g. RuntimeBroker.exe).
    pub fn seed_pid_comm(&mut self, map: HashMap<u32, String>) {
        self.pid_comm.extend(
            map.into_iter()
                .map(|(pid, comm)| (pid, PidFact::seeded(comm))),
        );
    }

    /// Pre-fills `pid_comm` with the processes already running at startup (read from
    /// `/proc`). Without this, only processes exec'd *after* the collector attaches are
    /// known — T1059 can then never resolve the comm of a web server started before the
    /// agent (the normal case: nginx/apache launched by systemd at boot, agent launched
    /// afterwards), blinding the rule to any service already in place. Found in real
    /// conditions on 2026-08-14: an nginx webshell (perl module,
    /// `system("/bin/sh", ...)`) triggered no T1059 alert as long as nginx had started
    /// before the agent — yet the most common case in practice. Best-effort: a
    /// `/proc/{pid}` that disappears between the listing and the read (process exiting)
    /// is simply ignored.
    pub fn seed_from_proc(&mut self) {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) else {
                continue;
            };
            self.pid_comm
                .insert(pid, PidFact::seeded(comm.trim_end().to_string()));
        }
    }

    /// Resolves a pid's comm: `pid_comm` first (filled by the execs seen since startup,
    /// plus `seed_from_proc`), then falls back to a live `/proc` read.
    ///
    /// The fallback is necessary: `pid_comm` only knows a process if it exec'd during
    /// the capture, or was already running at startup (`seed_from_proc`) — not
    /// processes `fork()`'d *after* startup that never exec afterwards (e.g. an nginx
    /// worker respawned by the master). Found in real conditions on 2026-08-14 with an
    /// unstable nginx perl module that kept churning workers: `seed_from_proc` alone
    /// let through any worker created after the collector attached. The fallback reads
    /// `/proc/{ppid}/comm`, valid as long as the parent is still alive at evaluation
    /// time — true in the vast majority of cases, the child executing right after the
    /// fork.
    ///
    /// `generation` is the incarnation of `pid` the caller means ([`PidFact`]): a
    /// cached name recorded for a different incarnation is a recycled pid's
    /// inheritance, not an answer, and falls through to the `/proc` read (#519).
    pub(crate) fn resolve_comm(&self, pid: u32, generation: Option<u64>) -> Option<String> {
        if let Some(comm) = PidFact::current(&self.pid_comm, pid, generation) {
            return Some(comm.to_string());
        }
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim_end().to_string())
    }

    /// T1059 — a shell executed directly by a web or database service process.
    /// Originally web-server-only (`nginx`/`apache2`/`httpd`); extended to
    /// `mysqld`/`mariadbd`/`postgres` and (by prefix) `php-fpm*` for issue
    /// #478's Level 1 — see [`SERVICE_COMMS`] and [`SERVICE_COMM_PREFIXES`]'s
    /// docs for why each needs its own matching.
    fn check_web_server_spawns_shell(&self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.as_str();
        if !SHELL_COMMS.contains(&comm) {
            return None;
        }
        let parent_comm =
            self.resolve_comm(event.meta.ppid, event.meta.parent_process_generation)?;
        let is_service = SERVICE_COMMS.iter().any(|w| parent_comm == *w)
            || SERVICE_COMM_PREFIXES
                .iter()
                .any(|p| parent_comm.starts_with(p));
        if !is_service {
            return None;
        }
        Some(Alert {
            technique: "T1059",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} executed directly by ppid={} comm={parent_comm} (service) — suspicious process lineage",
                event.meta.pid, comm, event.meta.ppid,
            ),
        })
    }

    /// T1105 — execution of a path recently written by `curl`/`wget`, within the
    /// correlation window. Compares `comm` (the process name, as derived by the kernel)
    /// to the basename of the downloaded path — not `argv[0]` nor a substring of the
    /// command line.
    ///
    /// Two bugs found in real conditions on 2026-08-13 while looking for the right
    /// criterion:
    /// - a naive `cmdline.contains(path)` also matched `chmod +x /tmp/payload` or
    ///   `rm /tmp/payload` (the path appears as an argument, without `chmod`/`rm` being
    ///   the executed payload) — three alerts for a single scenario.
    /// - comparing `argv[0]` to the full path missed the (yet most likely) case of a
    ///   payload with a shebang (`#!/bin/sh`): the kernel then executes the
    ///   interpreter, with `argv = ["/bin/sh", "/tmp/edr-payload"]` — `argv[0]` is
    ///   `/bin/sh`, not the downloaded path, hence a false negative on the actual
    ///   execution.
    ///
    /// `comm`, on the other hand, is reliable in both cases: the kernel derives it from
    /// the name of the executed file (`edr-payload`), even when the actual interpreter
    /// differs — confirmed in real conditions (`comm: "edr-payload"` while `cmdline`
    /// starts with `/bin/sh`). Known limitation: the Linux kernel truncates `comm` to
    /// 15 bytes, so a file name longer than that will not match exactly (a sensor
    /// property, reported by conformance).
    fn check_download_then_exec(&self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.as_str();
        let (path, write) =
            self.recent_writes
                .iter()
                .find(|(path, write): &(&String, &RecentWrite)| {
                    written_file_is(path, comm)
                        && event.meta.timestamp_ns.saturating_sub(write.timestamp_ns)
                            <= DOWNLOAD_EXEC_WINDOW_NS
                })?;
        Some(Alert {
            technique: "T1105",
            severity: Severity::High,
            message: format!(
                "pid={} comm={} executes {path}, written {} earlier by pid={} comm={}",
                event.meta.pid,
                comm,
                format_delta(event.meta.timestamp_ns.saturating_sub(write.timestamp_ns)),
                write.pid,
                write.comm,
            ),
        })
    }

    /// T1204.002 — User Execution: Malicious File. A file carrying a
    /// download-provenance mark (`FileQuarantine`: macOS quarantine xattr,
    /// Windows `Zone.Identifier`) is executed within
    /// [`QUARANTINE_EXEC_WINDOW_NS`] of being marked. Platform-neutral: the
    /// join is on the executed image path, which both ES and ETW report as the
    /// full path the mark was written for.
    ///
    /// One alert per mark (`alerted`): re-running the same download is not a
    /// new finding, a re-download writes a fresh mark and is. Paths are
    /// case-folded — NTFS and default APFS are both case-insensitive.
    ///
    /// Known gap: a downloaded *script* run through an interpreter
    /// (`powershell -File x.ps1`, `sh x.sh`) has the interpreter as its image
    /// path and does not join; T1105's comm-based match has the same shape of
    /// limit on Linux.
    ///
    /// Gated on the image's signature (#441): every installer a user downloads
    /// and runs matches the join, and almost all of them are signed. The
    /// signature is only known after enrichment, off the capture thread, so this
    /// returns a [`SignatureGatedAlert`] (see [`Self::on_exec_signature_gated`]).
    fn check_quarantined_exec(&mut self, event: &ExecEvent) -> Option<SignatureGatedAlert> {
        let now = event.meta.timestamp_ns;
        let mark = self
            .recent_quarantines
            .get_mut(&event.image_path.to_lowercase())?;
        let age = now.saturating_sub(mark.timestamp_ns);
        if mark.alerted || age > QUARANTINE_EXEC_WINDOW_NS {
            return None;
        }
        mark.alerted = true;
        Some(SignatureGatedAlert::new(Alert {
            technique: "T1204.002",
            severity: Severity::High,
            message: format!(
                "pid={} comm={} executes {}, downloaded {} earlier (origin: {}, marked by {})",
                event.meta.pid,
                event.meta.comm,
                event.image_path,
                format_delta(age),
                mark.origin_url.as_deref().unwrap_or("unrecorded"),
                mark.agent.as_deref().unwrap_or("unknown"),
            ),
        }))
    }

    /// T1197 — BITS Jobs. A file a BITS job downloaded is executed within
    /// [`BITS_EXEC_WINDOW_NS`] of the job adding it or completing (#284). BITS
    /// does the download from its own service, so neither the T1105 joins
    /// (keyed on the downloading comm) nor the correlator's connect+write
    /// rule (keyed on one pid) can see it; the job record is what names the
    /// client.
    ///
    /// One alert per download (`alerted`), case-folded paths. Files fetched
    /// from Microsoft update hosts are filtered at the sensor and never reach
    /// this table; the job's owner is not a filter.
    ///
    /// Not covered: notify-command persistence (`bitsadmin /SetNotifyCmdLine`)
    /// is no job state the provider reports, so its set-up shows only as the
    /// `bitsadmin` command line. The file it runs, when BITS downloaded it,
    /// still joins here.
    fn check_bits_download_exec(&mut self, event: &ExecEvent) -> Option<Alert> {
        let now = event.meta.timestamp_ns;
        let download = self
            .recent_bits_downloads
            .get_mut(&event.image_path.to_lowercase())?;
        let age = now.saturating_sub(download.timestamp_ns);
        if download.alerted || age > BITS_EXEC_WINDOW_NS {
            return None;
        }
        download.alerted = true;
        Some(Alert {
            technique: "T1197",
            // Below T1105/T1204.002: non-Microsoft updaters (Google Omaha,
            // OneDrive) download through BITS and run what they fetched.
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} executes {}, downloaded {} earlier by BITS job \"{}\" of pid={} comm={} (url: {})",
                event.meta.pid,
                event.meta.comm,
                event.image_path,
                format_delta(age),
                download.job_title,
                download.client_pid,
                download.client_comm,
                download.url,
            ),
        })
    }

    // ── Windows rules ────────────────────────────────────────────────────────

    /// T1059 — same process spawned N times in X seconds by the same parent.
    ///
    /// Windows only. The exclusion lists below are Windows `.exe` names dated to
    /// Windows lab captures, and the rule has no comm allowlist — so on Linux it
    /// fires on any script that re-spawns the same helper a few times in a loop
    /// (#159: `for i in 1..3; do sh -c …; done` trips 3 spawns of `sh` in <30s).
    /// A Linux respawn that matters surfaces through the web-shell lineage (T1059),
    /// download→exec (T1105), or the correlator's respawn+connect rule; a
    /// Linux-calibrated SELF-SPAWN would be its own pass.
    ///
    /// False positives documented in lab (2026-08-24/25): MpCmdRun.exe, WerFault.exe,
    /// RuntimeBroker.exe — excluded via `SELF_SPAWN_EXCLUSIONS` /
    /// `SELF_SPAWN_PARENT_EXCLUSIONS`. The agent's own children (issue #403,
    /// 2026-09-23) — excluded via `AGENT_CHILD_EXCLUSIONS`, gated on
    /// [`Self::seed_own_pid`].
    ///
    /// Three same-name children of one parent in 30s is routine when both sides
    /// are system images (a service host, an interactive shell running `schtasks`
    /// or the operator's `cli`; #432), so that pair needs
    /// [`SELF_SPAWN_TRUSTED_THRESHOLD`]. Either side outside a trusted path, or
    /// unknown, keeps [`SELF_SPAWN_THRESHOLD`]: a dropped payload respawning
    /// itself, or dropping a system `LOLBin` in a loop, is exactly the signal.
    /// So does a script-host child ([`SELF_SPAWN_SCRIPT_HOSTS`]), whatever the
    /// paths: a system shell looping `powershell.exe` is how a malicious script
    /// respawns itself without dropping a binary.
    fn check_self_spawn(&mut self, event: &ExecEvent) -> Option<Alert> {
        if !matches!(event.meta.user, User::Windows { .. }) {
            return None;
        }
        let comm = event.meta.comm.clone();
        // The agent's own known children (issue #403): wevtutil.exe/auditpol.exe
        // spawned by the Event Log sensor's poll loop. Gated on the ppid matching
        // the agent's own seeded pid, not just the name — ppid alone is spoofable
        // (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), so this must stay narrow.
        if self.own_pid == Some(event.meta.ppid)
            && AGENT_CHILD_EXCLUSIONS
                .iter()
                .any(|&e| comm.eq_ignore_ascii_case(e))
            && policy::name_exclusion_applies(Some(event.image_path.as_str()))
        {
            return None;
        }
        // Name alone is a bypass: a payload renamed `svchost.exe` in %TEMP% must
        // not inherit the exclusion — the image must live where the real binary
        // does (user finding; signature-based identity is the follow-up issue).
        if SELF_SPAWN_EXCLUSIONS
            .iter()
            .any(|&e| comm.eq_ignore_ascii_case(e))
            && policy::name_exclusion_applies(Some(event.image_path.as_str()))
            && policy::parent_exclusion_applies(&comm, event.parent_comm.as_deref())
        {
            return None;
        }
        // Parent-side exclusion: some system processes legitimately spawn the same
        // child in a loop (e.g. RuntimeBroker.exe → powershell.exe for UWP tasks).
        let parent_comm = PidFact::current(
            &self.pid_comm,
            event.meta.ppid,
            event.meta.parent_process_generation,
        )
        .unwrap_or_default()
        .to_string();
        if SELF_SPAWN_PARENT_EXCLUSIONS
            .iter()
            .any(|&e| parent_comm.eq_ignore_ascii_case(e))
            && policy::name_exclusion_applies(event.parent_image_path.as_deref())
        {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        let key = (event.meta.ppid, comm.clone());
        let entry = self
            .self_spawn
            .get_or_insert_with(key, SlidingCounter::default);
        let count = entry.record(ts, SELF_SPAWN_WINDOW_NS);
        let script_host = SELF_SPAWN_SCRIPT_HOSTS
            .iter()
            .any(|&h| comm.eq_ignore_ascii_case(h));
        let threshold = if !script_host
            && is_known_trusted(Some(&event.image_path))
            && is_known_trusted(event.parent_image_path.as_deref())
        {
            SELF_SPAWN_TRUSTED_THRESHOLD
        } else {
            SELF_SPAWN_THRESHOLD
        };
        if count >= threshold && entry.try_alert(ts, SELF_SPAWN_WINDOW_NS) {
            return Some(Alert {
                technique: "T1059",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={comm} spawned {count}x in {}s by ppid={} — suspected self-spawn",
                    event.meta.pid,
                    SELF_SPAWN_WINDOW_NS / 1_000_000_000,
                    event.meta.ppid,
                ),
            });
        }
        None
    }

    /// T1204/T1059 — Office/PDF application spawning an interpreter (macro/exploit).
    /// `resolve_comm` reads `pid_comm` then `/proc` as a fallback (Linux) — returns None
    /// on Windows if the parent has not yet sent an `ExecEvent`, which silently disables
    /// this rule for that case (mitigated by `seed_pid_comm` at startup).
    fn check_parent_suspect(&self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.as_str();
        if !SUSPECT_CHILDREN_WIN
            .iter()
            .any(|&e| comm.eq_ignore_ascii_case(e))
        {
            return None;
        }
        let parent_comm =
            self.resolve_comm(event.meta.ppid, event.meta.parent_process_generation)?;
        if !SUSPECT_PARENTS_WIN
            .iter()
            .any(|&p| parent_comm.eq_ignore_ascii_case(p))
        {
            return None;
        }
        Some(Alert {
            technique: "T1204/T1059",
            severity: Severity::High,
            message: format!(
                "pid={} comm={comm} spawned by ppid={} comm={parent_comm} — Office→interpreter lineage",
                event.meta.pid, event.meta.ppid,
            ),
        })
    }

    /// T1218/T1127 — `LOLBin` spawned by a non-dev parent (shellcode execution proxy).
    fn check_lolbin(&self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.as_str();
        if !LOLBINS.iter().any(|&l| comm.eq_ignore_ascii_case(l)) {
            return None;
        }
        let parent_comm =
            self.resolve_comm(event.meta.ppid, event.meta.parent_process_generation)?;
        if LOLBIN_LEGIT_PARENTS
            .iter()
            .any(|&p| parent_comm.eq_ignore_ascii_case(p))
        {
            return None;
        }
        Some(Alert {
            technique: "T1218/T1127",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={comm} (LOLBin) spawned by ppid={} comm={parent_comm}",
                event.meta.pid, event.meta.ppid,
            ),
        })
    }

    /// Shared BEACON exclusions (T1071/T1041) — same filter regardless of which
    /// telemetry source observed the connection.
    ///
    /// pid=4 (Windows System) is excluded by the caller, not here: `NetworkFlowEvent`
    /// (Linux-only, no Windows equivalent) never needs that check, so it stays
    /// specific to [`Self::check_beacon`].
    fn beacon_excluded(comm: &str, daddr: IpAddr, dport: u16) -> bool {
        // Known limitation: neither ConnectEvent nor NetworkFlowEvent carries an
        // image path, so the browser exclusion stays name-only here — the
        // correlator's exec-time masquerade tracking covers the rename bypass at
        // the correlation layer.
        if BROWSERS.iter().any(|&n| comm.eq_ignore_ascii_case(n)) {
            return true;
        }
        if STANDARD_PORTS.contains(&dport) {
            return true;
        }
        // `0.0.0.0:65535` / `:::65535` is no remote peer: it's the address-selection
        // probe sshd-session and sshd-auth run with a `connect()` on every login, which
        // crossed the 3-in-60s threshold on a lab VM with three SSH logins in a minute
        // (2026-09-29, #525). Only on that port: a connect to `0.0.0.0:<port>` reaches
        // the local host like `127.0.0.1:<port>`, which still counts, so the rest must
        // count too or a local-relay beacon could hide behind the unspecified address
        // (#536).
        if policy::is_address_selection_probe(daddr, dport) {
            return true;
        }
        // IPv4 multicast (224.0.0.0/4) and broadcast (last octet = 255): legitimate
        // network traffic emitted in a loop by system services (mDNS, SSDP, Spotify…),
        // never C2.
        if let IpAddr::V4(v4) = daddr {
            let o = v4.octets();
            if o[0] >= 224 || o[3] == 255 {
                return true;
            }
        }
        false
    }

    /// Records one occurrence toward the (comm, daddr, dport) BEACON counter and
    /// returns an alert once the threshold is crossed — the counting/alerting core
    /// shared by [`Self::check_beacon`] and [`Self::check_beacon_flow`], which
    /// differ only in what counts as "one occurrence" (see the latter's doc).
    fn record_beacon(
        &mut self,
        pid: u32,
        comm: &str,
        daddr: IpAddr,
        dport: u16,
        ts: u64,
    ) -> Option<Alert> {
        let daddr = daddr.to_string();
        let key = (comm.to_string(), daddr.clone(), dport);
        let entry = self.beacon.get_or_insert_with(key, SlidingCounter::default);
        let count = entry.record(ts, BEACON_WINDOW_NS);
        if count >= BEACON_THRESHOLD && entry.try_alert(ts, BEACON_WINDOW_NS) {
            return Some(Alert {
                technique: "T1071/T1041",
                severity: Severity::High,
                message: format!(
                    "pid={pid} comm={comm} → {daddr}:{dport} | {count}x in {}s — suspected beaconing",
                    BEACON_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// T1071/T1041 — repeated connections to the same destination on a non-standard
    /// port (C2 beaconing). Browsers excluded (repeated outbound traffic = normal
    /// behavior).
    fn check_beacon(&mut self, event: &ConnectEvent) -> Option<Alert> {
        // pid=4 = Windows System process: constantly emits low-level network traffic
        // (NetBIOS, SMB…) — never C2, guaranteed false positive.
        if event.meta.pid == 4 {
            return None;
        }
        if Self::beacon_excluded(&event.meta.comm, event.daddr, event.dport) {
            return None;
        }
        self.record_beacon(
            event.meta.pid,
            &event.meta.comm,
            event.daddr,
            event.dport,
            event.meta.timestamp_ns,
        )
    }

    /// SCAN-SPREAD (T1046/T1210, issue #465): many distinct destinations, one
    /// port, in a short window — a live Mirai detonation (309 connections to
    /// 300+ distinct IPs on port 23 in ~30s, default-credential telnet
    /// spread) produced no dedicated alert; `check_beacon`'s repeated-*same*-
    /// destination shape is the mirror image and structurally can't catch
    /// this. Keyed by (pid, dport): counts distinct `daddr`, not raw
    /// connection count, so a busy client hammering one server (BEACON's own
    /// shape, not this one) doesn't also cross this threshold.
    ///
    /// Deliberately not gated by `beacon_excluded`'s `STANDARD_PORTS` (22,
    /// 23, 3389, …-style ports are exactly what credential-spray/lateral-
    /// movement traffic targets — excluding them here would blind the rule
    /// to the exact case that motivated it) or by name (comm is spoofable,
    /// same reasoning the rest of this file gives elsewhere). Only pid=4
    /// (Windows System) is excluded, same guaranteed-false-positive reason
    /// as `check_beacon`. No other exclusions yet — none of BEACON's own
    /// carry over cleanly to a distinct-destination shape, and none has been
    /// calibrated against a real false positive here; the plausible one (a
    /// mail relay or monitoring agent fanning out to many hosts on one port
    /// in a burst) is left for a live capture to confirm, not guessed at.
    fn check_scan_spread(&mut self, event: &ConnectEvent) -> Option<Alert> {
        if event.meta.pid == 4 {
            return None;
        }
        let key = (event.meta.pid, event.dport);
        let ts = event.meta.timestamp_ns;
        let entry = self
            .scan_spread
            .get_or_insert_with(key, SlidingDistinct::default);
        let distinct = entry.record(event.daddr, ts, SCAN_SPREAD_WINDOW_NS);
        if distinct >= SCAN_SPREAD_THRESHOLD && entry.try_alert(ts, SCAN_SPREAD_WINDOW_NS) {
            return Some(Alert {
                technique: "T1046/T1210",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} contacted {distinct} distinct destinations on port {} in \
                     {}s — suspected scan/spread burst",
                    event.meta.pid,
                    event.meta.comm,
                    event.dport,
                    SCAN_SPREAD_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// SCAN-VERTICAL (T1046, #378): many distinct ports on one host from one pid in a short
    /// window, the vertical mirror of [`Self::check_scan_spread`] (many hosts, one port). A
    /// TCP connect scan of a target; the horizontal rule cannot see it, as it keys on the
    /// port. Loopback destinations are not counted (see [`SCAN_VERTICAL_THRESHOLD`]). Only
    /// pid 4 (Windows System) is excluded, as in SCAN-SPREAD.
    fn check_scan_vertical(&mut self, event: &ConnectEvent) -> Option<Alert> {
        if event.meta.pid == 4 || event.daddr.is_loopback() || event.daddr.is_unspecified() {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        let entry = self
            .scan_vertical
            .get_or_insert_with((event.meta.pid, event.daddr), SlidingDistinct::default);
        let distinct = entry.record(event.dport, ts, SCAN_VERTICAL_WINDOW_NS);
        if distinct >= SCAN_VERTICAL_THRESHOLD && entry.try_alert(ts, SCAN_VERTICAL_WINDOW_NS) {
            return Some(Alert {
                technique: "T1046",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} contacted {distinct} distinct ports on {} in {}s — \
                     suspected port scan",
                    event.meta.pid,
                    event.meta.comm,
                    event.daddr,
                    SCAN_VERTICAL_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// T1071/T1041 via conntrack polling (issue #92) — same rule as
    /// [`Self::check_beacon`], fed by a periodic flow snapshot instead of a discrete
    /// `connect()` trace. This is the "probe-free" source `sensor-linux-netlink`
    /// exists for: it produces the same alert where eBPF/ETW cannot run, or as a
    /// redundant cross-check alongside them.
    ///
    /// A poll-based source re-reports the *same* open flow on every poll — unlike
    /// `ConnectEvent`, one `NetworkFlowEvent` is not one connection attempt. Without
    /// deduping, an ordinary long-lived connection (SSH, a websocket) still open on
    /// its 3rd poll inside the window would false-positive BEACON on its own.
    /// [`FlowPortDedup`] keyed by `local_port` — this host's stable identity for one
    /// flow's lifetime — only lets a given flow count once per window; a real beacon
    /// (N distinct short-lived connections, N distinct local ports) still crosses
    /// the threshold exactly as `check_beacon` would.
    fn check_beacon_flow(&mut self, event: &NetworkFlowEvent) -> Option<Alert> {
        if Self::beacon_excluded(&event.meta.comm, event.daddr, event.dport) {
            return None;
        }
        let key = (
            event.meta.comm.clone(),
            event.daddr.to_string(),
            event.dport,
        );
        let ts = event.meta.timestamp_ns;
        let dedup = self
            .beacon_flow_dedup
            .get_or_insert_with(key, FlowPortDedup::default);
        if !dedup.is_new(event.local_port, ts, BEACON_WINDOW_NS) {
            return None;
        }
        self.record_beacon(
            event.meta.pid,
            &event.meta.comm,
            event.daddr,
            event.dport,
            ts,
        )
    }

    /// The lineage this exec belongs to (see [`crate::recon`]): the parent, or the parent of a
    /// one-shot wrapper the parent is. Records a wrapper's own lineage for its children and
    /// this process's lineage for the rules that see it later.
    fn record_lineage(&mut self, event: &ExecEvent) -> crate::recon::Lineage {
        use crate::recon::{self, ExecLineage, Wrapper};

        let ppid = event.meta.ppid;
        let lineage = Wrapper::lineage_for(
            self.recon_wrappers.peek(&ppid),
            event.meta.parent_process_generation,
        )
        .unwrap_or((ppid, event.meta.parent_process_generation));
        if recon::is_one_shot_wrapper(event) {
            self.recon_wrappers.insert(
                event.meta.pid,
                Wrapper {
                    generation: event.meta.process_generation,
                    lineage,
                },
            );
        }
        self.exec_lineage.insert(
            event.meta.pid,
            ExecLineage {
                generation: event.meta.process_generation,
                lineage,
            },
        );
        lineage
    }

    /// RECON-BURST (T1057/T1082/T1016/T1087, #378): six distinct discovery commands
    /// across three categories from one lineage in 30 s. See [`crate::recon`] for what
    /// counts, what a lineage is, and the false positives accepted.
    fn check_recon_burst(
        &mut self,
        event: &ExecEvent,
        lineage: crate::recon::Lineage,
    ) -> Option<Alert> {
        use crate::recon;

        let (command, category) = recon::discovery(event)?;
        let burst = self
            .recon_burst
            .get_or_insert_with(lineage, recon::ReconWindow::default)
            .record(command, category, event.meta.timestamp_ns)?;
        Some(Alert {
            technique: recon::RECON_BURST_TECHNIQUE,
            severity: Severity::Low,
            message: format!(
                "pid={} comm={}: lineage of pid={} ran {} distinct discovery commands ({}) \
                 across {} categories in {}s — reconnaissance, by hand or by script",
                event.meta.pid,
                event.meta.comm,
                lineage.0,
                burst.commands.len(),
                burst.commands.join(", "),
                burst.categories,
                recon::RECON_BURST_WINDOW_NS / 1_000_000_000,
            ),
        })
    }

    /// SECURITY-DISCOVERY (T1518.001, #378): three distinct security-software discovery
    /// commands from one lineage in 60 s: the posture questions (`getenforce`, `csrutil
    /// status`, `Get-MpComputerStatus`, `netsh advfirewall show`, `fltmc`) and lookups of a
    /// named security product (`ps | grep falcon`, `sc query windefend`). One command is
    /// what a hardening check does; three different ones in a minute is a host being sized
    /// up. Low: compliance scanners (`OpenSCAP`, lynis, Qualys-style audits) run the same set.
    fn check_security_discovery(
        &mut self,
        event: &ExecEvent,
        lineage: crate::recon::Lineage,
    ) -> Option<Alert> {
        use crate::recon::{SECURITY_DISCOVERY_THRESHOLD, SECURITY_DISCOVERY_WINDOW_NS};

        let label = crate::recon::security_discovery(event)?;
        let ts = event.meta.timestamp_ns;
        let entry = self
            .security_discovery
            .get_or_insert_with(lineage, SlidingDistinct::default);
        let distinct = entry.record(label, ts, SECURITY_DISCOVERY_WINDOW_NS);
        if distinct >= SECURITY_DISCOVERY_THRESHOLD
            && entry.try_alert(ts, SECURITY_DISCOVERY_WINDOW_NS)
        {
            let seen: Vec<&str> = entry.values().copied().collect();
            return Some(Alert {
                technique: "T1518.001",
                severity: Severity::Low,
                message: format!(
                    "pid={} comm={}: lineage of pid={} ran {distinct} distinct security-software \
                     discovery commands ({}) in {}s — the host's defences being sized up",
                    event.meta.pid,
                    event.meta.comm,
                    lineage.0,
                    seen.join(", "),
                    SECURITY_DISCOVERY_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// SERVICE-STOP-BURST (T1489, #381): five distinct services stopped from one lineage in
    /// 60 s, the pre-ransomware tell. An exec that names several services (`systemctl stop a
    /// b c`, `Stop-Service a,b,c`) counts each. See [`crate::servicestop`] for what counts and
    /// the false positives accepted. Medium. Not joined to the ransomware reflex or the
    /// damage manifest, which consume T1486 alerts only.
    fn check_service_stop_burst(
        &mut self,
        event: &ExecEvent,
        lineage: crate::recon::Lineage,
    ) -> Option<Alert> {
        use crate::servicestop::{SERVICE_STOP_THRESHOLD, SERVICE_STOP_WINDOW_NS};

        let stopped = crate::servicestop::services_stopped(event);
        if stopped.is_empty() {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        let entry = self
            .service_stop
            .get_or_insert_with(lineage, SlidingDistinct::default);
        let mut distinct = 0;
        for name in stopped {
            distinct = entry.record(name, ts, SERVICE_STOP_WINDOW_NS);
        }
        if distinct >= SERVICE_STOP_THRESHOLD && entry.try_alert(ts, SERVICE_STOP_WINDOW_NS) {
            let seen: Vec<&str> = entry.values().map(String::as_str).take(12).collect();
            return Some(Alert {
                technique: "T1489",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={}: lineage of pid={} stopped {distinct} distinct services ({}{}) \
                     in {}s — the services a ransomware run stops first, or a maintenance window",
                    event.meta.pid,
                    event.meta.comm,
                    lineage.0,
                    seen.join(", "),
                    if distinct as usize > seen.len() {
                        ", ..."
                    } else {
                        ""
                    },
                    SERVICE_STOP_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// SSH-FANOUT (T1021.004, #378): outbound SSH to eight distinct hosts from one lineage in
    /// 60 s. The lineage is the one the connecting process was exec'd under, so a loop that
    /// runs `ssh host cmd` per host (one process, one connect each) adds up where a per-pid
    /// counter such as SCAN-SPREAD sees one connection per process. Whether the lineage is
    /// interactive is not observable here, so a human typing eight `ssh` commands in a
    /// minute is indistinguishable from a script; what fires in practice is `pssh` and
    /// similar fleet tools run from one shell, the accepted cost. Loopback is not counted.
    /// A process the rules never saw exec'd (started before the agent) has no lineage and is
    /// not counted.
    fn check_ssh_fanout(&mut self, event: &ConnectEvent) -> Option<Alert> {
        use crate::recon::{ExecLineage, SSH_FANOUT_THRESHOLD, SSH_FANOUT_WINDOW_NS, SSH_PORT};

        if event.dport != SSH_PORT || event.daddr.is_loopback() || event.daddr.is_unspecified() {
            return None;
        }
        let lineage = ExecLineage::current(
            self.exec_lineage.peek(&event.meta.pid),
            event.meta.process_generation,
        )?;
        let ts = event.meta.timestamp_ns;
        let entry = self
            .ssh_fanout
            .get_or_insert_with(lineage, SlidingDistinct::default);
        let distinct = entry.record(event.daddr, ts, SSH_FANOUT_WINDOW_NS);
        if distinct >= SSH_FANOUT_THRESHOLD && entry.try_alert(ts, SSH_FANOUT_WINDOW_NS) {
            return Some(Alert {
                technique: "T1021.004",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={}: lineage of pid={} opened SSH sessions to {distinct} distinct \
                     hosts in {}s — lateral movement by script, or a fleet tool run from one shell",
                    event.meta.pid,
                    event.meta.comm,
                    lineage.0,
                    SSH_FANOUT_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// To be called for every `ExecEvent` in the stream, in chronological order.
    /// Updates the state (pid→comm table) after evaluation, so a process cannot match
    /// itself.
    pub fn on_exec(&mut self, event: &ExecEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        alerts.extend(self.check_web_server_spawns_shell(event));
        alerts.extend(self.check_download_then_exec(event));
        alerts.extend(self.check_bits_download_exec(event));
        alerts.extend(self.check_exec_after_motw_removal(event));
        alerts.extend(self.check_self_spawn(event));
        alerts.extend(self.check_parent_suspect(event));
        alerts.extend(self.check_lolbin(event));
        alerts.extend(self.check_memfd_exec(event));
        let lineage = self.record_lineage(event);
        alerts.extend(self.check_recon_burst(event, lineage));
        alerts.extend(self.check_security_discovery(event, lineage));
        alerts.extend(self.check_service_stop_burst(event, lineage));
        alerts.extend(crate::stateless::check_ld_preload_hijack(
            event,
            &self.ld_trust_extra,
        ));

        let generation = event.meta.process_generation;
        self.pid_comm.insert(
            event.meta.pid,
            PidFact::new(generation, event.meta.comm.clone()),
        );
        self.pid_image_path.insert(
            event.meta.pid,
            PidFact::new(generation, event.image_path.clone()),
        );
        alerts
    }

    /// The exec findings that wait for the image's signature (#441): today
    /// T1204.002, a downloaded file run within the mark window. To be called
    /// for every `ExecEvent`, beside [`Self::on_exec`]. The
    /// caller resolves each with the enrichment's verdict, or calls
    /// [`SignatureGatedAlert::unverified`] when it cannot wait for one.
    pub fn on_exec_signature_gated(&mut self, event: &ExecEvent) -> Option<SignatureGatedAlert> {
        self.check_quarantined_exec(event)
    }

    /// To be called for every `ConnectEvent` in the stream (mainly Windows ETW).
    pub fn on_connect(&mut self, event: &ConnectEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_beacon(event).into_iter().collect();
        alerts.extend(self.check_scan_spread(event));
        alerts.extend(self.check_scan_vertical(event));
        alerts.extend(self.check_archive_egress(&event.meta, event.daddr));
        alerts.extend(self.check_ssh_fanout(event));
        alerts
    }

    /// To be called for every `NetworkFlowEvent` in the stream (Linux conntrack
    /// polling, issue #92) — see [`Self::check_beacon_flow`].
    pub fn on_network_flow(&mut self, event: &NetworkFlowEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_beacon_flow(event).into_iter().collect();
        alerts.extend(self.check_egress_volume(event));
        alerts.extend(self.check_archive_egress(&event.meta, event.daddr));
        alerts
    }

    /// To be called for every `DnsQueryEvent` in the stream (the Linux `getaddrinfo` probe,
    /// opt-in; the Windows DNS-Client provider; the macOS network extension). Never alerts: it
    /// remembers that this pid resolved a listed storage or paste service to these addresses, for
    /// [`Self::check_egress_volume`] to join with the volume it later sends there.
    pub fn on_dns_query(&mut self, event: &DnsQueryEvent) {
        let Some(class) = egressdomain::classify_domain(&event.query) else {
            return;
        };
        if event.status != 0 {
            return;
        }
        let Some(result) = event.result.as_deref() else {
            return;
        };
        for address in egressdomain::resolved_addresses(result) {
            self.dns_class.insert(
                (event.meta.pid, address),
                DnsClassSighting {
                    generation: event.meta.process_generation,
                    class,
                    domain: event.query.to_ascii_lowercase(),
                    timestamp_ns: event.meta.timestamp_ns,
                },
            );
        }
    }

    /// ARCHIVE-EXFIL, first link: a pid that opens an archive-named file for writing starts
    /// counting its written bytes; a pid that opens a **staged** archive (see
    /// [`Self::record_archive_write`]) without write intent, within [`ARCHIVE_READ_WINDOW_NS`]
    /// of its staging, becomes a reader waiting for a connection. The writer itself is not a
    /// reader: extracting what it just wrote is not a hand-off.
    fn record_archive_open(&mut self, event: &FileOpenEvent) {
        let pid = event.meta.pid;
        let ts = event.meta.timestamp_ns;
        if has_write_intent(event.flags) {
            if is_archive_name(&event.path) {
                // A new write open of the path starts a new archive: a staging from an
                // earlier run (a nightly job rewriting `home.tar.gz`) must not outlive it,
                // or the read window would be measured from the first night forever.
                self.staged_archives.remove(&event.path);
                self.archive_writers.insert(
                    pid,
                    ArchiveWriter {
                        generation: event.meta.process_generation,
                        path: event.path.clone(),
                        bytes: 0,
                    },
                );
            }
            return;
        }
        let Some(&staged_ns) = self.staged_archives.peek(&event.path) else {
            return;
        };
        if ts.saturating_sub(staged_ns) > ARCHIVE_READ_WINDOW_NS {
            return;
        }
        if self.archive_writers.peek(&pid).is_some_and(|w| {
            w.path == event.path && same_incarnation(w.generation, event.meta.process_generation)
        }) {
            return;
        }
        self.archive_readers.insert(
            pid,
            ArchiveReader {
                generation: event.meta.process_generation,
                path: event.path.clone(),
                read_ns: ts,
                alerted: false,
            },
        );
    }

    /// ARCHIVE-EXFIL, second link: the bytes the writer pid writes after opening the archive.
    /// Crossing [`ARCHIVE_STAGED_BYTES`] stages it, once.
    fn record_archive_write(&mut self, event: &FileWriteEvent) {
        let Some(writer) = self.archive_writers.get_mut(&event.meta.pid) else {
            return;
        };
        if !same_incarnation(writer.generation, event.meta.process_generation) {
            return;
        }
        writer.bytes = writer.bytes.saturating_add(event.bytes_requested);
        if writer.bytes >= ARCHIVE_STAGED_BYTES {
            // The staging time is the last write past the threshold, not the first: a job
            // that keeps writing for hours is finished when it stops, and the read window
            // counts from there.
            let path = writer.path.clone();
            self.staged_archives.insert(path, event.meta.timestamp_ns);
        }
    }

    /// ARCHIVE-EXFIL (T1560/T1041, #380) — the chain: a pid wrote an archive of at least
    /// [`ARCHIVE_STAGED_BYTES`], **another** pid read that file, and that reader then
    /// connected to a public address within [`ARCHIVE_EGRESS_WINDOW_NS`]. One alert per
    /// reader. Medium, not higher: a backup job that archives and then uploads to an object
    /// store is exactly this shape, and no allowlist of such jobs exists yet (it needs a
    /// lab capture of the host's own backups). Gaps, stated: a stream that never touches a
    /// file (`tar | ssh`), an archive named without one of [`ARCHIVE_SUFFIXES`], and a
    /// sender that is not the reader (a file handed over by a pipe or a copy).
    ///
    /// False positives beyond the backup job, from the shape itself: the reader is any
    /// process that opens the file without write intent, and any public connection from that
    /// pid inside the window completes the chain, with no link between the bytes read and the
    /// destination. A long-lived daemon (an antivirus scanner, an indexer, a sync client) that
    /// touches the archive and later makes an unrelated connection alerts. Open, connect and
    /// flow events arrive from separate rings, so a connection stamped just before the open
    /// can be ordered after it; the window absorbs that.
    fn check_archive_egress(&mut self, meta: &schema::EventMeta, daddr: IpAddr) -> Option<Alert> {
        if !is_public_address(daddr) {
            return None;
        }
        let reader = self.archive_readers.get_mut(&meta.pid)?;
        if reader.alerted
            || !same_incarnation(reader.generation, meta.process_generation)
            || meta.timestamp_ns.saturating_sub(reader.read_ns) > ARCHIVE_EGRESS_WINDOW_NS
        {
            return None;
        }
        reader.alerted = true;
        Some(Alert {
            technique: "T1560/T1041",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} read the staged archive {} and connected to {}",
                meta.pid, meta.comm, reader.path, daddr,
            ),
        })
    }

    /// EGRESS-VOLUME (T1041/T1048, #380) — a process name that sends more than
    /// [`EGRESS_BYTES_THRESHOLD`] to one public address inside
    /// [`EGRESS_WINDOW_NS`], summed over all its connections to that address.
    ///
    /// Conntrack counters are cumulative per flow and a poll-based source re-reports
    /// a live flow every cycle, so the volume of one poll is the difference with the
    /// previous poll of the same flow. **The first poll of a flow only sets its
    /// baseline** and adds nothing: a flow already open when the agent started carries
    /// the history of its whole life, and counting it would alert on any long SSH or
    /// backup session at startup. The cost is named: a transfer that starts and ends
    /// between two polls of a brand-new flow is not counted; a sustained one is, from
    /// its second poll.
    ///
    /// Inert without volume data: `bytes_sent` is `None` unless the host enabled
    /// `net.netfilter.nf_conntrack_acct` (off by default, see [`NetworkFlowEvent`]), so
    /// silence here does not mean nothing was sent. Private, loopback, link-local,
    /// multicast and unspecified peers are excluded: a backup to the local network is
    /// not the signal this rule looks for. No name exclusion list yet, for the reason
    /// given at [`EGRESS_BYTES_THRESHOLD`].
    ///
    /// **EGRESS-DOMAIN (T1567, #380)** reads the same sum. When the pid itself resolved a listed
    /// storage or paste service to this address ([`Self::on_dns_query`],
    /// [`Self::resolved_service`]), the lower [`EGRESS_CLASSED_BYTES_THRESHOLD`] applies and the
    /// alert names the technique of the class (T1567.002 or T1567.003) and the domain. It is
    /// **dormant on a default host**: it needs `nf_conntrack_acct` for the volume *and* a DNS
    /// source for the lookup (the Linux `getaddrinfo` probe is opt-in, `UprobesConfig::with_dns_enabled`).
    /// Without the lookup the generic threshold above is all there is. Only the first address of a
    /// Linux lookup is recorded, so a connection to another address of the same answer is not
    /// joined (the Windows provider lists them all).
    fn check_egress_volume(&mut self, event: &NetworkFlowEvent) -> Vec<Alert> {
        let Some(sent) = event.bytes_sent else {
            return Vec::new();
        };
        if !is_public_address(event.daddr) {
            return Vec::new();
        }
        let flow = (
            event.meta.comm.clone(),
            event.daddr,
            event.dport,
            event.local_port,
        );
        let previous = self.egress_flow_last.get(&flow).copied();
        self.egress_flow_last.insert(flow, sent);
        // First poll of the flow: baseline only. A counter that went down is a new
        // flow on a reused local port: its whole value is new volume.
        let delta = match previous {
            None => return Vec::new(),
            Some(last) if sent >= last => sent - last,
            Some(_) => sent,
        };
        if delta == 0 {
            return Vec::new();
        }
        let ts = event.meta.timestamp_ns;
        let class = self.resolved_service(event);
        let entry = self.egress_volume.get_or_insert_with(
            (event.meta.comm.clone(), event.daddr),
            EgressVolume::default,
        );
        let total = entry.sum.add(ts, delta, EGRESS_WINDOW_NS);
        let mut alerts = Vec::new();
        let recently =
            |last: Option<u64>| last.is_some_and(|t| ts.saturating_sub(t) < EGRESS_WINDOW_NS);
        if let Some((class, domain)) = class
            && total >= EGRESS_CLASSED_BYTES_THRESHOLD
            && !recently(entry.last_class_alert_ns)
        {
            entry.last_class_alert_ns = Some(ts);
            alerts.push(Alert {
                technique: class.technique(),
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} sent {}MB to {} ({domain}, a {} service) in {}s — possible \
                     exfiltration to a web service",
                    event.meta.pid,
                    event.meta.comm,
                    total / (1024 * 1024),
                    event.daddr,
                    class.label(),
                    EGRESS_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        if total >= EGRESS_BYTES_THRESHOLD && !recently(entry.last_alert_ns) {
            entry.last_alert_ns = Some(ts);
            alerts.push(Alert {
                technique: "T1041/T1048",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} sent {}MB to {} in {}s — possible exfiltration over the \
                     network",
                    event.meta.pid,
                    event.meta.comm,
                    total / (1024 * 1024),
                    event.daddr,
                    EGRESS_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        alerts
    }

    /// EGRESS-DOMAIN's join key: the storage or paste service this very pid resolved to the
    /// flow's address, within [`DNS_CLASS_WINDOW_NS`], unless the pid is a browser (see
    /// [`EGRESS_DOMAIN_BROWSER_COMMS`]). The class comes from the process's own lookup because
    /// the address alone is shared with every other site behind the same CDN. A sighting
    /// recorded for another incarnation of the pid (a recycled number) is not an answer.
    fn resolved_service(&self, event: &NetworkFlowEvent) -> Option<(DomainClass, String)> {
        let sighting = self.dns_class.peek(&(event.meta.pid, event.daddr))?;
        let ts = event.meta.timestamp_ns;
        if ts.saturating_sub(sighting.timestamp_ns) > DNS_CLASS_WINDOW_NS
            || matches!(
                (sighting.generation, event.meta.process_generation),
                (Some(recorded), Some(current)) if recorded != current
            )
        {
            return None;
        }
        let image = PidFact::current(
            &self.pid_image_path,
            event.meta.pid,
            event.meta.process_generation,
        );
        let is_browser = EGRESS_DOMAIN_BROWSER_COMMS.contains(&event.meta.comm.as_str())
            && policy::name_exclusion_applies(image);
        (!is_browser).then(|| (sighting.class, sighting.domain.clone()))
    }

    /// LISTENER-DRIFT (issue #92, T1571 — non-standard port is the closest
    /// existing tag in this crate; no better precedent for "a new listener
    /// appeared" exists here yet, calibratable later) — a listening socket that
    /// wasn't in the startup baseline ([`Self::seed_listen_ports`]) nor already
    /// alerted on this run. One alert per (`local_addr`, `local_port`): the second
    /// poll to see the same listener is expected (a poll-based source re-reports
    /// it every cycle while it stays open, same reasoning as
    /// [`Self::check_beacon_flow`]'s dedup), not a second finding.
    ///
    /// No name/path exclusion list yet — unlike BEACON's `BROWSERS`/
    /// `STANDARD_PORTS`, there is no lab capture here to calibrate one honestly
    /// against (a dev server or `docker-proxy` binding a fresh port after
    /// startup will alert; a documented, known noise source, not a bug).
    fn check_listen_port_drift(&mut self, event: &ListenPortEvent) -> Option<Alert> {
        let key = (event.local_addr, event.local_port);
        if self.known_listeners.get(&key).is_some() {
            return None;
        }
        self.known_listeners.insert(key, ());
        Some(Alert {
            technique: "T1571",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} new listener on {}:{} — not seen at agent startup",
                event.meta.pid, event.meta.comm, event.local_addr, event.local_port,
            ),
        })
    }

    /// To be called for every `ListenPortEvent` in the stream (Linux `sock_diag`
    /// polling, issue #92) — see [`Self::check_listen_port_drift`].
    pub fn on_listen_port(&mut self, event: &ListenPortEvent) -> Vec<Alert> {
        self.check_listen_port_drift(event).into_iter().collect()
    }

    /// POLICY-DENIAL-DRIFT (issue #774, T1562-adjacent) — see
    /// `known_policy_denials`'s doc for why this alerts on a new
    /// (subject, object, class) triple rather than on every denial. Fires for
    /// `PolicyDenialEvent::enforced` either way (`SELinux` permissive logs the
    /// same fact a managed Enforcing host would act on) — the point is a new
    /// *shape* of denial, not whether this particular one was blocked.
    ///
    /// The key depends on the mechanism (#796), see `known_policy_denials`'s doc. A mechanism
    /// other than `SELinux`, `AppLocker` or WDAC never alerts. Severity is Medium, except Low
    /// for an `AppLocker` or WDAC denial in audit mode (`enforced: false`): a rollout in audit
    /// mode logs every unlisted binary once, and that is routine. `SELinux` stays Medium
    /// either way.
    ///
    /// Inert while the eBPF sensor is selected (#780): `SELinux` AVC denials
    /// only reach the agent through the audit sensor, so silence here does not
    /// mean no denials happened.
    ///
    /// The requested permission is part of the key (#813, recovered by
    /// `sensor-linux-audit`'s AVC parser): a routine `getattr` denial no longer
    /// silences a later, more interesting `read`/`write`/`open` on the same subject,
    /// object and class. `None` (an AppLocker/WDAC denial, or an AVC variant the
    /// parser doesn't recognize) is its own value, same as every other field here.
    ///
    /// Capped at [`POLICY_DENIAL_ALERT_CAP`] new-shape alerts per subject type per
    /// [`crate::exclusions::POLICY_DENIAL_ALERT_WINDOW_NS`] (#812, per subject since #840): a
    /// flood of shapes from one domain past its cap is counted (`policy_denial_alerts_shed`)
    /// rather than alerted, and never touches another domain's budget. A shed shape is not
    /// recorded in `known_policy_denials`, so it is still new — it can alert once its
    /// subject's budget refills in a later window instead of being silenced for the rest of the
    /// run. The cap bounds alert volume; `known_policy_denials` keeps deduplicating
    /// the shapes that did alert.
    ///
    /// The permission set in the key is normalised ([`normalized_permissions`]): `read
    /// write` and `write read` are one shape.
    fn check_policy_denial_drift(&mut self, event: &PolicyDenialEvent) -> Option<Alert> {
        let key: PolicyDenialKey = match event.mechanism.as_str() {
            POLICY_MECHANISM_SELINUX => (
                event.mechanism.clone(),
                Self::selinux_type_triple(event.subject_context.as_deref()),
                Self::selinux_type_triple(event.object_context.as_deref()),
                event.object_class.clone(),
                event.action.as_deref().map(normalized_permissions),
            ),
            // AppLocker: (rule collection, file). The sensor leaves both contexts `None`, so
            // the budget below is one shared by every AppLocker denial.
            POLICY_MECHANISM_APPLOCKER => (
                event.mechanism.clone(),
                None,
                event.object_path.as_deref().map(str::to_lowercase),
                event.object_class.clone(),
                None,
            ),
            // WDAC: (loading process, file, signing scenario), so the budget is per process.
            POLICY_MECHANISM_WDAC => (
                event.mechanism.clone(),
                event.subject_context.as_deref().map(str::to_lowercase),
                event.object_path.as_deref().map(str::to_lowercase),
                event.object_class.clone(),
                None,
            ),
            _ => return None,
        };
        if self.known_policy_denials.get(&key).is_some() {
            return None;
        }
        let now = event.meta.timestamp_ns;
        // The budget is the subject type's (`key.1`, the context without its MLS part), so a noisy
        // domain spends its own and nobody else's.
        let budget = self
            .policy_denial_budgets
            .get_or_insert_with(key.1.clone(), PolicyDenialBudget::default);
        if budget.window_start_ns.is_none_or(|start| {
            now.saturating_sub(start) >= crate::exclusions::POLICY_DENIAL_ALERT_WINDOW_NS
        }) {
            *budget = PolicyDenialBudget {
                window_start_ns: Some(now),
                ..PolicyDenialBudget::default()
            };
        }
        if budget.alerts >= POLICY_DENIAL_ALERT_CAP {
            if budget.shed == 0 {
                tracing::warn!(
                    cap = POLICY_DENIAL_ALERT_CAP,
                    subject = key.1.as_deref().unwrap_or("-"),
                    "policy-denial-drift: alert cap reached for this subject, its further new shapes are counted but not alerted until its budget refills"
                );
            }
            budget.shed += 1;
            self.policy_denial_alerts_shed += 1;
            self.report_policy_denial_evictions();
            return None;
        }
        budget.alerts += 1;
        self.known_policy_denials.insert(key, ());
        self.report_policy_denial_evictions();
        Some(Alert {
            technique: "T1562",
            // A Windows policy in audit mode logs every unlisted binary once during a rollout:
            // routine, not an incident. SELinux keeps Medium either way (see the doc above).
            severity: if event.mechanism != POLICY_MECHANISM_SELINUX && !event.enforced {
                Severity::Low
            } else {
                Severity::Medium
            },
            message: format!(
                "comm={} mechanism={} subject={} object={} class={} action={} path={} enforced={} — new denial shape, not seen this run",
                event.meta.comm,
                event.mechanism,
                event.subject_context.as_deref().unwrap_or("-"),
                event.object_context.as_deref().unwrap_or("-"),
                event.object_class.as_deref().unwrap_or("-"),
                event.action.as_deref().unwrap_or("-"),
                event.object_path.as_deref().unwrap_or("-"),
                event.enforced,
            ),
        })
    }

    /// Logs once per rise in `known_policy_denials`'s eviction count (#812): otherwise
    /// `known_policy_denials` evicting its oldest eighth at `COUNTER_CAP` and a shape
    /// re-alerting is silent loss (CLAUDE.md: counted, observable shedding), the same
    /// idiom as `agent::ransomware_join`'s `report_evictions`. Also carries the running
    /// total of alerts shed by [`POLICY_DENIAL_ALERT_CAP`] (review of #823): this is the
    /// only periodic signal the alert cap gets — once it is reached, the "alert cap
    /// reached" warning fires exactly once, never again, so without this an operator
    /// cannot tell 10 shed shapes from 100,000.
    fn report_policy_denial_evictions(&mut self) {
        let budgets_evicted = self.policy_denial_budgets.evicted();
        if budgets_evicted > self.policy_denial_budget_evictions_reported {
            tracing::warn!(
                budgets_evicted,
                "policy-denial-drift: subject alert budgets forgotten (least recently seen first); those subjects start a fresh budget"
            );
            self.policy_denial_budget_evictions_reported = budgets_evicted;
        }
        let evicted = self.known_policy_denials.evicted();
        if evicted > self.policy_denial_evictions_reported {
            tracing::warn!(
                evicted,
                alerts_shed = self.policy_denial_alerts_shed,
                "policy-denial-drift: tracked denial shapes shed (oldest first)"
            );
            self.policy_denial_evictions_reported = evicted;
        }
    }

    /// The `user:role:type` prefix of a `SELinux` security context
    /// (`user:role:type:sensitivity[:categories]`), dropped from
    /// [`PolicyDenialKey`] so a container's own MCS/MLS category pair does not
    /// make every denial from it a "new" shape (#781 review: two denials
    /// differing only in category gave two alerts). A bounded split, not a
    /// split on the last colon: the MLS field itself can contain one
    /// (`s0-s0:c0.c1023`). A bare type with no context at all (`httpd_t`)
    /// passes through unchanged.
    fn selinux_type_triple(context: Option<&str>) -> Option<String> {
        context.map(|c| c.splitn(4, ':').take(3).collect::<Vec<_>>().join(":"))
    }

    /// To be called for every `PolicyDenialEvent` in the stream (`SELinux` AVC
    /// on Linux issue #297, AppLocker/WDAC on Windows issue #283) — see
    /// [`Self::check_policy_denial_drift`].
    pub fn on_policy_denial(&mut self, event: &PolicyDenialEvent) -> Vec<Alert> {
        self.check_policy_denial_drift(event).into_iter().collect()
    }

    /// To be called for every `LdapSearchEvent` (Windows, #364): the
    /// directory-enumeration sweep, many distinct searches from one process
    /// in a short window. The single-search rules are
    /// [`crate::evaluate_ldap_search`].
    pub fn on_ldap_search(&mut self, event: &schema::LdapSearchEvent) -> Vec<Alert> {
        self.ldap_burst.observe(event).into_iter().collect()
    }

    /// To be called for every `AuthEvent` in the stream (issue #377, T1110):
    /// counts failures per (target user, source) on a sliding window and
    /// alerts once per window when the burst threshold is crossed. A success
    /// deliberately doesn't reset the counter — a success right after a burst
    /// is the *stronger* signal, not an all-clear. For a Windows RDP success
    /// that signal is [`Self::rdp_success`] (T1021.001, joined from a separate
    /// `SessionEvent`); for a local `sudo`/`su` success it is
    /// [`Self::sudo_success`] (#381, T1548.003 for `sudo` / T1110.001 for `su`
    /// — see `crate::sudo`'s module doc) below, joined from this same
    /// `AuthEvent` stream. A local `sudo`/`su` failure also counts into the burst
    /// counter below (key: target account, source `"local"`, `sudo` and `su` sharing
    /// one key), so five wrong passwords in the window raise T1110 by themselves,
    /// before and independently of any success (#838).
    ///
    /// A **successful** [`AuthKind::Logon`] also goes through FIRST-SEEN-LOGON
    /// ([`Self::check_first_seen_logon`], T1078); it is the one rule on `main` that fires
    /// on a successful logon.
    pub fn on_auth(&mut self, event: &AuthEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_first_seen_logon(event).into_iter().collect();
        alerts.extend(self.on_auth_failures_and_escalations(event));
        alerts
    }

    /// FIRST-SEEN-LOGON (T1078, #376) — a successful logon ([`AuthKind::Logon`], never a
    /// failure, never `su`/`sudo`'s [`AuthKind::ExplicitCredentials`] or
    /// [`AuthKind::PrivilegedSession`]) of an account that did not log on to this host during
    /// the first [`LOGON_LEARNING_NS`](crate::exclusions::LOGON_LEARNING_NS) after the first
    /// one the state saw. One alert per account: it is in the baseline afterwards. Low: a new
    /// colleague, a new service account and a reinstalled host look the same, and nothing
    /// here separates them.
    ///
    /// **This makes the control plane's identity join live** (`server/lib/fleet-case.ts`,
    /// #62, #940): the join reads the event a detection stores, and until this rule no rule
    /// on `main` fired on a successful logon. The limits of that join are this rule's: the
    /// generic accounts are excluded (see `crate::logon`), `vagrant` deliberately is not,
    /// and a `LogonFailure` never counts because its user name is chosen by whoever tries
    /// it.
    ///
    /// The baseline is **in memory**: an agent restart, an update included, begins a new
    /// learning window, and an account that logs on during the window is learned without an
    /// alert, an intruder's included. Expected false positives: a domain controller or file
    /// server, which sees every user's first logon; a new hire; a service account first
    /// used after an install. **Not built, and why: odd hours.** The event carries a UTC
    /// timestamp and no timezone, and no part of the agent knows the host's local time, so
    /// "outside working hours" cannot be said honestly yet.
    fn check_first_seen_logon(&mut self, event: &AuthEvent) -> Option<Alert> {
        if event.outcome != AuthOutcome::Success || event.kind != AuthKind::Logon {
            return None;
        }
        match self
            .logon_baseline
            .observe(&event.target_user, event.meta.timestamp_ns)
        {
            Observation::FirstSeen => {}
            Observation::Quiet | Observation::Known => return None,
        }
        let source = event
            .source_address
            .map_or_else(String::new, |address| format!(" from {address}"));
        Some(Alert {
            technique: "T1078",
            severity: Severity::Low,
            message: format!(
                "first successful logon of account {}{source} on this host since the baseline began",
                event.target_user,
            ),
        })
    }

    /// The failure-burst and `sudo`/`su` joins of [`Self::on_auth`].
    fn on_auth_failures_and_escalations(&mut self, event: &AuthEvent) -> Vec<Alert> {
        let ts = event.meta.timestamp_ns;
        if event.outcome == AuthOutcome::Success {
            // Only a local (Unix) privilege-escalation success joins the sudo/su
            // burst history — a Windows logon success is [`Self::rdp_success`]'s
            // job, fed from the Terminal Services session event instead, not
            // this one (see that field's doc). `PrivilegedSession`/
            // `ExplicitCredentials` are only ever produced for `sudo`/`su`
            // (`auth::to_auth_event`), so `event.meta.comm` is already one of
            // the two here; the explicit match is defense in depth, not a new
            // restriction. `sudo` joins on the trusted uid, not a name, and
            // `su` still joins on the target `AuthEvent::target_user` names —
            // see `crate::sudo`'s module doc for why they differ (review of
            // #838, Sollykhan 2026-10-19, point 1).
            let User::Unix { uid, .. } = event.meta.user else {
                return Vec::new();
            };
            return if matches!(
                event.kind,
                AuthKind::PrivilegedSession | AuthKind::ExplicitCredentials
            ) {
                match event.meta.comm.as_str() {
                    "sudo" => self.sudo_success.on_sudo_success(uid, ts),
                    "su" => self.sudo_success.on_su_success(&event.target_user, ts),
                    _ => Vec::new(),
                }
            } else {
                Vec::new()
            };
        }
        // "local" for console/service logons that legitimately carry no
        // source address (see `AuthEvent::source_address`'s doc) — a distinct
        // key, never a fabricated loopback.
        let source = event
            .source_address
            .map_or_else(|| "local".to_string(), |a| a.to_string());
        let key = (event.target_user.clone(), source.clone());
        // A success can reach the rules before the last failures that precede
        // it (two channels, two poll threads, for RDP's own join): this failure
        // may complete it. Only failures from the Windows Security log feed that
        // join: they carry a Windows identity and are stamped with the event's
        // own time, like the 1149. Application-log failures (`[logs]` sources)
        // are stamped when the line is read, so a restart replaying a backlog
        // would make hours-old failures look current: other clock, not joined.
        let mut alerts: Vec<Alert> = event
            .source_address
            .filter(|_| matches!(event.meta.user, User::Windows { .. }))
            .map(|address| self.rdp_success.on_failure(address, ts))
            .unwrap_or_default();
        // The sudo/su join has no such cross-channel concern (one journal
        // stream feeds both sides of it), but still joins by event time, not
        // arrival order — see the `sudo` module's doc. Gated on `comm`, not
        // just `User::Unix`: an sshd failure (`LogonFailure` from `SshFailed`)
        // is also a Unix identity, and must never reach this join at all —
        // unchanged by the point below. What changed (review of #838,
        // Sollykhan 2026-10-19, point 1): once an event *does* pass this
        // gate, `sudo`'s own side of the join now keys on the trusted uid
        // below, not on anything parsed from the message; `su`'s still keys
        // on the target name, which has its own, narrower residual exposure
        // — see `crate::sudo`'s doc for why the two differ.
        if let User::Unix { uid, .. } = event.meta.user {
            match event.meta.comm.as_str() {
                "sudo" => alerts.extend(self.sudo_success.on_sudo_failure(uid, ts)),
                "su" => alerts.extend(self.sudo_success.on_su_failure(&event.target_user, ts)),
                _ => {}
            }
        }
        let entry = self
            .auth_failures
            .get_or_insert_with(key, SlidingCounter::default);
        let count = entry.record(ts, AUTH_FAILURE_WINDOW_NS);
        if count >= AUTH_FAILURE_THRESHOLD && entry.try_alert(ts, AUTH_FAILURE_WINDOW_NS) {
            alerts.push(Alert {
                technique: "T1110",
                severity: Severity::Medium,
                message: format!(
                    "target={} source={source}: {count} failed authentications in {}s —                      brute-force/spray burst",
                    event.target_user,
                    AUTH_FAILURE_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        alerts
    }

    /// To be called for every `SessionEvent` in the stream (Windows Terminal
    /// Services, #285): a disconnected session reconnected from another
    /// client, T1563.002 (see the `session` module), or a successful RDP listener
    /// authentication after failures from that source, T1021.001.
    pub fn on_session(&mut self, event: &SessionEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.session_hijack.on_session(event).into_iter().collect();

        if event.state != SessionState::Connect || event.console {
            return alerts;
        }
        if let Some(address) = event.source_address {
            alerts.extend(self.rdp_success.on_success(
                address,
                event.meta.timestamp_ns,
                &event.target_user,
            ));
        }
        alerts
    }

    /// To be called for every `MemfdCreateEvent` in the stream (Linux, issue
    /// #265). `memfd_create(2)` alone is common in legitimate code (glibc,
    /// systemd, browser sandboxing); it's the *exec* that's the technique, not
    /// the creation, so this mostly just records the timestamp
    /// `check_memfd_exec` consumes as corroborating evidence for its
    /// `/proc/.../fd/<n>` shape.
    ///
    /// Can still produce an alert directly (#503 review, Nikolas): the kernel
    /// always creates the memfd before executing it, but userspace drains the
    /// `memfd_create` and `exec` ring buffers independently
    /// (`crates/sensors/linux/userspace`'s `tokio::select!`), so the *exec*
    /// event can be processed here first despite the kernel-side ordering.
    /// `check_memfd_exec` holds that exec as [`Self::pending_proc_fd_exec`]
    /// instead of dropping it outright; this method checks for one on every
    /// creation and fires retroactively if it's still within
    /// [`MEMFD_EXEC_WINDOW_NS`].
    ///
    /// The kernel always creates the memfd before the exec, so a creation
    /// timestamped *after* the pending exec can only mean the process made an
    /// unrelated `memfd_create` call later — not proof of anything (#503
    /// review, Jihair, caught live: an on-disk `/proc/self/fd` exec followed
    /// 8s later, same pid, by an unrelated `memfd_create` wrongly fired).
    /// `saturating_sub` alone can't tell the two orderings apart (a
    /// too-late creation saturates to a delta of 0, which trivially passes
    /// the window check), so the ordering itself is checked first.
    pub fn on_memfd_create(&mut self, event: &MemfdCreateEvent) -> Vec<Alert> {
        let creates = self
            .recent_memfd_creates
            .get_or_insert_with(event.meta.pid, Vec::new);
        if creates.len() >= MEMFD_CREATES_PER_PID {
            creates.remove(0);
        }
        creates.push((event.meta.timestamp_ns, event.fd));
        if let Some(pending) = self.pending_proc_fd_exec.peek(&event.meta.pid)
            && pending.fd == event.fd
            && event.meta.timestamp_ns <= pending.timestamp_ns
            && pending.timestamp_ns - event.meta.timestamp_ns <= MEMFD_EXEC_WINDOW_NS
        {
            let alert =
                memfd_proc_fd_exec_alert(event.meta.pid, &pending.comm, &pending.path, pending.fd);
            self.pending_proc_fd_exec.remove(&event.meta.pid);
            return vec![alert];
        }
        Vec::new()
    }

    /// T1620 — Reflective Code Loading: executing a payload that never touches
    /// disk via `memfd_create(2)` + `execveat(fd, "", ..., AT_EMPTY_PATH)`
    /// (issue #85's Linux scope).
    ///
    /// `ExecEvent::image_path` is `bprm->filename` at the kernel's
    /// `sched_process_exec` tracepoint (`crates/sensors/linux/ebpf`, #111) —
    /// **not** `/proc/<pid>/exe`. Traced against a live kernel (Alpine
    /// 6.18.50, #85 review) with a memfd copy of `/bin/true`, two distinct
    /// shapes, evidenced differently (#497 review — the first cut treated
    /// either shape alone as sufficient, which false-positived on every
    /// container start):
    /// - `execveat(fd, "", AT_EMPTY_PATH)`: `bprm->filename` is `/dev/fd/<n>`,
    ///   and the kernel names the task after the memfd dentry, so `comm`
    ///   reliably starts with `memfd:`. The path shape plus that `comm`
    ///   prefix together are the evidence — nothing else produces this exact
    ///   combination.
    /// - `execv` via `/proc/self/fd/<n>` (or `/proc/<pid>/fd/<n>`): `comm` is
    ///   whatever the caller set, not reliably `memfd:` — the path shape
    ///   *alone* is not evidence of a memfd. Confirmed live: `runc`'s own
    ///   CVE-2019-5736 self-protection re-execs `runc init` via
    ///   `/proc/self/fd/<n>` on every container start (any Docker/containerd/
    ///   Kubernetes host), with `comm` truncated to the fd number and no
    ///   memfd anywhere in the picture; a plain `open()` + `execveat(fd, "",
    ///   AT_EMPTY_PATH)` of a real on-disk binary produces the same path
    ///   shape too. This shape now requires corroborating evidence: a
    ///   `MemfdCreateEvent` for the same pid within
    ///   [`MEMFD_EXEC_WINDOW_NS`] — real memfd-exec creates, writes, then
    ///   execs its own payload back-to-back in one short-lived process,
    ///   while `runc init` and an on-disk exec via `/proc/self/fd` never
    ///   called `memfd_create` at all. This is deliberately not a
    ///   `parent_comm`-keyed exclusion for `runc` specifically (spoofable,
    ///   same reasoning `check_burst_write_volume`'s doc gives for avoiding
    ///   name-keyed exclusions) — the evidence gate handles it structurally.
    ///
    /// Neither shape ever produces `/memfd:<name> (deleted)` — that string is
    /// only what `readlink /proc/<pid>/exe` shows, which the sensor doesn't
    /// read. An earlier version of this check matched on that string and
    /// never fired on real telemetry.
    ///
    /// The `/proc/.../fd/<n>` shape used to be correlation by pid and time
    /// only (#503 review, Nikolas): a process that created a memfd for a
    /// legitimate reason and then exec'd an ordinary on-disk binary through a
    /// different, unrelated fd within the same window matched. Since #510 the
    /// sensor reports the descriptor `memfd_create(2)` returned
    /// ([`MemfdCreateEvent::fd`]), and the exec's `<n>` must equal it: the
    /// executed fd *is* the created memfd, not merely a neighbour. The path's pid
    /// component must also be `self` or the exec'ing pid itself — `/proc/<other>/fd/<n>`
    /// names a descriptor in a different process's table, which this pid's memfds
    /// say nothing about.
    ///
    /// What remains unproven is fd *reuse*: a process that closes its memfd, opens
    /// an on-disk binary onto the same number and execs it inside the window would
    /// still match. That takes close/dup tracking for a shape no fileless-exec
    /// tool produces, so it is accepted.
    fn check_memfd_exec(&mut self, event: &ExecEvent) -> Option<Alert> {
        let path = &event.image_path;
        if is_dev_fd_path(path) {
            if !event.meta.comm.starts_with("memfd:") {
                return None;
            }
            return Some(memfd_dev_fd_exec_alert(
                event.meta.pid,
                &event.meta.comm,
                path,
            ));
        }
        if let Some(fd) = proc_fd_number(path, event.meta.pid) {
            let created = self
                .recent_memfd_creates
                .peek(&event.meta.pid)
                .is_some_and(|creates| {
                    creates.iter().any(|&(created_ts, created_fd)| {
                        created_fd == fd
                            && created_ts <= event.meta.timestamp_ns
                            && event.meta.timestamp_ns - created_ts <= MEMFD_EXEC_WINDOW_NS
                    })
                });
            if created {
                return Some(memfd_proc_fd_exec_alert(
                    event.meta.pid,
                    &event.meta.comm,
                    path,
                    fd,
                ));
            }
            // No corroborating creation seen yet — it may still arrive after
            // this exec (#503 review). Hold it instead of dropping it;
            // `on_memfd_create` checks for it. One pending exec per pid, same
            // reasoning `recent_memfd_creates` gives for tracking only the
            // latest creation: a second `/proc/fd` exec for the same pid
            // before the first resolves is rare enough not to warrant a list.
            self.pending_proc_fd_exec.insert(
                event.meta.pid,
                PendingProcFdExec {
                    path: path.clone(),
                    fd,
                    comm: event.meta.comm.clone(),
                    timestamp_ns: event.meta.timestamp_ns,
                },
            );
        }
        None
    }

    /// To be called for every `FileQuarantineEvent` in the stream (macOS ES,
    /// Windows ETW `Zone.Identifier`). Does not produce alerts directly —
    /// records the mark consumed by `check_quarantined_exec`.
    pub fn on_file_quarantine(&mut self, event: &FileQuarantineEvent) {
        self.recent_quarantines.insert(
            event.path.to_lowercase(),
            RecentQuarantine {
                timestamp_ns: event.meta.timestamp_ns,
                agent: event.agent.clone(),
                origin_url: event.origin_url.clone(),
                alerted: false,
            },
        );
    }

    /// To be called for every `BitsJobEvent` in the stream: records the job's
    /// file for the T1197 download→exec join
    /// ([`Self::check_bits_download_exec`]). No alert on its own: BITS is
    /// also how browsers and updaters fetch their components.
    pub fn on_bits_job(&mut self, event: &BitsJobEvent) {
        let key = event.local_path.to_lowercase();
        let previous = self.recent_bits_downloads.peek(&key);
        let same_job = previous.is_some_and(|d| d.job_id == event.job_id);
        match event.state {
            BitsJobState::FileAdded => {
                // Another job's completed download is what sits at the path:
                // its window and attribution stand until a completion
                // replaces the file (#577 review).
                if previous.is_some_and(|d| d.on_disk && !same_job) {
                    return;
                }
                self.arm_bits_download(key, event, false, false);
            }
            BitsJobState::Completed => {
                // A late completion of the download that already alerted is not
                // a new download; another job's completion is.
                let alerted = same_job && previous.is_some_and(|d| d.alerted);
                self.arm_bits_download(key, event, true, alerted);
            }
            // A cancelled job deletes its own partial file: nothing of it left
            // to run. Only its own, and only a partial one: cancelling job B,
            // which targeted the path job A already downloaded, leaves A's
            // payload in place (#577 review).
            BitsJobState::Cancelled => {
                if same_job && previous.is_some_and(|d| !d.on_disk) {
                    self.recent_bits_downloads.remove(&key);
                }
            }
            // BITS retries a failed transfer on its own; keep the entry.
            BitsJobState::TransferError => {}
        }
    }

    fn arm_bits_download(
        &mut self,
        key: String,
        event: &BitsJobEvent,
        on_disk: bool,
        alerted: bool,
    ) {
        self.recent_bits_downloads.insert(
            key,
            RecentBitsDownload {
                timestamp_ns: event.meta.timestamp_ns,
                job_id: event.job_id.clone(),
                on_disk,
                client_pid: event.meta.pid,
                client_comm: event.meta.comm.clone(),
                job_title: event.job_title.clone(),
                url: event.url.clone(),
                alerted,
            },
        );
    }

    /// To be called for every `FileOpenEvent` in the stream. Reports T1053.005
    /// scheduled-task creation (deduplicated, see
    /// [`Self::check_task_registration`]) and updates the history of downloader
    /// writes, consumed by `check_download_then_exec`.
    pub fn on_file_open(&mut self, event: &FileOpenEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_task_registration(event).into_iter().collect();
        alerts.extend(crate::stateless::check_service_write_outside_datadir(
            event,
            |pid, generation| self.resolve_comm(pid, generation),
        ));
        alerts.extend(self.check_credential_file_read(event));
        alerts.extend(self.record_create(event));
        self.record_downloader_write(event);
        self.record_archive_open(event);
        alerts.extend(self.check_staging_dir(event));
        alerts
    }

    /// STAGING-DIR (T1074.001, #380) — one pid reads at least [`STAGING_READ_FILES`] distinct
    /// user-data files spread over [`STAGING_READ_DIRS`] directories and creates at least
    /// [`STAGING_WRITE_FILES`] distinct files in one staging directory (a subdirectory of a
    /// temp root or a hidden directory, see [`staging::staging_dir`]), all inside
    /// [`STAGING_WINDOW_NS`]. One alert per directory and window. Medium: the shape is also a
    /// folder copy, a backup tool and an indexer, and no allowlist of those exists yet (it
    /// needs a lab capture of the host's ordinary copies and builds).
    ///
    /// The evaluation runs on a create, so the last read must precede the last create it
    /// counts: a copy loop that interleaves reads and creates qualifies, a sweep that reads
    /// everything and then creates fewer than the threshold does not. `FileWriteEvent`
    /// carries no path, so the creating `open` is the signal, never a byte count: a staging
    /// file written to by another pid, or opened without `O_CREAT`, is a stated gap, and so
    /// is a collection that stages in `~/.cache` or a macOS per-user temp directory. The
    /// reader and the creator must be the same pid: `tar | gzip` style pipelines spread the
    /// two over processes and are not seen.
    fn check_staging_dir(&mut self, event: &FileOpenEvent) -> Option<Alert> {
        let meta = &event.meta;
        let ts = meta.timestamp_ns;
        if !has_write_intent(event.flags) {
            self.record_staging_read(meta, ts, &event.path);
            return None;
        }
        if event.flags & O_CREAT == 0 {
            return None;
        }
        let dir = staging::staging_dir(&event.path)?;
        let key = (meta.pid, dir.clone());
        if self
            .staging_dirs
            .peek(&key)
            .is_some_and(|d| !same_incarnation(d.generation, meta.process_generation))
        {
            self.staging_dirs.remove(&key);
        }
        let entry = self.staging_dirs.get_or_insert_with(key, || StagingDir {
            generation: meta.process_generation,
            files: SlidingDistinct::default(),
        });
        let created = entry
            .files
            .record(event.path.clone(), ts, STAGING_WINDOW_NS);
        if created < STAGING_WRITE_FILES {
            return None;
        }
        let (read_files, read_dirs) = self.staging_read_summary(meta, ts)?;
        let entry = self.staging_dirs.get_mut(&(meta.pid, dir.clone()))?;
        if !entry.files.try_alert(ts, STAGING_WINDOW_NS) {
            return None;
        }
        Some(Alert {
            technique: "T1074.001",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} read {read_files} user files from {read_dirs} directories and created {created} files in the staging directory /{dir}",
                meta.pid, meta.comm,
            ),
        })
    }

    /// STAGING-DIR, read half: remembers a user-data file the pid opened without write intent.
    fn record_staging_read(&mut self, meta: &schema::EventMeta, ts: u64, path: &str) {
        let Some((file, _)) = staging::user_data_file(path) else {
            return;
        };
        if self
            .staging_reads
            .peek(&meta.pid)
            .is_some_and(|r| !same_incarnation(r.generation, meta.process_generation))
        {
            self.staging_reads.remove(&meta.pid);
        }
        self.staging_reads
            .get_or_insert_with(meta.pid, || StagingReads {
                generation: meta.process_generation,
                files: SlidingDistinct::default(),
            })
            .files
            .record(file, ts, STAGING_WINDOW_NS);
    }

    /// STAGING-DIR: how many distinct user files, over how many directories, the pid read in
    /// the window — `None` when that is below the read thresholds.
    fn staging_read_summary(&mut self, meta: &schema::EventMeta, ts: u64) -> Option<(u32, usize)> {
        let reads = self.staging_reads.get_mut(&meta.pid)?;
        if !same_incarnation(reads.generation, meta.process_generation) {
            return None;
        }
        let files = reads.files.count(ts, STAGING_WINDOW_NS);
        let dirs: std::collections::HashSet<&str> = reads
            .files
            .values()
            .filter_map(|f| f.rsplit_once('/').map(|(dir, _)| dir))
            .collect();
        (files >= STAGING_READ_FILES && dirs.len() >= STAGING_READ_DIRS)
            .then_some((files, dirs.len()))
    }

    /// The image the pid was exec'd from, else its parent's: a child that forked and never
    /// exec'd (an older `sshd`'s privilege-separated child) is the same binary as its parent,
    /// and is in no exec table of its own.
    fn reader_image(&self, meta: &schema::EventMeta) -> Option<&str> {
        PidFact::current(&self.pid_image_path, meta.pid, meta.process_generation).or_else(|| {
            PidFact::current(
                &self.pid_image_path,
                meta.ppid,
                meta.parent_process_generation,
            )
        })
    }

    /// Whether `pid`'s own name, or its parent's, is a web or database service: a daemon with
    /// no business in a user's credential files, and the process a webshell runs under. The
    /// name comes from the exec table, not from the event's `comm`, which is the thread's
    /// (`one_connection` for a `mysqld` worker).
    fn reader_under_service(&self, meta: &schema::EventMeta) -> bool {
        let is_service = |comm: &str| {
            SERVICE_COMMS.contains(&comm)
                || SERVICE_COMM_PREFIXES
                    .iter()
                    .any(|prefix| comm.starts_with(prefix))
        };
        [
            PidFact::current(&self.pid_comm, meta.pid, meta.process_generation),
            PidFact::current(&self.pid_comm, meta.ppid, meta.parent_process_generation),
        ]
        .into_iter()
        .flatten()
        .any(is_service)
    }

    /// CREDENTIAL-READ (#377), on the file opens of a Unix host: T1003.008 for the shadow files,
    /// T1552.004 for an SSH private key, T1552.001 for the other credential files of a home
    /// directory, and on macOS T1555.001 for a keychain database and T1555.003 for a browser's
    /// saved-login and cookie stores (see `credfiles` for the paths and what the sensor cannot
    /// see).
    ///
    /// Only a read counts: a write-only open (`ssh-keygen` writing a key, `passwd` rewriting
    /// the file) is not one. Who may read differs by file, because who legitimately does
    /// differs:
    /// - The **shadow files** have a short, fixed list of readers (the authentication stack,
    ///   `credfiles::AUTH_STACK`); anything else that opens them alerts. Medium, not High:
    ///   an administrator's `cat`, a backup or integrity tool (`tar`, `rsync`, `rpm -V`,
    ///   AIDE) and a PAM service the list lacks look the same, and none is excluded here
    ///   because each is also what an attacker runs.
    /// - A **home credential file, keychain or browser store** has no fixed list: `python3` with `boto3`, `terraform`,
    ///   `kubectl`, `git` and `ssh` all read their own, from `/usr/bin`. So a read alerts only
    ///   when the reader is *unexpected* in a way the telemetry can show: a web or database
    ///   service (or a child of one), or a binary run from outside the system directories
    ///   (`/tmp`, a home directory, `/dev/shm`). Not caught: a system binary (`cat`, `tar`) run
    ///   by an intruder, and a tool a developer installed under their home (`~/.local/bin`,
    ///   `~/go/bin`) alerts although it is theirs, its own credentials read by its own
    ///   binary. Both are the price of not alerting on every `aws` call. On macOS the Apple
    ///   daemons that read a keychain and the browsers installed in `/Applications` run from
    ///   the system directories, so they should stay quiet (not observed on a Mac); a browser
    ///   installed under `~/Applications` alerts on its own store.
    ///
    /// One alert per (pid, kind) per [`CREDENTIAL_READ_ALERT_WINDOW_NS`]. No file content and
    /// no command line goes into the message, only the path the process asked for.
    fn check_credential_file_read(&mut self, event: &FileOpenEvent) -> Option<Alert> {
        if !credfiles::can_read(event.flags) {
            return None;
        }
        let kind = credfiles::classify(&event.path)?;
        let image = self.reader_image(&event.meta);
        let comm = event.meta.comm.as_str();
        let why = match kind {
            CredFile::Shadow if credfiles::is_auth_stack(comm, image) => return None,
            CredFile::Shadow => "outside the authentication stack",
            CredFile::PrivateKey
            | CredFile::HomeCredentials
            | CredFile::Keychain
            | CredFile::BrowserStore => {
                if self.reader_under_service(&event.meta) {
                    "a web or database service or its child"
                } else if credfiles::image_outside_system_dirs(image) {
                    "a binary outside the system directories"
                } else {
                    return None;
                }
            }
        };
        let ts = event.meta.timestamp_ns;
        let counter = self
            .credential_reads
            .get_or_insert_with((event.meta.pid, kind), SlidingCounter::default);
        if !counter.try_alert(ts, CREDENTIAL_READ_ALERT_WINDOW_NS) {
            return None;
        }
        Some(Alert {
            technique: kind.technique(),
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={comm}: opened {} for reading from {why}",
                event.meta.pid, event.path,
            ),
        })
    }

    /// T1053.005 creation (`check_scheduled_task_persistence`), reported once per
    /// registration. With both channels up, one `schtasks /Create` yields a 4698 and
    /// a 106 for the same task, in either order a few seconds apart; the sensor
    /// reads the 106's actions back from the task file, so the two usually match.
    ///
    /// A registration of an already-reported task inside
    /// [`TASK_REGISTRATION_DEDUP_WINDOW_NS`] is suppressed only when it adds
    /// nothing: an unknown-action report, or the same action list. A different
    /// action list alerts (a re-registration with a new payload), and so does a
    /// known action list after an unknown-action report, so the first-arriving
    /// 106 whose task file was unreadable never hides the 4698's actions.
    fn check_task_registration(&mut self, event: &FileOpenEvent) -> Option<Alert> {
        let alert = crate::stateless::check_scheduled_task_persistence(event)?;
        let actions =
            (event.flags & FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN == 0).then(|| event.path.clone());
        let now = event.meta.timestamp_ns;
        let duplicate = self
            .task_registrations
            .peek(&event.meta.comm)
            .is_some_and(|previous| {
                previous.timestamp_ns.abs_diff(now) <= TASK_REGISTRATION_DEDUP_WINDOW_NS
                    && (actions.is_none() || actions == previous.actions)
            });
        if duplicate {
            return None;
        }
        self.task_registrations.insert(
            event.meta.comm.clone(),
            ReportedTaskRegistration {
                timestamp_ns: now,
                actions,
            },
        );
        Some(alert)
    }

    fn record_downloader_write(&mut self, event: &FileOpenEvent) {
        let comm = event.meta.comm.as_str();
        if !DOWNLOADER_COMMS.contains(&comm) || !has_write_intent(event.flags) {
            return;
        }
        self.recent_writes.insert(
            event.path.clone(),
            RecentWrite {
                pid: event.meta.pid,
                comm: comm.to_string(),
                timestamp_ns: event.meta.timestamp_ns,
            },
        );
    }

    /// T1486 — Data Encrypted for Impact. Ransomware's near-universal tell: a burst
    /// of renames, each keeping the original filename intact and appending a new
    /// suffix (`invoice.pdf` → `invoice.pdf.locked`), from the same pid, in a tight
    /// window. Extension-agnostic by design — matching on "`old_path` is a strict
    /// prefix of `new_path`" catches every real family's naming scheme (`.locked`,
    /// `.encrypted`, `.WNCRY`, a random hex suffix, ...) without a list to keep
    /// current against new strains, and without false-positiving on renames that
    /// *don't* preserve the original name (a normal `mv a b` has no such relation).
    ///
    /// Deliberately keyed on rename shape alone, not `FileWriteEvent` volume: many
    /// legitimate bulk operations (package installs, `tar` extraction, a compiler's
    /// intermediate files) write many files quickly, but essentially none rename
    /// hundreds of pre-existing files to append a shared new suffix in seconds —
    /// see `RANSOMWARE_RENAME_THRESHOLD`'s doc for the calibration reasoning.
    ///
    /// Counted twice, so both real shapes reach the threshold (issue #262 review):
    /// per-pid for a single encryptor binary, and per-ppid for the shell-loop shape
    /// (`for f in *; do mv "$f" "$f.locked"; done`) where each rename is a separate
    /// short-lived `mv` pid but every one shares the loop's shell as `ppid`. The
    /// per-pid branch wins when it fires, so a single process yields one alert, not
    /// two (its renames also land in the per-ppid counter, but that branch is only
    /// consulted when the per-pid one did not fire this event).
    ///
    /// Known benign producers of this exact shape (#459 part 1 closes the first
    /// two; the third stays open, see below):
    /// - Log rotation (`app.log` → `app.log.1`): handled by [`is_rotation_suffix`]
    ///   (a suffix with no letter never counts) — the one case a shape signal settles.
    /// - In-place edit with a backup: `sed -i.bak` `rename(2)`s the
    ///   original to `f.bak`/`f.orig` from one pid; 20+ files in one command
    ///   (`sed -i.bak … *.conf`) used to trip this rule. [`is_in_place_edit_backup`]
    ///   now excludes it, gated on `comm` + the pid's exec-time `image_path`
    ///   (CLAUDE.md — name-keyed exclusions must be gated on evidence, cf.
    ///   [`policy::name_exclusion_applies`]; excluding on `comm` alone would be
    ///   spoofable, an encryptor can set `comm=sed` for free). Fails closed when
    ///   no path is known, see `Self::is_in_place_edit_backup`.
    /// - Maildir flag changes (`…:2,S` → `…:2,ST`): one IMAP pid, prefix-preserving,
    ///   lettered suffix; "mark all read" on a large folder can exceed the
    ///   threshold. [`is_maildir_flag_change`] now excludes it — structurally
    ///   (the flag-letter alphabet), deliberately *not* also comm-gated; see
    ///   that function's doc for why.
    ///
    /// Cross-directory moves (`~/docs/a.docx` → `~/.stash/a.docx.locked`, #512):
    /// when the directories differ the full-path prefix test can never hold, so the
    /// same appended-suffix relation is read off the file *names* instead
    /// ([`appended_suffix`]). Same counters, same exclusions; the one new benign
    /// producer that shape brings in is the Maildir delivery move
    /// (`new/msg` → `cur/msg:2,S`), excluded by [`is_maildir_delivery`].
    ///
    /// Shapes this rule still cannot see at all (write-new-then-unlink) need a
    /// separate open/delete correlation — still a follow-up, tracked in #512.
    fn check_mass_rename_pattern(&mut self, event: &FileRenameEvent) -> Option<Alert> {
        let suffix = appended_suffix(&event.old_path, &event.new_path)?;
        if suffix.is_empty()
            || is_rotation_suffix(suffix)
            || self.is_in_place_edit_backup(event)
            || is_maildir_flag_change(&event.old_path, suffix)
            || is_maildir_delivery(&event.old_path, &event.new_path, suffix)
        {
            return None;
        }
        let ts = event.meta.timestamp_ns;

        // Per-pid: a single encryptor process renaming its way through a tree.
        let pid_entry = self
            .ransomware_rename
            .get_or_insert_with(event.meta.pid, SlidingCounter::default);
        let pid_count = pid_entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if pid_count >= RANSOMWARE_RENAME_THRESHOLD
            && pid_entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "pid={} comm={}: {pid_count} files renamed with an appended suffix in {}s \
                     (e.g. {} → {}) — suspected ransomware encryption pass",
                    event.meta.pid,
                    event.meta.comm,
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                    event.old_path,
                    event.new_path,
                ),
            });
        }

        // Per-ppid: a shell loop spawning one short-lived `mv` per file — the per-pid
        // counter above never climbs, but the parent shell ties the burst together.
        // Only pids that are themselves light renamers feed this counter, so a single
        // busy process (already handled above) does not also drive the shared per-ppid
        // counter to a second alert — see `RANSOMWARE_LOOP_CHILD_MAX`.
        //
        // ppid 0 ("unknown" — a `PROC_LINEAGE` miss on the sensor, never real pid 0)
        // and ppid 1 (init — orphans and daemons reparent there) are shared buckets
        // that would lump unrelated processes into a false "shell-loop" alert; a real
        // loop's children have the loop's shell as parent, so skip both (#455 review).
        if pid_count > RANSOMWARE_LOOP_CHILD_MAX || event.meta.ppid <= 1 {
            return None;
        }
        let ppid_entry = self
            .ransomware_rename_by_ppid
            .get_or_insert_with(event.meta.ppid, SlidingCounter::default);
        let ppid_count = ppid_entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if ppid_count >= RANSOMWARE_RENAME_THRESHOLD
            && ppid_entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "ppid={}: {ppid_count} files renamed with an appended suffix by short-lived \
                     children in {}s (e.g. {} → {}, comm={}) — suspected ransomware encryption \
                     pass (shell-loop pattern)",
                    event.meta.ppid,
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                    event.old_path,
                    event.new_path,
                    event.meta.comm,
                ),
            });
        }
        None
    }

    /// To be called for every `FileDeleteEvent` in the stream: the unlink half of the
    /// write-new-then-unlink T1486 shape (#512 part B), see
    /// [`Self::check_write_new_then_unlink`], and the mark-of-the-web removal
    /// consumed by [`Self::check_exec_after_motw_removal`].
    pub fn on_file_delete(&mut self, event: &FileDeleteEvent) -> Vec<Alert> {
        self.record_motw_removal(event);
        self.record_touched(event.meta.pid, Event::FileDelete(event.clone()));
        self.check_write_new_then_unlink(event)
            .into_iter()
            .collect()
    }

    /// Remembers a Windows `FileDelete` of a `:Zone.Identifier` stream: the
    /// mark-of-the-web removed from its host file (#442). No alert on its own —
    /// `Unblock-File` over a downloaded module tree removes hundreds of marks
    /// legitimately, and the event itself stays in the telemetry for hunting.
    ///
    /// A `User::Unknown` remover counts: the Windows sensor reports it when the
    /// process exited or is protected before its token was read, which is the
    /// shape of a one-shot `cmd /c "powershell Unblock-File x.exe & x.exe"`.
    /// What rules out a Unix file merely named `x:Zone.Identifier` is a Unix
    /// user or a POSIX path, the evidence that it is not a Windows stream.
    fn record_motw_removal(&mut self, event: &FileDeleteEvent) {
        self.record_motw_gone(&event.path, &event.meta);
    }

    /// The same fact from a `FileRename` of the stream: `Rename-Item -Stream` or a
    /// `SetInformation` rename on the stream handle takes the mark off its host
    /// without deleting anything. Only the minifilter reports it (#136, #853: the
    /// Kernel-File rename, event 27, is not consumed). A rename that leaves the
    /// stream on the same host (a case change) removed nothing; one that moves the
    /// mark to another file still strips it from this one.
    fn record_motw_stream_rename(&mut self, event: &FileRenameEvent) {
        let still_marked = motw_stream_host(&event.new_path)
            .zip(motw_stream_host(&event.old_path))
            .is_some_and(|(new_host, old_host)| new_host.eq_ignore_ascii_case(old_host));
        if !still_marked {
            self.record_motw_gone(&event.old_path, &event.meta);
        }
    }

    /// `stream_path` is a `:Zone.Identifier` stream that no longer carries its mark,
    /// by `meta`'s process.
    fn record_motw_gone(&mut self, stream_path: &str, meta: &schema::EventMeta) {
        if matches!(meta.user, User::Unix { .. }) {
            return;
        }
        let Some(host) = motw_stream_host(stream_path).filter(|host| !host.starts_with('/')) else {
            return;
        };
        self.recent_motw_removals.insert(
            host.to_lowercase(),
            MotwRemoval {
                timestamp_ns: meta.timestamp_ns,
                pid: meta.pid,
                comm: meta.comm.clone(),
                alerted: false,
            },
        );
    }

    /// T1553.005 — Subvert Trust Controls: Mark-of-the-Web Bypass. A file whose
    /// mark-of-the-web was removed is executed within
    /// [`QUARANTINE_EXEC_WINDOW_NS`] of the removal: the SmartScreen/Office
    /// protected-view prompt that mark would have raised was taken out of the
    /// way first (#442). The removal alone doesn't alert, see
    /// [`Self::record_motw_removal`].
    ///
    /// Independent of T1204.002 ([`Self::check_quarantined_exec`]): a file both
    /// marked and unmarked inside the window raises both, since they are two
    /// techniques; the origin URL, when the mark was seen, is quoted here too.
    ///
    /// Not covered: a download that never got a mark (curl, certutil, most
    /// droppers, see `DOWNLOADER_COMMS`) and an archive extractor that drops it
    /// — there is no removal to see; a mark rewritten in place to `ZoneId=0`,
    /// or its stream renamed through the Kernel-File path (event 27; the
    /// minifilter's rename is consumed, [`Self::record_motw_stream_rename`]). The full
    /// list is in `docs/detection/download-provenance.md`.
    fn check_exec_after_motw_removal(&mut self, event: &ExecEvent) -> Option<Alert> {
        let key = event.image_path.to_lowercase();
        let now = event.meta.timestamp_ns;
        let removal = self.recent_motw_removals.get_mut(&key)?;
        let age = now.saturating_sub(removal.timestamp_ns);
        if removal.alerted || age > QUARANTINE_EXEC_WINDOW_NS {
            return None;
        }
        removal.alerted = true;
        let (remover_pid, remover_comm) = (removal.pid, removal.comm.clone());
        let origin = self
            .recent_quarantines
            .get_mut(&key)
            .and_then(|mark| mark.origin_url.clone());
        Some(Alert {
            technique: "T1553.005",
            // At least T1204.002's: the same execution, plus a deliberate step
            // to take the warning out of the way first.
            severity: Severity::High,
            message: format!(
                "pid={} comm={} executes {}, {} after its mark-of-the-web was removed by pid={} comm={} (origin: {})",
                event.meta.pid,
                event.meta.comm,
                event.image_path,
                format_delta(age),
                remover_pid,
                remover_comm,
                origin.as_deref().unwrap_or("unrecorded"),
            ),
        })
    }

    /// T1486, the shape `check_mass_rename_pattern` cannot see because none of it is a
    /// rename (#512 part B): the encryptor writes `file.docx.locked` as a **new** file and
    /// only then unlinks `file.docx` (safer than an in-place rewrite: the original
    /// survives until the copy is complete). Same appended-suffix relation
    /// ([`appended_suffix`], so a cross-directory pair counts too), same lettered,
    /// non-rotation, non-Maildir suffix filter, same threshold and window.
    ///
    /// The correlation is a write-intent `O_CREAT` open (`record_create`) and an unlink
    /// of the file whose name the new one extends, by one pid within
    /// [`CREATE_UNLINK_PAIR_WINDOW_NS`], in either arrival order (`pending_unlinks`).
    /// It cannot use `FileWriteEvent`: that event carries an fd and no path.
    ///
    /// The benign producer measured live (Debian 13) is compression: `gzip`, `xz`,
    /// `bzip2` and `zstd` each did 30 of these in 5 s over a `*.log` glob. They are
    /// excluded by [`COMPRESSOR_COMMS`] gated on the pid running the trusted binary of
    /// that name, failing closed ([`Self::runs_trusted_binary_named`]); a suffix
    /// allowlist (`.gz`) alone would be free for an encryptor to copy. `logrotate` with
    /// `compress` opens the `.gz` and unlinks the input itself (gzip only writes to an
    /// inherited fd), so it is excluded as a compression *driver*
    /// ([`Self::is_compression_driver`]): trusted binary named `logrotate` **and** a
    /// compression extension, both required (found live by Jihair on Alpine, #527). A third
    /// benign producer, `semodule -B`/`-DB` rebuilding the `SELinux` policy store, is excluded
    /// the same way as the compressors ([`Self::is_selinux_policy_tool`]): no suffix
    /// convention to also require (found live on Fedora, #1013). Nothing else measured
    /// (`zip -m`, `rsync --remove-source-files`, `git gc`, atomic writers, `apt`)
    /// exceeded 2. Restricted to Unix events: the Windows and macOS producers of this
    /// shape (Explorer, `ditto`, installers) were not measured.
    ///
    /// **Not covered**: a shell loop with one process per step (`openssl enc -out $f.enc`
    /// creates, a separate `rm $f` unlinks). Creation and unlink then belong to different
    /// pids, so no pair forms (confirmed live on Debian 13); tying them through the
    /// parent would also fold in ordinary `cp x x.bak; rm x` scripts, which was not
    /// measured. The rename shape of that loop is covered by `check_mass_rename_pattern`.
    ///
    /// Like every pid-keyed table here it inherits #519: a recycled pid keeps a stale
    /// history until it ages out of the window.
    fn check_write_new_then_unlink(&mut self, event: &FileDeleteEvent) -> Option<Alert> {
        if !matches!(event.meta.user, User::Unix { .. }) {
            return None;
        }
        let pid = event.meta.pid;
        let ts = event.meta.timestamp_ns;
        let created = self.recent_creates.get_mut(&pid).and_then(|creates| {
            let idx = creates.iter().rposition(|(created_ts, path)| {
                pairs_create_and_unlink(*created_ts, path, ts, &event.path)
            })?;
            creates.remove(idx).map(|(_, path)| path)
        });
        let Some(created) = created else {
            // No creation seen yet: it may still arrive after this unlink.
            let pending = self.pending_unlinks.get_or_insert_with(pid, VecDeque::new);
            if pending.len() >= CREATE_UNLINK_HISTORY_PER_PID {
                pending.pop_front();
            }
            pending.push_back((ts, event.path.clone()));
            return None;
        };
        self.count_create_unlink_pair(&event.meta, ts, &event.path, &created)
    }

    /// The creation half: remembers a write-intent `O_CREAT` open, or pairs it with an
    /// unlink that arrived first. Unix events only, see
    /// [`Self::check_write_new_then_unlink`].
    fn record_create(&mut self, event: &FileOpenEvent) -> Option<Alert> {
        if event.flags & O_CREAT == 0
            || !has_write_intent(event.flags)
            || !matches!(event.meta.user, User::Unix { .. })
        {
            return None;
        }
        let pid = event.meta.pid;
        let created_ts = event.meta.timestamp_ns;
        let unlinked = self.pending_unlinks.get_mut(&pid).and_then(|pending| {
            let idx = pending.iter().position(|(unlink_ts, path)| {
                pairs_create_and_unlink(created_ts, &event.path, *unlink_ts, path)
            })?;
            pending.remove(idx)
        });
        if let Some((unlink_ts, deleted)) = unlinked {
            return self.count_create_unlink_pair(&event.meta, unlink_ts, &deleted, &event.path);
        }
        let creates = self.recent_creates.get_or_insert_with(pid, VecDeque::new);
        if creates.len() >= CREATE_UNLINK_HISTORY_PER_PID {
            creates.pop_front();
        }
        creates.push_back((created_ts, event.path.clone()));
        None
    }

    /// Counts one matched write-new-then-unlink pair per pid, alerting at the
    /// mass-rename threshold. `ts` is the later (unlink) time.
    fn count_create_unlink_pair(
        &mut self,
        meta: &schema::EventMeta,
        ts: u64,
        deleted: &str,
        created: &str,
    ) -> Option<Alert> {
        if self.is_compressor(meta)
            || self.is_compression_driver(meta, deleted, created)
            || self.is_selinux_policy_tool(meta)
        {
            return None;
        }
        let pid_entry = self
            .ransomware_unlink
            .get_or_insert_with(meta.pid, SlidingCounter::default);
        let pid_count = pid_entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if pid_count >= RANSOMWARE_RENAME_THRESHOLD
            && pid_entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "pid={} comm={}: {pid_count} files replaced by a new file with an appended \
                     suffix and then unlinked in {}s (e.g. {deleted} → {created}) — suspected \
                     ransomware encryption pass (write-new-then-unlink)",
                    meta.pid,
                    meta.comm,
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// True when `comm` is a compression driver ([`COMPRESSION_DRIVER_COMMS`], i.e.
    /// `logrotate`) that really runs the trusted binary of that name and the new file
    /// only appends a compression extension to the old name.
    fn is_compression_driver(
        &self,
        meta: &schema::EventMeta,
        deleted: &str,
        created: &str,
    ) -> bool {
        COMPRESSION_DRIVER_COMMS.contains(&meta.comm.as_str())
            && appended_suffix(deleted, created)
                .is_some_and(|suffix| COMPRESSION_SUFFIXES.contains(&suffix))
            && self.runs_trusted_binary_named(meta)
    }

    /// True when `comm` is a compression tool ([`COMPRESSOR_COMMS`]) and the pid really
    /// runs the trusted binary of that name: see [`Self::runs_trusted_binary_named`].
    fn is_compressor(&self, meta: &schema::EventMeta) -> bool {
        COMPRESSOR_COMMS.contains(&meta.comm.as_str()) && self.runs_trusted_binary_named(meta)
    }

    /// True when `comm` is a `SELinux` policy-store tool ([`SELINUX_POLICY_TOOL_COMMS`]) and
    /// the pid really runs the trusted binary of that name (#1013): `semodule -B`'s
    /// create-then-replace of every module in the targeted policy base set matches this
    /// shape with no `comm`-independent suffix convention to additionally require, unlike
    /// [`Self::is_compression_driver`].
    fn is_selinux_policy_tool(&self, meta: &schema::EventMeta) -> bool {
        SELINUX_POLICY_TOOL_COMMS.contains(&meta.comm.as_str())
            && self.runs_trusted_binary_named(meta)
    }

    /// True when this pid's exec-time `image_path` is known, sits at a trusted system
    /// path **and is a binary named `comm`**. Both halves matter: a trusted path alone
    /// is not enough, because a process running the system `python3` can rename its own
    /// `comm` to `gzip` with `prctl(PR_SET_NAME)` and would otherwise inherit the
    /// exclusion; what an encryptor cannot fake is that the trusted binary it runs is
    /// *called* `gzip`. Unknown is **not** trusted (fails closed): delete events carry no
    /// rename-time `executable_path` to fall back on, and "no exec seen" (a forked child
    /// that only set `comm`) is not evidence of `/usr/bin/gzip`.
    fn runs_trusted_binary_named(&self, meta: &schema::EventMeta) -> bool {
        PidFact::current(&self.pid_image_path, meta.pid, meta.process_generation).is_some_and(|p| {
            !p.is_empty()
                && policy::name_exclusion_applies(Some(p))
                && written_file_is(p, &meta.comm)
        })
    }

    /// To be called for every `FileRenameEvent` in the stream (T1486, issue #262 +
    /// #82's write-volume corroboration).
    pub fn on_file_rename(&mut self, event: &FileRenameEvent) -> Vec<Alert> {
        self.record_motw_stream_rename(event);
        self.record_touched(event.meta.pid, Event::FileRename(event.clone()));
        let mut alerts: Vec<Alert> = self.check_mass_rename_pattern(event).into_iter().collect();
        alerts.extend(self.check_burst_write_volume(event));
        alerts
    }

    /// Remembers a rename or deletion for `pid`, dropping the oldest past the per-pid bound.
    fn record_touched(&mut self, pid: u32, event: Event) {
        let history = self.touched_files.get_or_insert_with(pid, VecDeque::new);
        if history.len() == TOUCHED_FILES_PER_PID {
            history.pop_front();
        }
        history.push_back(event);
    }

    /// The renames and deletions of the process incarnation `(pid, generation)` still
    /// remembered, oldest first: the damage manifest a ransomware detection carries
    /// (issue #82). Two known, different generations never mix (a recycled pid's earlier
    /// life is not this process's damage); a missing stamp keeps the pid-only behavior.
    #[must_use]
    pub fn touched_files(&self, pid: u32, generation: Option<u64>) -> Vec<Event> {
        self.touched_files
            .peek(&pid)
            .map(|history| {
                history
                    .iter()
                    .filter(|e| match (e.meta().process_generation, generation) {
                        (Some(a), Some(b)) => a == b,
                        _ => true,
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// To be called for every `FileWriteEvent` in the stream. Does not produce
    /// alerts directly — tracks write volume per pid (issue #82), consumed by
    /// `check_burst_write_volume` on the next `FileRenameEvent`.
    pub fn on_file_write(&mut self, event: &FileWriteEvent) {
        self.record_archive_write(event);
        self.write_volume
            .get_or_insert_with(event.meta.pid, SlidingSum::default)
            .add(
                event.meta.timestamp_ns,
                event.bytes_requested,
                RANSOMWARE_RENAME_WINDOW_NS,
            );
    }

    /// Second, independent T1486 signal (issue #82): heavy write volume alongside
    /// a rename burst, regardless of whether the rename shape matched
    /// `check_mass_rename_pattern`'s prefix-preserving pattern — catches a
    /// renamed-over-the-original-name encryptor shape that check's
    /// suffix-appending model doesn't.
    ///
    /// Only ever runs on `FileRenameEvent` (dispatched from `on_file_rename`,
    /// never on an unlink) — despite an earlier version of this doc's claim to
    /// catch a "writes-new-then-unlinks" shape, no unlink telemetry feeds this
    /// at all (review finding, #496). `bytes_written` comes from
    /// `FileWriteEvent::bytes_requested`, which `sensor-linux-ebpf`'s
    /// `sys_enter_write` hook records for every `write(2)` regardless of what
    /// the fd refers to — a regular file, a socket, a pipe — so a chatty
    /// network/IPC-heavy process's write volume counts the same as real disk
    /// writes toward this total. Both caveats are honest gaps, not yet closed.
    ///
    /// Deliberately no name-keyed exclusion here: `FileRenameEvent`/`FileWriteEvent`
    /// carry no executable path (same gap `check_mass_rename_pattern`'s doc
    /// describes, tracked in #459), so a `comm`-only exclusion would be spoofable.
    /// `RANSOMWARE_EXCLUDED_PATH_PREFIXES` is path-based, not name-based, and stays.
    /// [`is_package_manager_temp_rename`] requires both the filename shape and
    /// `comm` to match a known package manager (#496, hardened per #500
    /// review): the shape alone — staging heavy writes under `foo.dpkg-new`
    /// then renaming it onto `foo` — previously cleared both gates below and
    /// false-positived T1486, but the shape by itself is just a naming
    /// convention the renaming process controls; requiring `comm` too raises
    /// the bar to also impersonating the specific package manager it belongs
    /// to, not just picking a suffix.
    fn check_burst_write_volume(&mut self, event: &FileRenameEvent) -> Option<Alert> {
        if RANSOMWARE_EXCLUDED_PATH_PREFIXES
            .iter()
            .any(|prefix| event.new_path.starts_with(prefix))
            || is_package_manager_temp_rename(&event.old_path, &event.new_path, &event.meta.comm)
        {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        // Independent field from `rename_count` below — read first so the
        // `SlidingCounter` borrow can stay held through the `try_alert` call.
        let bytes_written = self
            .write_volume
            .get_or_insert_with(event.meta.pid, SlidingSum::default)
            .total(ts, RANSOMWARE_RENAME_WINDOW_NS);
        let entry = self
            .rename_count
            .get_or_insert_with(event.meta.pid, SlidingCounter::default);
        let rename_count = entry.record(ts, RANSOMWARE_RENAME_WINDOW_NS);
        if rename_count >= RANSOMWARE_RENAME_THRESHOLD
            && bytes_written >= BURST_WRITE_BYTES_THRESHOLD
            && entry.try_alert(ts, RANSOMWARE_RENAME_WINDOW_NS)
        {
            return Some(Alert {
                technique: "T1486",
                severity: Severity::Critical,
                message: format!(
                    "pid={} comm={} wrote {}MB and renamed {rename_count}x in {}s — \
                     suspected ransomware kill chain",
                    event.meta.pid,
                    event.meta.comm,
                    bytes_written / (1024 * 1024),
                    RANSOMWARE_RENAME_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }
}

/// The `/dev/fd/<n>` + `comm` starting with `memfd:` shape: structural
/// evidence (see `check_memfd_exec`'s doc), strong enough to say the payload
/// never touched disk.
fn memfd_dev_fd_exec_alert(pid: u32, comm: &str, path: &str) -> Alert {
    Alert {
        technique: "T1620",
        severity: Severity::High,
        message: format!(
            "pid={pid} comm={comm}: executed from a file descriptor ({path}), not a real \
             path — no payload ever touched disk",
        ),
    }
}

/// The `/proc/.../fd/<n>` shape, corroborated only by a same-pid
/// `MemfdCreateEvent` within the window (see `check_memfd_exec`'s doc for why
/// that's timing correlation, not proof the executed fd is the created one).
fn memfd_proc_fd_exec_alert(pid: u32, comm: &str, path: &str, fd: i32) -> Alert {
    Alert {
        technique: "T1620",
        severity: Severity::High,
        message: format!(
            "pid={pid} comm={comm}: executed from file descriptor {fd} ({path}), the memfd \
             this process created moments earlier — a payload that never touched disk",
        ),
    }
}

/// Suffixes logrotate and similar rotators append (`.1`, `-20260924`, `.1.2`, `~`
/// backups): no ASCII letter at all. Ransomware markers carry letters (`.locked`,
/// `.WNCRY`, `.id-<hex>.[mail]`); an all-digit random suffix is the one blind spot,
/// accepted over alerting on every rotation run.
fn is_rotation_suffix(suffix: &str) -> bool {
    !suffix.bytes().any(|b| b.is_ascii_alphabetic())
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Matches `/dev/fd/<n>` — `execveat(fd, "", AT_EMPTY_PATH)`'s `bprm->filename`
/// shape, see `check_memfd_exec`'s doc.
fn is_dev_fd_path(path: &str) -> bool {
    path.strip_prefix("/dev/fd/").is_some_and(is_all_digits)
}

/// The descriptor number `<n>` of `/proc/self/fd/<n>` or `/proc/<own_pid>/fd/<n>` — an
/// exec through one of the *exec'ing process's own* descriptors, see
/// `check_memfd_exec`'s doc. `None` for anything else, including
/// `/proc/<other pid>/fd/<n>` (a descriptor in a different table) and a number that
/// doesn't fit an `i32`.
fn proc_fd_number(path: &str, own_pid: u32) -> Option<i32> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid_or_self, fd) = rest.split_once("/fd/")?;
    let own = pid_or_self == "self"
        || (is_all_digits(pid_or_self) && pid_or_self.parse::<u32>().ok() == Some(own_pid));
    if !own || !is_all_digits(fd) {
        return None;
    }
    fd.parse().ok()
}

/// True when `old_path` is `new_path` with one of
/// [`PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES`] appended *and* `comm` is one of
/// [`PACKAGE_MANAGER_COMMS`] — the package-manager "stage under a temp name,
/// then rename over the real one" shape `check_burst_write_volume` excludes
/// (#496), corroborated by which process is doing it (#500 review) so the
/// filename convention alone isn't a free pass. The path relationship is the
/// reverse of [`is_rotation_suffix`]'s callers (`new_path` = `old_path` +
/// suffix): here the suffix is on the *old* name.
fn is_package_manager_temp_rename(old_path: &str, new_path: &str, comm: &str) -> bool {
    PACKAGE_MANAGER_COMMS.contains(&comm)
        && (old_path
            .strip_prefix(new_path)
            .is_some_and(|suffix| PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES.contains(&suffix))
            || is_apk_staging_rename(old_path, new_path))
}

/// True for apk-tools' real staging shape (#500 review, Jihair): `old_path`
/// sits in the same directory as `new_path` (not derived from it by suffix —
/// see [`APK_STAGING_FILE_PREFIX`]'s doc) and its basename is that prefix
/// followed by a hex digest, e.g. `usr/bin/.apk.e9a41015…` ->
/// `usr/bin/c89`. Splits on the last `/` rather than comparing absolute
/// prefixes because apk's renames are relative to a directory fd
/// (`renameat`), so there's no leading `/` to anchor on — `usr/bin/foo` and
/// `bin/foo` must both work, and no separator at all means "current
/// directory" for both sides equally.
fn is_apk_staging_rename(old_path: &str, new_path: &str) -> bool {
    let (old_dir, old_base) = old_path.rsplit_once('/').unwrap_or(("", old_path));
    let (new_dir, _) = new_path.rsplit_once('/').unwrap_or(("", new_path));
    old_dir == new_dir
        && old_base
            .strip_prefix(APK_STAGING_FILE_PREFIX)
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl RuleState {
    /// True for `check_mass_rename_pattern`'s in-place-edit-with-backup false
    /// positive (#459 part 1): `comm` is a known in-place-edit tool
    /// ([`IN_PLACE_EDIT_COMMS`]) and the binary behind the pid is at a trusted
    /// path ([`policy::name_exclusion_applies`]).
    ///
    /// The path is the exec-time `image_path` from [`Self::pid_image_path`], not
    /// `FileRenameEvent::executable_path`: the latter is a rename-time `/proc` read
    /// that a short-lived process loses (#513 review), and "unknown" there is
    /// something the process controls by exiting. Unlike the other name-keyed
    /// exclusions (whose image paths the kernel hands us at exec time), an
    /// unresolvable path here **fails closed**: a pid with no exec seen (it never
    /// exec'd since the agent started — e.g. a forked child that only set `comm`)
    /// is not evidence of `/usr/bin/sed`. `executable_path` is only a fallback for
    /// that gap, never a way to override a known exec-time path.
    fn is_in_place_edit_backup(&self, event: &FileRenameEvent) -> bool {
        if !IN_PLACE_EDIT_COMMS.contains(&event.meta.comm.as_str()) {
            return false;
        }
        let path = PidFact::current(
            &self.pid_image_path,
            event.meta.pid,
            event.meta.process_generation,
        )
        .or(event.executable_path.as_deref());
        // A trusted path is not enough on its own: the system `python3` can set its own
        // `comm` to `sed` (`prctl(PR_SET_NAME)`) and would inherit the exclusion. What
        // an encryptor cannot fake is that the trusted binary it runs is *called* `comm`.
        matches!(
            path,
            Some(p) if !p.is_empty()
                && policy::name_exclusion_applies(Some(p))
                && written_file_is(p, &event.meta.comm)
        )
    }
}

/// The suffix a rename appends to a file's name, when that is what it does: the tail
/// of `new_path` after `old_path` (same directory, `a.docx` → `a.docx.locked`), or,
/// when the directories differ, the tail of `new_path`'s *file name* after
/// `old_path`'s (`~/docs/a.docx` → `~/.stash/a.docx.locked`, #512). `None` when
/// neither relation holds. Splits on `/` and `\\` alike: Windows sensors feed this
/// rule too. Works on the raw path strings, so a relative pair (both relative to
/// the same unresolved dirfd or cwd) compares consistently without resolving it.
fn appended_suffix<'a>(old_path: &str, new_path: &'a str) -> Option<&'a str> {
    if let Some(suffix) = new_path.strip_prefix(old_path) {
        return Some(suffix);
    }
    let old_base = split_dir_base(old_path).1;
    let new_base = split_dir_base(new_path).1;
    // No `old_dir == new_dir` shortcut: with equal directories the literal prefix test
    // above only fails when the separators differ (`dir/a` vs `dir\a.locked`), and the
    // base-name comparison below is exactly what must still run then.
    if old_base.is_empty() {
        return None;
    }
    new_base.strip_prefix(old_base)
}

/// Whether creating `created` (at `created_ts`) and unlinking `deleted` (at `deleted_ts`)
/// is one write-new-then-unlink: the new file's name extends the deleted one's by a
/// lettered, non-rotation, non-Maildir suffix ([`appended_suffix`]), the kernel-time
/// order is create-then-unlink, and they are within [`CREATE_UNLINK_PAIR_WINDOW_NS`].
fn pairs_create_and_unlink(created_ts: u64, created: &str, deleted_ts: u64, deleted: &str) -> bool {
    created_ts <= deleted_ts
        && deleted_ts - created_ts <= CREATE_UNLINK_PAIR_WINDOW_NS
        && appended_suffix(deleted, created).is_some_and(|suffix| {
            !suffix.is_empty()
                && !is_rotation_suffix(suffix)
                && !is_maildir_delivery(deleted, created, suffix)
        })
}

/// `path` split at its last separator into `(directory, file name)`; no separator
/// means an empty directory part.
fn split_dir_base(path: &str) -> (&str, &str) {
    match path.rfind(['/', '\\']) {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

/// True for a suffix that is exactly a Maildir info marker: `:2,` followed by
/// zero or more flag letters. Delivering a message out of `new/` into `cur/` is a
/// cross-directory rename that appends precisely this (`msg` → `msg:2,S`), and an
/// IMAP server or `mbsync` does it for every message a client opens: 20+ in a
/// few seconds on "mark all read" (#512). Structural like
/// [`is_maildir_flag_change`], for the same reason: the alphabet is a tight shape
/// and there is no small fixed set of `comm` values to gate on.
fn is_maildir_info_suffix(suffix: &str) -> bool {
    suffix.strip_prefix(":2,").is_some_and(is_maildir_flags)
}

/// True for a real Maildir delivery: a move from a `new` directory into the `cur`
/// directory next to it, whose new name only appends a Maildir info suffix
/// ([`is_maildir_info_suffix`]). The directory shape is part of the test, not just the
/// suffix: `:2,` followed by lowercase keyword letters is a free, readable extension for
/// an encryptor (`f.docx` → `f.docx:2,locked`), so the suffix alone must never exclude
/// a rename (#526 review, found live on Alpine).
fn is_maildir_delivery(old_path: &str, new_path: &str, suffix: &str) -> bool {
    if !is_maildir_info_suffix(suffix) {
        return false;
    }
    let (old_dir, _) = split_dir_base(old_path);
    let (new_dir, _) = split_dir_base(new_path);
    let (old_parent, old_leaf) = split_dir_base(old_dir);
    let (new_parent, new_leaf) = split_dir_base(new_dir);
    old_leaf == "new" && new_leaf == "cur" && old_parent == new_parent
}

/// True for what follows `:2,` in a Maildir info suffix: the standard flag letters
/// ([`MAILDIR_FLAG_LETTERS`]) and then, optionally, Dovecot's IMAP keywords, which it
/// stores as lowercase `a`-`z` after them (`:2,Sa`, `:2,RSab`; Thunderbird tags,
/// `$Label1`, Junk/NonJunk). Delivering or tagging 20+ messages raised T1486 on the
/// standard alphabet alone (#526 review, live on Alpine). The order keeps the shape
/// tight: keywords never precede a standard flag.
fn is_maildir_flags(flags: &str) -> bool {
    let keywords = flags.trim_start_matches(|c: char| {
        u8::try_from(c).is_ok_and(|b| MAILDIR_FLAG_LETTERS.contains(&b))
    });
    keywords.bytes().all(|b| b.is_ascii_lowercase())
}

/// True for `check_mass_rename_pattern`'s Maildir-flag-change false positive
/// (#459 part 1): `old_path` already ends in the Maildir info/flags marker
/// (`:2,` optionally followed by flag letters) and `suffix` — the tail
/// `new_path` appends — is composed entirely of valid Maildir flag letters
/// ([`MAILDIR_FLAG_LETTERS`]).
///
/// Deliberately **not** also gated on `comm`, unlike [`is_in_place_edit_backup`]
/// and unlike issue #459's own suggestion: `sed` is one fixed,
/// well-known binary, but "a mail server touching Maildir" has no small
/// fixed `comm` set to enumerate without guessing (dovecot, courier,
/// procmail, maildrop, notmuch, mbsync, offlineimap, mutt, ...) — inventing
/// one would be exactly the uncalibrated-exclusion-list problem this crate's
/// own module doc warns against. The flag-letter alphabet constraint is
/// already a tight structural signal on its own, the same class of reasoning
/// [`is_rotation_suffix`]'s all-digit check relies on.
fn is_maildir_flag_change(old_path: &str, suffix: &str) -> bool {
    if suffix.is_empty() || !is_maildir_flags(suffix) {
        return false;
    }
    let Some(marker) = old_path.rfind(":2,") else {
        return false;
    };
    is_maildir_flags(&old_path[marker + 3..])
}

/// Whether the file at `path` is the one a process named `comm` runs from. A
/// Windows path (`C:\…`, `\\server\…`) is split on `\` and compared
/// case-insensitively, as NTFS names files; the first cut split on `/` only, so
/// the leaf of a Windows path was the whole path and never matched (#442).
fn written_file_is(path: &str, comm: &str) -> bool {
    let windows = path.as_bytes().get(1) == Some(&b':') || path.starts_with(r"\\");
    if windows {
        path.rsplit('\\')
            .next()
            .is_some_and(|leaf| leaf.eq_ignore_ascii_case(comm))
    } else {
        path.rsplit('/').next() == Some(comm)
    }
}

/// A path the sensor actually reported, at a trusted system location. Unlike
/// [`policy::name_exclusion_applies`], an unknown path is not trusted: here trust
/// raises an alert threshold, so the absence of evidence must not buy it.
fn is_known_trusted(path: Option<&str>) -> bool {
    path.is_some_and(|p| !p.is_empty() && policy::name_exclusion_applies(Some(p)))
}

/// The host file of a `:Zone.Identifier` stream path, `$DATA` type suffix or
/// not (`C:\d\a.exe:Zone.Identifier:$DATA` → `C:\d\a.exe`). Same rule as
/// the Windows sensor's `stream_host_path`, which this crate can't depend on.
fn motw_stream_host(path: &str) -> Option<&str> {
    let path = strip_suffix_ignore_ascii_case(path, ":$DATA").unwrap_or(path);
    let host = strip_suffix_ignore_ascii_case(path, ":Zone.Identifier")?;
    (!host.is_empty() && !host.ends_with(['\\', '/', ':'])).then_some(host)
}

fn strip_suffix_ignore_ascii_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let split = s.len().checked_sub(suffix.len())?;
    let tail = s.get(split..)?;
    tail.eq_ignore_ascii_case(suffix).then(|| &s[..split])
}

fn format_delta(delta_ns: u64) -> String {
    format!("{:.1}s", delta_ns as f64 / 1_000_000_000.0)
}
