//! Correlation rules: [`RuleState`] keeps a sliding history (pid→comm, recent writes,
//! per-window counters) and consults it on every event. Each rule stays a dedicated
//! method, with its calibration constants next to it.

use std::{collections::HashMap, net::IpAddr};

use schema::{
    AuthEvent, BitsJobEvent, ConnectEvent, DnsQueryEvent, Event, ExecEvent,
    FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN, FileDeleteEvent, FileOpenEvent, FileQuarantineEvent,
    FileRenameEvent, FileWriteEvent, ListenPortEvent, MemfdCreateEvent, NetworkFlowEvent, O_CREAT,
    POLICY_MECHANISM_APPLOCKER, POLICY_MECHANISM_SELINUX, POLICY_MECHANISM_WDAC, PolicyDenialEvent,
    SessionEvent, UnitStopEvent, User, detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    auth_state::AuthState,
    credfiles::{self, CredFile},
    download_state::DownloadState,
    exclusions::{
        AGENT_CHILD_EXCLUSIONS, CREDENTIAL_READ_ALERT_WINDOW_NS, LOLBIN_LEGIT_PARENTS, LOLBINS,
        MEMFD_EXEC_WINDOW_NS, POLICY_DENIAL_ALERT_CAP, POLICY_DENIAL_SUBJECT_CAP,
        SELF_SPAWN_EXCLUSIONS, SELF_SPAWN_PARENT_EXCLUSIONS, SELF_SPAWN_SCRIPT_HOSTS,
        SELF_SPAWN_THRESHOLD, SELF_SPAWN_TRUSTED_THRESHOLD, SELF_SPAWN_WINDOW_NS,
        SERVICE_COMM_PREFIXES, SERVICE_COMMS, SHELL_COMMS, STAGING_PID_CAP, STAGING_READ_DIRS,
        STAGING_READ_FILES, STAGING_WINDOW_NS, STAGING_WRITE_FILES, SUSPECT_CHILDREN_WIN,
        SUSPECT_PARENTS_WIN, TASK_REGISTRATION_DEDUP_WINDOW_NS,
    },
    has_write_intent,
    impact_state::ImpactState,
    lsass::{self, LSASS_ACCESS_ALERT_WINDOW_NS, LSASS_THREAD_ALERT_WINDOW_NS},
    network_state::NetworkState,
    privesc::IdentityRequests,
    signature_gate::SignatureGatedAlert,
    sliding::{SlidingCounter, SlidingDistinct},
    staging::{self, StagingDir, StagingReads},
};

/// False only when both generation stamps exist and differ: the same rule as
/// [`PidFact::current`], a pid reused by another process must not inherit a fact.
pub(crate) fn same_incarnation(recorded: Option<u64>, wanted: Option<u64>) -> bool {
    !matches!((recorded, wanted), (Some(a), Some(b)) if a != b)
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
    pub(crate) fn current(
        map: &BoundedMap<u32, Self>,
        pid: u32,
        generation: Option<u64>,
    ) -> Option<&str> {
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
    /// SETUID-ROOT-REQUEST's queued requests, stream clock and exec history: see
    /// [`IdentityRequests`].
    identity: IdentityRequests,
    /// T1105, T1204.002, T1197 and T1553.005, the download-to-execution joins: see
    /// [`DownloadState`].
    downloads: DownloadState,
    /// (ppid, comm) → sliding counter for SELF-SPAWN (T1059 Windows). LRU-bounded.
    self_spawn: BoundedMap<(u32, String), SlidingCounter>,
    /// RANSOMWARE-RENAME, write-new-then-unlink, write-volume T1486, the timestomp dedup and
    /// the damage manifest: see [`ImpactState`].
    impact: ImpactState,
    /// BEACON, SCAN-SPREAD/-VERTICAL, EGRESS-VOLUME/-DOMAIN and ARCHIVE-EXFIL: see
    /// [`NetworkState`].
    network: NetworkState,
    /// Lineage → the discovery commands it ran inside the window, for RECON-BURST
    /// (T1057/T1082/T1016/T1087, #378). LRU-bounded.
    recon_burst: BoundedMap<crate::recon::Lineage, crate::recon::ReconWindow>,
    /// pid → the lineage its children belong to, for each one-shot shell wrapper
    /// (`sh -c`, `cmd /c`) seen running. LRU-bounded.
    recon_wrappers: BoundedMap<u32, crate::recon::Wrapper>,
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
    /// Security-unit stops waiting to be judged, and what execs did to those units, for
    /// UNEXPLAINED-UNIT-STOP (T1562.001, #1085): see [`crate::unitstop`].
    unit_stops: crate::unitstop::UnitStops,
    /// Lineage → its last SERVICE-STOP-BURST finding, so a T1486 finding from the same lineage
    /// can say it was preceded by one (#973). Read for the message only. LRU-bounded.
    burst_marks: BoundedMap<crate::recon::Lineage, crate::impactctx::BurstMark>,
    /// Lineage → its last T1486 or T1490 finding, so a shutdown from the same lineage can be
    /// reported as context for it (T1529, #973). LRU-bounded.
    impact_marks: BoundedMap<crate::recon::Lineage, crate::impactctx::ImpactMark>,
    /// (`local_addr`, `local_port`, `protocol`) → seen, for LISTENER-DRIFT (issue
    /// #92, T1571). `protocol` is the IP protocol number, same convention as
    /// [`schema::ListenPortEvent::protocol`] — a UDP listener and a TCP listener
    /// on the same port are different shapes, not a collision (<https://github.com/synthaea-lab/agent/issues/40>): without
    /// it, a new UDP listener on a port already baselined as TCP (or vice versa)
    /// would be silently treated as already seen. [`Self::seed_listen_ports`]
    /// pre-fills this from one startup snapshot so every service already listening
    /// when the agent attaches is the baseline, not noise — the same "seed from the
    /// world as it already is" principle as [`Self::seed_from_proc`]/`seed_pid_comm`.
    /// LRU-bounded: the realistic listener space is a few dozen, not unbounded, but
    /// a hostile loop binding many ports must not grow this without limit either.
    known_listeners: BoundedMap<(IpAddr, u16, u8), ()>,
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
    /// FIRST-SEEN-LOGON, ODD-HOUR-LOGON, the T1110 failure burst and the RDP, `sudo`/`su` and
    /// session-reconnect joins: see [`AuthState`].
    auth: AuthState,
    /// (pid, kind of credential file) → the last alert, for CREDENTIAL-READ (T1003.008,
    /// T1552, #377): one alert per window, not one per open. LRU-bounded like every other
    /// counter.
    credential_reads: BoundedMap<(u32, CredFile), SlidingCounter>,
    /// (caller pid, process generation, granted) → the last alert, for LSASS-ACCESS
    /// (T1003.001, <https://github.com/synthaea-lab/agent/issues/45>): one alert per outcome per window, whatever masks the caller tries;
    /// the generation keeps a new process on a recycled pid from inheriting the window.
    /// LRU-bounded like every other counter.
    lsass_access: BoundedMap<(u32, Option<u64>, bool), SlidingCounter>,
    /// (creator pid, process generation) → the last alert, for LSASS-REMOTE-THREAD (T1055,
    /// <https://github.com/synthaea-lab/agent/issues/45>): one alert per injector per window. LRU-bounded like every other counter.
    lsass_threads: BoundedMap<(u32, Option<u64>), SlidingCounter>,
    /// Distinct LDAP searches per process for the enumeration-sweep rule
    /// (T1087.002, #364).
    ldap_burst: crate::ldap::LdapBurst,
    /// Task leaf name → last reported T1053.005 registration, so one registration
    /// seen on both Security 4698 and TaskScheduler/Operational 106 alerts once
    /// (#422). LRU-bounded like the counters.
    task_registrations: BoundedMap<String, ReportedTaskRegistration>,
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
pub(crate) const PID_COMM_CAP: usize = 65_536;
/// Counter/write-history bounds — one logical entity per key, far fewer than pids.
pub(crate) const COUNTER_CAP: usize = 16_384;

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
            identity: IdentityRequests::new(),
            downloads: DownloadState::new(),
            self_spawn: BoundedMap::new(COUNTER_CAP),
            impact: ImpactState::new(),
            ldap_burst: crate::ldap::LdapBurst::new(),
            network: NetworkState::new(),
            staging_reads: BoundedMap::new(STAGING_PID_CAP),
            staging_dirs: BoundedMap::new(STAGING_PID_CAP),
            recon_burst: BoundedMap::new(COUNTER_CAP),
            recon_wrappers: BoundedMap::new(COUNTER_CAP),
            exec_lineage: BoundedMap::new(PID_COMM_CAP),
            ssh_fanout: BoundedMap::new(COUNTER_CAP),
            security_discovery: BoundedMap::new(COUNTER_CAP),
            service_stop: BoundedMap::new(COUNTER_CAP),
            unit_stops: crate::unitstop::UnitStops::new(),
            burst_marks: BoundedMap::new(COUNTER_CAP),
            impact_marks: BoundedMap::new(COUNTER_CAP),
            known_listeners: BoundedMap::new(COUNTER_CAP),
            known_policy_denials: BoundedMap::new(COUNTER_CAP),
            policy_denial_budgets: BoundedMap::new(POLICY_DENIAL_SUBJECT_CAP),
            policy_denial_budget_evictions_reported: 0,
            policy_denial_alerts_shed: 0,
            policy_denial_evictions_reported: 0,
            auth: AuthState::new(),
            credential_reads: BoundedMap::new(COUNTER_CAP),
            lsass_access: BoundedMap::new(COUNTER_CAP),
            lsass_threads: BoundedMap::new(COUNTER_CAP),
            task_registrations: BoundedMap::new(COUNTER_CAP),
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
    pub fn seed_listen_ports(&mut self, ports: impl IntoIterator<Item = (IpAddr, u16, u8)>) {
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
        if distinct >= SERVICE_STOP_THRESHOLD {
            // Refreshed while the burst goes on, not only at the alert: a burst that runs
            // past one window is still the burst a later mass rename follows.
            self.burst_marks.insert(
                lineage,
                crate::impactctx::BurstMark {
                    at_ns: ts,
                    services: distinct,
                },
            );
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

    /// T1529 as case context (#973): a shutdown or reboot command from a lineage that already
    /// raised a T1486 or a T1490 finding within [`crate::impactctx::IMPACT_TO_SHUTDOWN_WINDOW_NS`].
    /// Without such a finding it returns nothing and records nothing, so a reboot is never a
    /// finding of its own. Also arms the lineages of a T1490 command. Low, once per finding.
    /// See [`crate::impactctx`] for what counts as a shutdown and why.
    fn check_shutdown_context(
        &mut self,
        event: &ExecEvent,
        lineage: crate::recon::Lineage,
    ) -> Option<Alert> {
        use crate::impactctx::{IMPACT_TO_SHUTDOWN_WINDOW_NS, shutdown_command};

        let ts = event.meta.timestamp_ns;
        if crate::stateless::check_recovery_inhibit(event).is_some() {
            self.mark_impact(
                Some(lineage),
                event.meta.pid,
                event.meta.process_generation,
                ts,
                "T1490",
            );
            return None;
        }
        let command = shutdown_command(event)?;
        let mark = self.impact_marks.get_mut(&lineage)?;
        if ts < mark.at_ns || ts - mark.at_ns > IMPACT_TO_SHUTDOWN_WINDOW_NS || mark.reported {
            return None;
        }
        mark.reported = true;
        Some(Alert {
            technique: "T1529",
            severity: Severity::Low,
            message: format!(
                "pid={} comm={}: `{command}` run {}s after a {} finding from the lineage of \
                 pid={} — context for that case, not a finding of its own (the command was \
                 seen, the host going down is not confirmed)",
                event.meta.pid,
                event.meta.comm,
                (ts - mark.at_ns) / 1_000_000_000,
                mark.technique,
                lineage.0,
            ),
        })
    }

    /// Remembers a T1486 or T1490 finding for the lineages that can own what follows it.
    fn mark_impact(
        &mut self,
        exec_lineage: Option<crate::recon::Lineage>,
        pid: u32,
        generation: Option<u64>,
        ts: u64,
        technique: &'static str,
    ) {
        for lineage in crate::impactctx::armed_lineages(exec_lineage, pid, generation) {
            self.impact_marks.insert(
                lineage,
                crate::impactctx::ImpactMark {
                    at_ns: ts,
                    technique,
                    reported: false,
                },
            );
        }
    }

    /// For the T1486 findings of one file event: tells each whether a SERVICE-STOP-BURST from
    /// the same lineage preceded it (corroboration, message only: technique, severity and
    /// thresholds are untouched, so the damage manifest and the reflex read what they always
    /// read), and arms the lineages for [`Self::check_shutdown_context`].
    fn note_t1486(&mut self, meta: &schema::EventMeta, alerts: &mut [Alert]) {
        use crate::{impactctx::BURST_TO_RENAME_WINDOW_NS, recon::ExecLineage};

        let ts = meta.timestamp_ns;
        let exec_lineage =
            ExecLineage::current(self.exec_lineage.peek(&meta.pid), meta.process_generation);
        for alert in alerts.iter_mut().filter(|a| a.technique == "T1486") {
            let burst =
                crate::impactctx::armed_lineages(exec_lineage, meta.pid, meta.process_generation)
                    .filter_map(|l| self.burst_marks.peek(&l).map(|m| (l, *m)))
                    .filter(|(_, m)| ts >= m.at_ns && ts - m.at_ns <= BURST_TO_RENAME_WINDOW_NS)
                    .max_by_key(|(_, m)| m.at_ns);
            if let Some((l, m)) = burst {
                alert.message.push_str(&format!(
                    " — corroborated: the lineage of pid={} stopped {} distinct services \
                     (SERVICE-STOP-BURST, T1489) {}s earlier",
                    l.0,
                    m.services,
                    (ts - m.at_ns) / 1_000_000_000,
                ));
            }
            self.mark_impact(exec_lineage, meta.pid, meta.process_generation, ts, "T1486");
        }
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
        alerts.extend(self.downloads.on_exec(event));
        alerts.extend(self.check_self_spawn(event));
        alerts.extend(self.check_parent_suspect(event));
        alerts.extend(self.check_lolbin(event));
        alerts.extend(self.check_memfd_exec(event));
        let lineage = self.record_lineage(event);
        alerts.extend(self.check_recon_burst(event, lineage));
        alerts.extend(self.check_security_discovery(event, lineage));
        alerts.extend(self.check_service_stop_burst(event, lineage));
        self.unit_stops.on_exec(event);
        alerts.extend(self.check_shutdown_context(event, lineage));
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
        self.identity.record_exec(event);
        alerts
    }

    /// The exec findings that wait for the image's signature (#441): today
    /// T1204.002, a downloaded file run within the mark window. To be called
    /// for every `ExecEvent`, beside [`Self::on_exec`]. The
    /// caller resolves each with the enrichment's verdict, or calls
    /// [`SignatureGatedAlert::unverified`] when it cannot wait for one.
    pub fn on_exec_signature_gated(&mut self, event: &ExecEvent) -> Option<SignatureGatedAlert> {
        self.downloads.check_quarantined_exec(event)
    }

    /// To be called for every `ConnectEvent` in the stream (mainly Windows ETW).
    pub fn on_connect(&mut self, event: &ConnectEvent) -> Vec<Alert> {
        let mut alerts = self.network.on_connect(event);
        alerts.extend(self.check_ssh_fanout(event));
        alerts
    }

    /// To be called for every `NetworkFlowEvent` in the stream (Linux conntrack
    /// polling, issue #92) — see [`NetworkState::on_network_flow`].
    pub fn on_network_flow(&mut self, event: &NetworkFlowEvent) -> Vec<Alert> {
        self.network.on_network_flow(event, &self.pid_image_path)
    }

    /// To be called for every `DnsQueryEvent` in the stream (the Linux `getaddrinfo` probe,
    /// opt-in; the Windows DNS-Client provider; the macOS network extension). Never alerts: it
    /// remembers that this pid resolved a listed storage or paste service to these addresses,
    /// for EGRESS-DOMAIN to join with the volume it later sends there.
    pub fn on_dns_query(&mut self, event: &DnsQueryEvent) {
        self.network.on_dns_query(event);
    }

    /// LISTENER-DRIFT (issue #92, T1571 — non-standard port is the closest
    /// existing tag in this crate; no better precedent for "a new listener
    /// appeared" exists here yet, calibratable later) — a listening socket that
    /// wasn't in the startup baseline ([`Self::seed_listen_ports`]) nor already
    /// alerted on this run. One alert per (`local_addr`, `local_port`, `protocol`): the
    /// second poll to see the same listener is expected (a poll-based source re-reports
    /// it every cycle while it stays open, same reasoning as
    /// [`NetworkState`]'s BEACON flow dedup), not a second finding — and a TCP and a UDP
    /// listener sharing a port (<https://github.com/synthaea-lab/agent/issues/40>) are different listeners, not one.
    ///
    /// No name/path exclusion list yet — unlike BEACON's `BROWSERS`/
    /// `STANDARD_PORTS`, there is no lab capture here to calibrate one honestly
    /// against (a dev server or `docker-proxy` binding a fresh port after
    /// startup will alert; a documented, known noise source, not a bug).
    fn check_listen_port_drift(&mut self, event: &ListenPortEvent) -> Option<Alert> {
        let key = (event.local_addr, event.local_port, event.protocol);
        if self.known_listeners.get(&key).is_some() {
            return None;
        }
        self.known_listeners.insert(key, ());
        Some(Alert {
            technique: "T1571",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} new {} listener on {}:{} — not seen at agent startup",
                event.meta.pid,
                event.meta.comm,
                protocol_label(event.protocol),
                event.local_addr,
                event.local_port,
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

    /// To be called for every `AuthEvent` in the stream: FIRST-SEEN-LOGON and ODD-HOUR-LOGON
    /// (T1078) on a successful logon, the failure burst (T1110), and the RDP (T1021.001) and
    /// `sudo`/`su` (T1548.003 / T1110.001) failure-then-success joins; see
    /// [`AuthState::on_auth`].
    pub fn on_auth(&mut self, event: &AuthEvent) -> Vec<Alert> {
        self.auth.on_auth(event)
    }

    /// Tells the rules the host's local time as minutes east of UTC (`120` for UTC+2,
    /// `-300` for UTC-5), which turns ODD-HOUR-LOGON on. False when the offset is outside
    /// -720..=840, and the rule keeps what it had. A fixed offset, and it overrides the
    /// platform zone ([`Self::set_local_zone`]): a host that changes its offset with daylight
    /// saving is an hour out for half the year under this one.
    pub fn set_local_utc_offset_minutes(&mut self, minutes: i32) -> bool {
        self.auth.odd_hours.set_offset_minutes(minutes)
    }

    /// Declares the local hours `[start, end)` in which a logon is ordinary for ODD-HOUR-LOGON
    /// (<https://github.com/synthaea-lab/agent/issues/64>); `start > end` wraps midnight (`22, 6`, a night shift). False, and the window
    /// keeps what it had, unless `start` is 0 to 23, `end` 1 to 24 and they differ. The default is
    /// [`WORK_HOURS_LOCAL`](crate::exclusions::WORK_HOURS_LOCAL).
    pub fn set_work_hours(&mut self, start: u32, end: u32) -> bool {
        self.auth.odd_hours.set_work_hours(start, end)
    }

    /// Declares the accounts whose odd-hour logons are expected (<https://github.com/synthaea-lab/agent/issues/64>): on-call staff, a
    /// schedule's service or batch account. ODD-HOUR-LOGON skips them; FIRST-SEEN-LOGON does not.
    /// An entry is `NAME` or `NAME|SID` (see `OddHours::set_exempt_accounts`); at most 64 are
    /// kept, a blank, over-long or malformed one is dropped, and the number kept is returned.
    /// Replaces the previous list; empty by default, so nothing is exempt until the operator says so.
    pub fn set_odd_hour_exempt_accounts(&mut self, accounts: &[String]) -> usize {
        self.auth.odd_hours.set_exempt_accounts(accounts)
    }

    /// Odd-hour logons the exempt list has suppressed since the agent started (<https://github.com/synthaea-lab/agent/issues/64>); read by the
    /// tests, and visible in production through the `skips` field of the info line of `OddHours`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn odd_hour_exempt_skips(&self) -> u64 {
        self.auth.odd_hours.exempt_skips()
    }

    /// Gives the rules the host's platform time zone (<https://github.com/synthaea-lab/agent/issues/15>): `zone` maps an instant (seconds
    /// since the Unix epoch) to minutes east of UTC at that instant, so a logon either side of a
    /// daylight-saving change is judged by the hour the host's clock showed. Turns ODD-HOUR-LOGON
    /// on. A fixed offset from [`Self::set_local_utc_offset_minutes`] overrides it whichever is
    /// set first. False, and the rule keeps what it had, when `zone` has no answer for `now_secs`.
    pub fn set_local_zone(&mut self, zone: crate::LocalOffsetAt, now_secs: i64) -> bool {
        self.auth.odd_hours.set_zone(zone, now_secs)
    }

    /// To be called for every `SessionEvent` in the stream (Windows Terminal
    /// Services, #285): a disconnected session reconnected from another
    /// client, T1563.002 (see the `session` module), or a successful RDP listener
    /// authentication after failures from that source, T1021.001.
    pub fn on_session(&mut self, event: &SessionEvent) -> Vec<Alert> {
        self.auth.on_session(event)
    }

    /// To be called for every `IdentityChangeEvent` in the stream (Linux, issue #266):
    /// SETUID-ROOT-REQUEST (T1548.001, #1041), see [`crate::privesc`]. A request for uid 0 is
    /// queued, not judged: its process's exec event arrives later than the request, so it is
    /// judged once the stream clock is [`crate::privesc::IDENTITY_DEFER_NS`] past it, against the
    /// image the pid (else its parent, for a child that forked and never exec'd) had **at the
    /// request's time**, never `comm`. Returns the requests that are now due, each with its own
    /// event so the alert is attributed to the right process; the sink also calls
    /// [`Self::take_due_identity_alerts`] after every exec, which moves the clock too.
    pub fn on_identity_change(
        &mut self,
        event: &schema::IdentityChangeEvent,
    ) -> Vec<(schema::IdentityChangeEvent, Alert)> {
        self.identity.on_identity_change(event)
    }

    /// UNEXPLAINED-UNIT-STOP (T1562.001, #1085), see [`crate::unitstop`]: the security-unit stops
    /// whose wait is over, judged, each with its own event so the alert is attributed to it. A
    /// stop is queued by [`Self::on_unit_stop`] and judged once the stream clock is
    /// [`crate::unitstop::START_WITHIN_NS`] past it; the sink calls this after every exec and
    /// unit stop, which are what move the clock.
    pub fn take_due_unit_stops(&mut self) -> Vec<(UnitStopEvent, Alert)> {
        self.unit_stops.take_due()
    }

    /// The queued identity requests whose wait is over, judged: see [`Self::on_identity_change`].
    pub fn take_due_identity_alerts(&mut self) -> Vec<(schema::IdentityChangeEvent, Alert)> {
        self.identity.take_due()
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
        self.downloads.on_file_quarantine(event);
    }

    /// To be called for every `BitsJobEvent` in the stream: records the job's
    /// file for the T1197 download→exec join
    /// ([`DownloadState::check_bits_download_exec`]). No alert on its own: BITS is
    /// also how browsers and updaters fetch their components.
    pub fn on_bits_job(&mut self, event: &BitsJobEvent) {
        self.downloads.on_bits_job(event);
    }

    /// To be called for every `ProcessAccessEvent` in the stream (Windows, <https://github.com/synthaea-lab/agent/issues/41>): LSASS-ACCESS
    /// (T1003.001, <https://github.com/synthaea-lab/agent/issues/45>), see [`crate::lsass`]. The caller's expected-reader exclusion reads
    /// its full image (exec-time, else the event's `caller_image_path`), never `comm`. One
    /// alert per (caller pid, process generation, outcome) per
    /// [`LSASS_ACCESS_ALERT_WINDOW_NS`].
    pub fn on_process_access(&mut self, event: &schema::ProcessAccessEvent) -> Vec<Alert> {
        let image = PidFact::current(
            &self.pid_image_path,
            event.meta.pid,
            event.meta.process_generation,
        )
        .filter(|path| !path.is_empty())
        .or(event.caller_image_path.as_deref());
        let Some(alert) = lsass::lsass_access_alert(event, image) else {
            return Vec::new();
        };
        let key = (
            event.meta.pid,
            event.meta.process_generation,
            event.status == 0,
        );
        let counter = self
            .lsass_access
            .get_or_insert_with(key, SlidingCounter::default);
        if !counter.try_alert(event.meta.timestamp_ns, LSASS_ACCESS_ALERT_WINDOW_NS) {
            return Vec::new();
        }
        vec![alert]
    }

    /// To be called for every `RemoteThreadEvent` in the stream (Windows, <https://github.com/synthaea-lab/agent/issues/41>):
    /// LSASS-REMOTE-THREAD (T1055, <https://github.com/synthaea-lab/agent/issues/45>), see [`crate::lsass`]. Other remote threads stay
    /// telemetry until calibrated. One alert per (creator pid, process generation) per
    /// [`LSASS_THREAD_ALERT_WINDOW_NS`].
    pub fn on_remote_thread(&mut self, event: &schema::RemoteThreadEvent) -> Vec<Alert> {
        let Some(alert) = lsass::lsass_remote_thread_alert(event) else {
            return Vec::new();
        };
        let counter = self.lsass_threads.get_or_insert_with(
            (event.meta.pid, event.meta.process_generation),
            SlidingCounter::default,
        );
        if !counter.try_alert(event.meta.timestamp_ns, LSASS_THREAD_ALERT_WINDOW_NS) {
            return Vec::new();
        }
        vec![alert]
    }

    /// To be called for every `UnitStopEvent` (the journal's report of a security unit stopping,
    /// #1127). Queues it for UNEXPLAINED-UNIT-STOP (#1085); the alert comes from
    /// [`Self::take_due_unit_stops`] once the wait is over.
    pub fn on_unit_stop(&mut self, event: &UnitStopEvent) {
        self.unit_stops.on_unit_stop(event);
    }

    /// To be called for every `FileOpenEvent` in the stream. Reports T1053.005
    /// scheduled-task creation (deduplicated, see
    /// [`Self::check_task_registration`]) and updates the history of downloader
    /// writes, consumed by [`DownloadState::check_download_then_exec`].
    pub fn on_file_open(&mut self, event: &FileOpenEvent) -> Vec<Alert> {
        self.unit_stops.advance_clock(event.meta.timestamp_ns);
        let mut alerts: Vec<Alert> = self.check_task_registration(event).into_iter().collect();
        alerts.extend(crate::stateless::check_service_write_outside_datadir(
            event,
            |pid, generation| self.resolve_comm(pid, generation),
        ));
        alerts.extend(self.check_credential_file_read(event));
        alerts.extend(self.impact.record_create(event, &self.pid_image_path));
        self.downloads.record_downloader_write(event);
        self.network.record_archive_open(event);
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

    /// To be called for every `FileDeleteEvent` in the stream: the unlink half of the
    /// write-new-then-unlink T1486 shape (#512 part B), see
    /// [`ImpactState::check_write_new_then_unlink`], and the mark-of-the-web removal
    /// consumed by [`DownloadState::check_exec_after_motw_removal`].
    pub fn on_file_delete(&mut self, event: &FileDeleteEvent) -> Vec<Alert> {
        self.downloads.record_motw_removal(event);
        let mut alerts: Vec<Alert> = self
            .impact
            .on_file_delete(event, &self.pid_image_path)
            .into_iter()
            .collect();
        self.note_t1486(&event.meta, &mut alerts);
        alerts
    }

    /// To be called for every `FileRenameEvent` in the stream (T1486, issue #262 +
    /// #82's write-volume corroboration).
    pub fn on_file_rename(&mut self, event: &FileRenameEvent) -> Vec<Alert> {
        self.downloads.record_motw_stream_rename(event);
        let mut alerts = self.impact.on_file_rename(event, &self.pid_image_path);
        self.note_t1486(&event.meta, &mut alerts);
        alerts
    }

    /// T1070.006, from `FileSetTimeEvent`s ([`crate::evaluate_file_set_time`]), deduplicated per
    /// process on Linux (#1036): the `inode_setattr` hook reports every explicit time, and
    /// `tar x`, `cp -a`, `rsync -a` and `cpio` set one per file, so a 3000-file unpack raised
    /// about 1000 Low alerts in the lab (the rest were lost to the ring buffer). One alert per
    /// process incarnation per
    /// [`SET_TIME_ALERT_WINDOW_NS`](crate::impact_state::SET_TIME_ALERT_WINDOW_NS) says the
    /// same thing; every `touch -d` of a stomping script is its own process and still alerts. Windows events carry no
    /// trustworthy process (the minifilter's `comm` is empty), so they pass through as before.
    pub fn on_file_set_time(&mut self, event: &schema::FileSetTimeEvent) -> Vec<Alert> {
        let alerts = crate::evaluate_file_set_time(event);
        if alerts.is_empty() || !matches!(event.meta.user, schema::User::Unix { .. }) {
            return alerts;
        }
        self.impact
            .dedup_file_set_time(event, alerts, &self.pid_image_path)
    }

    /// The renames and deletions of the process incarnation `(pid, generation)` still
    /// remembered, oldest first: the damage manifest a ransomware detection carries
    /// (issue #82). Two known, different generations never mix (a recycled pid's earlier
    /// life is not this process's damage); a missing stamp keeps the pid-only behavior.
    #[must_use]
    pub fn touched_files(&self, pid: u32, generation: Option<u64>) -> Vec<Event> {
        self.impact.touched_files(pid, generation)
    }

    /// To be called for every `FileWriteEvent` in the stream. Does not produce
    /// alerts directly — tracks write volume per pid (issue #82), consumed by
    /// `check_burst_write_volume` on the next `FileRenameEvent`.
    pub fn on_file_write(&mut self, event: &FileWriteEvent) {
        self.network.record_archive_write(event);
        self.impact.record_write(event);
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

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `event.protocol`'s IP protocol number, as a word for the LISTENER-DRIFT alert
/// (<https://github.com/synthaea-lab/agent/issues/40>) — `tcp`/`udp` for the two values every snapshot source reports
/// today, the bare number for anything else rather than guessing a name.
fn protocol_label(protocol: u8) -> std::borrow::Cow<'static, str> {
    match protocol {
        schema::IPPROTO_TCP => "tcp".into(),
        schema::IPPROTO_UDP => "udp".into(),
        other => other.to_string().into(),
    }
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

/// Whether the file at `path` is the one a process named `comm` runs from. A
/// Windows path (`C:\…`, `\\server\…`) is split on `\` and compared
/// case-insensitively, as NTFS names files; the first cut split on `/` only, so
/// the leaf of a Windows path was the whole path and never matched (#442).
pub(crate) fn written_file_is(path: &str, comm: &str) -> bool {
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
