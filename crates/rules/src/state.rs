//! Correlation rules: [`RuleState`] keeps a sliding history (pid→comm, recent writes,
//! per-window counters) and consults it on every event. Each rule stays a dedicated
//! method, with its calibration constants next to it.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
};

use schema::{
    AuthEvent, AuthOutcome, ConnectEvent, ExecEvent, FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN,
    FileDeleteEvent, FileOpenEvent, FileQuarantineEvent, FileRenameEvent, FileWriteEvent,
    ListenPortEvent, MemfdCreateEvent, NetworkFlowEvent, O_CREAT, User, detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{
        AGENT_CHILD_EXCLUSIONS, APK_STAGING_FILE_PREFIX, AUTH_FAILURE_THRESHOLD,
        AUTH_FAILURE_WINDOW_NS, BEACON_THRESHOLD, BEACON_WINDOW_NS, BROWSERS,
        BURST_WRITE_BYTES_THRESHOLD, COMPRESSION_DRIVER_COMMS, COMPRESSION_SUFFIXES,
        COMPRESSOR_COMMS, CREATE_UNLINK_HISTORY_PER_PID, CREATE_UNLINK_PAIR_WINDOW_NS,
        CREATE_UNLINK_PID_CAP, DOWNLOAD_EXEC_WINDOW_NS, DOWNLOADER_COMMS, IN_PLACE_EDIT_COMMS,
        LOLBIN_LEGIT_PARENTS, LOLBINS, MAILDIR_FLAG_LETTERS, MEMFD_EXEC_WINDOW_NS,
        PACKAGE_MANAGER_COMMS, PACKAGE_MANAGER_TEMP_RENAME_SUFFIXES, QUARANTINE_EXEC_WINDOW_NS,
        RANSOMWARE_EXCLUDED_PATH_PREFIXES, RANSOMWARE_LOOP_CHILD_MAX, RANSOMWARE_RENAME_THRESHOLD,
        RANSOMWARE_RENAME_WINDOW_NS, SCAN_SPREAD_THRESHOLD, SCAN_SPREAD_WINDOW_NS,
        SELF_SPAWN_EXCLUSIONS, SELF_SPAWN_PARENT_EXCLUSIONS, SELF_SPAWN_THRESHOLD,
        SELF_SPAWN_WINDOW_NS, SERVICE_COMM_PREFIXES, SERVICE_COMMS, SHELL_COMMS, STANDARD_PORTS,
        SUSPECT_CHILDREN_WIN, SUSPECT_PARENTS_WIN, TASK_REGISTRATION_DEDUP_WINDOW_NS,
    },
    has_write_intent,
    sliding::{FlowPortDedup, SlidingCounter, SlidingDistinct, SlidingSum},
};

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
/// stamp (Windows, macOS), behaves exactly as before.
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

/// Sliding history needed by the correlation rules:
/// - T1105 (Ingress Tool Transfer): a path recently written by `curl`/`wget` is
///   executed shortly after. Correlated by path + time window rather than by a strict
///   parent/child process link — more robust to the various invocation forms
///   (`curl -o x && x`, `sh -c 'wget -O x; x'`, where `x` is not necessarily a direct
///   child of `curl`/`wget`).
/// - T1059 (suspicious process lineage): a shell interpreter executed directly by a
///   web server process — classic indicator of a web shell / RCE.
///
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
    /// (ppid, comm) → sliding counter for SELF-SPAWN (T1059 Windows). LRU-bounded.
    self_spawn: BoundedMap<(u32, String), SlidingCounter>,
    /// (comm, daddr, dport) → sliding counter for BEACON (T1071 Windows). LRU-bounded.
    beacon: BoundedMap<(String, String, u16), SlidingCounter>,
    /// Same key as `beacon` → which local ports have already counted toward it —
    /// only consulted by [`Self::on_network_flow`] (a poll-based source, see
    /// [`FlowPortDedup`]'s doc); `on_connect`'s discrete syscall trace needs no
    /// dedup, each `ConnectEvent` already is one real connection attempt.
    beacon_flow_dedup: BoundedMap<(String, String, u16), FlowPortDedup>,
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
    /// (target user, source) → sliding failure counter for T1110 (AUTH-BURST).
    /// LRU-bounded like every other counter: a spray across many fabricated
    /// usernames must not grow this without limit.
    auth_failures: BoundedMap<(String, String), SlidingCounter>,
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
const COUNTER_CAP: usize = 16_384;
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
            self_spawn: BoundedMap::new(COUNTER_CAP),
            ldap_burst: crate::ldap::LdapBurst::new(),
            beacon: BoundedMap::new(COUNTER_CAP),
            beacon_flow_dedup: BoundedMap::new(COUNTER_CAP),
            scan_spread: BoundedMap::new(COUNTER_CAP),
            known_listeners: BoundedMap::new(COUNTER_CAP),
            auth_failures: BoundedMap::new(COUNTER_CAP),
            recent_creates: BoundedMap::new(CREATE_UNLINK_PID_CAP),
            pending_unlinks: BoundedMap::new(CREATE_UNLINK_PID_CAP),
            ransomware_unlink: BoundedMap::new(COUNTER_CAP),
            ransomware_rename: BoundedMap::new(COUNTER_CAP),
            ransomware_rename_by_ppid: BoundedMap::new(COUNTER_CAP),
            write_volume: BoundedMap::new(COUNTER_CAP),
            rename_count: BoundedMap::new(COUNTER_CAP),
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
    fn check_quarantined_exec(&mut self, event: &ExecEvent) -> Option<Alert> {
        let now = event.meta.timestamp_ns;
        let mark = self
            .recent_quarantines
            .get_mut(&event.image_path.to_lowercase())?;
        let age = now.saturating_sub(mark.timestamp_ns);
        if mark.alerted || age > QUARANTINE_EXEC_WINDOW_NS {
            return None;
        }
        mark.alerted = true;
        Some(Alert {
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
        if count >= SELF_SPAWN_THRESHOLD && entry.try_alert(ts, SELF_SPAWN_WINDOW_NS) {
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

    /// To be called for every `ExecEvent` in the stream, in chronological order.
    /// Updates the state (pid→comm table) after evaluation, so a process cannot match
    /// itself.
    pub fn on_exec(&mut self, event: &ExecEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        alerts.extend(self.check_web_server_spawns_shell(event));
        alerts.extend(self.check_download_then_exec(event));
        alerts.extend(self.check_quarantined_exec(event));
        alerts.extend(self.check_self_spawn(event));
        alerts.extend(self.check_parent_suspect(event));
        alerts.extend(self.check_lolbin(event));
        alerts.extend(self.check_memfd_exec(event));
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

    /// To be called for every `ConnectEvent` in the stream (mainly Windows ETW).
    pub fn on_connect(&mut self, event: &ConnectEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_beacon(event).into_iter().collect();
        alerts.extend(self.check_scan_spread(event));
        alerts
    }

    /// To be called for every `NetworkFlowEvent` in the stream (Linux conntrack
    /// polling, issue #92) — see [`Self::check_beacon_flow`].
    pub fn on_network_flow(&mut self, event: &NetworkFlowEvent) -> Vec<Alert> {
        self.check_beacon_flow(event).into_iter().collect()
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

    /// To be called for every `AuthEvent` in the stream (issue #377, T1110):
    /// counts failures per (target user, source) on a sliding window and
    /// alerts once per window when the burst threshold is crossed. Successes
    /// deliberately don't reset the counter — a success right after a burst
    /// is the *stronger* signal, not an all-clear (success-after-burst gets
    /// its own alert shape in a follow-up; today the burst itself already
    /// fired).
    /// To be called for every `LdapSearchEvent` (Windows, #364): the
    /// directory-enumeration sweep, many distinct searches from one process
    /// in a short window. The single-search rules are
    /// [`crate::evaluate_ldap_search`].
    pub fn on_ldap_search(&mut self, event: &schema::LdapSearchEvent) -> Vec<Alert> {
        self.ldap_burst.observe(event).into_iter().collect()
    }

    pub fn on_auth(&mut self, event: &AuthEvent) -> Vec<Alert> {
        if event.outcome != AuthOutcome::Failure {
            return Vec::new();
        }
        // "local" for console/service logons that legitimately carry no
        // source address (see `AuthEvent::source_address`'s doc) — a distinct
        // key, never a fabricated loopback.
        let source = event
            .source_address
            .map_or_else(|| "local".to_string(), |a| a.to_string());
        let key = (event.target_user.clone(), source.clone());
        let ts = event.meta.timestamp_ns;
        let entry = self
            .auth_failures
            .get_or_insert_with(key, SlidingCounter::default);
        let count = entry.record(ts, AUTH_FAILURE_WINDOW_NS);
        if count >= AUTH_FAILURE_THRESHOLD && entry.try_alert(ts, AUTH_FAILURE_WINDOW_NS) {
            return vec![Alert {
                technique: "T1110",
                severity: Severity::Medium,
                message: format!(
                    "target={} source={source}: {count} failed authentications in {}s —                      brute-force/spray burst",
                    event.target_user,
                    AUTH_FAILURE_WINDOW_NS / 1_000_000_000,
                ),
            }];
        }
        Vec::new()
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
        alerts.extend(self.record_create(event));
        self.record_downloader_write(event);
        alerts
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
    /// [`Self::check_write_new_then_unlink`].
    pub fn on_file_delete(&mut self, event: &FileDeleteEvent) -> Vec<Alert> {
        self.check_write_new_then_unlink(event)
            .into_iter()
            .collect()
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
    /// compression extension, both required (found live by Jihair on Alpine, #527). Nothing else measured
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
        if self.is_compressor(meta) || self.is_compression_driver(meta, deleted, created) {
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
        let mut alerts: Vec<Alert> = self.check_mass_rename_pattern(event).into_iter().collect();
        alerts.extend(self.check_burst_write_volume(event));
        alerts
    }

    /// To be called for every `FileWriteEvent` in the stream. Does not produce
    /// alerts directly — tracks write volume per pid (issue #82), consumed by
    /// `check_burst_write_volume` on the next `FileRenameEvent`.
    pub fn on_file_write(&mut self, event: &FileWriteEvent) {
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

fn format_delta(delta_ns: u64) -> String {
    format!("{:.1}s", delta_ns as f64 / 1_000_000_000.0)
}
