//! Correlation rules: [`RuleState`] keeps a sliding history (pid→comm, recent writes,
//! per-window counters) and consults it on every event. Each rule stays a dedicated
//! method, with its calibration constants next to it.

use std::{collections::HashMap, net::IpAddr};

use schema::{
    AuthEvent, AuthOutcome, ConnectEvent, ExecEvent, FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN,
    FileOpenEvent, FileQuarantineEvent, FileRenameEvent, ListenPortEvent, NetworkFlowEvent, User,
};
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{
        AGENT_CHILD_EXCLUSIONS, AUTH_FAILURE_THRESHOLD, AUTH_FAILURE_WINDOW_NS, BEACON_THRESHOLD,
        BEACON_WINDOW_NS, BROWSERS, DOWNLOAD_EXEC_WINDOW_NS, DOWNLOADER_COMMS,
        LOLBIN_LEGIT_PARENTS, LOLBINS, QUARANTINE_EXEC_WINDOW_NS, RANSOMWARE_LOOP_CHILD_MAX,
        RANSOMWARE_RENAME_THRESHOLD, RANSOMWARE_RENAME_WINDOW_NS, SELF_SPAWN_EXCLUSIONS,
        SELF_SPAWN_PARENT_EXCLUSIONS, SELF_SPAWN_THRESHOLD, SELF_SPAWN_WINDOW_NS, SHELL_COMMS,
        STANDARD_PORTS, SUSPECT_CHILDREN_WIN, SUSPECT_PARENTS_WIN,
        TASK_REGISTRATION_DEDUP_WINDOW_NS, WEB_SERVER_COMMS,
    },
    has_write_intent,
    sliding::{FlowPortDedup, SlidingCounter},
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
    pub(crate) pid_comm: BoundedMap<u32, String>,
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
    /// ppid → the same counter, for the shell-loop shape (`for f in *; do mv "$f"
    /// "$f.locked"; done`, `find … -exec mv {} {}.x \;`): each rename runs in its own
    /// short-lived `mv` pid, so the per-pid counter never climbs, but every child
    /// shares the loop's shell as `ppid`. Real Linux ransomware ships this way, so the
    /// per-pid counter alone would miss it (issue #262 review, old-dov). LRU-bounded.
    /// `ppid <= 1` (unknown/init) is never keyed here — see `check_mass_rename_pattern`.
    ransomware_rename_by_ppid: BoundedMap<u32, SlidingCounter>,
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
}

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
            recent_writes: BoundedMap::new(RECENT_WRITES_CAP),
            recent_quarantines: BoundedMap::new(RECENT_WRITES_CAP),
            self_spawn: BoundedMap::new(COUNTER_CAP),
            beacon: BoundedMap::new(COUNTER_CAP),
            beacon_flow_dedup: BoundedMap::new(COUNTER_CAP),
            known_listeners: BoundedMap::new(COUNTER_CAP),
            auth_failures: BoundedMap::new(COUNTER_CAP),
            ransomware_rename: BoundedMap::new(COUNTER_CAP),
            ransomware_rename_by_ppid: BoundedMap::new(COUNTER_CAP),
            task_registrations: BoundedMap::new(COUNTER_CAP),
            own_pid: None,
            ld_trust_extra: Vec::new(),
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
        self.pid_comm.extend(map);
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
            self.pid_comm.insert(pid, comm.trim_end().to_string());
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
    pub(crate) fn resolve_comm(&self, pid: u32) -> Option<String> {
        if let Some(comm) = self.pid_comm.peek(&pid) {
            return Some(comm.clone());
        }
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim_end().to_string())
    }

    /// T1059 — a shell executed directly by a web server process.
    fn check_web_server_spawns_shell(&self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.as_str();
        if !SHELL_COMMS.contains(&comm) {
            return None;
        }
        let parent_comm = self.resolve_comm(event.meta.ppid)?;
        if !WEB_SERVER_COMMS.iter().any(|w| parent_comm == *w) {
            return None;
        }
        Some(Alert {
            technique: "T1059",
            message: format!(
                "pid={} comm={} executed directly by ppid={} comm={parent_comm} (web server) — suspicious process lineage",
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
        let parent_comm = self
            .pid_comm
            .peek(&event.meta.ppid)
            .cloned()
            .unwrap_or_default();
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
        let parent_comm = self.resolve_comm(event.meta.ppid)?;
        if !SUSPECT_PARENTS_WIN
            .iter()
            .any(|&p| parent_comm.eq_ignore_ascii_case(p))
        {
            return None;
        }
        Some(Alert {
            technique: "T1204/T1059",
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
        let parent_comm = self.resolve_comm(event.meta.ppid)?;
        if LOLBIN_LEGIT_PARENTS
            .iter()
            .any(|&p| parent_comm.eq_ignore_ascii_case(p))
        {
            return None;
        }
        Some(Alert {
            technique: "T1218/T1127",
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
        alerts.extend(crate::stateless::check_ld_preload_hijack(
            event,
            &self.ld_trust_extra,
        ));

        self.pid_comm
            .insert(event.meta.pid, event.meta.comm.clone());
        alerts
    }

    /// To be called for every `ConnectEvent` in the stream (mainly Windows ETW).
    pub fn on_connect(&mut self, event: &ConnectEvent) -> Vec<Alert> {
        self.check_beacon(event).into_iter().collect()
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
                message: format!(
                    "target={} source={source}: {count} failed authentications in {}s —                      brute-force/spray burst",
                    event.target_user,
                    AUTH_FAILURE_WINDOW_NS / 1_000_000_000,
                ),
            }];
        }
        Vec::new()
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
        let alerts = self.check_task_registration(event).into_iter().collect();
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
    /// Known benign producers of this exact shape that this rule does **not** yet
    /// discriminate, because a `FileRenameEvent` carries only `comm`, never the
    /// executable path an evidence-gated exclusion needs (CLAUDE.md — name-keyed
    /// exclusions must be gated on evidence, cf. [`policy::name_exclusion_applies`]):
    /// - Log rotation (`app.log` → `app.log.1`): handled by [`is_rotation_suffix`]
    ///   (a suffix with no letter never counts) — the one case a shape signal settles.
    /// - In-place edit with a backup: `sed -i.bak`, `perl -i.orig` `rename(2)` the
    ///   original to `f.bak`/`f.orig` from one pid; 20+ files in one command
    ///   (`sed -i.bak … *.conf`) trip this rule.
    /// - Maildir flag changes (`…:2,S` → `…:2,ST`): one IMAP pid, prefix-preserving,
    ///   lettered suffix; "mark all read" on a large folder can exceed the threshold.
    ///
    /// Excluding those on `comm` alone would be spoofable (an encryptor sets
    /// `comm=sed`), so the proper fix is to add the exe path to `FileRenameEvent` and
    /// gate on `comm` + trusted path — tracked as a follow-up. Shapes this rule
    /// cannot see at all (write-new-then-unlink, cross-directory moves) need a
    /// separate write/delete correlation, also follow-up.
    fn check_mass_rename_pattern(&mut self, event: &FileRenameEvent) -> Option<Alert> {
        let suffix = event.new_path.strip_prefix(event.old_path.as_str())?;
        if suffix.is_empty() || is_rotation_suffix(suffix) {
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

    /// To be called for every `FileRenameEvent` in the stream (T1486, issue #262).
    pub fn on_file_rename(&mut self, event: &FileRenameEvent) -> Vec<Alert> {
        self.check_mass_rename_pattern(event).into_iter().collect()
    }
}

/// Suffixes logrotate and similar rotators append (`.1`, `-20260924`, `.1.2`, `~`
/// backups): no ASCII letter at all. Ransomware markers carry letters (`.locked`,
/// `.WNCRY`, `.id-<hex>.[mail]`); an all-digit random suffix is the one blind spot,
/// accepted over alerting on every rotation run.
fn is_rotation_suffix(suffix: &str) -> bool {
    !suffix.bytes().any(|b| b.is_ascii_alphabetic())
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
