//! Correlation rules: [`RuleState`] keeps a sliding history (pid→comm, recent writes,
//! per-window counters) and consults it on every event. Each rule stays a dedicated
//! method, with its calibration constants next to it.

use std::{collections::HashMap, net::IpAddr};

use schema::{ConnectEvent, ExecEvent, FileOpenEvent};
use store::BoundedMap;

use crate::{
    Alert,
    exclusions::{
        BEACON_THRESHOLD, BEACON_WINDOW_NS, BROWSERS, DOWNLOAD_EXEC_WINDOW_NS, DOWNLOADER_COMMS,
        LOLBIN_LEGIT_PARENTS, LOLBINS, SELF_SPAWN_EXCLUSIONS, SELF_SPAWN_PARENT_EXCLUSIONS,
        SELF_SPAWN_THRESHOLD, SELF_SPAWN_WINDOW_NS, SHELL_COMMS, STANDARD_PORTS,
        SUSPECT_CHILDREN_WIN, SUSPECT_PARENTS_WIN, WEB_SERVER_COMMS,
    },
    has_write_intent,
    sliding::SlidingCounter,
};

struct RecentWrite {
    pid: u32,
    comm: String,
    timestamp_ns: u64,
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
    /// (ppid, comm) → sliding counter for SELF-SPAWN (T1059 Windows). LRU-bounded.
    self_spawn: BoundedMap<(u32, String), SlidingCounter>,
    /// (comm, daddr, dport) → sliding counter for BEACON (T1071 Windows). LRU-bounded.
    beacon: BoundedMap<(String, String, u16), SlidingCounter>,
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
            self_spawn: BoundedMap::new(COUNTER_CAP),
            beacon: BoundedMap::new(COUNTER_CAP),
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
                    path.rsplit('/').next().unwrap_or(path.as_str()) == comm
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

    // ── Windows rules ────────────────────────────────────────────────────────

    /// T1059 — same process spawned N times in X seconds by the same parent.
    /// False positives documented in lab (2026-08-24/25): MpCmdRun.exe, WerFault.exe,
    /// RuntimeBroker.exe — excluded via `SELF_SPAWN_EXCLUSIONS` /
    /// `SELF_SPAWN_PARENT_EXCLUSIONS`.
    fn check_self_spawn(&mut self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.clone();
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

    /// T1071/T1041 — repeated connections to the same destination on a non-standard
    /// port (C2 beaconing). Browsers excluded (repeated outbound traffic = normal
    /// behavior).
    fn check_beacon(&mut self, event: &ConnectEvent) -> Option<Alert> {
        // pid=4 = Windows System process: constantly emits low-level network traffic
        // (NetBIOS, SMB…) — never C2, guaranteed false positive.
        if event.meta.pid == 4 {
            return None;
        }
        let comm = event.meta.comm.clone();
        // Known limitation: ConnectEvent carries no image path, so the browser
        // exclusion stays name-only here — the correlator's exec-time masquerade
        // tracking covers the rename bypass at the correlation layer.
        if BROWSERS.iter().any(|&n| comm.eq_ignore_ascii_case(n)) {
            return None;
        }
        if STANDARD_PORTS.contains(&event.dport) {
            return None;
        }
        // IPv4 multicast (224.0.0.0/4) and broadcast (last octet = 255): legitimate
        // network traffic emitted in a loop by system services (mDNS, SSDP, Spotify…),
        // never C2.
        if let IpAddr::V4(v4) = event.daddr {
            let o = v4.octets();
            if o[0] >= 224 || o[3] == 255 {
                return None;
            }
        }
        let daddr = event.daddr.to_string();
        let ts = event.meta.timestamp_ns;
        let key = (comm.clone(), daddr.clone(), event.dport);
        let entry = self.beacon.get_or_insert_with(key, SlidingCounter::default);
        let count = entry.record(ts, BEACON_WINDOW_NS);
        if count >= BEACON_THRESHOLD && entry.try_alert(ts, BEACON_WINDOW_NS) {
            return Some(Alert {
                technique: "T1071/T1041",
                message: format!(
                    "pid={} comm={comm} → {daddr}:{} | {count}x in {}s — suspected beaconing",
                    event.meta.pid,
                    event.dport,
                    BEACON_WINDOW_NS / 1_000_000_000,
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
        alerts.extend(self.check_self_spawn(event));
        alerts.extend(self.check_parent_suspect(event));
        alerts.extend(self.check_lolbin(event));

        self.pid_comm
            .insert(event.meta.pid, event.meta.comm.clone());
        alerts
    }

    /// To be called for every `ConnectEvent` in the stream (mainly Windows ETW).
    pub fn on_connect(&mut self, event: &ConnectEvent) -> Vec<Alert> {
        self.check_beacon(event).into_iter().collect()
    }

    /// To be called for every `FileOpenEvent` in the stream. Does not produce alerts
    /// directly — updates the history of downloader writes, consumed by
    /// `check_download_then_exec`.
    pub fn on_file_open(&mut self, event: &FileOpenEvent) {
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
}

fn format_delta(delta_ns: u64) -> String {
    format!("{:.1}s", delta_ns as f64 / 1_000_000_000.0)
}
