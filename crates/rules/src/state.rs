//! Correlation rules: [`RuleState`] keeps a sliding history (pid→comm, recent writes,
//! per-window counters) and consults it on every event. Each rule stays a dedicated
//! method, with its calibration constants next to it.

use std::{collections::HashMap, net::IpAddr};

use store::BoundedMap;

use schema::{ConnectEvent, ExecEvent, FileOpenEvent};

use crate::{Alert, has_write_intent};

const DOWNLOADER_COMMS: &[&str] = &["curl", "wget"];
const WEB_SERVER_COMMS: &[&str] = &["nginx", "apache2", "httpd"];
const SHELL_COMMS: &[&str] = &["sh", "bash", "dash", "zsh", "ash"];

/// Correlation window between the write of a downloaded file and its execution: past
/// this delay, the two events are no longer linked (avoids keeping an unbounded
/// history, and an execution hours later is no longer the same "download & run"
/// scenario anyway).
const DOWNLOAD_EXEC_WINDOW_NS: u64 = 60_000_000_000; // 60s

// ── Windows constants (ETW rules — T1059/T1218/T1071) ───────────────────────

/// SELF-SPAWN threshold and window (T1059): N spawns of the same name in X seconds.
pub(crate) const SELF_SPAWN_THRESHOLD: u32 = 3;
const SELF_SPAWN_WINDOW_NS: u64 = 30_000_000_000; // 30s

/// BEACON threshold and window (T1071/T1041): N connections to the same dest in X seconds.
pub(crate) const BEACON_THRESHOLD: u32 = 3;
const BEACON_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Processes excluded from SELF-SPAWN (child side) — frequent legitimate self-spawn
/// confirmed in lab.
/// MpCmdRun.exe (Defender): false positive observed during the 2026-08-24 tests.
/// wermgr.exe / WerFault.exe: Windows Error Reporting — respawns in a loop when a
/// process keeps crashing (e.g. malware with no reachable C2). The spawn comes from WER
/// itself, not from direct malicious behavior — false positive observed during the
/// 2026-08-25 VM tests.
/// SecurityHealthH = SecurityHealthHost.exe (ETW-truncated to 15 chars) — Windows
/// Defender Health service, repeatedly respawned by svchost (ppid=956) under normal
/// conditions — NjRAT FP 2026-08-28.
const SELF_SPAWN_EXCLUSIONS: &[&str] = &[
    "MpCmdRun.exe",
    "mpcmdrun.exe",
    "TiWorker.exe",
    "svchost.exe",
    "wermgr.exe",
    "WerFault.exe",
    "WerFaultSecure.exe",
    "SecurityHealthH",
    "SecurityHealthHost.exe",
];

/// Parents excluded from SELF-SPAWN — some system processes legitimately spawn the
/// same child in a loop, with no link to malicious activity.
/// RuntimeBroker.exe: UWP permissions broker, spawns PowerShell for system tasks
/// (notifications, policies) — false positive observed in lab 2026-08-25.
const SELF_SPAWN_PARENT_EXCLUSIONS: &[&str] = &["RuntimeBroker.exe"];

/// LOLBins abused for shellcode injection or executing unsigned code (T1218/T1127).
const LOLBINS: &[&str] = &[
    "aspnet_compiler.exe",
    "aspnet_compiler", // truncated by Windows ETW (20 → 15 chars)
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "ieexec.exe",
    "msdeploy.exe",
    "dfsvc.exe",
    "cmstp.exe",
    "wab.exe",
    "odbcconf.exe",
];

/// Legitimate parents allowed to spawn LOLBins (dev environments).
const LOLBIN_LEGIT_PARENTS: &[&str] = &["devenv.exe", "msbuild.exe", "dotnet.exe", "nuget.exe"];

/// Office/PDF applications often exploited to spawn interpreters (T1204/T1059).
const SUSPECT_PARENTS_WIN: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "acrobat.exe",
    "foxit.exe",
    "iexplore.exe",
];

/// Interpreters and tools frequently launched by Windows macros/exploits.
const SUSPECT_CHILDREN_WIN: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "msiexec.exe",
];

/// Standard ports — connections ignored for BEACON (expected legitimate traffic).
/// 137 = NetBIOS-NS, 138 = NetBIOS-DGM, 5353 = mDNS, 5355 = LLMNR — native Windows
/// network protocols emitted in a loop by the System process and legitimate services,
/// not C2.
/// 3478 = STUN/TURN — used by CrossDeviceService, Teams, WebRTC for NAT traversal,
/// legitimate beaconing observed in lab (false positive, NjRAT capture 2026-08-28).
const STANDARD_PORTS: &[u16] = &[
    80, 443, 53, 8080, 8443, 8000, 25, 587, 465, 993, 995, 143, 137, 138, 5353, 5355, 3478,
];

/// Browsers — repeated outbound connections = normal behavior, not beaconing.
const BROWSERS: &[&str] = &[
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "opera.exe",
    "brave.exe",
    "iexplore.exe",
    "vivaldi.exe",
];

struct RecentWrite {
    pid: u32,
    comm: String,
    timestamp_ns: u64,
}

/// Sliding-window counter: (count, first_ts_ns, alerted). Shared by SELF-SPAWN and
/// BEACON, which follow the same "N occurrences in X seconds, one alert per window"
/// scheme.
type WindowedCounter = (u32, u64, bool);

/// Sliding history needed by the correlation rules:
/// - T1105 (Ingress Tool Transfer): a path recently written by `curl`/`wget` is
///   executed shortly after. Correlated by path + time window rather than by a strict
///   parent/child process link — more robust to the various invocation forms
///   (`curl -o x && x`, `sh -c 'wget -O x; x'`, where `x` is not necessarily a direct
///   child of `curl`/`wget`).
/// - T1059 (suspicious process lineage): a shell interpreter executed directly by a
///   web server process — classic indicator of a web shell / RCE.
///
/// Deliberately unbounded for now (lifetime of a lab session, not of a long-lived
/// production agent): no eviction of old entries beyond the correlation window of
/// `check_download_then_exec`. Known limitation — the bounded entity store
/// (`crates/store`, issue #15) takes this over.
pub struct RuleState {
    /// pid → comm of the last exec seen for this pid, to recover the parent's comm
    /// (T1059) with a simple `ppid` lookup without having to walk the process tree in
    /// userspace. LRU-bounded (`store::BoundedMap`) — a long-lived agent must not
    /// grow this without limit. `pub(crate)` for the seed_from_proc test.
    pub(crate) pid_comm: BoundedMap<u32, String>,
    /// path → info about the last write by a known downloader (T1105).
    recent_writes: HashMap<String, RecentWrite>,
    /// (ppid, comm) → windowed counter for SELF-SPAWN (T1059 Windows).
    self_spawn: HashMap<(u32, String), WindowedCounter>,
    /// (comm, daddr, dport) → windowed counter for BEACON (T1071 Windows).
    beacon: HashMap<(String, String, u16), WindowedCounter>,
}

/// Same bound as the correlator's entity table: the realistic live-pid space.
const PID_COMM_CAP: usize = 65_536;

impl Default for RuleState {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleState {
    pub fn new() -> Self {
        Self {
            pid_comm: BoundedMap::new(PID_COMM_CAP),
            recent_writes: HashMap::new(),
            self_spawn: HashMap::new(),
            beacon: HashMap::new(),
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
    /// processes fork()'d *after* startup that never exec afterwards (e.g. an nginx
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
        let (path, write) = self.recent_writes.iter().find(|(path, write)| {
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
    /// RuntimeBroker.exe — excluded via SELF_SPAWN_EXCLUSIONS /
    /// SELF_SPAWN_PARENT_EXCLUSIONS.
    fn check_self_spawn(&mut self, event: &ExecEvent) -> Option<Alert> {
        let comm = event.meta.comm.clone();
        if SELF_SPAWN_EXCLUSIONS
            .iter()
            .any(|&e| comm.eq_ignore_ascii_case(e))
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
        {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        let key = (event.meta.ppid, comm.clone());
        let entry = self.self_spawn.entry(key).or_insert((0, ts, false));
        // Reset if outside the window
        if ts.saturating_sub(entry.1) > SELF_SPAWN_WINDOW_NS {
            *entry = (0, ts, false);
        }
        entry.0 += 1;
        if entry.0 >= SELF_SPAWN_THRESHOLD && !entry.2 {
            entry.2 = true;
            return Some(Alert {
                technique: "T1059",
                message: format!(
                    "pid={} comm={comm} spawned {}x in {}s by ppid={} — suspected self-spawn",
                    event.meta.pid,
                    entry.0,
                    SELF_SPAWN_WINDOW_NS / 1_000_000_000,
                    event.meta.ppid,
                ),
            });
        }
        None
    }

    /// T1204/T1059 — Office/PDF application spawning an interpreter (macro/exploit).
    /// `resolve_comm` reads pid_comm then `/proc` as a fallback (Linux) — returns None
    /// on Windows if the parent has not yet sent an ExecEvent, which silently disables
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

    /// T1218/T1127 — LOLBin spawned by a non-dev parent (shellcode execution proxy).
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
        let entry = self.beacon.entry(key).or_insert((0, ts, false));
        if ts.saturating_sub(entry.1) > BEACON_WINDOW_NS {
            *entry = (0, ts, false);
        }
        entry.0 += 1;
        if entry.0 >= BEACON_THRESHOLD && !entry.2 {
            entry.2 = true;
            return Some(Alert {
                technique: "T1071/T1041",
                message: format!(
                    "pid={} comm={comm} → {daddr}:{} | {}x in {}s — suspected beaconing",
                    event.meta.pid,
                    event.dport,
                    entry.0,
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
