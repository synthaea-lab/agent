//! Calibration catalogues for the stateful rules: process lists, thresholds,
//! windows, and exclusions. Every exclusion entry documents WHY it exists, with
//! the date and lab scenario that produced the false positive — and name-keyed
//! exclusions only apply through `policy::name_exclusion_applies` (a rename in
//! %TEMP% must not inherit them).

pub(crate) const DOWNLOADER_COMMS: &[&str] = &["curl", "wget"];
pub(crate) const WEB_SERVER_COMMS: &[&str] = &["nginx", "apache2", "httpd"];
pub(crate) const SHELL_COMMS: &[&str] = &["sh", "bash", "dash", "zsh", "ash"];

/// Correlation window between the write of a downloaded file and its execution: past
/// this delay, the two events are no longer linked (avoids keeping an unbounded
/// history, and an execution hours later is no longer the same "download & run"
/// scenario anyway).
pub(crate) const DOWNLOAD_EXEC_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Window between a download-provenance mark (`FileQuarantine`: macOS quarantine
/// xattr, Windows `Zone.Identifier`) and an exec of the marked file that still
/// counts as "downloaded, then run" (T1204.002, #365). Wider than
/// [`DOWNLOAD_EXEC_WINDOW_NS`]: a user opens a download minutes later, not
/// within a script's seconds. Uncalibrated first cut (2026-09-23) — every
/// legitimate installer run inside the window alerts too; revisit against
/// fleet volume.
pub(crate) const QUARANTINE_EXEC_WINDOW_NS: u64 = 600_000_000_000; // 10 min

// ── Windows constants (ETW rules — T1059/T1218/T1071) ───────────────────────

/// SELF-SPAWN threshold and window (T1059): N spawns of the same name in X seconds.
pub(crate) const SELF_SPAWN_THRESHOLD: u32 = 3;
pub(crate) const SELF_SPAWN_WINDOW_NS: u64 = 30_000_000_000; // 30s

/// BEACON threshold and window (T1071/T1041): N connections to the same dest in X seconds.
/// T1110 — failed authentications per (target user, source) inside
/// [`AUTH_FAILURE_WINDOW_NS`] before the burst alerts. 5-in-60s clears any
/// human fumbling a password (2-3 tries then a reset) while catching even a
/// slow scripted spray.
pub(crate) const AUTH_FAILURE_THRESHOLD: u32 = 5;
/// Sliding window for [`AUTH_FAILURE_THRESHOLD`].
pub(crate) const AUTH_FAILURE_WINDOW_NS: u64 = 60_000_000_000; // 60s
pub(crate) const BEACON_THRESHOLD: u32 = 3;
pub(crate) const BEACON_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Pairing window for one scheduled-task registration seen on both Security 4698
/// and TaskScheduler/Operational 106 (#422, T1053.005). The two are normalized by
/// separate poll threads, each on a 2s cadence, so their timestamps land a few
/// seconds apart in either order. 60s covers a slow poll with ample margin, while a
/// real re-registration of the same task with the same action inside it adds
/// nothing an analyst would miss. Uncalibrated against fleet traffic (2026-09-25).
pub(crate) const TASK_REGISTRATION_DEDUP_WINDOW_NS: u64 = 60_000_000_000; // 60s

/// Processes excluded from SELF-SPAWN (child side) — frequent legitimate self-spawn
/// confirmed in lab.
/// MpCmdRun.exe (Defender): false positive observed during the 2026-08-24 tests.
/// wermgr.exe / WerFault.exe: Windows Error Reporting — respawns in a loop when a
/// process keeps crashing (e.g. malware with no reachable C2). The spawn comes from WER
/// itself, not from direct malicious behavior — false positive observed during the
/// 2026-08-25 VM tests.
/// `SecurityHealthH` = SecurityHealthHost.exe (ETW-truncated to 15 chars) — Windows
/// Defender Health service, repeatedly respawned by svchost (ppid=956) under normal
/// conditions — `NjRAT` FP 2026-08-28.
pub(crate) const SELF_SPAWN_EXCLUSIONS: &[&str] = &[
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
/// RuntimeBroker.exe: UWP permissions broker, spawns `PowerShell` for system tasks
/// (notifications, policies) — false positive observed in lab 2026-08-25.
pub(crate) const SELF_SPAWN_PARENT_EXCLUSIONS: &[&str] = &["RuntimeBroker.exe"];

/// The agent's own known children — narrower than [`SELF_SPAWN_EXCLUSIONS`]: only
/// applies when the spawning `ppid` is the agent's own seeded pid (issue #403).
/// `wevtutil.exe`: the Event Log sensor's `wevtutil qe` poll loop, one spawn every
/// 2s per enabled channel — ~60 spawns/30s across the default four channels, well
/// past `SELF_SPAWN_THRESHOLD`. `auditpol.exe`: run once at startup per channel
/// needing an audit subcategory enabled. Both false-positived on the agent itself
/// in the 2026-09-23 live lab validation of #391. Never a blanket "ignore every
/// child of the agent": `ppid` alone is spoofable
/// (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), so `check_self_spawn` also requires
/// the image to live at a trusted system path (`policy::name_exclusion_applies`),
/// same pairing as `SELF_SPAWN_EXCLUSIONS`.
pub(crate) const AGENT_CHILD_EXCLUSIONS: &[&str] = &["wevtutil.exe", "auditpol.exe"];

/// `LOLBins` abused for shellcode injection or executing unsigned code (T1218/T1127).
pub(crate) const LOLBINS: &[&str] = &[
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

/// Legitimate parents allowed to spawn `LOLBins` (dev environments).
pub(crate) const LOLBIN_LEGIT_PARENTS: &[&str] =
    &["devenv.exe", "msbuild.exe", "dotnet.exe", "nuget.exe"];

/// Office/PDF applications often exploited to spawn interpreters (T1204/T1059).
pub(crate) const SUSPECT_PARENTS_WIN: &[&str] = &[
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
pub(crate) const SUSPECT_CHILDREN_WIN: &[&str] = &[
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
/// 3478 = STUN/TURN — used by `CrossDeviceService`, Teams, WebRTC for NAT traversal,
/// legitimate beaconing observed in lab (false positive, `NjRAT` capture 2026-08-28).
pub(crate) const STANDARD_PORTS: &[u16] = &[
    80, 443, 53, 8080, 8443, 8000, 25, 587, 465, 993, 995, 143, 137, 138, 5353, 5355, 3478,
];

/// Browsers — repeated outbound connections = normal behavior, not beaconing.
pub(crate) const BROWSERS: &[&str] = &[
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "opera.exe",
    "brave.exe",
    "iexplore.exe",
    "vivaldi.exe",
];
