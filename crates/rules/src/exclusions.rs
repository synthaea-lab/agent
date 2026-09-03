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

// ── Windows constants (ETW rules — T1059/T1218/T1071) ───────────────────────

/// SELF-SPAWN threshold and window (T1059): N spawns of the same name in X seconds.
pub(crate) const SELF_SPAWN_THRESHOLD: u32 = 3;
pub(crate) const SELF_SPAWN_WINDOW_NS: u64 = 30_000_000_000; // 30s

/// BEACON threshold and window (T1071/T1041): N connections to the same dest in X seconds.
pub(crate) const BEACON_THRESHOLD: u32 = 3;
pub(crate) const BEACON_WINDOW_NS: u64 = 60_000_000_000; // 60s

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
