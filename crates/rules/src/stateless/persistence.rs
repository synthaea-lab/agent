//! Persistence (TA0003): writes to persistence paths, and the OS records of a task,
//! service, account, systemd unit or launch item being created.

use schema::{
    FLAG_PERSISTENCE_ACCOUNT_ARTIFACT, FLAG_PERSISTENCE_ARTIFACT, FLAG_PERSISTENCE_BTM_ARTIFACT,
    FLAG_PERSISTENCE_SYSTEMD_ARTIFACT, FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN,
    FLAG_PERSISTENCE_TASK_ARTIFACT, FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT, FileOpenEvent,
    detection::Severity,
};

use crate::{Alert, has_write_intent};

/// Each persistence location maps to its own ATT&CK technique. The first cut
/// tagged every path `T1037.004/T1053.003`, but none of them is an RC script
/// (T1037.004), and only the cron path is T1053.003 (#495).
const UNIX_SHELL_CONFIG_MODIFICATION: &str = "T1546.004";
const CRON: &str = "T1053.003";
const SYSTEMD_SERVICE: &str = "T1543.002";
/// The paths added with the macOS sensor (#32) keep the original tag until their
/// mapping is confirmed on that side (#495).
const MACOS_PATHS_PENDING_REVIEW: &str = "T1037.004/T1053.003";

/// Write-intent opens on known persistence paths, each with its technique. List
/// deliberately restricted to the threat-model examples, not exhaustive coverage of
/// Linux persistence mechanisms. Per-platform path sets are follow-up scope (Windows
/// persistence arrives with registry telemetry, M3).
const PERSISTENCE_PATH_PATTERNS: &[(&str, &str)] = &[
    (UNIX_SHELL_CONFIG_MODIFICATION, ".bashrc"),
    // zsh config is the same technique as bash's, and zsh runs on Linux as much as
    // on macOS: this entry is not platform-gated (#499 review).
    (UNIX_SHELL_CONFIG_MODIFICATION, ".zshrc"),
    (UNIX_SHELL_CONFIG_MODIFICATION, "/etc/profile.d/"),
    (CRON, "/etc/cron.d/"),
    (SYSTEMD_SERVICE, "/etc/systemd/system/"),
    // macOS (issue #32): substring match deliberately catches the per-user
    // (`~/Library/...`) and system (`/Library/...`) launchd directories alike.
    (MACOS_PATHS_PENDING_REVIEW, "/Library/LaunchAgents/"),
    (MACOS_PATHS_PENDING_REVIEW, "/Library/LaunchDaemons/"),
    (MACOS_PATHS_PENDING_REVIEW, "/etc/periodic/"),
    // at(1) jobs — rare on modern macOS, which is exactly why a write there
    // is signal.
    (MACOS_PATHS_PENDING_REVIEW, "/var/at/tabs/"),
];

/// A path captured by the `open` collector can be relative to an unresolved `dfd`
/// (known limitation of the eBPF collector) — the substring filter tolerates this case
/// as long as the meaningful path fragment (e.g. `.bashrc`) is present verbatim.
#[must_use]
pub(crate) fn check_persistence_write(event: &FileOpenEvent) -> Option<Alert> {
    let path = &event.path;
    let &(technique, matched_pattern) = PERSISTENCE_PATH_PATTERNS
        .iter()
        .find(|(_, pattern)| path.contains(*pattern))?;

    if !has_write_intent(event.flags) {
        return None;
    }

    Some(Alert {
        technique,
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: write to a known persistence path ({matched_pattern}): {path}",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// T1053.005 — Scheduled Task/Job: Scheduled Task. A Windows scheduled task was
/// just created (Security log event 4698, "A scheduled task was created"). It
/// flows through `FileOpenEvent` (`FLAG_PERSISTENCE_TASK_ARTIFACT`) rather than a
/// dedicated `Event::Persistence` variant so no `SCHEMA_VERSION` bump forces every
/// consumer to grow a match arm (ADR-0004).
///
/// The signal is deterministic: `sensor-windows-eventlog` pushes this exact
/// `FileOpenEvent` iff Windows wrote a 4698, and 4698 is only emitted when a
/// scheduled task is actually created via any Windows-supported path
/// (`schtasks.exe`, `New-ScheduledTask*`, Task Scheduler COM, the Task Scheduler
/// UI). The flag **is** the signal — no substring or path heuristic needed, no
/// audit-subcategory guessing (the sensor also enables the required subcategory
/// itself, "Other Object Access Events").
///
/// Alert content carries the task's action path (`event.path`) and the task's
/// leaf name (`event.meta.comm`) so an analyst can jump straight from the alert
/// to the persistence artifact for triage/removal via
/// `schtasks /Delete /TN <name> /F`.
#[must_use]
pub(crate) fn check_scheduled_task_persistence(event: &FileOpenEvent) -> Option<Alert> {
    if event.flags & FLAG_PERSISTENCE_TASK_ARTIFACT == 0 {
        return None;
    }
    Some(Alert {
        technique: "T1053.005",
        severity: Severity::Medium,
        message: format!(
            "task={} pid={}: scheduled task persistence created — action path: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// Action-path fragments (lowercase) that make a scheduled-task *update* worth an
/// alert: user-writable staging directories, and script hosts / proxy-execution
/// binaries a hijacked task is typically repointed at. Uncalibrated against fleet
/// traffic (first cut, 2026-09-23) — revisit once real 4702 volume is observed.
///
/// Matched against the path with `/` normalized to `\`. Task actions are stored
/// as written, so the directories also appear as their unexpanded `%VAR%` tokens
/// — the usual shape of a user-level task. The agent runs as SYSTEM and cannot
/// expand per-user variables reliably, so the tokens are matched as-is (#399
/// review).
const TASK_HIJACK_ACTION_PATTERNS: &[&str] = &[
    r"\appdata\",
    r"\temp\",
    r"\downloads\",
    r"\users\public\",
    r"\programdata\",
    "%temp%",
    "%tmp%",
    "%appdata%",
    "%localappdata%",
    "%public%",
    "%userprofile%",
    "%programdata%",
    "cmd.exe",
    "powershell",
    "pwsh",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
];

/// T1053.005 — Scheduled Task/Job: Scheduled Task, task-hijack sub-case: an
/// *existing* scheduled task's action was rewritten (Security log event 4702, "A
/// scheduled task was updated"). Sibling of [`check_scheduled_task_persistence`]
/// (4698, creation), distinct marker `FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT`.
///
/// Unlike the creation rule, the flag alone is not enough: Windows rewrites its own
/// tasks routinely, and `schtasks /create` itself emits 4702 as part of its
/// registration (lab, 2026-09-22) — alerting on every 4702 would bury the signal.
/// The rule therefore also requires the new action path to match
/// `TASK_HIJACK_ACTION_PATTERNS`. A benign creation that also matches still fires
/// the 4698 rule on its own event, so the pair can double-report one `schtasks
/// /create` pointed at a suspicious path — accepted: correlation groups them.
///
/// `event.path` joins **every** action of the new definition (#443), so the gate
/// matches a malicious second action behind a benign first one. An update whose
/// action the sensor could not read (`FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN`)
/// alerts without the gate: routine rewrites keep a readable `Exec`/`ComHandler`,
/// and the placeholder path would otherwise let an unreadable action slip past
/// the pattern check — same stance as #422 for creation.
///
/// Alert content carries the task's leaf name (`event.meta.comm`) and its new
/// action path (`event.path`), for triage via `schtasks /Query /TN <name> /XML`.
#[must_use]
pub(crate) fn check_scheduled_task_update_persistence(event: &FileOpenEvent) -> Option<Alert> {
    if event.flags & FLAG_PERSISTENCE_TASK_UPDATE_ARTIFACT == 0 {
        return None;
    }
    let reason = if event.flags & FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN == 0 {
        let path_lower = event.path.to_ascii_lowercase().replace('/', r"\");
        *TASK_HIJACK_ACTION_PATTERNS
            .iter()
            .find(|pattern| path_lower.contains(*pattern))?
    } else {
        "action unreadable"
    };
    Some(Alert {
        technique: "T1053.005",
        severity: Severity::High,
        message: format!(
            "task={} pid={}: existing scheduled task repointed ({reason}) — new action \
             path: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// T1543.003 — Create or Modify System Process: Windows Service. A Windows service
/// was just installed (Security log event 7045, "A service was installed in the
/// system") — same eventlog-polling pipeline as T1053.005 (ADR-0004). Flows
/// through `FileOpenEvent` with `FLAG_PERSISTENCE_ARTIFACT` (distinct bit from
/// `FLAG_PERSISTENCE_TASK_ARTIFACT`, so the two techniques never cross-fire).
///
/// The signal is deterministic: `sensor-windows-eventlog` pushes this exact
/// `FileOpenEvent` iff Windows wrote a 7045, and 7045 is emitted on any
/// service install path (`sc.exe create`, `New-Service`, the Service Control
/// Manager API, an MSI installer's service registration). The flag **is** the
/// signal — no heuristic on service name, image path or start type here; the
/// System log (not Security) provides 7045 unconditionally, no audit
/// subcategory to enable.
///
/// Alert content carries the service's image path (`event.path`) and the
/// service name (`event.meta.comm`) so an analyst can jump straight from the
/// alert to the persistence artifact for triage/removal via
/// `sc.exe delete <name>`.
#[must_use]
pub(crate) fn check_service_install_persistence(event: &FileOpenEvent) -> Option<Alert> {
    if event.flags & FLAG_PERSISTENCE_ARTIFACT == 0 {
        return None;
    }
    Some(Alert {
        technique: "T1543.003",
        severity: Severity::High,
        message: format!(
            "service={} pid={}: service persistence installed — image path: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// T1136.001 — Create Account: Local Account. A Windows local user account was
/// just created (Security log event 4720, "A user account was created") — same
/// eventlog-polling pipeline as T1053.005 and T1543.003 (ADR-0004). Flows
/// through `FileOpenEvent` with `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT` (distinct
/// bit from the two other persistence flags, so the three techniques never
/// cross-fire off a single event).
///
/// The signal is deterministic: `sensor-windows-eventlog` pushes this exact
/// `FileOpenEvent` iff Windows wrote a 4720 on THIS machine, and 4720 is
/// emitted on any local account creation path (`net user /add`, `New-LocalUser`,
/// the Local Users MMC applet, the `NetUserAdd` Win32 API). Domain account
/// creation writes 4720 on the domain controller, not the reporting machine —
/// out of scope regardless (T1136.002).
///
/// Alert content carries the new account's SAM name (`event.meta.comm`) and its
/// SID (`event.path`) so an analyst can jump straight from the alert to
/// `net user <name> /delete` for triage. The SID (rather than a path) survives
/// an attacker renaming the account before triage runs.
#[must_use]
pub(crate) fn check_account_creation_persistence(event: &FileOpenEvent) -> Option<Alert> {
    if event.flags & FLAG_PERSISTENCE_ACCOUNT_ARTIFACT == 0 {
        return None;
    }
    Some(Alert {
        technique: "T1136.001",
        severity: Severity::High,
        message: format!(
            "account={} pid={}: local account persistence created — sid: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// T1543.002 — Create or Modify System Process: Systemd Service. A systemd unit
/// was just observed starting for the first time since this agent started —
/// `sensor-linux-journal`'s `persistence::UnitPersistenceTracker` (issue #93),
/// the Linux sibling of `check_service_install_persistence`'s Windows T1543.003.
/// Flows through `FileOpenEvent` with `FLAG_PERSISTENCE_SYSTEMD_ARTIFACT`
/// (distinct bit, so this never cross-fires with the three Windows persistence
/// techniques off a single event).
///
/// Unlike the Windows signal, this is an approximation, not a deterministic
/// "just installed" fact: journald's `JOB_TYPE=start`/`JOB_RESULT=done` fires on
/// every start of a unit, install or routine restart alike — the tracker only
/// suppresses repeats *within one agent lifetime*, so a unit already running
/// before the agent started still alerts once, and an agent restart forgets
/// what it had already seen. See [`FLAG_PERSISTENCE_SYSTEMD_ARTIFACT`]'s own
/// doc for the full caveat.
///
/// Alert content carries the unit name from both `event.meta.comm` and
/// `event.path` (journald's job-completion record has no image-path equivalent
/// to Windows' 7045, so there is no second field to distinguish them).
#[must_use]
pub(crate) fn check_systemd_service_persistence(event: &FileOpenEvent) -> Option<Alert> {
    if event.flags & FLAG_PERSISTENCE_SYSTEMD_ARTIFACT == 0 {
        return None;
    }
    Some(Alert {
        technique: "T1543.002",
        severity: Severity::Medium,
        message: format!(
            "unit={} pid={}: systemd service first seen starting — unit: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// T1543.001/.004, T1547.015 — Create or Modify System Process: Launch
/// Agent/Daemon, and Boot or Logon Autostart: Login Items. macOS Background
/// Task Management just registered a launch item (`EndpointSecurity`'s
/// `BTM_LAUNCH_ITEM_ADD`, `sensor-macos`, issue #32) — the macOS sibling of
/// `check_service_install_persistence`'s Windows 7045. Flows through
/// `FileOpenEvent` with `FLAG_PERSISTENCE_BTM_ARTIFACT` (distinct bit, so this
/// never cross-fires with the other persistence techniques off a single
/// event).
///
/// Like the Windows signal (and unlike the Linux systemd approximation), this
/// is a registration-time fact from the OS: BTM emits it when the item is
/// added, whatever the path taken (plist drop, `SMAppService`, MDM). The flag
/// **is** the signal — no path heuristic here; a raw plist write into a
/// launchd directory is the separate, complementary
/// [`check_persistence_write`] signal (see the flag's doc in `schema` for why
/// the two are not duplicates).
///
/// Alert content carries the persistence payload (`event.path` — the
/// executable resolved from the launchd plist when BTM provides it, else the
/// item URL) and the instigating process (`event.meta.comm`), so an analyst
/// can jump straight to triage via `sfltool dumpbtm` / removal in System
/// Settings → Login Items.
#[must_use]
pub(crate) fn check_btm_launch_item_persistence(event: &FileOpenEvent) -> Option<Alert> {
    if event.flags & FLAG_PERSISTENCE_BTM_ARTIFACT == 0 {
        return None;
    }
    Some(Alert {
        technique: "T1543.001/T1547.015",
        severity: Severity::Medium,
        message: format!(
            "instigator={} pid={}: macOS launch item registered — payload: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}
