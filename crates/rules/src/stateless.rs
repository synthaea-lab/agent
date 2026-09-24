//! Stateless rules: a single event is enough to decide — no history, no state.

use schema::{
    ExecEvent, FLAG_PERSISTENCE_ACCOUNT_ARTIFACT, FLAG_PERSISTENCE_ARTIFACT,
    FLAG_PERSISTENCE_BTM_ARTIFACT, FLAG_PERSISTENCE_SYSTEMD_ARTIFACT,
    FLAG_PERSISTENCE_TASK_ARTIFACT, FileOpenEvent,
};

use crate::{Alert, has_write_intent};

/// T1059.004 — Command and Scripting Interpreter: Unix Shell, sub-case base64-encoded
/// command. Deliberately simple heuristic (`base64` substrings + a decode flag): no
/// entropy analysis here — that is the role of the ML model as a complement, not of
/// this deterministic rule.
#[must_use]
pub(crate) fn check_base64_decode(event: &ExecEvent) -> Option<Alert> {
    let cmdline = &event.cmdline;
    let has_base64 = cmdline.contains("base64");
    let has_decode_flag =
        cmdline.contains("-d") || cmdline.contains("-D") || cmdline.contains("--decode");
    if has_base64 && has_decode_flag {
        Some(Alert {
            technique: "T1059.004",
            message: format!(
                "pid={} comm={}: command line contains a base64 decode: {cmdline}",
                event.meta.pid, event.meta.comm,
            ),
        })
    } else {
        None
    }
}

/// T1059.001 — Command and Scripting Interpreter: `PowerShell`, sub-case
/// base64-encoded command (`-EncodedCommand` / `-enc`). Same philosophy as
/// `check_base64_decode`: deterministic substring heuristic on the cmdline, no
/// entropy analysis (that is the ML model's role as a complement, per
/// `threat-model.md`).
///
/// Matches the `PowerShell` parameter alias `-EncodedCommand` in its canonical
/// form and the short truncation `-enc` — the two shapes observed in T1059.001
/// tradecraft in the wild. Rarer intermediate truncations (`-e`, `-en`,
/// `-enco`, ...) are accepted by `PowerShell` itself but are a follow-up
/// widening once we have telemetry to guide the trade-off against false
/// positives (any shell script with a token starting with `-e` is very common
/// on Linux).
///
/// Requires the cmdline to also mention a `PowerShell` interpreter
/// (`powershell` on Windows via `powershell.exe`, `pwsh` on Linux/macOS and
/// `PowerShell` Core on Windows) to filter out unrelated
/// `-enc`/`-encodedcommand` tokens (an `openssl enc` pipeline, a fictitious
/// tool with its own `-encodedcommand` flag, ...). Both anchor strings are
/// specific enough that false positives are negligible in practice.
/// Case-insensitive on the full string — `PowerShell` parameter names and
/// image paths are.
#[must_use]
pub(crate) fn check_encoded_powershell(event: &ExecEvent) -> Option<Alert> {
    let cmdline = &event.cmdline;
    let cmdline_lower = cmdline.to_ascii_lowercase();
    let mentions_powershell =
        cmdline_lower.contains("powershell") || cmdline_lower.contains("pwsh");
    if !mentions_powershell {
        return None;
    }
    let has_encoded_flag = cmdline_lower
        .split(|c: char| c.is_whitespace() || c == '\0')
        .any(|token| token == "-encodedcommand" || token == "-enc");
    if has_encoded_flag {
        Some(Alert {
            technique: "T1059.001",
            message: format!(
                "pid={} comm={}: PowerShell EncodedCommand invocation: {cmdline}",
                event.meta.pid, event.meta.comm,
            ),
        })
    } else {
        None
    }
}

/// T1037.004 (Boot or Logon Initialization Scripts) / T1053.003 (Cron) — write to a
/// known persistence path. List deliberately restricted to the threat-model examples,
/// not exhaustive coverage of Linux persistence mechanisms. Per-platform path sets are
/// follow-up scope (Windows persistence arrives with registry telemetry, M3).
const PERSISTENCE_PATH_PATTERNS: &[&str] = &[
    ".bashrc",
    "/etc/profile.d/",
    "/etc/cron.d/",
    "/etc/systemd/system/",
    // macOS (issue #32): substring match deliberately catches the per-user
    // (`~/Library/...`) and system (`/Library/...`) launchd directories alike.
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    ".zshrc",
    "/etc/periodic/",
    // at(1) jobs — rare on modern macOS, which is exactly why a write there
    // is signal.
    "/var/at/tabs/",
];

/// A path captured by the `open` collector can be relative to an unresolved `dfd`
/// (known limitation of the eBPF collector) — the substring filter tolerates this case
/// as long as the meaningful path fragment (e.g. `.bashrc`) is present verbatim.
#[must_use]
pub(crate) fn check_persistence_write(event: &FileOpenEvent) -> Option<Alert> {
    let path = &event.path;
    let matched_pattern = PERSISTENCE_PATH_PATTERNS
        .iter()
        .find(|pattern| path.contains(*pattern))?;

    if !has_write_intent(event.flags) {
        return None;
    }

    Some(Alert {
        technique: "T1037.004/T1053.003",
        message: format!(
            "pid={} comm={}: write to a known persistence path ({matched_pattern}): {path}",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// Evaluates all stateless rules applicable to an `ExecEvent`.
#[must_use]
pub fn evaluate_exec(event: &ExecEvent) -> Vec<Alert> {
    check_base64_decode(event)
        .into_iter()
        .chain(check_encoded_powershell(event))
        .chain(check_masquerading(event))
        .chain(check_recovery_inhibit(event))
        .chain(check_log_clear_exec(event))
        .collect()
}

/// T1611 — Escape to Host: a containerized process opening `/proc/<pid>/root` reaches
/// through procfs into another process's root filesystem — normal containerized
/// workloads have no legitimate reason to do this. The textbook path is a container
/// run with a shared/host PID namespace (`--pid=host`) reaching `/proc/1/root` to
/// read/write the host's own filesystem (issue #80's suggested example). This needs
/// the container attribution #80 built, since the signal is "a containerized process
/// did X", not X alone — host-side tooling reaches into other processes'
/// `/proc/<pid>/root` constantly and legitimately (procfs walkers, `nsenter`,
/// debuggers); a bare-metal process doing this is unremarkable, a containerized one
/// almost never has a legitimate reason to.
///
/// Needs `event.meta.container` to be populated. Originally had a coverage gap here,
/// confirmed against a real Docker daemon: the sensor's attribution lost a race for a
/// process whose entire lifetime was one `open()` then exit (a bare `cat <path>`),
/// because attribution was read from `/proc/<pid>/cgroup` at drain time, after the pid
/// could already be gone. Closed by issue #204 — attribution is now keyed off a cgroup
/// id captured kernel-side at syscall time (see `container_id_from_cgroupfs`'s doc
/// comment in `sensor-linux`), which does not depend on the pid still existing by
/// drain time.
#[must_use]
pub(crate) fn check_proc_root_escape(event: &FileOpenEvent) -> Option<Alert> {
    let container = event.meta.container.as_ref()?;

    let mut segments = event.path.split('/').filter(|s| !s.is_empty());
    let is_proc_pid_root = matches!(segments.next(), Some("proc"))
        && segments.next().is_some_and(|s| s.parse::<u64>().is_ok())
        && matches!(segments.next(), Some("root"));
    if !is_proc_pid_root {
        return None;
    }

    Some(Alert {
        technique: "T1611",
        message: format!(
            "pid={} comm={} container={}: opened {} — containerized process reaching \
             into another process's root filesystem via procfs, a common \
             container-escape path",
            event.meta.pid, event.meta.comm, container.id, event.path,
        ),
    })
}

/// T1053.005 — Scheduled Task/Job: Scheduled Task. A Windows scheduled task was
/// just created (Security log event 4698, "A scheduled task was created") — see
/// `docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md` for why
/// this flows through `FileOpenEvent` (`FLAG_PERSISTENCE_TASK_ARTIFACT`) rather
/// than a dedicated `Event::Persistence` variant.
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
        message: format!(
            "task={} pid={}: scheduled task persistence created — action path: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// T1543.003 — Create or Modify System Process: Windows Service. A Windows service
/// was just installed (Security log event 7045, "A service was installed in the
/// system") — same eventlog-polling pipeline as T1053.005, see
/// `docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md`. Flows
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
        message: format!(
            "service={} pid={}: service persistence installed — image path: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// T1136.001 — Create Account: Local Account. A Windows local user account was
/// just created (Security log event 4720, "A user account was created") — same
/// eventlog-polling pipeline as T1053.005 and T1543.003, see
/// `docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md`. Flows
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
        message: format!(
            "instigator={} pid={}: macOS launch item registered — payload: {}",
            event.meta.comm, event.meta.pid, event.path,
        ),
    })
}

/// Evaluates all stateless rules applicable to a `FileOpenEvent`.
#[must_use]
pub fn evaluate_file_open(event: &FileOpenEvent) -> Vec<Alert> {
    check_persistence_write(event)
        .into_iter()
        .chain(check_proc_root_escape(event))
        .chain(check_scheduled_task_persistence(event))
        .chain(check_service_install_persistence(event))
        .chain(check_account_creation_persistence(event))
        .chain(check_systemd_service_persistence(event))
        .chain(check_btm_launch_item_persistence(event))
        .collect()
}

/// System-binary names an attacker impersonates, with the directory prefixes
/// the real binary lives under. Unix side (Linux + macOS — both checked, a
/// path matching either platform's legitimate home is fine; the *mismatch*
/// is the signal, not the platform).
const MASQUERADE_UNIX: &[(&str, &[&str])] = &[
    ("bash", &["/bin/", "/usr/bin/", "/usr/local/bin/"]),
    ("sh", &["/bin/", "/usr/bin/"]),
    ("zsh", &["/bin/", "/usr/bin/"]),
    (
        "sshd",
        &[
            "/usr/sbin/",
            "/usr/libexec/",
            "/usr/lib/ssh/",
            "/usr/lib/openssh/",
        ],
    ),
    ("sudo", &["/usr/bin/", "/bin/"]),
    ("systemd", &["/usr/lib/systemd/", "/lib/systemd/"]),
    ("launchd", &["/sbin/"]),
    ("cron", &["/usr/sbin/", "/usr/bin/"]),
    ("login", &["/usr/bin/", "/bin/"]),
];

/// Windows side — compared case-insensitively (NTFS is), against lowercase
/// prefixes.
const MASQUERADE_WINDOWS: &[(&str, &[&str])] = &[
    (
        "svchost.exe",
        &["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    ),
    ("lsass.exe", &["c:\\windows\\system32\\"]),
    ("services.exe", &["c:\\windows\\system32\\"]),
    ("csrss.exe", &["c:\\windows\\system32\\"]),
    ("winlogon.exe", &["c:\\windows\\system32\\"]),
    ("smss.exe", &["c:\\windows\\system32\\"]),
    (
        "explorer.exe",
        &["c:\\windows\\", "c:\\windows\\syswow64\\"],
    ),
    (
        "powershell.exe",
        &[
            "c:\\windows\\system32\\windowspowershell\\",
            "c:\\windows\\syswow64\\windowspowershell\\",
        ],
    ),
    (
        "rundll32.exe",
        &["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    ),
];

/// T1036.005 — Masquerading: Match Legitimate Name or Location. A binary
/// *named* like a core system process executing from outside that binary's
/// legitimate directories (`svchost.exe` in a temp dir, `bash` in
/// `/tmp`). The name lists are deliberately short and high-value: every
/// entry is a binary attackers actually impersonate, and the allowed-prefix
/// sets are the platform's real install locations — no heuristics, so the
/// only false-positive surface is a user legitimately naming their own
/// binary `lsass.exe`, which is itself worth an alert.
///
/// Relative or truncated paths (the Linux `dfd` limitation
/// [`check_persistence_write`] documents) are skipped, not guessed: a
/// masquerade verdict needs the real absolute location.
#[must_use]
pub(crate) fn check_masquerading(event: &ExecEvent) -> Option<Alert> {
    let path = &event.image_path;
    let name = path.rsplit(['/', '\\']).next().unwrap_or("");
    if name.is_empty() {
        return None;
    }

    let (matched, allowed): (&str, &[&str]) = if path.starts_with('/') {
        let entry = MASQUERADE_UNIX.iter().find(|(n, _)| *n == name)?;
        (entry.0, entry.1)
    } else {
        // Windows paths only — anything else (relative, dfd-truncated) is
        // skipped per the doc above.
        let lower_name = name.to_ascii_lowercase();
        let drive_absolute = path.as_bytes().get(1) == Some(&b':');
        if !drive_absolute {
            return None;
        }
        let entry = MASQUERADE_WINDOWS.iter().find(|(n, _)| *n == lower_name)?;
        (entry.0, entry.1)
    };

    let lower_path = path.to_ascii_lowercase();
    let legitimate = allowed.iter().any(|prefix| lower_path.starts_with(prefix));
    if legitimate {
        return None;
    }
    Some(Alert {
        technique: "T1036.005",
        message: format!(
            "pid={} comm={}: system-binary name `{matched}` executing from outside its \
             legitimate location: {path}",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking. `LD_PRELOAD` (and its
/// quieter `LD_AUDIT` sibling) force the dynamic linker to load an attacker-chosen
/// shared object into every dynamically linked exec that inherits the variable; a path
/// outside the linker's own trust set is exactly that shape. The trust set is the
/// built-in baseline ([`crate::ld_trust::LD_TRUST_PREFIXES`]) plus `extra_trust`, the
/// directories the host's `/etc/ld.so.conf` declares — seeded once at startup by
/// [`crate::RuleState::seed_ld_trust_from_system`], which is why this runs from
/// [`crate::RuleState::on_exec`] rather than [`evaluate_exec`]. A path already inside
/// the trust set is standard operational use (some distros ship a legitimate preload
/// this way) and does not fire — no heuristics beyond the trust set, same
/// false-positive posture as `check_masquerading`.
///
/// Evidence-gated on [`ExecEvent::env_security`] actually carrying the variable
/// (#363): capture is a fixed allowlist, so this never scans the full environment for
/// names it doesn't already have — it only ever judges what the sensor chose to keep.
#[must_use]
pub(crate) fn check_ld_preload_hijack(event: &ExecEvent, extra_trust: &[String]) -> Option<Alert> {
    let (name, value) = event
        .env_security
        .iter()
        .find(|(name, _)| name.as_str() == "LD_PRELOAD" || name.as_str() == "LD_AUDIT")?;
    if crate::ld_trust::all_paths_trusted(value, extra_trust) {
        return None;
    }
    Some(Alert {
        technique: "T1574.006",
        message: format!(
            "pid={} comm={}: {name}={value} loads a shared object outside the dynamic \
             linker's trusted search path",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// T1490 — Inhibit System Recovery. The commands that destroy a host's
/// ability to roll back before encryption: shadow-copy deletion, backup
/// catalog wipes, recovery-boot disabling, and Time Machine local-snapshot
/// destruction. Deterministic multi-token matches on the command line — each
/// pattern requires every listed token, so `vssadmin list shadows` never
/// fires.
#[must_use]
pub(crate) fn check_recovery_inhibit(event: &ExecEvent) -> Option<Alert> {
    const PATTERNS: &[(&str, &[&str])] = &[
        ("shadow-copy deletion", &["vssadmin", "delete", "shadows"]),
        ("shadow-copy deletion", &["wmic", "shadowcopy", "delete"]),
        ("backup catalog wipe", &["wbadmin", "delete", "catalog"]),
        (
            "recovery boot disabled",
            &["bcdedit", "recoveryenabled", "no"],
        ),
        (
            "local snapshot destruction",
            &["tmutil", "deletelocalsnapshots"],
        ),
    ];
    let cmdline = event.cmdline.to_ascii_lowercase();
    let (label, _) = PATTERNS
        .iter()
        .find(|(_, tokens)| tokens.iter().all(|t| cmdline.contains(t)))?;
    Some(Alert {
        technique: "T1490",
        message: format!(
            "pid={} comm={}: {label} — the pre-encryption tell: {}",
            event.meta.pid, event.meta.comm, event.cmdline,
        ),
    })
}

/// T1070.002 — Indicator Removal: Clear Logs (the exec-side half; the
/// file-deletion half is [`check_log_file_delete`]). Platform log-wipe
/// commands: Windows event-log clearing, the macOS unified-log erase, and
/// journald vacuuming to nothing.
#[must_use]
pub(crate) fn check_log_clear_exec(event: &ExecEvent) -> Option<Alert> {
    const PATTERNS: &[&[&str]] = &[
        &["wevtutil", "cl"],
        &["wevtutil", "clear-log"],
        &["clear-eventlog"],
        &["log", "erase"],
        &["journalctl", "--vacuum"],
    ];
    let cmdline = event.cmdline.to_ascii_lowercase();
    PATTERNS
        .iter()
        .find(|tokens| tokens.iter().all(|t| cmdline.contains(t)))?;
    Some(Alert {
        technique: "T1070.002",
        message: format!(
            "pid={} comm={}: log-clearing command: {}",
            event.meta.pid, event.meta.comm, event.cmdline,
        ),
    })
}

/// Log locations whose deletion is the anti-forensics signal
/// ([`check_log_file_delete`]). Substring/prefix matches, same tolerance as
/// [`check_persistence_write`]'s patterns.
const LOG_PATH_PATTERNS: &[&str] = &["/var/log/", "/private/var/log/", "/log/journal/", ".evtx"];

/// T1070.002 — the file-deletion half: a log file removed outright. Consumes
/// [`schema::FileDeleteEvent`]s (Linux unlink tracing, macOS ES `UNLINK`;
/// Windows deletions arrive with the minifilter, #136).
#[must_use]
pub(crate) fn check_log_file_delete(event: &schema::FileDeleteEvent) -> Option<Alert> {
    let path = &event.path;
    let matched = LOG_PATH_PATTERNS.iter().find(|p| path.contains(*p))?;
    Some(Alert {
        technique: "T1070.002",
        message: format!(
            "pid={} comm={}: log file deleted ({matched}): {path}",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// Evaluates all stateless rules applicable to a `FileDeleteEvent`.
#[must_use]
pub fn evaluate_file_delete(event: &schema::FileDeleteEvent) -> Vec<Alert> {
    check_log_file_delete(event).into_iter().collect()
}

/// `SIGSTOP`'s platform-native number: the one signal of
/// [`tamper_signal_name`]'s set that differs between Linux and macOS. Signal
/// events carry the sending host's numbering, and rules run on that same host.
const SIGSTOP: u32 = if cfg!(target_os = "macos") { 17 } else { 19 };

/// Name of `signal` when it ends or freezes its target, `None` otherwise. Signal
/// `0` (an existence probe) and the user-defined or job-control signals are left
/// out: they neither stop the agent nor blind it. Every number but `SIGSTOP` is
/// the same on Linux and macOS.
fn tamper_signal_name(signal: u32) -> Option<&'static str> {
    match signal {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        6 => Some("SIGABRT"),
        9 => Some("SIGKILL"),
        15 => Some("SIGTERM"),
        s if s == SIGSTOP => Some("SIGSTOP"),
        _ => None,
    }
}

/// T1562.001 — Impair Defenses: Disable or Modify Tools, the process-termination
/// half (issue #362). Every [`schema::SignalEvent`] already targets a protected
/// security process: the sensors filter at the source (Linux: the eBPF
/// `SIGNAL_WATCH_PID` gate on the agent's own pid; macOS: the Endpoint Security
/// client gate). This rule only keeps the signals that end or freeze the target.
///
/// On Linux it is the only record of a `SIGKILL`'s sender: the agent's own
/// `kill_loudness` can only attribute the catchable signals. The kernel-side
/// record of a `SIGKILL` survives the kill in a pinned map and is replayed by the
/// restarted agent, so that alert arrives one restart late.
#[must_use]
pub(crate) fn check_security_process_signal(event: &schema::SignalEvent) -> Option<Alert> {
    let name = tamper_signal_name(event.signal)?;
    let target = event.target_image_path.as_deref().unwrap_or("?");
    let sender_uid = match &event.meta.user {
        schema::User::Unix { uid, .. } => format!(" uid={uid}"),
        _ => String::new(),
    };
    Some(Alert {
        technique: "T1562.001",
        message: format!(
            "pid={} comm={}{sender_uid}: sent {name} ({}) to security process pid={} ({target})",
            event.meta.pid, event.meta.comm, event.signal, event.target_pid,
        ),
    })
}

/// Evaluates all stateless rules applicable to a `SignalEvent`.
#[must_use]
pub fn evaluate_signal(event: &schema::SignalEvent) -> Vec<Alert> {
    check_security_process_signal(event).into_iter().collect()
}
