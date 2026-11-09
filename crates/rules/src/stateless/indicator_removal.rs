//! Indicator Removal (T1070): logs cleared or deleted, timestamps changed.

use schema::{ExecEvent, FileSetTimeEvent, User, detection::Severity};

use crate::Alert;

/// ATT&CK splits log clearing by platform: T1070.001 is Windows event logs,
/// T1070.002 is Linux and macOS system logs. The first cut tagged everything
/// `.002`, Windows included (#424).
const CLEAR_WINDOWS_EVENT_LOGS: &str = "T1070.001";
const CLEAR_UNIX_SYSTEM_LOGS: &str = "T1070.002";

/// T1070.001 / T1070.002 — Indicator Removal: Clear Logs (the exec-side half;
/// the file-deletion half is [`check_log_file_delete`]). Platform log-wipe
/// commands: Windows event-log clearing (`.001`), the macOS unified-log erase
/// and journald vacuuming to nothing (`.002`).
#[must_use]
pub(crate) fn check_log_clear_exec(event: &ExecEvent) -> Option<Alert> {
    const PATTERNS: &[(&str, &[&str])] = &[
        (CLEAR_WINDOWS_EVENT_LOGS, &["wevtutil", "cl"]),
        (CLEAR_WINDOWS_EVENT_LOGS, &["wevtutil", "clear-log"]),
        (CLEAR_WINDOWS_EVENT_LOGS, &["clear-eventlog"]),
        (CLEAR_UNIX_SYSTEM_LOGS, &["log", "erase"]),
        (CLEAR_UNIX_SYSTEM_LOGS, &["journalctl", "--vacuum"]),
    ];
    let cmdline = event.cmdline.to_ascii_lowercase();
    let &(technique, _) = PATTERNS
        .iter()
        .find(|(_, tokens)| tokens.iter().all(|t| cmdline.contains(t)))?;
    Some(Alert {
        technique,
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: log-clearing command: {}",
            event.meta.pid, event.meta.comm, event.cmdline,
        ),
    })
}

/// Unix log locations whose deletion is the anti-forensics signal
/// ([`check_log_file_delete`]). Substring/prefix matches, same tolerance as
/// [`check_persistence_write`](super::check_persistence_write)'s patterns.
const UNIX_LOG_DIRS: &[&str] = &["/var/log/", "/private/var/log/", "/log/journal/"];

/// A Windows event log, matched on its extension at the very end of the path
/// (any case): `Security.evtx:Zone.Identifier` is a stream of the file, and
/// its deletion is `Unblock-File` on a downloaded `.evtx`, not a log deleted.
const WINDOWS_EVENT_LOG_EXTENSION: &str = ".evtx";

/// The technique and the matched pattern when `path` is a log file.
fn log_file_technique(path: &str) -> Option<(&'static str, &'static str)> {
    if let Some(dir) = UNIX_LOG_DIRS.iter().find(|dir| path.contains(**dir)) {
        return Some((CLEAR_UNIX_SYSTEM_LOGS, dir));
    }
    let tail = path
        .as_bytes()
        .get(path.len().saturating_sub(WINDOWS_EVENT_LOG_EXTENSION.len())..)?;
    tail.eq_ignore_ascii_case(WINDOWS_EVENT_LOG_EXTENSION.as_bytes())
        .then_some((CLEAR_WINDOWS_EVENT_LOGS, WINDOWS_EVENT_LOG_EXTENSION))
}

/// T1070.001 / T1070.002 — the file-deletion half: a log file removed outright
/// (`.evtx` event logs are `.001`, Unix system logs `.002`). Consumes
/// [`schema::FileDeleteEvent`]s: Linux unlink tracing and macOS ES `UNLINK`.
/// On Windows the ETW sensor forwards only `:Zone.Identifier` stream deletes
/// (#442), which never match; an `.evtx` deleted outright is seen once the
/// minifilter reports deletions (#136).
#[must_use]
pub(crate) fn check_log_file_delete(event: &schema::FileDeleteEvent) -> Option<Alert> {
    let path = &event.path;
    let (technique, matched) = log_file_technique(path)?;
    Some(Alert {
        technique,
        severity: Severity::Medium,
        message: format!(
            "pid={} comm={}: log file deleted ({matched}): {path}",
            event.meta.pid, event.meta.comm,
        ),
    })
}

/// T1070.001 — the OS-record half (#799): Windows says a log was cleared
/// (Security 1102, System 104), however it was done. [`check_log_clear_exec`]
/// only sees the clears whose command line spells them; this sees the API and
/// .NET ones too. A `wevtutil cl` raises both, a duplicate accepted for now.
///
/// High, one alert per clear, with no exclusion: a legitimate clear is rare and
/// an administrator emptying a log is worth seeing anyway. A backup taken first
/// is named in the message but does not lower the severity, since an attacker
/// can ask for one as easily.
#[must_use]
pub fn evaluate_log_cleared(event: &schema::LogClearedEvent) -> Vec<Alert> {
    let who = if event.subject_user.is_empty() {
        "-"
    } else {
        &event.subject_user
    };
    let sid = match &event.meta.user {
        schema::User::Windows { sid, .. } => sid.as_str(),
        _ => "-",
    };
    let logon = event
        .subject_logon_id
        .as_ref()
        .map_or_else(String::new, |id| format!(" logon={id}"));
    let backup = event
        .backup_path
        .as_ref()
        .map_or_else(String::new, |path| format!(", backed up to {path}"));
    vec![Alert {
        technique: CLEAR_WINDOWS_EVENT_LOGS,
        severity: Severity::High,
        message: format!(
            "event log cleared: channel={} by={who} (sid={sid}{logon}){backup}",
            event.channel
        ),
    }]
}

/// T1070.006 — Indicator Removal: Timestomp. The minifilter reports a successful explicit
/// `FileBasicInformation` request; `comm` is intentionally not used (and not printed) because
/// that sensor has no trustworthy process image. Windows -1/-2 values request automatic
/// updates, not chosen times.
///
/// Low, not Medium (`SherlockOmss`'s/`SoFrexs`'s #1006 review): this is unmeasured, and several
/// ordinary tools explicitly set destination timestamps on every file they touch —
/// `CopyFileEx` (Explorer, `copy`, `Copy-Item`), robocopy's default `/COPY:DAT`, 7-Zip/tar/
/// Explorer zip extraction, OneDrive/Dropbox sync. Each minifilter event also carries `ppid 0`
/// and an empty `comm`, folding every one of these into a single verdict entity with no way to
/// tell a benign bulk copy from a targeted stomp. Escalating back to Medium needs either a live
/// volume measurement (a copy/extraction of a few thousand files) or a per-pid/parent-directory
/// aggregation the driver's wire format does not yet carry — tracked as a follow-up, not solved
/// here by guessing a threshold.
///
/// Linux (#1036): the BPF-LSM `inode_setattr` hook does know the process, so `comm` is printed.
/// The package managers (`rpm`/`dpkg`/`pacman` and their frontends set the archive's stored mtime
/// on every file they unpack) are skipped by `RuleState::on_file_set_time`, not here: the skip
/// needs the exec-time image, because `comm` alone is attacker-controlled. Everything else stays
/// Low for the reason above (`touch -d`, `cp -p`, `tar x`, `rsync -t` are ordinary too). Telling a build tool's
/// `touch` from a targeted stomp needs the parent or a per-process count, which the event does
/// not carry: not guessed here.
#[must_use]
pub fn evaluate_file_set_time(event: &FileSetTimeEvent) -> Vec<Alert> {
    let requested = [
        event.creation_time,
        event.last_access_time,
        event.last_write_time,
        event.change_time,
    ];
    if !requested
        .into_iter()
        .flatten()
        .any(|time| time != 0 && time != -1 && time != -2)
    {
        return Vec::new();
    }
    let unix = matches!(event.meta.user, User::Unix { .. });
    let message = if unix {
        format!(
            "pid={} comm={}: explicit timestamp change requested for {}",
            event.meta.pid, event.meta.comm, event.path,
        )
    } else {
        format!(
            "pid={}: explicit timestamp change requested for {}",
            event.meta.pid, event.path,
        )
    };
    vec![Alert {
        technique: "T1070.006",
        severity: Severity::Low,
        message,
    }]
}

/// Whether `comm` names a Linux package manager or back end: they stamp every unpacked file with
/// the archive's mtime. Only a name: the caller must also check what the process runs.
#[must_use]
pub(crate) fn is_package_manager_comm(comm: &str) -> bool {
    PACKAGE_MANAGERS.contains(&comm)
}

/// Exact `comm` values (15 bytes at most: `unattended-upgr` is the kernel's own truncation of
/// `unattended-upgrade`, a script run by an interpreter, so it never passes the image check and
/// alerts at Low).
const PACKAGE_MANAGERS: &[&str] = &[
    "rpm",
    "dpkg",
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "zypper",
    "pacman",
    "apk",
    "snapd",
    "unattended-upgr",
];
