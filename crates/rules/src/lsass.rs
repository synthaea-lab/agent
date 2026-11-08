//! LSASS-ACCESS and LSASS-REMOTE-THREAD (#960): credential dumping from LSASS memory
//! (T1003.001) and a thread started inside LSASS by another process (T1055), over the
//! driver-free Windows telemetry of #720 ([`schema::ProcessAccessEvent`],
//! [`schema::RemoteThreadEvent`]).
//!
//! The sensor already narrows both: a `ProcessAccessEvent` is an open of the system's LSASS
//! (confirmed by its full path, session and parent) from another user process asking for a
//! right that reaches its memory, denied opens included; a `RemoteThreadEvent` is a thread
//! whose creator is not the process that owns it, minus the kernel's and the initial thread
//! of a new process. What is left to decide here is who is allowed to read LSASS, and how
//! loud the rest is.
//!
//! The access mask does not grade the alert. Mimikatz's `sekurlsa` asks for the smallest mask
//! that reads memory (`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, `0x1010`), the
//! same shape as a process viewer, while a `MiniDumpWriteDump` dumper asks for more; a larger
//! mask is not a worse intent. What does grade it is the outcome: a granted open has access
//! to the credentials, a denied one (a `RunAsPPL` LSASS refusing an unprotected caller) is an
//! attempt that failed. Two cases where the outcome does not show that access step down to
//! Medium: a granted open whose only memory right is `MAXIMUM_ALLOWED` (a `RunAsPPL` LSASS
//! grants it with a reduced mask, without `PROCESS_VM_READ`), and a caller whose image is
//! unknown but whose name is an expected reader's.
//!
//! Not calibrated: no capture of who opens LSASS on a real fleet exists yet (#715 measured
//! volumes, not callers), so the reader list below is the documented one, kept short on
//! purpose, and is where an operator's measurement will add to it. Neither is
//! LSASS-REMOTE-THREAD: whether Defender ever starts a thread inside LSASS is unmeasured.

use schema::{ProcessAccessEvent, RemoteThreadEvent, detection::Severity};

use crate::Alert;

/// Named constants, not literals inside a `match`: `tools/attack-coverage.py` reads a
/// technique from a `technique` field or from a string constant of this shape.
const LSASS_ACCESS_TECHNIQUE: &str = "T1003.001";
const LSASS_THREAD_TECHNIQUE: &str = "T1055";

/// One LSASS-ACCESS alert per (caller pid, process generation, outcome) per window: the
/// sensor already folds an identical open (caller, mask, status) into one per minute, but a
/// dumper that tries several masks, or retries, is one finding.
pub(crate) const LSASS_ACCESS_ALERT_WINDOW_NS: u64 = 300_000_000_000; // 5 min

/// One LSASS-REMOTE-THREAD alert per (creator pid, process generation) per window. The
/// sensor folds a thread per (creator, owner, 64 KiB of start address) per minute and never
/// drops a thread into LSASS on its per-creator budget, so this is the bound on one injector
/// starting threads at many addresses.
pub(crate) const LSASS_THREAD_ALERT_WINDOW_NS: u64 = 300_000_000_000; // 5 min

/// Readers of LSASS memory that are part of the operating system or of its built-in
/// antivirus, each with the directories it is installed in (lowercase components below the
/// drive root; `*` is one version directory). A reader is excluded only when its full image
/// is directly in one of them ([`is_known_reader`]): not anywhere under a trusted path,
/// since whoever can open LSASS is an administrator, and an administrator can write under
/// `Program Files` (#1152 review).
///
/// - `wininit.exe`: starts LSASS and supervises it for the session's lifetime.
/// - `csrss.exe`: the Win32 subsystem server, which holds a handle to every Win32 process.
/// - `MsMpEng.exe`: the Defender engine, which scans process memory, LSASS included; in
///   `Program Files`, or in its platform directory once Defender has updated itself (only
///   `SYSTEM` and `TrustedInstaller` can write there).
/// - `MsSense.exe`: the Defender for Endpoint sensor, which does the same.
///
/// Deliberately **not** here, each being a documented way to dump LSASS:
/// - `WerFault.exe`: the silent-process-exit dump (`SilentProcessExit` → `WerFault -s`).
/// - `Taskmgr.exe`: "Create dump file" on LSASS.
/// - `rundll32.exe`: `comsvcs.dll,MiniDump`.
/// - `svchost.exe`, `wmiprvse.exe`: generic hosts; excluding the name exempts any service
///   or provider DLL loaded into them.
/// - the agent itself: it opens a new process with `PROCESS_VM_READ` to read its command
///   line, which reaches LSASS only if LSASS starts after the agent, i.e. never short of a
///   restart of LSASS, which is itself a reboot.
const LSASS_READERS: &[(&str, &[&[&str]])] = &[
    ("wininit.exe", &[&["windows", "system32"]]),
    ("csrss.exe", &[&["windows", "system32"]]),
    (
        "msmpeng.exe",
        &[
            &["program files", "windows defender"],
            &[
                "programdata",
                "microsoft",
                "windows defender",
                "platform",
                "*",
            ],
        ],
    ),
    (
        "mssense.exe",
        &[&[
            "program files",
            "windows defender advanced threat protection",
        ]],
    ),
];

/// LSASS's location below the drive root.
const LSASS_HOME: &[&str] = &["windows", "system32", "lsass.exe"];

/// The lowercase components of an absolute `<letter>:\...` path below its drive root, `\`
/// or `/` separated; `None` for anything else, and for a path with an empty, `.` or `..`
/// component, which no sensor-normalized image path has.
fn components_below_drive(path: &str) -> Option<Vec<String>> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    if bytes[2] != b'\\' && bytes[2] != b'/' {
        return None;
    }
    let parts: Vec<String> = path[3..]
        .split(['\\', '/'])
        .map(str::to_ascii_lowercase)
        .collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(parts)
}

/// Whether `parts` is exactly `home` (`*` matching any one component).
fn matches_home(parts: &[String], home: &[&str]) -> bool {
    parts.len() == home.len()
        && parts
            .iter()
            .zip(home)
            .all(|(part, want)| *want == "*" || part == want)
}

/// Whether `name` (a `comm`) is one of [`LSASS_READERS`], with or without its `.exe`.
fn is_reader_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LSASS_READERS.iter().any(|(reader, _)| {
        *reader == lower
            || reader
                .strip_suffix(".exe")
                .is_some_and(|stem| stem == lower)
    })
}

/// Whether the caller of an LSASS open, whose full image is `image`, is one of the expected
/// readers: its file name is a reader's and it sits directly in one of that reader's
/// directories ([`LSASS_READERS`]). Only the full image decides: a `comm` is the file name
/// alone, which a renamed dumper chooses, so an unknown image is never a known reader
/// (#1152 review).
pub(crate) fn is_known_reader(image: &str) -> bool {
    let Some(parts) = components_below_drive(image) else {
        return false;
    };
    let Some((file, dir)) = parts.split_last() else {
        return false;
    };
    LSASS_READERS
        .iter()
        .any(|(reader, homes)| file == reader && homes.iter().any(|home| matches_home(dir, home)))
}

/// Whether `path` is the system's LSASS: exactly `<drive>:\Windows\System32\lsass.exe`. The
/// sensor confirms LSASS against `%SystemRoot%`, which the rule engine does not know; this
/// is the same claim with the default root, so an `lsass.exe` in a deeper `System32` (a
/// user-writable `spool\drivers\color`, #1152 review) is not LSASS.
pub(crate) fn is_lsass_path(path: &str) -> bool {
    components_below_drive(path).is_some_and(|parts| matches_home(&parts, LSASS_HOME))
}

/// `MAXIMUM_ALLOWED`.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The rights that reach a process's memory, by name: the set the sensor reports an open
/// of LSASS for (`sensor-windows`' `cross_process::MEMORY_RIGHTS`).
const MEMORY_RIGHTS: [(u32, &str); 10] = [
    (0x0010, "PROCESS_VM_READ"),
    (0x0020, "PROCESS_VM_WRITE"),
    (0x0008, "PROCESS_VM_OPERATION"),
    (0x0002, "PROCESS_CREATE_THREAD"),
    (0x0040, "PROCESS_DUP_HANDLE"),
    (0x0080, "PROCESS_CREATE_PROCESS"),
    (MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED"),
    (0x1000_0000, "GENERIC_ALL"),
    (0x4000_0000, "GENERIC_WRITE"),
    (0x8000_0000, "GENERIC_READ"),
];

/// The rights in an access mask that reach memory, by name, for the alert text.
fn memory_rights(mask: u32) -> String {
    let names: Vec<&str> = MEMORY_RIGHTS
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|&(_, name)| name)
        .collect();
    if names.is_empty() {
        "no memory right".to_string()
    } else {
        names.join("|")
    }
}

/// Whether `MAXIMUM_ALLOWED` is the mask's only right that reaches memory: what such an
/// open was granted is not in the event.
fn only_maximum_allowed(mask: u32) -> bool {
    let memory: u32 = MEMORY_RIGHTS
        .iter()
        .map(|(bit, _)| bit)
        .fold(0, |a, b| a | b);
    mask & memory == MAXIMUM_ALLOWED
}

/// LSASS-ACCESS, before deduplication: the alert an open of LSASS raises, or `None` when the
/// event is not an open of LSASS or the caller is an expected reader. `image` is the
/// caller's full image: the rule engine's exec-time one, else the event's
/// [`ProcessAccessEvent::caller_image_path`].
pub(crate) fn lsass_access_alert(event: &ProcessAccessEvent, image: Option<&str>) -> Option<Alert> {
    if !event
        .target_image_path
        .as_deref()
        .is_some_and(is_lsass_path)
    {
        return None;
    }
    let image = image.filter(|path| !path.is_empty());
    if image.is_some_and(is_known_reader) {
        return None;
    }
    let comm = event.meta.comm.as_str();
    let granted = event.status == 0;
    let mut notes = Vec::new();
    let severity = if image.is_none() && is_reader_name(comm) {
        notes.push("caller image unknown, name of an expected reader");
        Severity::Medium
    } else if !granted {
        Severity::Medium
    } else if only_maximum_allowed(event.desired_access) {
        notes.push("granted access unknown (MAXIMUM_ALLOWED)");
        Severity::Medium
    } else {
        Severity::High
    };
    let outcome = if granted {
        "granted".to_string()
    } else {
        format!("denied (status {:#010x})", event.status)
    };
    let from = match image {
        Some(path) => format!(" image={path}"),
        None => " image=unknown".to_string(),
    };
    let notes = if notes.is_empty() {
        String::new()
    } else {
        format!("; {}", notes.join("; "))
    };
    Some(Alert {
        technique: LSASS_ACCESS_TECHNIQUE,
        severity,
        message: format!(
            "pid={} comm={comm}{from}: opened LSASS (pid={}) with a right that reaches its memory, access {:#x} ({}), {outcome}{notes}",
            event.meta.pid,
            event.target_pid,
            event.desired_access,
            memory_rights(event.desired_access),
        ),
    })
}

/// LSASS-REMOTE-THREAD, before deduplication: a thread another process started inside LSASS
/// (T1055), High. No expected creator is known: the kernel's threads and LSASS's own never
/// reach this event, and the user-mode ways to run code in LSASS this way (a
/// `CreateRemoteThread` of a `LoadLibrary`, a reflective loader) are the injection itself.
/// An unknown owner image decides nothing. The start address is reported, never judged:
/// the creator chooses it.
pub(crate) fn lsass_remote_thread_alert(event: &RemoteThreadEvent) -> Option<Alert> {
    if !event
        .target_image_path
        .as_deref()
        .is_some_and(is_lsass_path)
    {
        return None;
    }
    Some(Alert {
        technique: LSASS_THREAD_TECHNIQUE,
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: started thread {} inside LSASS (pid={}) at {:#x}",
            event.meta.pid, event.meta.comm, event.thread_id, event.target_pid, event.start_address,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_system_lsass_path_is_lsass() {
        assert!(is_lsass_path(r"C:\Windows\System32\lsass.exe"));
        assert!(is_lsass_path(r"c:\windows\system32\LSASS.EXE"));
        assert!(is_lsass_path(r"D:\Windows\System32\lsass.exe"));
        for path in [
            r"C:\Users\Public\lsass.exe",
            r"C:\Windows\Temp\System32\lsass.exe",
            r"C:\Windows\System32\spool\drivers\color\System32\lsass.exe",
            r"C:\Windows\System32\..\..\Users\x\System32\lsass.exe",
            r"C:\Windows\SysWOW64\lsass.exe",
            r"C:\Program Files\Windows\System32\lsass.exe",
            r"System32\lsass.exe",
            r"\\server\share\Windows\System32\lsass.exe",
            "lsass.exe",
            "",
        ] {
            assert!(!is_lsass_path(path), "{path}");
        }
    }

    #[test]
    fn a_reader_name_matches_with_or_without_its_extension_in_any_case() {
        assert!(is_reader_name("MsMpEng.exe"));
        assert!(is_reader_name("msmpeng.EXE"));
        assert!(is_reader_name("MsMpEng"));
        assert!(!is_reader_name("MsMpEng.exe.exe"));
        assert!(!is_reader_name("procdump64.exe"));
        assert!(!is_reader_name(""));
    }

    #[test]
    fn each_reader_is_known_only_in_its_own_directory() {
        for image in [
            r"C:\Windows\System32\wininit.exe",
            r"C:\Windows\System32\csrss.exe",
            r"c:\windows\system32\CSRSS.EXE",
            r"C:\Program Files\Windows Defender\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
            r"d:/programdata/microsoft/windows defender/platform/4.18/MsMpEng.exe",
            r"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe",
        ] {
            assert!(is_known_reader(image), "{image}");
        }
        for image in [
            r"C:\Program Files\x\csrss.exe",
            r"C:\Program Files (x86)\Windows Defender\MsMpEng.exe",
            r"C:\Windows\System32\drivers\csrss.exe",
            r"C:\Windows\csrss.exe",
            r"C:\Windows\System32\MsMpEng.exe",
            r"C:\Program Files\Windows Defender\MsSense.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\..\..\..\..\Users\x\MsMpEng.exe",
            r"C:\Users\Public\MsMpEng.exe",
            "csrss.exe",
            "",
        ] {
            assert!(!is_known_reader(image), "{image}");
        }
    }

    #[test]
    fn memory_rights_names_each_right_of_the_mask_that_reaches_memory() {
        assert_eq!(memory_rights(0x1010), "PROCESS_VM_READ");
        assert_eq!(
            memory_rights(0x1F_FFFF),
            "PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD|PROCESS_DUP_HANDLE|PROCESS_CREATE_PROCESS"
        );
        assert_eq!(memory_rights(0x0200_0000), "MAXIMUM_ALLOWED");
        assert_eq!(memory_rights(0x9000_0000), "GENERIC_ALL|GENERIC_READ");
        assert_eq!(memory_rights(0x1040), "PROCESS_DUP_HANDLE");
        assert_eq!(memory_rights(0x1000), "no memory right");
    }

    #[test]
    fn maximum_allowed_alone_is_told_from_a_mask_with_a_named_right() {
        assert!(only_maximum_allowed(MAXIMUM_ALLOWED));
        assert!(only_maximum_allowed(MAXIMUM_ALLOWED | 0x1000));
        assert!(!only_maximum_allowed(MAXIMUM_ALLOWED | 0x0010));
        assert!(!only_maximum_allowed(0x0010));
    }
}
