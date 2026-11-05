//! LSASS-ACCESS and LSASS-REMOTE-THREAD (#960): credential dumping from LSASS memory
//! (T1003.001) and a thread started inside LSASS by another process (T1055), over the
//! driver-free Windows telemetry of #720 ([`schema::ProcessAccessEvent`],
//! [`schema::RemoteThreadEvent`]).
//!
//! The sensor already narrows both: a `ProcessAccessEvent` is an open of the system's LSASS
//! (confirmed by its full path) from another user process asking for a right that reads its
//! memory, denied opens included; a `RemoteThreadEvent` is a thread whose creator is not the
//! process that owns it, minus the kernel's and the initial thread of a new process. What is
//! left to decide here is who is allowed to read LSASS, and how loud the rest is.
//!
//! The access mask does not grade the alert. Mimikatz's `sekurlsa` asks for the smallest mask
//! that reads memory (`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, `0x1010`), the
//! same shape as a process viewer, while a `MiniDumpWriteDump` dumper asks for more; a larger
//! mask is not a worse intent. What does grade it is the outcome: a granted open has read
//! access to the credentials, a denied one (a `RunAsPPL` LSASS refusing an unprotected
//! caller) is an attempt that failed.
//!
//! Not calibrated: no capture of who opens LSASS for reading on a real fleet exists yet (#715
//! measured volumes, not callers), so the reader list below is the documented one, kept short
//! on purpose, and is where an operator's measurement will add to it.

use schema::{ProcessAccessEvent, RemoteThreadEvent, detection::Severity};

use crate::Alert;

/// Named constants, not literals inside a `match`: `tools/attack-coverage.py` reads a
/// technique from a `technique` field or from a string constant of this shape.
const LSASS_ACCESS_TECHNIQUE: &str = "T1003.001";
const LSASS_THREAD_TECHNIQUE: &str = "T1055";

/// One LSASS-ACCESS alert per (caller pid, outcome) per window: the sensor already folds an
/// identical open (caller, mask, status) into one per minute, but a dumper that tries several
/// masks, or retries, is one finding.
pub(crate) const LSASS_ACCESS_ALERT_WINDOW_NS: u64 = 300_000_000_000; // 5 min

/// Readers of LSASS memory that are part of the operating system or of its built-in
/// antivirus, by image basename (compared case-insensitively). Each is excluded only with
/// evidence ([`is_known_reader`]): a known exec-time image must sit at a trusted system path,
/// or, for Defender, in its platform directory.
///
/// - `wininit.exe`: starts LSASS and supervises it for the session's lifetime.
/// - `csrss.exe`: the Win32 subsystem server, which holds a handle to every Win32 process.
/// - `MsMpEng.exe`: the Defender engine, which scans process memory, LSASS included.
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
const LSASS_READERS: &[&str] = &["wininit.exe", "csrss.exe", "MsMpEng.exe", "MsSense.exe"];

/// Defender's platform directory below the drive root (lowercase, `\`-separated): where
/// `MsMpEng.exe` lives once Defender has updated itself, outside `Program Files`. Only
/// `SYSTEM` and `TrustedInstaller` can write there, which is the evidence a trusted system
/// path gives elsewhere.
const DEFENDER_PLATFORM_DIR: &str = r"\programdata\microsoft\windows defender\platform\";

/// The image's file name, `\` or `/` separated.
fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Whether `name` (a basename or a `comm`) is one of [`LSASS_READERS`], with or without its
/// `.exe`.
fn is_reader_name(name: &str) -> bool {
    LSASS_READERS.iter().any(|reader| {
        reader.eq_ignore_ascii_case(name)
            || reader
                .strip_suffix(".exe")
                .is_some_and(|stem| stem.eq_ignore_ascii_case(name))
    })
}

/// Whether `path` is under Defender's platform directory on some drive.
fn in_defender_platform(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    lower.as_bytes().get(1) == Some(&b':')
        && lower[2..].starts_with(DEFENDER_PLATFORM_DIR)
        && !lower.split('\\').any(|part| part == "..")
}

/// Whether the caller of an LSASS open is one of the expected readers.
///
/// `image` is the caller's exec-time image when the rule engine saw its exec. A known image
/// decides alone: its basename must be a reader and it must sit at a trusted system path
/// (`policy::name_exclusion_applies`) or in Defender's platform directory, so a renamed
/// `MsMpEng.exe` in a user directory is not excluded, whatever its `comm`. With no known
/// image (a process that predates the agent, which is the usual case for these long-lived
/// readers) the sensor's `comm` is all there is, and the exclusion applies on it: a sensor
/// limitation is not evidence of masquerade. Carrying the caller's image in the event would
/// close that gap; the sensor's pid store has it.
pub(crate) fn is_known_reader(comm: &str, image: Option<&str>) -> bool {
    match image {
        Some(path) if !path.is_empty() => {
            is_reader_name(basename(path))
                && (policy::name_exclusion_applies(Some(path)) || in_defender_platform(path))
        }
        _ => is_reader_name(comm),
    }
}

/// Whether `path` is the system's LSASS: `lsass.exe` directly in a `System32` directory at a
/// trusted system path. The sensor confirms LSASS against `%SystemRoot%`, which the rule
/// engine does not know; this is the same claim without the root.
pub(crate) fn is_lsass_path(path: &str) -> bool {
    let mut parts = path.rsplit(['\\', '/']);
    let file = parts.next().unwrap_or_default();
    let dir = parts.next().unwrap_or_default();
    file.eq_ignore_ascii_case("lsass.exe")
        && dir.eq_ignore_ascii_case("system32")
        && !path.split(['\\', '/']).any(|part| part == "..")
        && path.as_bytes().get(1) == Some(&b':')
        && policy::name_exclusion_applies(Some(path))
}

/// The rights in an access mask that make it a memory read, by name, for the alert text.
fn read_rights(mask: u32) -> String {
    const RIGHTS: [(u32, &str); 4] = [
        (0x0010, "PROCESS_VM_READ"),
        (0x0200_0000, "MAXIMUM_ALLOWED"),
        (0x1000_0000, "GENERIC_ALL"),
        (0x8000_0000, "GENERIC_READ"),
    ];
    let names: Vec<&str> = RIGHTS
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|&(_, name)| name)
        .collect();
    if names.is_empty() {
        "no memory-read right".to_string()
    } else {
        names.join("|")
    }
}

/// LSASS-ACCESS, before deduplication: the alert an open of LSASS raises, or `None` when the
/// event is not an open of LSASS or the caller is an expected reader. `image` as in
/// [`is_known_reader`].
pub(crate) fn lsass_access_alert(event: &ProcessAccessEvent, image: Option<&str>) -> Option<Alert> {
    if !event
        .target_image_path
        .as_deref()
        .is_some_and(is_lsass_path)
    {
        return None;
    }
    let comm = event.meta.comm.as_str();
    if is_known_reader(comm, image) {
        return None;
    }
    let granted = event.status == 0;
    let outcome = if granted {
        "granted".to_string()
    } else {
        format!("denied (status {:#010x})", event.status)
    };
    let from = match image {
        Some(path) if !path.is_empty() => format!(" image={path}"),
        _ => String::new(),
    };
    Some(Alert {
        technique: LSASS_ACCESS_TECHNIQUE,
        severity: if granted {
            Severity::High
        } else {
            Severity::Medium
        },
        message: format!(
            "pid={} comm={comm}{from}: opened LSASS (pid={}) for reading its memory, access {:#x} ({}), {outcome}",
            event.meta.pid,
            event.target_pid,
            event.desired_access,
            read_rights(event.desired_access),
        ),
    })
}

/// LSASS-REMOTE-THREAD: a thread another process started inside LSASS (T1055), High. No
/// expected creator is known: the kernel's threads and LSASS's own never reach this event,
/// and the user-mode ways to run code in LSASS this way (a `CreateRemoteThread` of a
/// `LoadLibrary`, a reflective loader) are the injection itself. An unknown owner image
/// decides nothing.
#[must_use]
pub fn evaluate_remote_thread(event: &RemoteThreadEvent) -> Vec<Alert> {
    if !event
        .target_image_path
        .as_deref()
        .is_some_and(is_lsass_path)
    {
        return Vec::new();
    }
    vec![Alert {
        technique: LSASS_THREAD_TECHNIQUE,
        severity: Severity::High,
        message: format!(
            "pid={} comm={}: started thread {} inside LSASS (pid={}) at {:#x}",
            event.meta.pid, event.meta.comm, event.thread_id, event.target_pid, event.start_address,
        ),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_lsass_is_recognized_and_a_copy_elsewhere_is_not() {
        assert!(is_lsass_path(r"C:\Windows\System32\lsass.exe"));
        assert!(is_lsass_path(r"c:\windows\system32\LSASS.EXE"));
        assert!(is_lsass_path(r"D:\Windows\System32\lsass.exe"));
        for path in [
            r"C:\Users\Public\lsass.exe",
            r"C:\Windows\Temp\System32\lsass.exe",
            r"C:\Windows\System32\..\..\Users\x\System32\lsass.exe",
            r"C:\Windows\SysWOW64\lsass.exe",
            r"System32\lsass.exe",
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
    fn defender_platform_directory_is_recognized_on_any_drive_but_not_through_dot_dot() {
        assert!(in_defender_platform(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"
        ));
        assert!(in_defender_platform(
            r"d:/programdata/microsoft/windows defender/platform/4.18/MsMpEng.exe"
        ));
        assert!(!in_defender_platform(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\..\..\..\..\Users\x\MsMpEng.exe"
        ));
        assert!(!in_defender_platform(r"C:\ProgramData\MsMpEng.exe"));
    }

    #[test]
    fn read_rights_names_each_memory_read_right_of_the_mask() {
        assert_eq!(read_rights(0x1010), "PROCESS_VM_READ");
        assert_eq!(read_rights(0x1F_FFFF), "PROCESS_VM_READ");
        assert_eq!(read_rights(0x0200_0000), "MAXIMUM_ALLOWED");
        assert_eq!(read_rights(0x9000_0000), "GENERIC_ALL|GENERIC_READ");
        assert_eq!(read_rights(0x1000), "no memory-read right");
    }
}
