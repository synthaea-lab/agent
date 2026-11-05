//! Cross-process telemetry from driver-free providers (#720, ADR-0026 follow-up 6): a thread
//! started in another process (Kernel-Process `ThreadStart`, the native Sysmon 8) and a
//! memory-reading open of LSASS (Kernel-Audit-API-Calls `PsOpenProcess`, the native Sysmon 10).
//!
//! The decisions are here, apart from the ETW callbacks, so they can be tested without a
//! session. The lab capture behind them (#715, Windows 11 build 26300, one host): 55 to 71
//! thread starts per second, 22 % of them cross-process before the exclusions below and
//! about 2 % (1 to 2 per second) after them; 280 to 330 process opens per second, about half
//! of them with `PROCESS_VM_READ`, so the open filter keys on the target first.

use std::collections::HashMap;

/// Processes whose initial thread is still expected, and initial threads seen before their
/// process's start. Each map holds at most this many pids.
const ORIGINS_CAP: usize = 4_096;
/// How long a process start waits for its initial thread, and an early thread for its
/// process start. The two records of one creation are milliseconds apart; a minute covers
/// ETW buffer-flush jitter many times over.
const ORIGINS_WINDOW_NS: u64 = 60_000_000_000;

/// The pids the kernel uses for itself: the idle process and `System`. A thread that one
/// of them starts in a user process is the kernel's (a worker, an APC delivery), not a
/// user-mode injection, which is what Sysmon 8 reports.
const KERNEL_PIDS: [u32; 2] = [0, 4];

/// What a `ThreadStart` is, as far as injection goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadOrigin {
    /// Started by the process that owns it: the ordinary case.
    OwnProcess,
    /// Started by the kernel (pid 0 or 4).
    Kernel,
    /// The first thread of a new process, which its creator starts as part of creating it.
    /// The creation is already reported as an exec.
    Initial,
    /// Started by another user process: what [`schema::RemoteThreadEvent`] reports.
    Remote,
}

/// Tells the initial thread of a new process from a thread injected into it, whichever of
/// `ProcessStart` and the initial `ThreadStart` the session delivers first.
///
/// The first thread of a process is started by its creator, so it looks cross-process
/// (#715: most of the raw 22 %). It is recognized by pairing: a `ProcessStart` leaves its
/// pid waiting for one initial thread, and the first cross-process thread of that pid is
/// that one. When the thread arrives first, the owner is a pid the sensor has never heard
/// of (its start is still in flight); that thread is taken as the initial one and remembered,
/// so the start that follows does not wait for a second one. A process that existed before
/// the trace is never waiting, so every cross-process thread into it is remote.
///
/// The cost of the second rule: a thread injected into a process the pid store lost (its
/// `ProcessStart` dropped under buffer pressure, or evicted) passes as initial once. Both
/// maps are bounded; what they forget is counted.
#[derive(Debug, Default)]
pub(crate) struct ThreadOrigins {
    /// pid → `ProcessStart` time, until its initial thread.
    awaiting: HashMap<u32, u64>,
    /// pid → time of an initial thread seen before its `ProcessStart`.
    early: HashMap<u32, u64>,
    /// Live entries dropped because a map was full of them: each is a process whose
    /// initial thread will now be reported as remote (or an early thread whose start will
    /// wait in vain). Volume, never a missed injection.
    pub(crate) forgotten: u64,
}

impl ThreadOrigins {
    /// A `ProcessStart` for `pid`.
    pub(crate) fn process_started(&mut self, pid: u32, now_ns: u64) {
        if self.early.remove(&pid).is_some() {
            return;
        }
        insert_bounded(&mut self.awaiting, pid, now_ns, &mut self.forgotten);
    }

    /// A `ProcessStop` for `pid`: whatever was waiting for it is over.
    pub(crate) fn process_ended(&mut self, pid: u32) {
        self.awaiting.remove(&pid);
        self.early.remove(&pid);
    }

    /// Classifies a `ThreadStart` of a thread owned by `owner`, started by `creator`.
    /// `owner_known` is asked only for a cross-process thread whose owner is not waiting
    /// for its initial thread: whether the sensor already knows that process (the pid
    /// store), which tells an injection into it from an initial thread that came early.
    pub(crate) fn classify(
        &mut self,
        creator: u32,
        owner: u32,
        now_ns: u64,
        owner_known: impl FnOnce() -> bool,
    ) -> ThreadOrigin {
        if creator == owner {
            return ThreadOrigin::OwnProcess;
        }
        if KERNEL_PIDS.contains(&creator) {
            return ThreadOrigin::Kernel;
        }
        if self
            .awaiting
            .remove(&owner)
            .is_some_and(|started| now_ns.saturating_sub(started) < ORIGINS_WINDOW_NS)
        {
            return ThreadOrigin::Initial;
        }
        if owner_known() {
            return ThreadOrigin::Remote;
        }
        insert_bounded(&mut self.early, owner, now_ns, &mut self.forgotten);
        ThreadOrigin::Initial
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.awaiting.len() + self.early.len()
    }
}

/// Inserts `pid`, first dropping the entries older than the window when the map is full,
/// then, if it is still full of live ones, all of them (counted in `forgotten`).
fn insert_bounded(map: &mut HashMap<u32, u64>, pid: u32, now_ns: u64, forgotten: &mut u64) {
    if map.len() >= ORIGINS_CAP && !map.contains_key(&pid) {
        map.retain(|_, at| now_ns.saturating_sub(*at) < ORIGINS_WINDOW_NS);
        if map.len() >= ORIGINS_CAP {
            *forgotten += map.len() as u64;
            tracing::warn!(
                forgotten = *forgotten,
                cap = ORIGINS_CAP,
                "thread-origin map full of live processes: their initial threads may be reported as remote"
            );
            map.clear();
        }
    }
    map.insert(pid, now_ns);
}

/// The start address a [`schema::RemoteThreadEvent`] reports: the user-mode one
/// (`Win32StartAddr`, the routine `CreateRemoteThread` was given), else the kernel's
/// (`StartAddr`).
pub(crate) fn start_address(win32_start: u64, start: u64) -> u64 {
    if win32_start == 0 { start } else { win32_start }
}

/// `PROCESS_VM_READ`.
const PROCESS_VM_READ: u32 = 0x0010;
/// `MAXIMUM_ALLOWED`: whatever the caller may have, `PROCESS_VM_READ` included.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// `GENERIC_ALL`: maps to `PROCESS_ALL_ACCESS`.
const GENERIC_ALL: u32 = 0x1000_0000;
/// `GENERIC_READ`: maps to `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` for a process.
const GENERIC_READ: u32 = 0x8000_0000;

/// Whether an open asking for `desired_access` can read the target's memory. The event
/// carries the mask as passed, before generic rights are mapped, so the generic and
/// maximum rights that include `PROCESS_VM_READ` count too.
pub(crate) fn reads_memory(desired_access: u32) -> bool {
    desired_access & (PROCESS_VM_READ | MAXIMUM_ALLOWED | GENERIC_ALL | GENERIC_READ) != 0
}

/// Whether an open of LSASS by `caller` is worth reporting: not LSASS opening itself, not
/// the kernel, and a right that reads memory.
pub(crate) fn lsass_open_is_reported(caller: u32, lsass: u32, desired_access: u32) -> bool {
    caller != lsass && !KERNEL_PIDS.contains(&caller) && reads_memory(desired_access)
}

/// LSASS's image under `system_root`: `<system root>\System32\lsass.exe`.
pub(crate) fn lsass_image(system_root: &str) -> String {
    format!(r"{}\System32\lsass.exe", system_root.trim_end_matches('\\'))
}

/// Whether `image_path` is the system's LSASS, [`lsass_image`] (case-insensitive). Only
/// that path: an `lsass.exe` elsewhere is not the process that holds the credentials, and
/// picking it would leave the real one unwatched.
pub(crate) fn is_lsass_image(image_path: &str, system_root: &str) -> bool {
    !system_root.trim_end_matches('\\').is_empty()
        && image_path.eq_ignore_ascii_case(&lsass_image(system_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;
    const CREATOR: u32 = 100;
    const CHILD: u32 = 200;

    fn known() -> bool {
        true
    }

    fn unknown() -> bool {
        false
    }

    #[test]
    fn a_thread_started_by_its_own_process_is_not_remote() {
        let mut origins = ThreadOrigins::default();
        assert_eq!(
            origins.classify(CHILD, CHILD, 0, known),
            ThreadOrigin::OwnProcess
        );
    }

    #[test]
    fn a_thread_the_kernel_starts_is_not_remote() {
        let mut origins = ThreadOrigins::default();
        for kernel in KERNEL_PIDS {
            assert_eq!(
                origins.classify(kernel, CHILD, 0, known),
                ThreadOrigin::Kernel
            );
        }
    }

    #[test]
    fn the_initial_thread_after_its_process_start_is_not_remote_but_the_next_one_is() {
        let mut origins = ThreadOrigins::default();
        origins.process_started(CHILD, 0);
        assert_eq!(
            origins.classify(CREATOR, CHILD, SEC, known),
            ThreadOrigin::Initial
        );
        assert_eq!(
            origins.classify(CREATOR, CHILD, 2 * SEC, known),
            ThreadOrigin::Remote,
            "a second thread from the creator is an injection into its child"
        );
    }

    #[test]
    fn an_initial_thread_before_its_process_start_is_not_remote_and_the_start_waits_for_no_other() {
        let mut origins = ThreadOrigins::default();
        assert_eq!(
            origins.classify(CREATOR, CHILD, 0, unknown),
            ThreadOrigin::Initial
        );
        origins.process_started(CHILD, SEC);
        assert_eq!(
            origins.classify(CREATOR, CHILD, 2 * SEC, known),
            ThreadOrigin::Remote,
            "the start found its early thread, so it does not excuse a later one"
        );
        assert_eq!(origins.tracked(), 0);
    }

    #[test]
    fn a_thread_into_a_process_that_predates_the_trace_is_remote() {
        let mut origins = ThreadOrigins::default();
        assert_eq!(
            origins.classify(CREATOR, CHILD, 0, known),
            ThreadOrigin::Remote
        );
    }

    #[test]
    fn a_process_start_whose_initial_thread_never_came_does_not_excuse_a_late_injection() {
        let mut origins = ThreadOrigins::default();
        origins.process_started(CHILD, 0);
        assert_eq!(
            origins.classify(CREATOR, CHILD, ORIGINS_WINDOW_NS, known),
            ThreadOrigin::Remote
        );
    }

    #[test]
    fn a_process_end_clears_what_waited_for_it() {
        let mut origins = ThreadOrigins::default();
        origins.process_started(CHILD, 0);
        origins.classify(CREATOR, 300, 0, unknown);
        origins.process_ended(CHILD);
        origins.process_ended(300);
        assert_eq!(origins.tracked(), 0);
        // A recycled pid starts afresh.
        assert_eq!(
            origins.classify(CREATOR, CHILD, SEC, known),
            ThreadOrigin::Remote
        );
    }

    #[test]
    fn the_maps_stay_bounded_and_count_what_they_forget() {
        let mut origins = ThreadOrigins::default();
        for pid in 0..(ORIGINS_CAP as u32 * 2) {
            origins.process_started(pid + 1_000, 0);
        }
        assert!(origins.tracked() <= ORIGINS_CAP);
        assert_eq!(origins.forgotten, ORIGINS_CAP as u64);
    }

    #[test]
    fn expired_entries_are_dropped_before_live_ones_and_not_counted() {
        let mut origins = ThreadOrigins::default();
        for pid in 0..ORIGINS_CAP as u32 {
            origins.process_started(pid + 1_000, 0);
        }
        origins.process_started(1, ORIGINS_WINDOW_NS);
        assert_eq!(origins.forgotten, 0);
        assert_eq!(origins.tracked(), 1);
    }

    #[test]
    fn the_user_mode_start_address_is_preferred() {
        assert_eq!(start_address(0x7ff0, 0x1000), 0x7ff0);
        assert_eq!(start_address(0, 0x1000), 0x1000);
    }

    #[test]
    fn rights_that_read_memory_are_recognized_as_passed() {
        assert!(reads_memory(0x0010), "PROCESS_VM_READ");
        assert!(reads_memory(0x1410), "a dumper's usual mask");
        assert!(reads_memory(0x001F_FFFF), "PROCESS_ALL_ACCESS");
        assert!(reads_memory(MAXIMUM_ALLOWED));
        assert!(reads_memory(GENERIC_ALL));
        assert!(reads_memory(GENERIC_READ));
        assert!(!reads_memory(0x1000), "PROCESS_QUERY_LIMITED_INFORMATION");
        assert!(
            !reads_memory(0x0400 | 0x0100_0000),
            "query + ACCESS_SYSTEM_SECURITY"
        );
        assert!(!reads_memory(0x0001), "PROCESS_TERMINATE");
    }

    #[test]
    fn an_lsass_open_is_reported_only_from_another_user_process_with_a_read_right() {
        const LSASS: u32 = 812;
        assert!(lsass_open_is_reported(4242, LSASS, 0x1410));
        assert!(!lsass_open_is_reported(4242, LSASS, 0x1000));
        assert!(!lsass_open_is_reported(LSASS, LSASS, 0x1410));
        assert!(!lsass_open_is_reported(4, LSASS, 0x1410));
        assert!(!lsass_open_is_reported(0, LSASS, 0x1410));
    }

    #[test]
    fn only_the_system_lsass_is_lsass() {
        let root = r"C:\Windows";
        assert!(is_lsass_image(r"C:\Windows\System32\lsass.exe", root));
        assert!(is_lsass_image(r"c:\windows\system32\LSASS.EXE", root));
        assert!(is_lsass_image(
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\"
        ));
        assert!(!is_lsass_image(r"C:\Users\Public\lsass.exe", root));
        assert!(!is_lsass_image(r"C:\Windows\SysWOW64\lsass.exe", root));
        assert!(!is_lsass_image(r"D:\Windows\System32\lsass.exe", root));
        assert!(!is_lsass_image(r"C:\Windows\System32\lsass.exe.bak", root));
        assert!(!is_lsass_image(r"C:\Windows\System32\lsass.exe", ""));
        assert!(!is_lsass_image("lsass.exe", root));
        assert!(!is_lsass_image(
            "C:\\Wind\u{e9}ws\\System32\\lsass.exe",
            root
        ));
        assert_eq!(
            lsass_image(r"C:\Windows\"),
            r"C:\Windows\System32\lsass.exe"
        );
    }
}
