//! Cross-process telemetry from driver-free providers (<https://github.com/synthaea-lab/edr-agent/issues/41>, ADR-0026 follow-up 6): a thread
//! started in another process (Kernel-Process `ThreadStart`, the native Sysmon 8) and a
//! memory-reading open of LSASS (Kernel-Audit-API-Calls `PsOpenProcess`, the native Sysmon 10).
//!
//! The decisions are here, apart from the ETW callbacks, so they can be tested without a
//! session. The lab capture behind them (#715, Windows 11 build 26300, one host): 55 to 71
//! thread starts per second, 22 % of them cross-process before the exclusions below and
//! about 2 % (1 to 2 per second) after them; 280 to 330 process opens per second, about half
//! of them with `PROCESS_VM_READ`, so the open filter keys on the target first.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU32, Ordering},
};

/// Processes whose initial thread is still expected, and initial threads seen before their
/// process's start. Each map holds at most this many pids.
const ORIGINS_CAP: usize = 4_096;
/// How long a process start is remembered for its initial thread, and an early thread for
/// its process start. The two records of one creation are milliseconds apart; a minute
/// covers ETW buffer-flush jitter many times over.
pub(crate) const ORIGINS_WINDOW_NS: u64 = 60_000_000_000;

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

/// A `ProcessStart` the session delivered, until the window closes.
#[derive(Debug, Clone, Copy)]
struct Start {
    at_ns: u64,
    /// Whether the process's initial thread has been seen: every later cross-process
    /// thread is then remote.
    initial_seen: bool,
}

/// Tells the initial thread of a new process from a thread injected into it, whichever of
/// `ProcessStart` and the initial `ThreadStart` the session delivers first.
///
/// The first thread of a process is started by its creator, so it looks cross-process
/// (#715: most of the raw 22 %). It is recognized by pairing:
/// - a `ProcessStart` is remembered for [`ORIGINS_WINDOW_NS`]; the first cross-process (or
///   kernel) thread of that pid inside the window is its initial thread, and every later
///   one is remote, whatever the pid store remembers of the process;
/// - a thread whose owner has no remembered start and did not exist before the window
///   (`owner_predates`, asked of the caller: the pid store, then the process's creation
///   time) is taken as the initial thread of a process whose start is still in flight,
///   **once**: a second such thread is remote, and the start that follows does not wait
///   for another;
/// - a process that existed before the trace, or before the window, never has an initial
///   thread to excuse, so every cross-process thread into it is remote.
///
/// So the pid store's LRU eviction does not decide the classification on its own: an owner
/// whose start was seen is judged on that start, and an owner the store lost is judged on
/// its creation time. What is left (#1150 review): a process that started within the window,
/// whose `ProcessStart` was lost or forgotten, and that is evicted from the pid store,
/// excuses one injected thread. Both maps are bounded; what they forget is counted.
#[derive(Debug, Default)]
pub(crate) struct ThreadOrigins {
    /// pid → its `ProcessStart`, for the window.
    started: HashMap<u32, Start>,
    /// pid → time of an initial thread seen before its `ProcessStart`.
    early: HashMap<u32, u64>,
    /// Live entries dropped because a map was full of them: each is a process whose
    /// initial thread may now be reported as remote (or an early thread whose start will
    /// not find it). Volume, and in the worst case one excused thread (see above).
    pub(crate) forgotten: u64,
}

impl ThreadOrigins {
    /// A `ProcessStart` for `pid`. An early initial thread younger than the window is
    /// its own; an older one belonged to a previous process on a recycled pid whose
    /// `ProcessStop` was lost, and is dropped.
    pub(crate) fn process_started(&mut self, pid: u32, now_ns: u64) {
        let initial_seen = self.early.remove(&pid).is_some_and(|at| fresh(at, now_ns));
        insert_bounded(
            &mut self.started,
            pid,
            Start {
                at_ns: now_ns,
                initial_seen,
            },
            now_ns,
            |start| start.at_ns,
            &mut self.forgotten,
        );
    }

    /// A `ProcessStop` for `pid`: whatever was remembered of it is over.
    pub(crate) fn process_ended(&mut self, pid: u32) {
        self.started.remove(&pid);
        self.early.remove(&pid);
    }

    /// Classifies a `ThreadStart` of a thread owned by `owner`, started by `creator`.
    /// `owner_predates` is asked only for a cross-process thread whose owner has no
    /// remembered start: whether the owner existed before the window (the pid store knows
    /// it, or its creation time is older), which tells an injection into it from an
    /// initial thread that came early.
    pub(crate) fn classify(
        &mut self,
        creator: u32,
        owner: u32,
        now_ns: u64,
        owner_predates: impl FnOnce() -> bool,
    ) -> ThreadOrigin {
        if creator == owner {
            return ThreadOrigin::OwnProcess;
        }
        let kernel = KERNEL_PIDS.contains(&creator);
        match self.started.get_mut(&owner) {
            Some(start) if fresh(start.at_ns, now_ns) => {
                let initial = !start.initial_seen;
                // A process whose initial thread the kernel started has had its initial
                // thread: the next user-mode one is an injection (#1150 review).
                start.initial_seen = true;
                return if kernel {
                    ThreadOrigin::Kernel
                } else if initial {
                    ThreadOrigin::Initial
                } else {
                    ThreadOrigin::Remote
                };
            }
            Some(_) => {
                self.started.remove(&owner);
            }
            None => {}
        }
        if kernel {
            return ThreadOrigin::Kernel;
        }
        if owner_predates() || self.early.contains_key(&owner) {
            return ThreadOrigin::Remote;
        }
        insert_bounded(
            &mut self.early,
            owner,
            now_ns,
            now_ns,
            |at| *at,
            &mut self.forgotten,
        );
        ThreadOrigin::Initial
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.started.len() + self.early.len()
    }
}

/// Whether something recorded at `at_ns` is still inside the window at `now_ns`.
fn fresh(at_ns: u64, now_ns: u64) -> bool {
    now_ns.saturating_sub(at_ns) < ORIGINS_WINDOW_NS
}

/// Whether a process created at `created_ns` existed before the window that would let a
/// thread at `now_ns` be its initial one ([`ThreadOrigins::classify`]'s `owner_predates`).
pub(crate) fn created_before_window(created_ns: u64, now_ns: u64) -> bool {
    !fresh(created_ns, now_ns)
}

/// Inserts `pid`, first dropping the entries older than the window when the map is full,
/// then, if it is still full of live ones, all of them (counted in `forgotten`).
fn insert_bounded<V>(
    map: &mut HashMap<u32, V>,
    pid: u32,
    value: V,
    now_ns: u64,
    at: impl Fn(&V) -> u64,
    forgotten: &mut u64,
) {
    if map.len() >= ORIGINS_CAP && !map.contains_key(&pid) {
        map.retain(|_, entry| fresh(at(entry), now_ns));
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
    map.insert(pid, value);
}

/// The start address a [`schema::RemoteThreadEvent`] reports: the user-mode one
/// (`Win32StartAddr`, the routine `CreateRemoteThread` was given), else the kernel's
/// (`StartAddr`).
pub(crate) fn start_address(win32_start: u64, start: u64) -> u64 {
    if win32_start == 0 { start } else { win32_start }
}

/// Start addresses of one (creator, owner) pair are deduplicated per 64 KiB: a harmless
/// first thread (`Sleep` in `kernel32`) then does not hide the shellcode thread that
/// follows it at another address (#1150 review), while one injector re-running the same
/// routine stays one fact.
const START_BUCKET_SHIFT: u32 = 16;

/// The dedup key of a remote thread: creator, owner and start-address bucket.
pub(crate) fn remote_thread_key(creator: u32, owner: u32, start_address: u64) -> String {
    format!(
        "{creator}>{owner}>{:x}",
        start_address >> START_BUCKET_SHIFT
    )
}

/// Whether a remote thread is reported: its key not seen within the dedup window, and the
/// creator's budget not spent — except for a thread into LSASS, which the budget never
/// drops. The key is recorded only for a thread that is reported, so an injector that
/// spends its own budget on decoys (#1150 review) does not also silence the pair it
/// was refused on.
pub(crate) fn admit_remote_thread(
    dedup: &mut crate::budget::KeyDedup,
    budget: &mut crate::budget::PidBudget,
    key: &str,
    creator: u32,
    into_lsass: bool,
    now_ns: u64,
) -> bool {
    if dedup.is_repeat(key, now_ns) {
        return false;
    }
    if !into_lsass && !budget.spend(creator, now_ns) {
        return false;
    }
    dedup.record(key, now_ns);
    true
}

/// `PROCESS_CREATE_THREAD`: start a thread in the target (with `PROCESS_VM_WRITE` and
/// `PROCESS_VM_OPERATION`, the injection set).
const PROCESS_CREATE_THREAD: u32 = 0x0002;
/// `PROCESS_VM_OPERATION`: change the target's memory protection or allocate in it.
const PROCESS_VM_OPERATION: u32 = 0x0008;
/// `PROCESS_VM_READ`.
const PROCESS_VM_READ: u32 = 0x0010;
/// `PROCESS_VM_WRITE`.
const PROCESS_VM_WRITE: u32 = 0x0020;
/// `PROCESS_DUP_HANDLE`: duplicate the target's own pseudo-handle out of it, which yields
/// a full-access handle with no further `PsOpenProcess` (#1150 review).
const PROCESS_DUP_HANDLE: u32 = 0x0040;
/// `PROCESS_CREATE_PROCESS`: clone the target (`NtCreateProcessEx` with it as parent, or a
/// process snapshot) and read the clone, whose pid is not the target's (#1150 review).
const PROCESS_CREATE_PROCESS: u32 = 0x0080;
/// `MAXIMUM_ALLOWED`: whatever the caller may have, `PROCESS_VM_READ` included.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// `GENERIC_ALL`: maps to `PROCESS_ALL_ACCESS`.
const GENERIC_ALL: u32 = 0x1000_0000;
/// `GENERIC_WRITE`: maps to `PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS |
/// PROCESS_VM_OPERATION | PROCESS_VM_WRITE | ...` for a process.
const GENERIC_WRITE: u32 = 0x4000_0000;
/// `GENERIC_READ`: maps to `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` for a process.
const GENERIC_READ: u32 = 0x8000_0000;

/// The rights that reach the target's memory, directly or in one step: read it, write it
/// or run code in it, hand out a full handle to it, or clone it. The event carries the
/// mask as passed, before generic rights are mapped, so the generic and maximum rights
/// that include one of them count too.
pub(crate) const MEMORY_RIGHTS: u32 = PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_DUP_HANDLE
    | PROCESS_CREATE_PROCESS
    | MAXIMUM_ALLOWED
    | GENERIC_ALL
    | GENERIC_WRITE
    | GENERIC_READ;

/// Whether an open asking for `desired_access` can reach the target's memory
/// ([`MEMORY_RIGHTS`]).
pub(crate) fn reaches_memory(desired_access: u32) -> bool {
    desired_access & MEMORY_RIGHTS != 0
}

/// Whether an open of LSASS by `caller` is worth reporting: not LSASS opening itself, not
/// the kernel, and a right that reaches memory.
pub(crate) fn lsass_open_is_reported(caller: u32, lsass: u32, desired_access: u32) -> bool {
    caller != lsass && !KERNEL_PIDS.contains(&caller) && reaches_memory(desired_access)
}

/// `<system root>\System32\<name>`.
fn system32_image(system_root: &str, name: &str) -> String {
    format!(r"{}\System32\{name}", system_root.trim_end_matches('\\'))
}

/// LSASS's image under `system_root`: `<system root>\System32\lsass.exe`.
pub(crate) fn lsass_image(system_root: &str) -> String {
    system32_image(system_root, "lsass.exe")
}

/// Whether `image_path` is the system's LSASS image, [`lsass_image`] (case-insensitive).
/// Necessary, not sufficient: anyone can start a copy of that file
/// ([`is_system_lsass`]).
pub(crate) fn is_lsass_image(image_path: &str, system_root: &str) -> bool {
    !system_root.trim_end_matches('\\').is_empty()
        && image_path.eq_ignore_ascii_case(&lsass_image(system_root))
}

/// What the sensor knows of a process whose image is [`lsass_image`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct LsassClaim<'a> {
    /// The process's image path.
    pub(crate) image_path: &'a str,
    /// Its session, `None` when unknown.
    pub(crate) session_id: Option<u32>,
    /// Its parent's image path, `None` when unknown.
    pub(crate) parent_image_path: Option<&'a str>,
}

/// Whether a process is the system's LSASS, not a copy of its file (#1150 review): the
/// image at [`lsass_image`], in session 0, started by `<system root>\System32\wininit.exe`.
/// An unprivileged user can start `System32\lsass.exe` by hand, but in their own session
/// and under their own process; spoofing wininit as the parent needs a
/// `PROCESS_CREATE_PROCESS` handle to it, which a protected wininit refuses even to an
/// administrator. Unknown session or parent is not the system LSASS.
pub(crate) fn is_system_lsass(claim: &LsassClaim<'_>, system_root: &str) -> bool {
    is_lsass_image(claim.image_path, system_root)
        && claim.session_id == Some(0)
        && claim.parent_image_path.is_some_and(|parent| {
            parent.eq_ignore_ascii_case(&system32_image(system_root, "wininit.exe"))
        })
}

/// The pid of the system's LSASS, 0 while unknown (<https://github.com/synthaea-lab/edr-agent/issues/41>).
///
/// Taken only by a process [`is_system_lsass`] confirms, and never over a live one: a
/// second claimant, real or not, cannot move it. When the tracked LSASS ends (a crash,
/// which reboots the host), the caller looks it up again instead of leaving it unwatched.
#[derive(Debug, Default)]
pub(crate) struct LsassTracker {
    pid: AtomicU32,
}

impl LsassTracker {
    /// The tracked pid, 0 while unknown.
    pub(crate) fn pid(&self) -> u32 {
        self.pid.load(Ordering::Relaxed)
    }

    /// Whether `pid` is the tracked LSASS.
    pub(crate) fn is(&self, pid: u32) -> bool {
        pid != 0 && self.pid() == pid
    }

    /// Sets the pid found by a lookup ([`is_system_lsass`] already applied), 0 for none.
    pub(crate) fn set(&self, pid: u32) {
        self.pid.store(pid, Ordering::Relaxed);
    }

    /// A `ProcessStart`: takes the slot when it is empty and `claim` is the system LSASS.
    /// Returns whether it did.
    pub(crate) fn process_started(
        &self,
        pid: u32,
        claim: &LsassClaim<'_>,
        system_root: &str,
    ) -> bool {
        is_system_lsass(claim, system_root)
            && self
                .pid
                .compare_exchange(0, pid, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    /// A `ProcessStop`: when `pid` is the tracked LSASS, the slot takes what `look_up`
    /// finds (0 for nothing). Any other pid's end, a copy's included, changes nothing.
    pub(crate) fn process_ended(&self, pid: u32, look_up: impl FnOnce() -> u32) {
        if self.is(pid) {
            let found = look_up();
            let _ = self
                .pid
                .compare_exchange(pid, found, Ordering::Relaxed, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;
    const CREATOR: u32 = 100;
    const CHILD: u32 = 200;

    /// `owner_predates`: the owner existed before the window (pid store or creation time).
    fn known() -> bool {
        true
    }

    /// `owner_predates`: the owner is new or unknown.
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
        assert!(origins.early.is_empty());
    }

    #[test]
    fn a_second_thread_into_an_unknown_owner_is_remote() {
        let mut origins = ThreadOrigins::default();
        assert_eq!(
            origins.classify(CREATOR, CHILD, 0, unknown),
            ThreadOrigin::Initial
        );
        assert_eq!(
            origins.classify(CREATOR, CHILD, SEC, unknown),
            ThreadOrigin::Remote,
            "only one thread passes as an early initial one"
        );
        assert_eq!(
            origins.classify(CREATOR, CHILD, ORIGINS_WINDOW_NS * 2, unknown),
            ThreadOrigin::Remote,
            "nor does a later one once the early entry has aged"
        );
    }

    #[test]
    fn an_owner_the_pid_store_lost_after_its_start_is_judged_on_that_start() {
        let mut origins = ThreadOrigins::default();
        origins.process_started(CHILD, 0);
        assert_eq!(
            origins.classify(CREATOR, CHILD, SEC, known),
            ThreadOrigin::Initial
        );
        // The pid store evicted the child (LRU flood): it no longer vouches for it.
        assert_eq!(
            origins.classify(CREATOR, CHILD, 2 * SEC, unknown),
            ThreadOrigin::Remote
        );
    }

    #[test]
    fn a_kernel_started_initial_thread_leaves_no_excuse_for_the_next_one() {
        let mut origins = ThreadOrigins::default();
        origins.process_started(CHILD, 0);
        assert_eq!(origins.classify(4, CHILD, SEC, known), ThreadOrigin::Kernel);
        assert_eq!(
            origins.classify(CREATOR, CHILD, 2 * SEC, known),
            ThreadOrigin::Remote
        );
    }

    #[test]
    fn a_stale_early_thread_does_not_answer_for_a_new_process_on_its_pid() {
        let mut origins = ThreadOrigins::default();
        assert_eq!(
            origins.classify(CREATOR, CHILD, 0, unknown),
            ThreadOrigin::Initial
        );
        // The previous process's stop was lost; a new one gets the pid much later.
        origins.process_started(CHILD, ORIGINS_WINDOW_NS);
        assert_eq!(
            origins.classify(CREATOR, CHILD, ORIGINS_WINDOW_NS + SEC, known),
            ThreadOrigin::Initial,
            "the new process still waits for its own initial thread"
        );
    }

    #[test]
    fn creation_time_tells_a_process_that_predates_the_window() {
        assert!(created_before_window(0, ORIGINS_WINDOW_NS));
        assert!(!created_before_window(SEC, ORIGINS_WINDOW_NS));
        assert!(!created_before_window(
            2 * ORIGINS_WINDOW_NS,
            ORIGINS_WINDOW_NS
        ));
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
    fn rights_that_reach_memory_are_recognized_as_passed() {
        assert!(reaches_memory(0x0010), "PROCESS_VM_READ");
        assert!(reaches_memory(0x1410), "a dumper's usual mask");
        assert!(reaches_memory(0x001F_FFFF), "PROCESS_ALL_ACCESS");
        assert!(reaches_memory(MAXIMUM_ALLOWED));
        assert!(reaches_memory(GENERIC_ALL));
        assert!(reaches_memory(GENERIC_READ));
        assert!(reaches_memory(GENERIC_WRITE));
        assert!(
            reaches_memory(0x0040 | 0x1000),
            "PROCESS_DUP_HANDLE: a full handle out of it"
        );
        assert!(
            reaches_memory(0x0080 | 0x1000),
            "PROCESS_CREATE_PROCESS: a clone to dump"
        );
        assert!(reaches_memory(0x0002), "PROCESS_CREATE_THREAD");
        assert!(reaches_memory(0x0008), "PROCESS_VM_OPERATION");
        assert!(reaches_memory(0x0020), "PROCESS_VM_WRITE");
        assert!(!reaches_memory(0x1000), "PROCESS_QUERY_LIMITED_INFORMATION");
        assert!(
            !reaches_memory(0x0400 | 0x0100_0000),
            "query + ACCESS_SYSTEM_SECURITY"
        );
        assert!(!reaches_memory(0x0001), "PROCESS_TERMINATE");
        assert!(
            !reaches_memory(0x0100_0000 | 0x0010_0000),
            "SYNCHRONIZE + ACCESS_SYSTEM_SECURITY"
        );
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

    const ROOT: &str = r"C:\Windows";
    const WININIT: &str = r"C:\Windows\System32\wininit.exe";
    const LSASS_IMAGE: &str = r"C:\Windows\System32\lsass.exe";

    fn system_lsass() -> LsassClaim<'static> {
        LsassClaim {
            image_path: LSASS_IMAGE,
            session_id: Some(0),
            parent_image_path: Some(WININIT),
        }
    }

    /// What an unprivileged user gets by starting `System32\lsass.exe` by hand.
    fn hand_started_copy() -> LsassClaim<'static> {
        LsassClaim {
            image_path: LSASS_IMAGE,
            session_id: Some(1),
            parent_image_path: Some(r"C:\Windows\explorer.exe"),
        }
    }

    #[test]
    fn the_system_lsass_is_its_image_in_session_0_under_wininit() {
        assert!(is_system_lsass(&system_lsass(), ROOT));
        assert!(!is_system_lsass(&hand_started_copy(), ROOT));
        let in_session_1 = LsassClaim {
            session_id: Some(1),
            ..system_lsass()
        };
        assert!(!is_system_lsass(&in_session_1, ROOT));
        let other_parent = LsassClaim {
            parent_image_path: Some(r"C:\Users\Public\wininit.exe"),
            ..system_lsass()
        };
        assert!(!is_system_lsass(&other_parent, ROOT));
        let unknown_session = LsassClaim {
            session_id: None,
            ..system_lsass()
        };
        assert!(!is_system_lsass(&unknown_session, ROOT));
        let unknown_parent = LsassClaim {
            parent_image_path: None,
            ..system_lsass()
        };
        assert!(!is_system_lsass(&unknown_parent, ROOT));
        let copy_elsewhere = LsassClaim {
            image_path: r"C:\Users\Public\lsass.exe",
            ..system_lsass()
        };
        assert!(!is_system_lsass(&copy_elsewhere, ROOT));
    }

    #[test]
    fn a_second_lsass_path_start_then_its_end_leaves_the_tracked_pid_unchanged() {
        const REAL: u32 = 812;
        const COPY: u32 = 6000;
        let lsass = LsassTracker::default();
        lsass.set(REAL);
        assert!(!lsass.process_started(COPY, &hand_started_copy(), ROOT));
        assert!(
            !lsass.process_started(COPY, &system_lsass(), ROOT),
            "even a confirmed claimant never takes a live slot"
        );
        lsass.process_ended(COPY, || unreachable!("a copy's end looks nothing up"));
        assert_eq!(lsass.pid(), REAL);
    }

    #[test]
    fn an_empty_slot_is_taken_only_by_the_system_lsass() {
        let lsass = LsassTracker::default();
        assert!(!lsass.process_started(6000, &hand_started_copy(), ROOT));
        assert_eq!(lsass.pid(), 0);
        assert!(lsass.process_started(812, &system_lsass(), ROOT));
        assert_eq!(lsass.pid(), 812);
    }

    #[test]
    fn the_end_of_the_tracked_lsass_looks_it_up_again() {
        let lsass = LsassTracker::default();
        lsass.set(812);
        lsass.process_ended(812, || 900);
        assert_eq!(lsass.pid(), 900);
        lsass.process_ended(900, || 0);
        assert_eq!(lsass.pid(), 0);
        assert!(!lsass.is(0), "no pid is LSASS while it is unknown");
    }

    mod admission {
        use super::*;
        use crate::budget::{KeyDedup, PidBudget};

        const WINDOW: u64 = 60 * SEC;
        const LIMIT: u32 = 32;
        const BUDGET_WINDOW: u64 = 10 * SEC;

        fn state() -> (KeyDedup, PidBudget) {
            (
                KeyDedup::new("test", WINDOW),
                PidBudget::new("test", LIMIT, BUDGET_WINDOW),
            )
        }

        #[test]
        fn a_refused_thread_does_not_mark_its_pair() {
            let (mut dedup, mut budget) = state();
            for decoy in 0..LIMIT {
                let key = remote_thread_key(CREATOR, 1_000 + decoy, 0x7ff0_0000);
                assert!(admit_remote_thread(
                    &mut dedup,
                    &mut budget,
                    &key,
                    CREATOR,
                    false,
                    0
                ));
            }
            let real = remote_thread_key(CREATOR, CHILD, 0x7ff0_0000);
            assert!(!admit_remote_thread(
                &mut dedup,
                &mut budget,
                &real,
                CREATOR,
                false,
                SEC
            ));
            assert!(
                admit_remote_thread(
                    &mut dedup,
                    &mut budget,
                    &real,
                    CREATOR,
                    false,
                    BUDGET_WINDOW + SEC
                ),
                "the pair was refused, not reported: it is not inside its dedup window"
            );
        }

        #[test]
        fn a_thread_into_lsass_is_never_dropped_on_budget() {
            let (mut dedup, mut budget) = state();
            for decoy in 0..LIMIT {
                let key = remote_thread_key(CREATOR, 1_000 + decoy, 0);
                admit_remote_thread(&mut dedup, &mut budget, &key, CREATOR, false, 0);
            }
            let key = remote_thread_key(CREATOR, 812, 0x1000_0000);
            assert!(admit_remote_thread(
                &mut dedup,
                &mut budget,
                &key,
                CREATOR,
                true,
                SEC
            ));
        }

        #[test]
        fn a_harmless_first_thread_does_not_hide_one_at_another_address() {
            let (mut dedup, mut budget) = state();
            let harmless = remote_thread_key(CREATOR, CHILD, 0x7ffa_1234_5678);
            let shellcode = remote_thread_key(CREATOR, CHILD, 0x0000_01d0_0000);
            assert!(admit_remote_thread(
                &mut dedup,
                &mut budget,
                &harmless,
                CREATOR,
                false,
                0
            ));
            assert!(admit_remote_thread(
                &mut dedup,
                &mut budget,
                &shellcode,
                CREATOR,
                false,
                SEC
            ));
            let again = remote_thread_key(CREATOR, CHILD, 0x7ffa_1234_9abc);
            assert!(
                !admit_remote_thread(&mut dedup, &mut budget, &again, CREATOR, false, 2 * SEC),
                "the same routine again, same 64 KiB: one fact"
            );
        }
    }
}
