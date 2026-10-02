//! Budgeted YARA scanning of process memory (issue #85).
//!
//! File scanning (`crate::ScanQueue`) cannot see fileless tradecraft: a payload run from
//! a `memfd`, reflectively loaded shellcode, a hollowed process. Those live only in
//! memory, so this module scans the *executable regions that no file backs* of one
//! process. It is triggered by a detection (a `memfd` exec, an injection signal), never
//! a fleet-wide sweep, and every bound is explicit and counted:
//!
//! - **per scan** ([`MemoryBudget`]): regions, bytes per region, bytes in total; the
//!   regions most likely to hold a payload are read first, the rest are skipped and
//!   counted;
//! - **per process**: a cooldown per `(pid, generation)`, so a process that keeps
//!   re-triggering is scanned once per window, not once per trigger;
//! - **globally**: a sliding scans-per-minute cap and a small bounded queue.
//!
//! Reading another process's memory is OS-specific and privileged, so it sits behind
//! [`MemorySource`]: this crate holds the policy (what to read, how much, how often), a
//! platform sensor holds the mechanism (`/proc/<pid>/mem` on Linux, which needs
//! `CAP_SYS_PTRACE` for a process the agent does not own; see ADR-0023).

use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

use store::BoundedMap;

use crate::{RuleSet, YaraMatch};

/// Permissions of a mapped region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // r/w/x/p are four independent mapping flags
pub struct RegionPerms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl RegionPerms {
    /// Parses the `rwxp` column of `/proc/<pid>/maps` (and anything shaped like it).
    #[must_use]
    pub fn parse(perms: &str) -> Self {
        let has = |c: char| perms.contains(c);
        Self {
            read: has('r'),
            write: has('w'),
            exec: has('x'),
        }
    }
}

/// What backs a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Anonymous memory: no file behind it (shellcode, JIT output, an unpacked payload).
    Anonymous,
    /// A `memfd` (`/memfd:name`): an in-memory file, the fileless-exec carrier.
    Memfd,
    /// A mapping of a file that has been deleted from disk (a binary run then unlinked).
    Deleted,
    /// A mapping of a file on disk: covered by the file scan, not read here.
    FileBacked,
    /// `[stack]`, `[vdso]`, `[vsyscall]` and the like: never a payload carrier.
    Special,
}

/// One mapped region of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    /// Exclusive end.
    pub end: u64,
    pub perms: RegionPerms,
    pub kind: RegionKind,
}

impl MemoryRegion {
    /// Size in bytes (0 for a malformed `end <= start`).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the region is empty (or malformed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Worth reading: readable, executable, and not file-backed. Executable because a
    /// payload that never runs is not what a fileless-exec trigger is about; not
    /// file-backed because those bytes are on disk and the file scan owns them.
    #[must_use]
    pub fn is_candidate(&self) -> bool {
        self.perms.read
            && self.perms.exec
            && matches!(
                self.kind,
                RegionKind::Anonymous | RegionKind::Memfd | RegionKind::Deleted
            )
    }

    /// Scan order, lowest first: writable-and-executable memory is the strongest
    /// injection tell, then memfd and deleted-file mappings, then plain executable
    /// anonymous memory.
    fn priority(&self) -> u8 {
        if self.perms.write {
            0
        } else if matches!(self.kind, RegionKind::Memfd | RegionKind::Deleted) {
            1
        } else {
            2
        }
    }
}

/// Reads one process's memory. Implemented by a platform sensor; the budget and
/// trigger policy live here. Errors (`PermissionDenied`, a process that exited) are
/// expected and counted, never fatal.
pub trait MemorySource: Send + Sync {
    /// The mapped regions of `pid`.
    ///
    /// # Errors
    ///
    /// When the process's map cannot be read (it exited, or access is denied).
    fn regions(&self, pid: u32) -> io::Result<Vec<MemoryRegion>>;

    /// Up to `len` bytes of `pid`'s memory at `start`; fewer when the read comes up short.
    ///
    /// # Errors
    ///
    /// When the memory cannot be read (unmapped since `regions`, or access is denied).
    fn read(&self, pid: u32, start: u64, len: usize) -> io::Result<Vec<u8>>;
}

/// Bounds on one memory scan. Memory is attacker-controlled and can be huge, so each is
/// a hard cap, not a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryBudget {
    /// Regions read per scan.
    pub max_regions: usize,
    /// Bytes read from one region (a larger region is truncated and counted).
    pub max_region_bytes: u64,
    /// Bytes read per scan across all regions.
    pub max_total_bytes: u64,
}

impl Default for MemoryBudget {
    /// 16 regions, 16 MiB each, 64 MiB in all (the file-scan cap, [`crate::MAX_SCAN_BYTES`]):
    /// enough for a loader, shellcode and a staged payload, not a whole heap.
    fn default() -> Self {
        Self {
            max_regions: 16,
            max_region_bytes: 16 * 1024 * 1024,
            max_total_bytes: crate::MAX_SCAN_BYTES,
        }
    }
}

/// What one memory scan did, including everything it chose not to do.
#[derive(Debug, Clone, Default)]
pub struct MemoryScanReport {
    /// Distinct matching rules across all scanned regions.
    pub matches: Vec<YaraMatch>,
    pub regions_scanned: usize,
    /// Candidate regions left unread because a budget was spent.
    pub regions_skipped: usize,
    /// Regions that could not be read (unmapped since the map was read, access denied).
    pub regions_unreadable: usize,
    /// Regions read only in part because of `max_region_bytes` or `max_total_bytes`.
    pub regions_truncated: usize,
    pub bytes_scanned: u64,
}

/// Scans the candidate regions of `pid` within `budget`.
///
/// # Errors
///
/// When the process's region map cannot be read at all. A region that cannot be read, or a
/// scan the engine fails, is counted in the report and the scan carries on.
pub fn scan_memory(
    rules: &RuleSet,
    source: &dyn MemorySource,
    pid: u32,
    budget: &MemoryBudget,
) -> io::Result<MemoryScanReport> {
    let mut candidates: Vec<MemoryRegion> = source
        .regions(pid)?
        .into_iter()
        .filter(|r| !r.is_empty() && r.is_candidate())
        .collect();
    candidates.sort_by_key(|r| (r.priority(), r.start));

    let mut report = MemoryScanReport::default();
    for (index, region) in candidates.iter().enumerate() {
        let remaining = budget.max_total_bytes.saturating_sub(report.bytes_scanned);
        if report.regions_scanned >= budget.max_regions || remaining == 0 {
            report.regions_skipped = candidates.len() - index;
            break;
        }
        let want = region.len().min(budget.max_region_bytes).min(remaining);
        let Ok(len) = usize::try_from(want) else {
            report.regions_unreadable += 1;
            continue;
        };
        match source.read(pid, region.start, len) {
            Ok(bytes) if !bytes.is_empty() => {
                report.bytes_scanned += bytes.len() as u64;
                if (bytes.len() as u64) < region.len() {
                    report.regions_truncated += 1;
                }
                report.regions_scanned += 1;
                let origin = format!("pid {pid} {:#x}..{:#x}", region.start, region.end);
                match rules.scan_bytes(&bytes, &origin) {
                    Ok(found) => {
                        for m in found {
                            if !report.matches.iter().any(|k| k.identifier == m.identifier) {
                                report.matches.push(m);
                            }
                        }
                    }
                    Err(e) => tracing::debug!(error = %e, "yara: memory region scan failed"),
                }
            }
            Ok(_) | Err(_) => report.regions_unreadable += 1,
        }
    }
    Ok(report)
}

/// One scan's result, delivered when it found something.
#[derive(Debug, Clone)]
pub struct MemoryScanOutcome {
    pub pid: u32,
    pub generation: Option<u64>,
    pub report: MemoryScanReport,
}

/// Counters of the memory-scan queue: every scan not run is accounted for by a reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryScanStats {
    /// Scans fully handled: ran to a report and, if it matched, the callback returned.
    pub scanned: u64,
    /// Requests dropped because the queue was full.
    pub shed_queue_full: u64,
    /// Requests dropped because the process was scanned recently.
    pub shed_cooldown: u64,
    /// Requests dropped because the global scans-per-minute cap was spent.
    pub shed_rate: u64,
    /// Scans that could not read the process's regions at all (exited, access denied).
    pub unreadable: u64,
}

/// Queue capacity: scans are rare and each can read tens of MiB, so the backlog is small.
const QUEUE_CAP: usize = 16;
/// A process is not scanned again within this window (nanoseconds of event time).
pub const COOLDOWN_NS: u64 = 5 * 60 * 1_000_000_000;
/// Global cap: scans started per rolling minute.
pub const MAX_SCANS_PER_MINUTE: usize = 6;
/// Processes whose cooldown is remembered at once.
const COOLDOWN_ENTRIES: usize = 4_096;
const MINUTE_NS: u64 = 60 * 1_000_000_000;

struct Request {
    pid: u32,
    generation: Option<u64>,
}

/// Admission control shared by every caller of [`MemoryScanQueue::enqueue`].
struct Gate {
    /// `(pid, generation)` → event time of the last admitted scan. A recycled pid has
    /// a different generation and is a new process (#590).
    last_scan: BoundedMap<(u32, Option<u64>), u64>,
    /// Event times of scans admitted in the last minute.
    recent: VecDeque<u64>,
}

/// One worker behind a bounded channel, with a per-process cooldown and a global rate
/// cap in front of it. Dropping the queue stops the worker after the backlog.
pub struct MemoryScanQueue {
    tx: mpsc::SyncSender<Request>,
    gate: Mutex<Gate>,
    scanned: Arc<AtomicU64>,
    unreadable: Arc<AtomicU64>,
    shed_queue_full: AtomicU64,
    shed_cooldown: AtomicU64,
    shed_rate: AtomicU64,
}

impl MemoryScanQueue {
    /// Starts the worker. `on_match` runs on it for every scan that found a rule.
    ///
    /// # Panics
    ///
    /// Panics when the OS refuses to spawn the worker thread, at agent startup, with
    /// nothing to degrade to (same stance as [`crate::ScanQueue::start`]).
    pub fn start(
        rules: RuleSet,
        source: Arc<dyn MemorySource>,
        budget: MemoryBudget,
        on_match: impl Fn(MemoryScanOutcome) + Send + 'static,
    ) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Request>(QUEUE_CAP);
        let scanned = Arc::new(AtomicU64::new(0));
        let unreadable = Arc::new(AtomicU64::new(0));
        let (scanned_w, unreadable_w) = (scanned.clone(), unreadable.clone());
        std::thread::Builder::new()
            .name("yara-memscan".into())
            .spawn(move || {
                while let Ok(Request { pid, generation }) = rx.recv() {
                    match scan_memory(&rules, source.as_ref(), pid, &budget) {
                        Ok(report) => {
                            if !report.matches.is_empty() {
                                on_match(MemoryScanOutcome {
                                    pid,
                                    generation,
                                    report,
                                });
                            }
                            // After the callback, so "scanned" means fully handled and a
                            // caller waiting on it never beats the match it is waiting for.
                            scanned_w.fetch_add(1, Ordering::Relaxed);
                        }
                        // Exited, or no right to read it: the normal outcomes, counted.
                        Err(e) => {
                            unreadable_w.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(pid, error = %e, "yara: memory scan skipped");
                        }
                    }
                }
            })
            .expect("spawning the yara memory-scan worker thread");
        Self {
            tx,
            gate: Mutex::new(Gate {
                last_scan: BoundedMap::new(COOLDOWN_ENTRIES),
                recent: VecDeque::new(),
            }),
            scanned,
            unreadable,
            shed_queue_full: AtomicU64::new(0),
            shed_cooldown: AtomicU64::new(0),
            shed_rate: AtomicU64::new(0),
        }
    }

    /// Asks for a scan of `pid`, subject to the cooldown, the global cap and the queue.
    /// Returns whether it was queued; a shed request is counted under its reason.
    /// `now_ns` is event time, the clock the rest of the detection state uses.
    ///
    /// # Panics
    ///
    /// Only if the admission lock is poisoned by a panic elsewhere.
    pub fn enqueue(&self, pid: u32, generation: Option<u64>, now_ns: u64) -> bool {
        let mut gate = self.gate.lock().unwrap();
        let key = (pid, generation);
        if let Some(&last) = gate.last_scan.peek(&key)
            && now_ns.saturating_sub(last) < COOLDOWN_NS
        {
            self.shed_cooldown.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        while gate
            .recent
            .front()
            .is_some_and(|&t| now_ns.saturating_sub(t) >= MINUTE_NS)
        {
            gate.recent.pop_front();
        }
        if gate.recent.len() >= MAX_SCANS_PER_MINUTE {
            self.shed_rate.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if self.tx.try_send(Request { pid, generation }).is_err() {
            self.shed_queue_full.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // Only an admitted request spends the cooldown and the rate: a shed one must
        // not keep a process from being scanned when the pressure is gone.
        gate.last_scan.insert(key, now_ns);
        gate.recent.push_back(now_ns);
        true
    }

    #[must_use]
    pub fn stats(&self) -> MemoryScanStats {
        MemoryScanStats {
            scanned: self.scanned.load(Ordering::Relaxed),
            shed_queue_full: self.shed_queue_full.load(Ordering::Relaxed),
            shed_cooldown: self.shed_cooldown.load(Ordering::Relaxed),
            shed_rate: self.shed_rate.load(Ordering::Relaxed),
            unreadable: self.unreadable.load(Ordering::Relaxed),
        }
    }

    /// Blocks until `scanned + unreadable` reaches `count` or `timeout` passes; for tests
    /// and orderly shutdown.
    #[must_use]
    pub fn wait_for_completed(&self, count: u64, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let s = self.stats();
            if s.scanned + s.unreadable >= count {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    const MARKER: &[u8] = b"MEMORY-ONLY-MARKER";

    fn rules() -> RuleSet {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(
                br#"
rule mem_marker {
    meta:
        severity = "high"
        technique = "T1620"
        falsepositives = "none, test-only rule"
    strings:
        $m = "MEMORY-ONLY-MARKER"
    condition:
        $m
}
"#
                .as_slice(),
            )
            .unwrap();
        RuleSet::from_compiled(compiler.build()).unwrap()
    }

    fn region(start: u64, len: u64, perms: &str, kind: RegionKind) -> MemoryRegion {
        MemoryRegion {
            start,
            end: start + len,
            perms: RegionPerms::parse(perms),
            kind,
        }
    }

    /// A process whose regions and bytes are in a map; unlisted starts are unreadable.
    struct Fake {
        regions: io::Result<Vec<MemoryRegion>>,
        bytes: HashMap<u64, Vec<u8>>,
        reads: Mutex<Vec<(u64, usize)>>,
    }

    impl Fake {
        fn new(regions: Vec<MemoryRegion>, bytes: Vec<(u64, Vec<u8>)>) -> Self {
            Self {
                regions: Ok(regions),
                bytes: bytes.into_iter().collect(),
                reads: Mutex::new(Vec::new()),
            }
        }
    }

    impl MemorySource for Fake {
        fn regions(&self, _pid: u32) -> io::Result<Vec<MemoryRegion>> {
            match &self.regions {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            }
        }

        fn read(&self, _pid: u32, start: u64, len: usize) -> io::Result<Vec<u8>> {
            self.reads.lock().unwrap().push((start, len));
            let data = self
                .bytes
                .get(&start)
                .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
            Ok(data[..len.min(data.len())].to_vec())
        }
    }

    fn payload(len: usize) -> Vec<u8> {
        let mut v = vec![0x90; len];
        v[len / 2..len / 2 + MARKER.len()].copy_from_slice(MARKER);
        v
    }

    #[test]
    fn only_executable_regions_no_file_backs_are_read() {
        let fake = Fake::new(
            vec![
                region(0x1000, 4096, "r-xp", RegionKind::FileBacked), // a library: file scan's job
                region(0x2000, 4096, "rw-p", RegionKind::Anonymous),  // data, not code
                region(0x3000, 4096, "r-xp", RegionKind::Special),    // [vdso]
                region(0x4000, 4096, "---p", RegionKind::Anonymous),  // unreadable by perms
                region(0x5000, 4096, "r-xp", RegionKind::Anonymous),  // the candidate
            ],
            vec![(0x5000, payload(4096))],
        );
        let report = scan_memory(&rules(), &fake, 1, &MemoryBudget::default()).unwrap();
        assert_eq!(report.regions_scanned, 1);
        assert_eq!(*fake.reads.lock().unwrap(), vec![(0x5000, 4096)]);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].identifier, "mem_marker");
    }

    #[test]
    fn an_empty_or_inverted_region_is_not_read() {
        let mut inverted = region(0x9000, 0, "r-xp", RegionKind::Anonymous);
        inverted.end = 0x8000;
        let fake = Fake::new(vec![inverted], vec![]);
        let report = scan_memory(&rules(), &fake, 1, &MemoryBudget::default()).unwrap();
        assert_eq!(report.regions_scanned + report.regions_unreadable, 0);
        assert!(fake.reads.lock().unwrap().is_empty());
    }

    #[test]
    fn writable_and_executable_memory_is_read_before_the_rest() {
        let fake = Fake::new(
            vec![
                region(0x1000, 64, "r-xp", RegionKind::Anonymous),
                region(0x2000, 64, "r-xp", RegionKind::Memfd),
                region(0x3000, 64, "rwxp", RegionKind::Anonymous),
            ],
            vec![
                (0x1000, vec![0; 64]),
                (0x2000, vec![0; 64]),
                (0x3000, vec![0; 64]),
            ],
        );
        scan_memory(&rules(), &fake, 1, &MemoryBudget::default()).unwrap();
        let order: Vec<u64> = fake.reads.lock().unwrap().iter().map(|r| r.0).collect();
        assert_eq!(
            order,
            vec![0x3000, 0x2000, 0x1000],
            "rwx, then memfd, then plain"
        );
    }

    #[test]
    fn the_region_cap_skips_and_counts_the_rest_lowest_priority_last() {
        let regions: Vec<_> = (0..5)
            .map(|i| region(0x1000 * (i + 1), 64, "r-xp", RegionKind::Anonymous))
            .collect();
        let bytes = regions.iter().map(|r| (r.start, vec![0; 64])).collect();
        let fake = Fake::new(regions, bytes);
        let budget = MemoryBudget {
            max_regions: 2,
            ..MemoryBudget::default()
        };
        let report = scan_memory(&rules(), &fake, 1, &budget).unwrap();
        assert_eq!((report.regions_scanned, report.regions_skipped), (2, 3));
        assert_eq!(
            fake.reads.lock().unwrap().len(),
            2,
            "skipped regions are never read"
        );
    }

    #[test]
    fn a_region_over_the_per_region_cap_is_truncated_and_counted() {
        let fake = Fake::new(
            vec![region(0x1000, 1 << 20, "r-xp", RegionKind::Anonymous)],
            vec![(0x1000, vec![0; 1 << 20])],
        );
        let budget = MemoryBudget {
            max_region_bytes: 4096,
            ..MemoryBudget::default()
        };
        let report = scan_memory(&rules(), &fake, 1, &budget).unwrap();
        assert_eq!(*fake.reads.lock().unwrap(), vec![(0x1000, 4096)]);
        assert_eq!((report.regions_truncated, report.bytes_scanned), (1, 4096));
    }

    #[test]
    fn the_total_byte_cap_bounds_the_scan_and_skips_what_is_left() {
        let regions: Vec<_> = (0..4)
            .map(|i| region(0x10_0000 * (i + 1), 4096, "r-xp", RegionKind::Anonymous))
            .collect();
        let bytes = regions.iter().map(|r| (r.start, vec![0; 4096])).collect();
        let fake = Fake::new(regions, bytes);
        let budget = MemoryBudget {
            max_total_bytes: 6000,
            ..MemoryBudget::default()
        };
        let report = scan_memory(&rules(), &fake, 1, &budget).unwrap();
        assert!(report.bytes_scanned <= 6000, "{report:?}");
        assert_eq!(report.regions_scanned, 2, "4096 then the 1904 that remain");
        assert_eq!(report.regions_skipped, 2);
        assert_eq!(report.regions_truncated, 1);
    }

    #[test]
    fn an_unreadable_region_is_counted_and_the_scan_carries_on() {
        let fake = Fake::new(
            vec![
                region(0x1000, 64, "rwxp", RegionKind::Anonymous), // no bytes: denied
                region(0x2000, 4096, "r-xp", RegionKind::Anonymous),
            ],
            vec![(0x2000, payload(4096))],
        );
        let report = scan_memory(&rules(), &fake, 1, &MemoryBudget::default()).unwrap();
        assert_eq!((report.regions_unreadable, report.regions_scanned), (1, 1));
        assert_eq!(report.matches.len(), 1, "the readable region still matched");
    }

    #[test]
    fn a_process_whose_map_cannot_be_read_is_an_error_not_a_panic() {
        let mut fake = Fake::new(vec![], vec![]);
        fake.regions = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let err = scan_memory(&rules(), &fake, 1, &MemoryBudget::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn the_same_rule_in_two_regions_is_reported_once() {
        let fake = Fake::new(
            vec![
                region(0x1000, 4096, "r-xp", RegionKind::Anonymous),
                region(0x2000, 4096, "r-xp", RegionKind::Anonymous),
            ],
            vec![(0x1000, payload(4096)), (0x2000, payload(4096))],
        );
        let report = scan_memory(&rules(), &fake, 1, &MemoryBudget::default()).unwrap();
        assert_eq!(report.regions_scanned, 2);
        assert_eq!(report.matches.len(), 1);
    }

    #[test]
    fn perms_parse_the_proc_maps_column() {
        assert_eq!(
            RegionPerms::parse("rwxp"),
            RegionPerms {
                read: true,
                write: true,
                exec: true
            }
        );
        assert_eq!(
            RegionPerms::parse("r--s"),
            RegionPerms {
                read: true,
                write: false,
                exec: false
            }
        );
    }

    // --- the queue ---

    fn queue_over(fake: Fake) -> (MemoryScanQueue, Arc<Mutex<Vec<MemoryScanOutcome>>>) {
        let hits: Arc<Mutex<Vec<MemoryScanOutcome>>> = Arc::new(Mutex::new(Vec::new()));
        let hits_w = hits.clone();
        let queue =
            MemoryScanQueue::start(rules(), Arc::new(fake), MemoryBudget::default(), move |o| {
                hits_w.lock().unwrap().push(o);
            });
        (queue, hits)
    }

    fn implant() -> Fake {
        Fake::new(
            vec![region(0x1000, 4096, "rwxp", RegionKind::Anonymous)],
            vec![(0x1000, payload(4096))],
        )
    }

    #[test]
    fn a_triggered_scan_delivers_a_match_attributed_to_the_process() {
        let (queue, hits) = queue_over(implant());
        assert!(queue.enqueue(42, Some(7), 1));
        assert!(queue.wait_for_completed(1, Duration::from_secs(5)));
        let hits = hits.lock().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!((hits[0].pid, hits[0].generation), (42, Some(7)));
        assert_eq!(hits[0].report.matches[0].identifier, "mem_marker");
    }

    #[test]
    fn a_process_is_not_rescanned_within_the_cooldown() {
        let (queue, _hits) = queue_over(implant());
        assert!(queue.enqueue(42, Some(1), 0));
        assert!(
            !queue.enqueue(42, Some(1), COOLDOWN_NS - 1),
            "still cooling down"
        );
        assert!(queue.enqueue(42, Some(1), COOLDOWN_NS), "window over");
        assert_eq!(queue.stats().shed_cooldown, 1);
    }

    #[test]
    fn a_recycled_pid_is_a_new_process_for_the_cooldown() {
        let (queue, _hits) = queue_over(implant());
        assert!(queue.enqueue(42, Some(1), 0));
        assert!(
            queue.enqueue(42, Some(2), 1),
            "another incarnation of pid 42"
        );
        assert!(!queue.enqueue(42, Some(2), 2));
    }

    #[test]
    fn the_global_rate_cap_sheds_and_counts_then_recovers() {
        let (queue, _hits) = queue_over(implant());
        for pid in 0..MAX_SCANS_PER_MINUTE as u32 {
            assert!(queue.enqueue(100 + pid, None, 1_000 + u64::from(pid)));
        }
        assert!(!queue.enqueue(999, None, 2_000), "cap spent");
        assert_eq!(queue.stats().shed_rate, 1);
        assert!(
            queue.enqueue(999, None, 61 * 1_000_000_000),
            "a minute later"
        );
    }

    #[test]
    fn a_shed_request_does_not_spend_the_cooldown() {
        let (queue, _hits) = queue_over(implant());
        for pid in 0..MAX_SCANS_PER_MINUTE as u32 {
            assert!(queue.enqueue(100 + pid, None, 1_000));
        }
        assert!(!queue.enqueue(999, None, 2_000), "rate-shed");
        // 999 was shed by the rate cap, not scanned: once the minute passes it is
        // admitted at once, not held back by a cooldown it never earned.
        assert!(queue.enqueue(999, None, 61 * 1_000_000_000));
    }

    #[test]
    fn a_process_that_cannot_be_read_is_counted_not_reported() {
        let mut fake = implant();
        fake.regions = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let (queue, hits) = queue_over(fake);
        assert!(queue.enqueue(1, None, 0));
        assert!(queue.wait_for_completed(1, Duration::from_secs(5)));
        assert_eq!(queue.stats().unreadable, 1);
        assert_eq!(queue.stats().scanned, 0);
        assert!(hits.lock().unwrap().is_empty());
    }

    #[test]
    fn a_clean_process_is_scanned_and_reports_nothing() {
        let clean = Fake::new(
            vec![region(0x1000, 64, "rwxp", RegionKind::Anonymous)],
            vec![(0x1000, vec![0x90; 64])],
        );
        let (queue, hits) = queue_over(clean);
        assert!(queue.enqueue(1, None, 0));
        assert!(queue.wait_for_completed(1, Duration::from_secs(5)));
        assert_eq!(queue.stats().scanned, 1);
        assert!(hits.lock().unwrap().is_empty());
    }

    /// A source that holds the worker inside `regions` until released, to fill the queue.
    struct Gated {
        open: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl MemorySource for Gated {
        fn regions(&self, _pid: u32) -> io::Result<Vec<MemoryRegion>> {
            let (lock, cv) = &*self.open;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            Ok(Vec::new())
        }

        fn read(&self, _pid: u32, _start: u64, _len: usize) -> io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_full_queue_sheds_and_counts_instead_of_blocking_the_caller() {
        let open = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let queue = MemoryScanQueue::start(
            rules(),
            Arc::new(Gated { open: open.clone() }),
            MemoryBudget::default(),
            |_| {},
        );
        // Event times a minute apart so the global rate cap never bites: only the
        // queue's own capacity can refuse. The worker takes the first request and
        // blocks on it; the channel then holds QUEUE_CAP more.
        let minute = MINUTE_NS + 1;
        let mut admitted = 0_u32;
        for pid in 0..(QUEUE_CAP as u32 + 4) {
            if queue.enqueue(pid, None, u64::from(pid) * minute) {
                admitted += 1;
            }
        }
        assert!(
            admitted <= QUEUE_CAP as u32 + 1,
            "never more than queue + one in flight"
        );
        assert!(queue.stats().shed_queue_full >= 1, "{:?}", queue.stats());
        // Release the worker so the thread can end with the queue.
        *open.0.lock().unwrap() = true;
        open.1.notify_all();
    }
}
