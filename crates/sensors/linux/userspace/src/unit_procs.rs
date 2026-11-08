//! Which processes belong to a security tool's systemd unit (#1103, T1562.001).
//!
//! [`schema::SECURITY_SERVICES`] are **unit names**, not process names: `clamav-daemon` runs
//! `clamd`, `mdatp` runs `wdavdaemon`, `apparmor` runs nothing. A signal arrives as a pid, so
//! the watch set is built from the unit's cgroup, which is the answer systemd itself gives to
//! "does this process belong to unit X", with no D-Bus and no comm match (a comm is per thread
//! and any process can set its own).
//!
//! Each scan reads `<cgroup>/system.slice/<unit>.service/cgroup.procs` (cgroup v2; the hybrid
//! v1 layout under `<cgroup>/systemd/` is read too) and the sub-cgroups below it, and keeps
//! the unit and the executable per tgid. The executable is read **now**: a `SIGKILL`ed target
//! is gone by the time its event is drained, and `/proc/<pid>/exe` with it.
//!
//! What this does not cover, stated rather than hidden: a tool not run by a systemd unit, a
//! template instance (`clamd@scan.service` is not `clamd.service`), and the window between a
//! unit's restart and the next scan, where its new pid is unwatched.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Sub-cgroup levels read below a unit's own. A unit with `Delegate=` or a worker slice has a
/// few; the bound keeps a hostile or odd tree from turning a scan into a walk of the host.
const MAX_DEPTH: usize = 4;

/// Processes kept per unit. A tool's process tree is tens of processes: past this it is a fork
/// bomb in the unit, and the first ones are the tool's own.
const MAX_PROCS_PER_UNIT: usize = 256;

/// Processes kept after they left their unit's cgroup, all units together. One cap for the whole
/// set, not one per unit: root can create the cgroup of a listed unit that is not installed, so a
/// per-unit cap would let the moved-out set double the map's worst case (review of #1114).
const MAX_MOVED_OUT: usize = MAX_PROCS_PER_UNIT;

// The kernel map holds every listed unit at the per-unit process cap plus the moved-out cap, with
// headroom for removals that failed (review of #1114).
const _: () = assert!(
    schema::SECURITY_SERVICES.len() * MAX_PROCS_PER_UNIT + MAX_MOVED_OUT
        < sensor_linux_wire::SIGNAL_WATCH_TOOLS_ENTRIES as usize,
    "SIGNAL_WATCH_TOOLS_ENTRIES must exceed SECURITY_SERVICES.len() * MAX_PROCS_PER_UNIT + MAX_MOVED_OUT"
);

/// Cgroup directories read per unit and layout, the unit's own included. `MAX_DEPTH` bounds the
/// depth, not the width: a delegated unit can hold thousands of sibling sub-cgroups, and the scan
/// runs on the loop that drains the ring. Past this the rest are not read (logged).
const MAX_CGROUPS_PER_UNIT: usize = 256;

/// What the watch set knows about a watched process, taken at scan time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitProc {
    /// The unit as listed in `SECURITY_SERVICES` (lowercase, no `.service`).
    pub unit: String,
    /// `/proc/<pid>/exe` when it could be read at scan time.
    pub exe: Option<String>,
    /// The process start time (`/proc/<pid>/stat`, field 22, clock ticks since boot) at scan
    /// time: with the pid it names one process, which the exe alone cannot (a pid reused by the
    /// same program, or a kernel thread with no exe).
    pub start: Option<u64>,
    /// `SigCgt` of `/proc/<pid>/status` at scan time: the signals the process catches, bit
    /// `sig - 1`. It is the value of the process's `SIGNAL_WATCH_TOOLS` entry: the probe drops a
    /// reload signal (`SIGHUP`, `SIGUSR1`, `SIGUSR2`, real-time) the process catches. Unknown
    /// counts as nothing caught, so the signal is reported, not hidden.
    pub sig_cgt: Option<u64>,
}

/// Resolves the listed units to their processes.
pub(crate) struct UnitResolver {
    cgroup_root: PathBuf,
    proc_root: PathBuf,
    units: Vec<String>,
}

impl UnitResolver {
    /// A resolver over explicit roots, for tests and for hosts that mount the cgroup tree
    /// elsewhere.
    pub(crate) fn new(cgroup_root: &Path, proc_root: &Path, units: &[&str]) -> Self {
        Self {
            cgroup_root: cgroup_root.to_owned(),
            proc_root: proc_root.to_owned(),
            units: units.iter().map(|unit| (*unit).to_owned()).collect(),
        }
    }

    /// The real host: `/sys/fs/cgroup`, `/proc` and every listed security service.
    pub(crate) fn system() -> Self {
        Self::new(
            Path::new("/sys/fs/cgroup"),
            Path::new("/proc"),
            schema::SECURITY_SERVICES,
        )
    }

    /// tgid → its unit and executable, for every listed unit present on the host. A unit that is
    /// not installed, not running or not under `system.slice` contributes nothing.
    pub(crate) fn scan(&self) -> BTreeMap<u32, UnitProc> {
        let mut found = BTreeMap::new();
        for unit in &self.units {
            let mut pids = Vec::new();
            for layout in ["system.slice", "systemd/system.slice"] {
                let dir = self
                    .cgroup_root
                    .join(layout)
                    .join(format!("{unit}.service"));
                let mut budget = MAX_CGROUPS_PER_UNIT;
                let mut skipped = false;
                collect_procs(&dir, 0, &mut budget, &mut skipped, &mut pids);
                // Only when a directory was left unread: a unit with exactly the cap and none
                // skipped is not truncated.
                if skipped {
                    tracing::warn!(
                        unit = %unit,
                        cap = MAX_CGROUPS_PER_UNIT,
                        "unit_procs: a security unit has more sub-cgroups than the cap, the rest are not read"
                    );
                }
            }
            if pids.len() > MAX_PROCS_PER_UNIT {
                tracing::warn!(
                    unit = %unit,
                    found = pids.len(),
                    kept = MAX_PROCS_PER_UNIT,
                    "unit_procs: a security unit has more processes than the cap, the rest are not watched"
                );
                pids.truncate(MAX_PROCS_PER_UNIT);
            }
            for pid in pids {
                found.entry(pid).or_insert_with(|| UnitProc {
                    unit: unit.clone(),
                    exe: self.exe_of(pid),
                    start: self.start_of(pid),
                    sig_cgt: self.sig_cgt_of(pid),
                });
            }
        }
        found
    }

    /// Whether `pid` is still the process `known` described: the same start time. A tool that
    /// was moved out of its unit's cgroup passes; an exited one, or a pid handed to another
    /// process, does not. Without a start time recorded at scan time nothing can be said, so
    /// the answer is no.
    pub(crate) fn still_is(&self, pid: u32, known: &UnitProc) -> bool {
        known.start.is_some() && self.start_of(pid) == known.start
    }

    /// `SigCgt:` of `/proc/<pid>/status`, a hex mask with bit `sig - 1` per caught signal.
    fn sig_cgt_of(&self, pid: u32) -> Option<u64> {
        let status =
            fs::read_to_string(self.proc_root.join(pid.to_string()).join("status")).ok()?;
        let line = status.lines().find_map(|l| l.strip_prefix("SigCgt:"))?;
        u64::from_str_radix(line.trim(), 16).ok()
    }

    /// Field 22 of `/proc/<pid>/stat`. The command name (field 2) may hold spaces and
    /// parentheses, so the fields are counted from the last `)`.
    fn start_of(&self, pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(self.proc_root.join(pid.to_string()).join("stat")).ok()?;
        let after_comm = stat.get(stat.rfind(')')? + 1..)?;
        // `state` is field 3, so `starttime` (field 22) is the 20th token after the `)`.
        after_comm.split_whitespace().nth(19)?.parse().ok()
    }

    fn exe_of(&self, pid: u32) -> Option<String> {
        let target = fs::read_link(self.proc_root.join(pid.to_string()).join("exe")).ok()?;
        Some(target.to_string_lossy().into_owned())
    }
}

/// The tgids of `dir/cgroup.procs` and of the cgroups below `dir`, in file order.
fn collect_procs(
    dir: &Path,
    depth: usize,
    budget: &mut usize,
    skipped: &mut bool,
    out: &mut Vec<u32>,
) {
    if *budget == 0 {
        *skipped = true;
        return;
    }
    *budget -= 1;
    let Ok(procs) = fs::read_to_string(dir.join("cgroup.procs")) else {
        return;
    };
    out.extend(
        procs
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok()),
    );
    if depth >= MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect();
    children.sort();
    for child in children {
        collect_procs(&child, depth + 1, budget, skipped, out);
    }
}

/// The pids to add to and to drop from the kernel-side watch set to go from `previous` to
/// `current`. A pid whose unit changed is both: it is dropped and added again.
pub(crate) fn changes(
    previous: &BTreeMap<u32, UnitProc>,
    current: &BTreeMap<u32, UnitProc>,
) -> (Vec<u32>, Vec<u32>) {
    let added = current
        .iter()
        .filter(|(pid, proc)| previous.get(pid) != Some(proc))
        .map(|(pid, _)| *pid)
        .collect();
    let removed = previous
        .keys()
        .filter(|pid| !current.contains_key(pid))
        .copied()
        .collect();
    (added, removed)
}

/// The kernel-side set of watched tgids (`SIGNAL_WATCH_TOOLS`), as far as [`ToolWatch`] needs it:
/// a trait so the refresh logic is tested without a kernel.
pub(crate) trait WatchSet {
    /// `sig_cgt` is the process's caught-signal mask, the value the probe reads.
    fn insert(&mut self, pid: u32, sig_cgt: u64) -> Result<(), String>;
    /// `Ok(true)`: removed. `Ok(false)`: it was not in the set, which is what was wanted.
    /// `Err`: still in the set, to be retried.
    fn remove(&mut self, pid: u32) -> Result<bool, String>;
}

impl WatchSet for aya::maps::HashMap<aya::maps::MapData, u32, u64> {
    fn insert(&mut self, pid: u32, sig_cgt: u64) -> Result<(), String> {
        aya::maps::HashMap::insert(self, &pid, &sig_cgt, 0).map_err(|e| e.to_string())
    }

    fn remove(&mut self, pid: u32) -> Result<bool, String> {
        match aya::maps::HashMap::remove(self, &pid) {
            Ok(()) => Ok(true),
            Err(aya::maps::MapError::KeyNotFound) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// What the drain reads to name a target: tgid → unit and exe, as of the last scan.
pub(crate) type ToolProcs = Arc<Mutex<BTreeMap<u32, UnitProc>>>;

/// Keeps the kernel-side watch set equal to the listed units' processes, and the cache the drain
/// enriches from.
///
/// The cache is the last scan plus the one before it, so a tool that died is forgotten two scans
/// later ([`crate::sensor`] rescans every few seconds): an event for it is drained within
/// milliseconds of the signal, but possibly after a rescan, and keeping a dead tgid longer would
/// hand its number to an unrelated process that reuses it. The kernel-side set drops it at the
/// first scan, so no new event names it.
pub(crate) struct ToolWatch<S> {
    resolver: UnitResolver,
    set: S,
    /// What the kernel-side set holds now: an insert that failed is absent, so the next scan
    /// tries it again.
    applied: BTreeMap<u32, UnitProc>,
    /// The cache of the scan before the last one: a tgid that left the units between two scans
    /// stays nameable for one more scan, since its last event is drained after the rescan can win.
    previous_scan: BTreeMap<u32, UnitProc>,
    /// Moved-out tools already logged, so the warning comes once, not at every scan.
    moved_logged: std::collections::BTreeSet<u32>,
    /// The moved-out processes kept at the last scan: they keep their place under
    /// [`MAX_MOVED_OUT`] before any newcomer.
    moved_kept: std::collections::BTreeSet<u32>,
    procs: ToolProcs,
}

impl<S: WatchSet> ToolWatch<S> {
    pub(crate) fn new(resolver: UnitResolver, set: S) -> Self {
        Self {
            resolver,
            set,
            applied: BTreeMap::new(),
            previous_scan: BTreeMap::new(),
            moved_logged: std::collections::BTreeSet::new(),
            moved_kept: std::collections::BTreeSet::new(),
            procs: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// The cache to enrich from; the same one after every [`Self::refresh`].
    pub(crate) fn procs(&self) -> ToolProcs {
        Arc::clone(&self.procs)
    }

    /// Scans the units and brings the kernel-side set up to date. Returns how many processes are
    /// watched. A failed edit is logged and retried by the next scan, never fatal: the probe
    /// keeps working on what it has.
    pub(crate) fn refresh(&mut self) -> usize {
        let mut next = self.resolver.scan();
        // A watched process that left its unit's cgroup is still the tool (root can move it with
        // `echo <pid> > cgroup.procs` to blind the probe): keep watching it until it exits.
        // Capped (`MAX_MOVED_OUT`): a process of any uid can be moved in by root, and each one would
        // otherwise fill the map for as long as it lives (review of #1114).
        let mut moved: Vec<(u32, &UnitProc)> = self
            .applied
            .iter()
            .filter(|(pid, known)| !next.contains_key(pid) && self.resolver.still_is(**pid, known))
            .map(|(pid, known)| (*pid, known))
            .collect();
        // Kept at the last scan first, then the oldest: a process moved out later, or started
        // later, never takes the place of one already watched. By pid order, root could evict a
        // moved-out tool with 256 lower pids moved through the unit (review of #1114).
        moved.sort_by_key(|(pid, known)| (!self.moved_kept.contains(pid), known.start, *pid));
        let mut kept = std::collections::BTreeSet::new();
        for (pid, known) in moved {
            if kept.len() >= MAX_MOVED_OUT {
                // Not gated on `moved_logged`: the pid was logged as "still watched" before, and an
                // eviction must still be said. It leaves `applied`, so this is logged once.
                tracing::warn!(
                    pid,
                    unit = %known.unit,
                    "unit_procs: too many processes moved out of the units' cgroups, one is no longer watched"
                );
                continue;
            }
            if self.moved_logged.insert(pid) {
                tracing::warn!(
                    pid,
                    unit = %known.unit,
                    "unit_procs: a security tool process left its unit's cgroup, still watched"
                );
            }
            kept.insert(pid);
            next.insert(pid, known.clone());
        }
        self.moved_kept = kept;
        let (added, removed) = changes(&self.applied, &next);
        for pid in removed {
            match self.set.remove(pid) {
                Ok(_) => {
                    self.applied.remove(&pid);
                }
                // Still in the kernel set: keep it as applied so the next scan asks again, and
                // keep it named, or a process reusing the tgid would be reported as the tool.
                Err(e) => {
                    tracing::warn!(
                        pid,
                        error = %e,
                        "SIGNAL_WATCH_TOOLS: could not stop watching a process, retrying at the next scan"
                    );
                    if let Some(known) = self.applied.get(&pid) {
                        next.insert(pid, known.clone());
                    }
                }
            }
        }
        for pid in added {
            match self
                .set
                .insert(pid, next.get(&pid).and_then(|p| p.sig_cgt).unwrap_or(0))
            {
                Ok(()) => {
                    if let Some(proc) = next.get(&pid) {
                        self.applied.insert(pid, proc.clone());
                    }
                }
                Err(e) => tracing::warn!(
                    pid,
                    error = %e,
                    "SIGNAL_WATCH_TOOLS: could not watch a security tool process, retrying at the next scan"
                ),
            }
        }
        self.moved_logged.retain(|pid| next.contains_key(pid));
        let watched = self.applied.len();
        let mut cache = next.clone();
        for (pid, known) in &self.previous_scan {
            cache.entry(*pid).or_insert_with(|| known.clone());
        }
        self.previous_scan = next;
        *self
            .procs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = cache;
        watched
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// A fake `/sys/fs/cgroup` and `/proc`, removed on drop.
    struct Host {
        root: PathBuf,
    }

    impl Host {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().join(format!(
                "unit-procs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("cgroup")).unwrap();
            fs::create_dir_all(root.join("proc")).unwrap();
            Self { root }
        }

        fn resolver(&self, units: &[&str]) -> UnitResolver {
            UnitResolver::new(&self.root.join("cgroup"), &self.root.join("proc"), units)
        }

        /// Writes `cgroup.procs` of `<slice>/<unit>.service[/<sub>]`.
        fn unit(&self, slice: &str, cgroup: &str, pids: &[u32]) {
            let dir = self.root.join("cgroup").join(slice).join(cgroup);
            fs::create_dir_all(&dir).unwrap();
            let lines: Vec<String> = pids.iter().map(u32::to_string).collect();
            fs::write(dir.join("cgroup.procs"), lines.join("\n") + "\n").unwrap();
        }

        /// `/proc/<pid>/status` with a `SigCgt` mask (hex).
        fn caught(&self, pid: u32, mask: u64) {
            let dir = self.root.join("proc").join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("status"),
                format!("Name:\ttool\nSigBlk:\t0000000000000000\nSigCgt:\t{mask:016x}\n"),
            )
            .unwrap();
        }

        /// The process exits: its `/proc/<pid>` is gone.
        fn gone(&self, pid: u32) {
            let _ = fs::remove_dir_all(self.root.join("proc").join(pid.to_string()));
        }

        fn exe(&self, pid: u32, path: &str) {
            self.exe_started(pid, path, 1000);
        }

        /// `/proc/<pid>` with an exe and a stat line: the command name holds a space and a
        /// parenthesis on purpose, `start` is field 22.
        fn exe_started(&self, pid: u32, path: &str, start: u64) {
            let dir = self.root.join("proc").join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            let _ = fs::remove_file(dir.join("exe"));
            std::os::unix::fs::symlink(path, dir.join("exe")).unwrap();
            fs::write(
                dir.join("stat"),
                format!(
                    "{pid} (my (tool) x) S 1 {pid} {pid} 0 -1 4194560 0 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 100 18446744073709551615\n"
                ),
            )
            .unwrap();
        }
    }

    impl Drop for Host {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_listed_unit_resolves_to_its_processes_with_the_exe_read_at_scan_time() {
        let host = Host::new();
        host.unit("system.slice", "auditd.service", &[612]);
        host.exe(612, "/usr/sbin/auditd");
        let found = host.resolver(&["auditd"]).scan();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[&612],
            UnitProc {
                unit: "auditd".to_owned(),
                exe: Some("/usr/sbin/auditd".to_owned()),
                start: Some(1000),
                sig_cgt: None,
            }
        );
    }

    #[test]
    fn a_process_whose_exe_cannot_be_read_is_still_watched_without_one() {
        let host = Host::new();
        host.unit("system.slice", "falco.service", &[900]);
        let found = host.resolver(&["falco"]).scan();
        assert_eq!(found[&900].exe, None);
    }

    /// A daemon that forks: the main process and its workers, some in a sub-cgroup.
    #[test]
    fn a_daemon_that_forks_is_watched_in_every_process_including_sub_cgroups() {
        let host = Host::new();
        host.unit("system.slice", "wazuh-agent.service", &[700, 701, 702]);
        host.unit("system.slice", "wazuh-agent.service/workers", &[710, 711]);
        host.unit("system.slice", "wazuh-agent.service/workers/deep", &[720]);
        let found = host.resolver(&["wazuh-agent"]).scan();
        let pids: Vec<u32> = found.keys().copied().collect();
        assert_eq!(pids, [700, 701, 702, 710, 711, 720]);
        assert!(found.values().all(|proc| proc.unit == "wazuh-agent"));
    }

    /// A daemon that restarts: the next scan has a new pid and none of the old ones, which is
    /// what [`changes`] turns into the kernel-side edits.
    #[test]
    fn a_restarted_daemon_gives_a_new_pid_and_the_old_one_is_dropped() {
        let host = Host::new();
        host.unit("system.slice", "auditd.service", &[612]);
        let resolver = host.resolver(&["auditd"]);
        let before = resolver.scan();
        host.unit("system.slice", "auditd.service", &[944]);
        let after = resolver.scan();
        let (added, removed) = changes(&before, &after);
        assert_eq!(added, [944]);
        assert_eq!(removed, [612]);
        // Nothing moved: nothing to do.
        assert_eq!(changes(&after, &resolver.scan()), (vec![], vec![]));
    }

    #[test]
    fn a_pid_that_changed_unit_is_dropped_and_added_again() {
        let proc = |unit: &str| UnitProc {
            unit: unit.to_owned(),
            exe: None,
            start: None,
            sig_cgt: None,
        };
        let before = BTreeMap::from([(5, proc("falco"))]);
        let after = BTreeMap::from([(5, proc("osqueryd"))]);
        assert_eq!(changes(&before, &after), (vec![5], vec![]));
    }

    #[test]
    fn only_listed_units_are_resolved() {
        let host = Host::new();
        host.unit("system.slice", "nginx.service", &[300]);
        host.unit("system.slice", "auditd-helper.service", &[301]);
        host.unit("system.slice", "auditd.service", &[302]);
        let found = host.resolver(&["auditd"]).scan();
        assert_eq!(found.keys().copied().collect::<Vec<_>>(), [302]);
    }

    #[test]
    fn a_unit_that_is_not_installed_or_not_running_contributes_nothing() {
        let host = Host::new();
        assert!(host.resolver(&["auditd", "falco"]).scan().is_empty());
        host.unit("system.slice", "falco.service", &[]);
        assert!(host.resolver(&["falco"]).scan().is_empty());
    }

    #[test]
    fn the_hybrid_cgroup_v1_layout_is_read_too() {
        let host = Host::new();
        host.unit("systemd/system.slice", "osqueryd.service", &[410]);
        let found = host.resolver(&["osqueryd"]).scan();
        assert_eq!(found[&410].unit, "osqueryd");
    }

    #[test]
    fn a_unit_listed_in_both_layouts_keeps_one_entry_per_pid() {
        let host = Host::new();
        host.unit("system.slice", "auditd.service", &[612]);
        host.unit("systemd/system.slice", "auditd.service", &[612]);
        assert_eq!(host.resolver(&["auditd"]).scan().len(), 1);
    }

    #[test]
    fn lines_that_are_not_pids_are_ignored() {
        let host = Host::new();
        let dir = host.root.join("cgroup/system.slice/auditd.service");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("cgroup.procs"),
            "612\n\nnot-a-pid\n-4\n99999999999\n613\n",
        )
        .unwrap();
        let found = host.resolver(&["auditd"]).scan();
        assert_eq!(found.keys().copied().collect::<Vec<_>>(), [612, 613]);
    }

    #[test]
    fn the_depth_and_the_process_count_are_bounded() {
        let host = Host::new();
        let mut cgroup = "auditd.service".to_owned();
        for level in 0..=MAX_DEPTH + 2 {
            host.unit("system.slice", &cgroup, &[1000 + level as u32]);
            cgroup.push_str("/c");
        }
        let found = host.resolver(&["auditd"]).scan();
        // The unit's own cgroup plus MAX_DEPTH levels below it.
        assert_eq!(found.len(), MAX_DEPTH + 1);

        let many: Vec<u32> = (1..=(MAX_PROCS_PER_UNIT as u32 + 50)).collect();
        host.unit("system.slice", "falco.service", &many);
        let found = host.resolver(&["falco"]).scan();
        assert_eq!(
            found.values().filter(|proc| proc.unit == "falco").count(),
            MAX_PROCS_PER_UNIT
        );
    }

    /// On whatever host runs the tests (no systemd in a container, a tool or two on a lab VM):
    /// the scan never fails, and what it returns is only listed units.
    #[test]
    fn the_real_host_scan_returns_only_listed_units() {
        for proc in UnitResolver::system().scan().values() {
            assert!(
                schema::SECURITY_SERVICES.contains(&proc.unit.as_str()),
                "{}",
                proc.unit
            );
        }
    }

    /// A kernel-side set that can be told to refuse an insert.
    #[derive(Default)]
    struct FakeSet {
        pids: std::collections::BTreeSet<u32>,
        /// The `SigCgt` mask each pid was last inserted with.
        masks: std::collections::BTreeMap<u32, u64>,
        /// Every successful insert, in order: `(pid, mask)`.
        inserts: Vec<(u32, u64)>,
        refuse: std::collections::BTreeSet<u32>,
        /// Every `remove` fails with an error other than "absent".
        fail_remove: bool,
    }

    impl WatchSet for &mut FakeSet {
        fn insert(&mut self, pid: u32, sig_cgt: u64) -> Result<(), String> {
            if self.refuse.contains(&pid) {
                return Err("full".to_owned());
            }
            self.pids.insert(pid);
            self.masks.insert(pid, sig_cgt);
            self.inserts.push((pid, sig_cgt));
            Ok(())
        }

        fn remove(&mut self, pid: u32) -> Result<bool, String> {
            if self.fail_remove {
                return Err("busy".to_owned());
            }
            Ok(self.pids.remove(&pid))
        }
    }

    #[test]
    fn a_refresh_follows_a_daemon_that_forks_and_restarts() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        host.exe(612, "/usr/sbin/auditd");
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        let procs = watch.procs();
        assert_eq!(procs.lock().unwrap()[&612].unit, "auditd");

        // It forks a worker.
        host.unit("system.slice", "auditd.service", &[612, 613]);
        assert_eq!(watch.refresh(), 2);
        // It restarts: new pid, old one gone, and the same cache handle sees it. The old pids
        // stay nameable for one more scan (their last event may be drained after the rescan).
        host.gone(612);
        host.unit("system.slice", "auditd.service", &[944]);
        assert_eq!(watch.refresh(), 1);
        assert_eq!(
            procs.lock().unwrap().keys().copied().collect::<Vec<_>>(),
            [612, 613, 944]
        );
        assert_eq!(watch.refresh(), 1);
        assert_eq!(
            procs.lock().unwrap().keys().copied().collect::<Vec<_>>(),
            [944]
        );
        drop(watch);
        assert_eq!(set.pids.iter().copied().collect::<Vec<_>>(), [944]);
    }

    #[test]
    fn an_insert_that_fails_is_not_counted_and_is_retried_at_the_next_scan() {
        let host = Host::new();
        let mut set = FakeSet::default();
        set.refuse.insert(612);
        host.unit("system.slice", "auditd.service", &[612]);
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 0, "not watched, so not counted");
        drop(watch);
        assert!(set.pids.is_empty());

        set.refuse.clear();
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
    }

    #[test]
    fn the_start_time_is_field_22_even_with_parentheses_in_the_command_name() {
        let host = Host::new();
        host.exe_started(612, "/usr/sbin/auditd", 4242);
        assert_eq!(host.resolver(&["auditd"]).start_of(612), Some(4242));
        assert_eq!(host.resolver(&["auditd"]).start_of(613), None);
    }

    #[test]
    fn a_pid_reused_by_the_same_program_is_not_kept() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        host.exe(612, "/usr/sbin/auditd");
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        host.unit("system.slice", "auditd.service", &[]);
        host.exe_started(612, "/usr/sbin/auditd", 9999);
        assert_eq!(watch.refresh(), 0);
    }

    #[test]
    fn a_process_with_no_recorded_start_time_is_not_kept_after_leaving_the_cgroup() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        fs::create_dir_all(host.root.join("proc/612")).unwrap();
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        host.unit("system.slice", "auditd.service", &[]);
        assert_eq!(watch.refresh(), 0);
    }

    #[test]
    fn a_remove_that_fails_is_retried_and_the_pid_stays_applied() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        host.unit("system.slice", "auditd.service", &[]);
        watch.set.fail_remove = true;
        assert_eq!(watch.refresh(), 1, "still in the kernel set, still applied");
        assert!(watch.procs().lock().unwrap().contains_key(&612));
        watch.set.fail_remove = false;
        assert_eq!(watch.refresh(), 0);
        drop(watch);
        assert!(set.pids.is_empty());
    }

    #[test]
    fn a_remove_of_a_pid_the_kernel_already_dropped_is_not_an_error() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        watch.set.pids.clear();
        host.unit("system.slice", "auditd.service", &[]);
        assert_eq!(watch.refresh(), 0);
    }

    #[test]
    fn a_tool_moved_out_of_its_cgroup_stays_watched_until_it_exits() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        host.exe(612, "/usr/sbin/auditd");
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        // Root moves it to another cgroup: it is no longer in the unit's `cgroup.procs`.
        host.unit("system.slice", "auditd.service", &[]);
        assert_eq!(watch.refresh(), 1, "still watched");
        assert_eq!(watch.procs().lock().unwrap()[&612].unit, "auditd");
        // It exits: dropped from the set at the next scan.
        host.gone(612);
        assert_eq!(watch.refresh(), 0);
        drop(watch);
        assert!(set.pids.is_empty());
    }

    #[test]
    fn a_pid_reused_by_another_program_is_not_kept() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        host.exe(612, "/usr/sbin/auditd");
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        host.unit("system.slice", "auditd.service", &[]);
        host.gone(612);
        host.exe_started(612, "/usr/bin/sleep", 7777);
        assert_eq!(watch.refresh(), 0);
    }

    #[test]
    fn a_tool_gone_between_two_scans_is_still_named_for_one_more_scan() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612]);
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        watch.refresh();
        host.gone(612);
        host.unit("system.slice", "auditd.service", &[]);
        watch.refresh();
        assert!(watch.procs().lock().unwrap().contains_key(&612));
        watch.refresh();
        assert!(!watch.procs().lock().unwrap().contains_key(&612));
    }

    #[test]
    fn sigcgt_says_whether_a_tool_catches_sighup() {
        let host = Host::new();
        host.unit("system.slice", "auditd.service", &[612, 613, 614]);
        // 612 catches SIGHUP and SIGTERM (bits 0 and 14), 613 catches only SIGTERM, 614 has no status.
        host.caught(612, 1 | (1 << 14));
        host.caught(613, 1 << 14);
        let found = host.resolver(&["auditd"]).scan();
        assert_eq!(found[&612].sig_cgt, Some(1 | (1 << 14)));
        assert_eq!(found[&613].sig_cgt, Some(1 << 14));
        assert_eq!(found[&614].sig_cgt, None, "unknown: reported, not hidden");
    }

    /// The mask the probe reads is the one `refresh` scanned: written at insert, `0` when unknown,
    /// and written again when it changes (a handler installed after the first scan), since both
    /// reload fixes rest on that value.
    #[test]
    fn refresh_writes_the_scanned_sigcgt_to_the_kernel_set() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.unit("system.slice", "auditd.service", &[612, 613]);
        host.caught(612, 1 | (1 << 14));
        // 613 has no status: unknown counts as nothing caught.
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 2);
        assert_eq!(watch.set.masks[&612], 1 | (1 << 14), "the scanned value");
        assert_eq!(watch.set.masks[&613], 0, "an unknown mask is 0");

        // Nothing changed: no second insert.
        watch.refresh();
        assert_eq!(watch.set.inserts.len(), 2);

        // 612 installs a SIGUSR1 handler: the pid is inserted again with the new mask.
        host.caught(612, 1 | (1 << 9) | (1 << 14));
        assert_eq!(watch.refresh(), 2);
        assert_eq!(watch.set.masks[&612], 1 | (1 << 9) | (1 << 14));
        assert_eq!(watch.set.inserts.len(), 3);
        assert_eq!(watch.set.inserts[2].0, 612);
    }

    #[test]
    fn processes_moved_out_of_a_unit_are_kept_up_to_the_cap() {
        let host = Host::new();
        let mut set = FakeSet::default();
        let round =
            |first: u32| -> Vec<u32> { (first..first + MAX_PROCS_PER_UNIT as u32).collect() };
        let (a, b) = (round(1000), round(5000));
        for pid in a.iter().chain(&b) {
            host.exe(*pid, "/usr/sbin/auditd");
        }
        // Round 1: 256 processes in the unit, then moved out while round 2 moves in.
        host.unit("system.slice", "auditd.service", &a);
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), MAX_PROCS_PER_UNIT);
        host.unit("system.slice", "auditd.service", &b);
        assert_eq!(
            watch.refresh(),
            2 * MAX_PROCS_PER_UNIT,
            "256 in the unit plus 256 moved out"
        );
        // Round 2 moves out too: 512 moved-out candidates, kept up to the cap.
        host.unit("system.slice", "auditd.service", &[]);
        assert_eq!(watch.refresh(), MAX_MOVED_OUT);
        // Round 1 was kept at the last scan: it keeps its place, round 2 is the one dropped.
        assert!(a.iter().all(|pid| watch.set.pids.contains(pid)));
        assert!(b.iter().all(|pid| !watch.set.pids.contains(pid)));
    }

    /// Review of #1114: root moves the tool out, then moves 256 processes with lower pids through
    /// the unit and out. By pid order they took the tool's place, silently.
    #[test]
    fn a_moved_out_tool_is_not_displaced_by_lower_pids_moved_out_later() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.exe_started(9000, "/usr/sbin/auditd", 100);
        host.unit("system.slice", "auditd.service", &[9000]);
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        assert_eq!(watch.refresh(), 1);
        host.unit("system.slice", "auditd.service", &[]);
        assert_eq!(watch.refresh(), 1, "moved out, still watched");

        let low: Vec<u32> = (1..=MAX_MOVED_OUT as u32).collect();
        for pid in &low {
            host.exe_started(*pid, "/usr/bin/sleep", 5000);
        }
        host.unit("system.slice", "auditd.service", &low);
        watch.refresh();
        host.unit("system.slice", "auditd.service", &[]);
        assert_eq!(watch.refresh(), MAX_MOVED_OUT);
        assert!(watch.set.pids.contains(&9000), "the tool keeps its place");
    }

    /// Residual, pinned as it is (review of #1114, not redesigned): processes kept at an earlier
    /// scan keep their place, so root can fill the cap first and move the tool out after. The tool
    /// is then evicted (and `refresh` warns, see the eviction branch).
    #[test]
    fn a_tool_moved_out_after_the_cap_is_full_is_evicted() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.exe_started(9000, "/usr/sbin/auditd", 100);
        let low: Vec<u32> = (1..=MAX_MOVED_OUT as u32).collect();
        for pid in &low {
            host.exe_started(*pid, "/usr/bin/sleep", 5000);
        }
        host.unit("system.slice", "auditd.service", &low);
        let mut watch = ToolWatch::new(host.resolver(&["auditd"]), &mut set);
        watch.refresh();
        host.unit("system.slice", "auditd.service", &[9000]);
        assert_eq!(
            watch.refresh(),
            MAX_MOVED_OUT + 1,
            "256 moved out, tool in unit"
        );
        // The squatters stay kept; the tool leaves the unit after the cap is full.
        host.unit("system.slice", "auditd.service", &[]);
        assert_eq!(watch.refresh(), MAX_MOVED_OUT);
        assert!(!watch.set.pids.contains(&9000), "the tool is evicted");
        assert!(low.iter().all(|pid| watch.set.pids.contains(pid)));
    }

    /// Moved out in the same scan, from two units (root can create the cgroup of a listed unit that
    /// is not installed): the cap is shared, and the oldest process is kept, whatever its pid.
    #[test]
    fn the_moved_out_cap_is_shared_by_all_units_and_keeps_the_oldest() {
        let host = Host::new();
        let mut set = FakeSet::default();
        host.exe_started(9000, "/usr/sbin/auditd", 100);
        let low: Vec<u32> = (1..=MAX_MOVED_OUT as u32).collect();
        for pid in &low {
            host.exe_started(*pid, "/usr/bin/sleep", 5000);
        }
        host.unit("system.slice", "auditd.service", &[9000]);
        host.unit("system.slice", "falco.service", &low);
        let mut watch = ToolWatch::new(host.resolver(&["auditd", "falco"]), &mut set);
        assert_eq!(watch.refresh(), MAX_MOVED_OUT + 1);
        host.unit("system.slice", "auditd.service", &[]);
        host.unit("system.slice", "falco.service", &[]);
        assert_eq!(watch.refresh(), MAX_MOVED_OUT, "one cap for all units");
        assert!(watch.set.pids.contains(&9000), "the oldest is kept");
    }

    #[test]
    fn the_number_of_cgroups_read_per_unit_is_bounded() {
        let host = Host::new();
        host.unit("system.slice", "auditd.service", &[1]);
        for n in 0..(MAX_CGROUPS_PER_UNIT as u32 + 100) {
            host.unit(
                "system.slice",
                &format!("auditd.service/sub{n:04}"),
                &[10_000 + n],
            );
        }
        let found = host.resolver(&["auditd"]).scan();
        // The unit's own cgroup plus MAX_CGROUPS_PER_UNIT - 1 sub-cgroups, then the budget is spent.
        assert_eq!(found.len(), MAX_CGROUPS_PER_UNIT.min(MAX_PROCS_PER_UNIT));
    }

    #[test]
    fn a_unit_with_exactly_the_cap_of_cgroups_is_not_truncated() {
        let host = Host::new();
        host.unit("system.slice", "auditd.service", &[1]);
        for n in 0..(MAX_CGROUPS_PER_UNIT as u32 - 1) {
            host.unit("system.slice", &format!("auditd.service/sub{n:04}"), &[]);
        }
        let dir = host.root.join("cgroup/system.slice/auditd.service");
        let (mut budget, mut skipped, mut pids) = (MAX_CGROUPS_PER_UNIT, false, Vec::new());
        collect_procs(&dir, 0, &mut budget, &mut skipped, &mut pids);
        assert_eq!(budget, 0, "the budget is spent");
        assert!(!skipped, "but nothing was left unread");

        host.unit("system.slice", "auditd.service/one-more", &[]);
        let (mut budget, mut skipped, mut pids) = (MAX_CGROUPS_PER_UNIT, false, Vec::new());
        collect_procs(&dir, 0, &mut budget, &mut skipped, &mut pids);
        assert!(skipped, "now one directory is left unread");
    }
}
