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

/// What the watch set knows about a watched process, taken at scan time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitProc {
    /// The unit as listed in `SECURITY_SERVICES` (lowercase, no `.service`).
    pub unit: String,
    /// `/proc/<pid>/exe` when it could be read at scan time.
    pub exe: Option<String>,
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
                collect_procs(&dir, 0, &mut pids);
            }
            pids.truncate(MAX_PROCS_PER_UNIT);
            for pid in pids {
                found.entry(pid).or_insert_with(|| UnitProc {
                    unit: unit.clone(),
                    exe: self.exe_of(pid),
                });
            }
        }
        found
    }

    fn exe_of(&self, pid: u32) -> Option<String> {
        let target = fs::read_link(self.proc_root.join(pid.to_string()).join("exe")).ok()?;
        Some(target.to_string_lossy().into_owned())
    }
}

/// The tgids of `dir/cgroup.procs` and of the cgroups below `dir`, in file order.
fn collect_procs(dir: &Path, depth: usize, out: &mut Vec<u32>) {
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
        collect_procs(&child, depth + 1, out);
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
    fn insert(&mut self, pid: u32) -> Result<(), String>;
    fn remove(&mut self, pid: u32) -> Result<(), String>;
}

impl WatchSet for aya::maps::HashMap<aya::maps::MapData, u32, u8> {
    fn insert(&mut self, pid: u32) -> Result<(), String> {
        aya::maps::HashMap::insert(self, pid, 1, 0).map_err(|e| e.to_string())
    }

    fn remove(&mut self, pid: u32) -> Result<(), String> {
        aya::maps::HashMap::remove(self, &pid).map_err(|e| e.to_string())
    }
}

/// What the drain reads to name a target: tgid → unit and exe, as of the last scan.
pub(crate) type ToolProcs = Arc<Mutex<BTreeMap<u32, UnitProc>>>;

/// Keeps the kernel-side watch set equal to the listed units' processes, and the cache the drain
/// enriches from.
///
/// The cache is replaced by each scan, so a tool that died is forgotten one scan later
/// ([`crate::sensor`] rescans every few seconds): an event for it is drained within milliseconds
/// of the signal, and keeping a dead tgid longer would hand its number to an unrelated process
/// that reuses it.
pub(crate) struct ToolWatch<S> {
    resolver: UnitResolver,
    set: S,
    /// What the kernel-side set holds now: an insert that failed is absent, so the next scan
    /// tries it again.
    applied: BTreeMap<u32, UnitProc>,
    procs: ToolProcs,
}

impl<S: WatchSet> ToolWatch<S> {
    pub(crate) fn new(resolver: UnitResolver, set: S) -> Self {
        Self {
            resolver,
            set,
            applied: BTreeMap::new(),
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
        let next = self.resolver.scan();
        let (added, removed) = changes(&self.applied, &next);
        for pid in removed {
            match self.set.remove(pid) {
                Ok(()) => {
                    self.applied.remove(&pid);
                }
                // A tgid that is already gone from the map is what was wanted.
                Err(e) => {
                    tracing::debug!(pid, error = %e, "SIGNAL_WATCH_TOOLS: remove failed");
                    self.applied.remove(&pid);
                }
            }
        }
        for pid in added {
            match self.set.insert(pid) {
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
        let watched = self.applied.len();
        *self
            .procs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
        watched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

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

        fn exe(&self, pid: u32, path: &str) {
            let dir = self.root.join("proc").join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::symlink(path, dir.join("exe")).unwrap();
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
        refuse: std::collections::BTreeSet<u32>,
    }

    impl WatchSet for &mut FakeSet {
        fn insert(&mut self, pid: u32) -> Result<(), String> {
            if self.refuse.contains(&pid) {
                return Err("full".to_owned());
            }
            self.pids.insert(pid);
            Ok(())
        }

        fn remove(&mut self, pid: u32) -> Result<(), String> {
            self.pids
                .remove(&pid)
                .then_some(())
                .ok_or("absent".to_owned())
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
        // It restarts: new pid, old one gone, and the same cache handle sees it.
        host.unit("system.slice", "auditd.service", &[944]);
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
}
