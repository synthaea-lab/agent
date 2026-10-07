//! Canary planting at agent start (issue #81): turns the operator's `[deception]` table
//! into planted decoy files and the [`Tripwires`] the detection sink matches events with.
//!
//! The per-install seed lives in the state directory, next to the inventory. Everything
//! here degrades: a seed that cannot be read or a directory that cannot be written costs
//! the tripwires, never the agent.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use deception::{Inventory, Kind, Placement, Seed, Tripwires};

const SEED_LEN: usize = 32;

fn deception_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("deception")
}

fn inventory_path(state_dir: &Path) -> PathBuf {
    deception_dir(state_dir).join("inventory.json")
}

fn seed_path(state_dir: &Path) -> PathBuf {
    deception_dir(state_dir).join("seed")
}

/// The install's seed: read from the state directory, or generated once and written there
/// with owner-only permissions. A seed file of the wrong length is an error, not a reason
/// to regenerate: new names would orphan the canaries already planted.
fn load_or_create_seed(state_dir: &Path) -> io::Result<Seed> {
    let path = seed_path(state_dir);
    match fs::read(&path) {
        Ok(bytes) => {
            let bytes: [u8; SEED_LEN] = bytes.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "seed file is not 32 bytes")
            })?;
            return Ok(Seed::from_bytes(bytes));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::create_dir_all(deception_dir(state_dir))?;
    let mut bytes = [0u8; SEED_LEN];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(&path)?.write_all(&bytes)?;
    Ok(Seed::from_bytes(bytes))
}

/// Executables the operator declared as legitimate canary readers (indexers, backup
/// agents), matched on the toucher's resolved image path.
///
/// An allow-list keyed on `comm` would let any process rename itself past the tripwire, so
/// the entry must match `/proc/<pid>/exe` and sit in a trusted system location
/// (`policy::name_exclusion_applies`). Anything that cannot be resolved (the process
/// already exited, a non-Linux platform, a binary replaced since: `... (deleted)`) is not
/// allowed. This fails closed, the opposite of the exclusions that keep an unknown path.
pub(crate) struct CanaryAllow {
    exes: Vec<PathBuf>,
    resolve: fn(u32) -> Option<PathBuf>,
}

impl CanaryAllow {
    /// The allow-list of `config`; an entry outside a trusted system location is dropped
    /// with a warning rather than honoured.
    pub(crate) fn new(config: &config::DeceptionConfig) -> Self {
        Self::with_resolver(config, proc_exe)
    }

    fn with_resolver(
        config: &config::DeceptionConfig,
        resolve: fn(u32) -> Option<PathBuf>,
    ) -> Self {
        let exes = config
            .allow_exe
            .iter()
            .filter(|exe| {
                let trusted = policy::name_exclusion_applies(exe.to_str());
                if !trusted {
                    tracing::warn!(
                        exe = %exe.display(),
                        "deception: allow_exe entry is not in a trusted system location, ignored"
                    );
                }
                trusted && exe.to_str().is_some_and(|p| !p.is_empty())
            })
            .cloned()
            .collect();
        Self { exes, resolve }
    }

    #[cfg(test)]
    pub(crate) fn for_test(exe: &str, resolve: fn(u32) -> Option<PathBuf>) -> Self {
        Self {
            exes: vec![PathBuf::from(exe)],
            resolve,
        }
    }

    /// Whether `pid` runs an allowed executable.
    pub(crate) fn allows(&self, pid: u32) -> bool {
        !self.exes.is_empty() && (self.resolve)(pid).is_some_and(|exe| self.exes.contains(&exe))
    }
}

/// The executable behind `pid`. Linux only; elsewhere nothing resolves, so nothing is
/// allowed.
fn proc_exe(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// The configured directories whose canaries the Linux sensor does not report a read of.
///
/// The sensor drops read-only opens under `/tmp`, `/var/tmp`, `/dev/shm` (and everything
/// under `/dev`, `/sys`, `/proc`), so a canary placed there still fires on a delete, rename
/// or write-intent open (the ransomware path) but never on a read (the recon path). The
/// answer comes from the sensor's own filter, so the two cannot drift. Empty off Linux.
fn read_blind_dirs(dirs: &[PathBuf]) -> Vec<&PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        dirs.iter()
            .filter(|dir| {
                let probe = dir.join("canary");
                sensor_linux_wire::is_filtered_path(probe.as_os_str().as_bytes(), 0, false)
            })
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dirs;
        Vec::new()
    }
}

/// Plants the configured canaries and returns the tripwires over everything inventoried.
/// `None` when nothing is configured or planting failed (said in the log).
///
/// With no directories configured, canaries planted by an earlier run are removed: dropping
/// the `[deception]` table is how an operator turns the feature off, and it leaves no residue.
pub(crate) fn start(config: &config::DeceptionConfig, state_dir: &Path) -> Option<Tripwires> {
    let inventory = inventory_path(state_dir);
    if config.canary_dirs.is_empty() {
        retire(&inventory);
        return None;
    }
    let seed = match load_or_create_seed(state_dir) {
        Ok(seed) => seed,
        Err(error) => {
            tracing::error!(%error, "deception: no seed, no canaries planted");
            return None;
        }
    };
    for dir in read_blind_dirs(&config.canary_dirs) {
        tracing::warn!(
            dir = %dir.display(),
            "deception: the sensor does not report read-only opens under this directory, so a \
             canary here fires on delete, rename and write but not on a read; place canaries \
             elsewhere to catch reconnaissance"
        );
    }
    let placements: Vec<Placement> = config
        .canary_dirs
        .iter()
        .map(|dir| Placement {
            dir: dir.clone(),
            kinds: Kind::ALL.to_vec(),
        })
        .collect();
    plant_each_directory(&deception::plan(&seed, &placements), &inventory);
    match Inventory::load(&inventory) {
        Ok(inventory) => Some(Tripwires::from_inventory(&inventory)).filter(|t| !t.is_empty()),
        Err(error) => {
            tracing::error!(%error, "deception: inventory unreadable, no tripwires");
            None
        }
    }
}

/// Plants the canaries one directory at a time, so a directory the agent cannot write (the
/// packaged unit's `ProtectSystem=strict` makes most of the host read-only) costs only its
/// own canaries. The plan is made once for every placement: planning per directory would
/// give each the same names.
fn plant_each_directory(canaries: &[deception::Canary], inventory: &Path) {
    let mut by_dir: Vec<(&Path, Vec<deception::Canary>)> = Vec::new();
    for canary in canaries {
        let dir = canary.path.parent().unwrap_or(Path::new(""));
        match by_dir.iter_mut().find(|(d, _)| *d == dir) {
            Some((_, group)) => group.push(canary.clone()),
            None => by_dir.push((dir, vec![canary.clone()])),
        }
    }
    for (dir, group) in by_dir {
        match deception::plant(&group, inventory) {
            Ok(report) => tracing::info!(
                dir = %dir.display(),
                planted = report.planted.len(),
                unchanged = report.unchanged.len(),
                skipped = report.skipped.len(),
                "deception: canaries planted"
            ),
            Err(error) => tracing::error!(
                dir = %dir.display(),
                %error,
                "deception: planting failed here (is the directory writable by the agent? \
                 the packaged unit needs it in ReadWritePaths, see docs/operations/deception.md)"
            ),
        }
    }
}

/// Removes canaries a previous run planted, when the operator no longer configures any.
fn retire(inventory: &Path) {
    match deception::remove(inventory) {
        Ok(report) => report_removal(&report),
        Err(error) => tracing::error!(%error, "deception: removing old canaries failed"),
    }
}

/// Says what a removal left behind. A canary replaced by someone's own data is left in place
/// and dropped from the inventory, so without this line nobody would learn it is still there.
fn report_removal(report: &deception::RemoveReport) {
    if !report.removed.is_empty() {
        tracing::info!(
            removed = report.removed.len(),
            "deception: canaries removed"
        );
    }
    if !report.foreign.is_empty() {
        tracing::warn!(
            foreign = report.foreign.len(),
            "deception: canaries replaced by other content were left in place and are no \
             longer tracked; look for them by hand"
        );
    }
    if !report.is_clean() {
        tracing::warn!(
            refused = report.refused.len(),
            failed = report.failed.len(),
            "deception: some canaries could not be removed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for(dirs: &[&Path]) -> config::DeceptionConfig {
        config::DeceptionConfig {
            canary_dirs: dirs.iter().map(|d| d.to_path_buf()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn nothing_configured_plants_nothing() {
        let state = tempfile::tempdir().unwrap();
        assert!(start(&config_for(&[]), state.path()).is_none());
        assert!(!deception_dir(state.path()).exists());
    }

    #[test]
    fn configured_directories_get_one_canary_per_kind_and_a_tripwire_each() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let tripwires = start(&config_for(&[dir.path()]), state.path()).unwrap();
        assert_eq!(tripwires.len(), Kind::ALL.len());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), Kind::ALL.len());
    }

    #[test]
    fn a_restart_keeps_the_same_canaries() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = start(&config_for(&[dir.path()]), state.path()).unwrap();
        let second = start(&config_for(&[dir.path()]), state.path()).unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), Kind::ALL.len());
    }

    #[test]
    fn two_installs_get_different_canary_names() {
        let (state_a, state_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        start(&config_for(&[dir_a.path()]), state_a.path()).unwrap();
        start(&config_for(&[dir_b.path()]), state_b.path()).unwrap();
        let names = |d: &Path| -> Vec<_> {
            let mut n: Vec<_> = fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            n.sort();
            n
        };
        assert_ne!(names(dir_a.path()), names(dir_b.path()));
    }

    #[test]
    fn dropping_the_configuration_removes_what_was_planted() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        start(&config_for(&[dir.path()]), state.path()).unwrap();
        assert!(start(&config_for(&[]), state.path()).is_none());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn dropping_the_configuration_leaves_a_canary_replaced_by_the_users_own_data() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        start(&config_for(&[dir.path()]), state.path()).unwrap();
        let mine = fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(&mine, "my own data").unwrap();
        assert!(start(&config_for(&[]), state.path()).is_none());
        assert_eq!(fs::read_to_string(&mine).unwrap(), "my own data");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(!inventory_path(state.path()).exists());
    }

    #[test]
    fn a_truncated_seed_file_plants_nothing_instead_of_renaming_the_canaries() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(deception_dir(state.path())).unwrap();
        fs::write(seed_path(state.path()), b"short").unwrap();
        assert!(start(&config_for(&[dir.path()]), state.path()).is_none());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn the_seed_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let state = tempfile::tempdir().unwrap();
        load_or_create_seed(state.path()).unwrap();
        let mode = fs::metadata(seed_path(state.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Makes `dir` read-only and says whether that bound this process. Root ignores the mode
    /// bits, and then the failure these tests need cannot be produced.
    #[cfg(unix)]
    fn locked(dir: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
        let probe = dir.join("probe");
        let writable = fs::write(&probe, b"x").is_ok();
        let _ = fs::remove_file(probe);
        !writable
    }

    #[cfg(unix)]
    fn unlock(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_the_agent_cannot_write_costs_only_its_own_canaries() {
        let state = tempfile::tempdir().unwrap();
        let (ro, open) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        if !locked(ro.path()) {
            return;
        }
        let tripwires = start(&config_for(&[ro.path(), open.path()]), state.path());
        unlock(ro.path());
        // The agent keeps running with the writable directory's canaries watched.
        assert_eq!(tripwires.unwrap().len(), Kind::ALL.len());
        assert_eq!(fs::read_dir(ro.path()).unwrap().count(), 0);
        assert_eq!(fs::read_dir(open.path()).unwrap().count(), Kind::ALL.len());
    }

    #[cfg(unix)]
    #[test]
    fn when_no_directory_is_writable_there_are_no_tripwires_and_no_inventory_entries() {
        let state = tempfile::tempdir().unwrap();
        let ro = tempfile::tempdir().unwrap();
        if !locked(ro.path()) {
            return;
        }
        let tripwires = start(&config_for(&[ro.path()]), state.path());
        unlock(ro.path());
        assert!(tripwires.is_none());
        let inventory = Inventory::load(&inventory_path(state.path())).unwrap();
        assert!(inventory.entries.is_empty());
    }

    fn allow_of(exes: &[&str], resolve: fn(u32) -> Option<PathBuf>) -> CanaryAllow {
        CanaryAllow::with_resolver(
            &config::DeceptionConfig {
                allow_exe: exes.iter().map(PathBuf::from).collect(),
                ..Default::default()
            },
            resolve,
        )
    }

    #[test]
    fn a_process_running_an_allowed_system_executable_is_allowed() {
        let allow = allow_of(&["/usr/bin/updatedb"], |_| Some("/usr/bin/updatedb".into()));
        assert!(allow.allows(10));
    }

    #[test]
    fn another_executable_is_not_allowed_even_with_the_same_name() {
        let allow = allow_of(&["/usr/bin/updatedb"], |_| Some("/tmp/updatedb".into()));
        assert!(!allow.allows(10));
    }

    #[test]
    fn an_unresolvable_process_is_not_allowed() {
        let allow = allow_of(&["/usr/bin/updatedb"], |_| None);
        assert!(!allow.allows(10));
    }

    #[test]
    fn an_entry_outside_a_trusted_location_is_ignored() {
        let allow = allow_of(&["/tmp/updatedb"], |_| Some("/tmp/updatedb".into()));
        assert!(!allow.allows(10));
    }

    #[test]
    fn a_replaced_binary_is_not_allowed() {
        let allow = allow_of(&["/usr/bin/updatedb"], |_| {
            Some("/usr/bin/updatedb (deleted)".into())
        });
        assert!(!allow.allows(10));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directories_the_sensor_does_not_read_report_are_flagged() {
        let dirs: Vec<PathBuf> = [
            "/tmp/x",
            "/var/tmp",
            "/dev/shm/a",
            "/srv/share",
            "/home/u/docs",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        let blind: Vec<_> = read_blind_dirs(&dirs)
            .into_iter()
            .map(|d| d.to_str().unwrap())
            .collect();
        assert_eq!(blind, ["/tmp/x", "/var/tmp", "/dev/shm/a"]);
    }
}
