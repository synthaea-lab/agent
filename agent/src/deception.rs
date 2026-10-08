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

/// What the agent saw when a process executed: the image the sensor reported, and whether the
/// process runs in a container. Kept per pid by [`ExecImages`], so that allowing a process
/// does not depend on reading `/proc` (which needs `CAP_SYS_PTRACE` for another user's).
#[derive(Clone, Debug)]
pub(crate) struct ExecImage {
    path: String,
    /// The process incarnation (`process_generation`) that exec'd it, when the sensor stamps one.
    generation: Option<u64>,
    in_container: bool,
}

/// Bounded `pid -> image` table fed by `Exec` events. Newest wins (a process that execs again
/// replaces its entry); eviction is counted by the map and costs a `/proc` fallback.
pub(crate) struct ExecImages {
    seen: store::BoundedMap<u32, ExecImage>,
}

/// Most pids remembered. An exec is short-lived state: the oldest are dropped first.
const EXEC_IMAGES: usize = 8192;

impl ExecImages {
    pub(crate) fn new() -> Self {
        Self {
            seen: store::BoundedMap::new(EXEC_IMAGES),
        }
    }

    #[cfg(test)]
    fn with_capacity(cap: usize) -> Self {
        Self {
            seen: store::BoundedMap::new(cap),
        }
    }

    /// Records the image a process executed.
    pub(crate) fn record(&mut self, exec: &schema::ExecEvent) {
        self.seen.insert(
            exec.meta.pid,
            ExecImage {
                path: exec.image_path.clone(),
                generation: exec.meta.process_generation,
                in_container: exec.meta.container.is_some(),
            },
        );
    }

    /// The image `pid` was seen to execute, if it was and the entry is of this incarnation:
    /// both stamped and equal. An unstamped side is not enough to tell a recycled pid, so it
    /// is not trusted (the caller falls back to `/proc`). A lookup refreshes the entry's
    /// recency: an allowed process that keeps touching canaries must not be evicted by the
    /// execs of everything else, which would make it look unknown again.
    pub(crate) fn image_of(&mut self, pid: u32, generation: Option<u64>) -> Option<ExecImage> {
        let seen = self.seen.get(&pid)?;
        match (seen.generation, generation) {
            (Some(a), Some(b)) if a == b => Some(seen.clone()),
            _ => None,
        }
    }
}

/// Executables the operator declared as legitimate canary readers (indexers, backup
/// agents), matched on the toucher's image, never its name.
///
/// An allow-list keyed on `comm` would let any process rename itself past the tripwire. The
/// image comes from the process's own `Exec` event when the agent saw it start (the kernel's
/// `bprm->filename`, which is what the sensor reports as `image_path`), and from
/// `/proc/<pid>/exe` otherwise (a process that predates the agent). Either way the entry sits
/// in a trusted system location (`policy::name_exclusion_applies`) and anything that cannot be
/// resolved (the process exited, a non-Linux platform, a binary replaced since: `(deleted)`,
/// a container, a relative exec) is not allowed. This fails closed, the opposite of the
/// exclusions that keep an unknown path.
pub(crate) struct CanaryAllow {
    /// Entries as `/proc/<pid>/exe` shows them (symlinks resolved).
    exes: Vec<PathBuf>,
    /// The same entries as the operator wrote them: an exec through the link's name
    /// (`/usr/bin/updatedb`) is reported as written, not resolved.
    as_written: Vec<PathBuf>,
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
        let mut exes = Vec::new();
        let mut as_written = Vec::new();
        for written in &config.allow_exe {
            let canonical = canonical_entry(written);
            let trusted = policy::name_exclusion_applies(canonical.to_str());
            if !trusted {
                tracing::warn!(
                    exe = %canonical.display(),
                    "deception: allow_exe entry is not in a trusted system location, ignored"
                );
            }
            if trusted && canonical.to_str().is_some_and(|p| !p.is_empty()) {
                exes.push(canonical);
                // The name an exec is reported under is matched as text, so it must sit in a
                // trusted location itself: a user-writable link (`/tmp/tools/updatedb` to
                // `/usr/bin/updatedb`) passes the canonical check, and whoever can repoint it
                // would be allowed. Without it only the resolved path matches.
                if policy::name_exclusion_applies(written.to_str()) {
                    as_written.push(written.clone());
                } else {
                    tracing::warn!(
                        exe = %written.display(),
                        "deception: allow_exe entry resolves to a trusted location but its own \
                         path is not in one; an exec through that name is not matched"
                    );
                }
            }
        }
        Self {
            exes,
            as_written,
            resolve,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(exe: &str, resolve: fn(u32) -> Option<PathBuf>) -> Self {
        Self {
            exes: vec![PathBuf::from(exe)],
            as_written: vec![PathBuf::from(exe)],
            resolve,
        }
    }

    /// Whether the process `pid` runs an allowed executable. `seen` is what the agent recorded
    /// when this incarnation of the pid executed ([`ExecImages::image_of`], already checked
    /// against the pid's incarnation), if anything; with none, the `/proc` route decides.
    /// The caller passes a clone and holds no lock: the `/proc` read below can be slow.
    pub(crate) fn allows(&self, pid: u32, seen: Option<&ExecImage>) -> bool {
        if self.exes.is_empty() {
            return false;
        }
        let now = (self.resolve)(pid);
        match seen {
            // The table is the image of the last `Exec` the agent recorded for this incarnation.
            // The generation is stamped at fork, not at exec, so it cannot tell that the process
            // exec'd again and that event was shed or arrived late. `/proc`, where the agent can
            // read it, shows the image now: if it names something else the entry is stale and
            // the process is not allowed. Where `/proc` says nothing (no ptrace access, another
            // mount namespace) the table decides alone, and that residue is documented.
            Some(image) => {
                !image.in_container
                    && self.matches_image(&image.path)
                    && now.is_none_or(|exe| self.exes.contains(&exe))
            }
            None => now.is_some_and(|exe| self.exes.contains(&exe)),
        }
    }

    /// An absolute image equal to an entry, resolved or as written. A relative exec
    /// (`./updatedb`) names nothing and never matches.
    fn matches_image(&self, image: &str) -> bool {
        is_absolute_image(image) && {
            let path = Path::new(image);
            self.exes.iter().any(|e| e == path) || self.as_written.iter().any(|e| e == path)
        }
    }
}

/// Whether an image path from a sensor names an absolute location. Decided on the string, not
/// with `Path::is_absolute`: that follows the rules of the host the agent runs on, and a
/// Linux sensor's `/usr/bin/updatedb` has no drive letter, so it is not absolute on Windows
/// (a Windows build compiles this code and its tests too). A leading separator, a drive
/// letter or a UNC prefix counts; `./updatedb` and `updatedb` do not.
fn is_absolute_image(image: &str) -> bool {
    let bytes = image.as_bytes();
    image.starts_with('/')
        || image.starts_with('\\')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/'))
}

/// An entry as `/proc/<pid>/exe` will show it: with symlinks resolved. `/usr/bin/updatedb`
/// is a link to `updatedb.plocate` on Debian and `/bin/x` is `/usr/bin/x` under usrmerge, and
/// the kernel reports the real file, so an entry under the link's name would never match.
/// An entry that does not resolve (not installed here) is kept as written: it can only match
/// by being exactly what the kernel reports.
fn canonical_entry(exe: &Path) -> PathBuf {
    fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf())
}

/// The mount namespace of `pid` (`mnt:[inode]`), `None` when it cannot be read.
#[cfg(target_os = "linux")]
fn mount_namespace(pid: impl std::fmt::Display) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()
}

/// The executable behind `pid`, as a path the agent can compare with its allow-list. Linux
/// only; elsewhere nothing resolves, so nothing is allowed.
///
/// A process in another mount namespace (a container, a chroot) reports a path in *its* view,
/// so its own `/usr/bin/updatedb` would equal the host's. Such a process is not resolved:
/// the agent's namespace is the only one in which a path means what the allow-list says.
/// Reading either namespace link of another user's process needs the same ptrace access as
/// `/proc/<pid>/exe` does, so where the agent lacks it nothing resolves and the hit is raised.
fn proc_exe(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        if mount_namespace(pid)? != mount_namespace("self")? {
            return None;
        }
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
    let canaries = planned_canaries(config, &seed);
    plant_each_directory(&canaries, &inventory);
    // A canary deleted while the agent was down is put back now; see `refresh_once`.
    refresh_once(&canaries, &inventory);
    match Inventory::load(&inventory) {
        Ok(inventory) => Some(Tripwires::from_inventory(&inventory)).filter(|t| !t.is_empty()),
        Err(error) => {
            tracing::error!(%error, "deception: inventory unreadable, no tripwires");
            None
        }
    }
}

/// The canaries `config` calls for, named and filled from `seed`: the same on every call.
fn planned_canaries(config: &config::DeceptionConfig, seed: &Seed) -> Vec<deception::Canary> {
    let placements: Vec<Placement> = config
        .canary_dirs
        .iter()
        .map(|dir| Placement {
            dir: dir.clone(),
            kinds: Kind::ALL.to_vec(),
        })
        .collect();
    deception::plan(seed, &placements)
}

/// How often the refresh puts back canaries that were deleted while the agent runs.
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// The refresh policy (issue #81): a planted canary that is gone is planted again, with the
/// content it had, so the decoy is there for the next intruder. It fills gaps and nothing
/// else: a file that was modified or replaced is left alone and counted, and a canary the
/// inventory does not know is not planted here. The deletion itself was already a tripwire
/// hit (a delete of a canary), so restoring it hides nothing.
pub(crate) fn refresh_once(canaries: &[deception::Canary], inventory: &Path) {
    match deception::refresh(canaries, inventory) {
        Ok(report) => {
            if !report.restored.is_empty() {
                tracing::info!(
                    restored = report.restored.len(),
                    "deception: deleted canaries replanted"
                );
            }
            if !report.changed.is_empty() || !report.unrestorable.is_empty() {
                tracing::warn!(
                    changed = report.changed.len(),
                    unrestorable = report.unrestorable.len(),
                    "deception: some canaries are not as planted and were left alone"
                );
            }
        }
        Err(error) => tracing::error!(%error, "deception: refresh failed"),
    }
}

/// Runs [`refresh_once`] every [`REFRESH_INTERVAL`] in a detached thread: nothing waits for it.
pub(crate) fn spawn_refresh(config: config::DeceptionConfig, state_dir: PathBuf) {
    if config.canary_dirs.is_empty() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("deception-refresh".into())
        .spawn(move || {
            loop {
                std::thread::sleep(REFRESH_INTERVAL);
                match load_or_create_seed(&state_dir) {
                    Ok(seed) => refresh_once(
                        &planned_canaries(&config, &seed),
                        &inventory_path(&state_dir),
                    ),
                    Err(error) => tracing::error!(%error, "deception: refresh has no seed"),
                }
            }
        });
    if let Err(error) = spawned {
        tracing::error!(%error, "deception: could not start the refresh thread");
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
        assert!(allow.allows(10, None));
    }

    #[test]
    fn another_executable_is_not_allowed_even_with_the_same_name() {
        let allow = allow_of(&["/usr/bin/updatedb"], |_| Some("/tmp/updatedb".into()));
        assert!(!allow.allows(10, None));
    }

    #[test]
    fn an_unresolvable_process_is_not_allowed() {
        let allow = allow_of(&["/usr/bin/updatedb"], |_| None);
        assert!(!allow.allows(10, None));
    }

    #[test]
    fn an_entry_outside_a_trusted_location_is_ignored() {
        let allow = allow_of(&["/tmp/updatedb"], |_| Some("/tmp/updatedb".into()));
        assert!(!allow.allows(10, None));
    }

    #[test]
    fn a_replaced_binary_is_not_allowed() {
        let allow = allow_of(&["/usr/bin/updatedb"], |_| {
            Some("/usr/bin/updatedb (deleted)".into())
        });
        assert!(!allow.allows(10, None));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn the_executable_of_the_agents_own_process_resolves() {
        let exe = proc_exe(std::process::id()).expect("own exe in own namespace");
        assert_eq!(
            exe,
            fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_pid_that_does_not_exist_does_not_resolve() {
        assert!(mount_namespace(u32::MAX).is_none());
        assert!(proc_exe(u32::MAX).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_in_another_mount_namespace_does_not_resolve() {
        // `unshare` needs privilege that CI and a normal user lack; where it is not
        // available there is nothing to test, and the comparison itself is a one-line
        // inequality on the two links.
        let Ok(child) = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "sleep", "5"])
            .spawn()
        else {
            return;
        };
        let mut child = child;
        std::thread::sleep(std::time::Duration::from_millis(300));
        let theirs = mount_namespace(child.id());
        let ours = mount_namespace("self");
        let resolved = proc_exe(child.id());
        let _ = child.kill();
        let _ = child.wait();
        if theirs.is_some() && theirs != ours {
            assert!(
                resolved.is_none(),
                "another mount namespace must not resolve"
            );
        }
    }

    #[test]
    fn an_entry_that_is_a_symlink_is_compared_by_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("updatedb.plocate");
        fs::write(&target, b"x").unwrap();
        let link = dir.path().join("updatedb");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(not(unix))]
        fs::write(&link, b"x").unwrap();
        let resolved = fs::canonicalize(&target).unwrap();
        #[cfg(unix)]
        assert_eq!(canonical_entry(&link), resolved);
        assert_eq!(canonical_entry(&target), resolved);
    }

    #[test]
    fn an_entry_that_does_not_resolve_is_kept_as_written() {
        let missing = Path::new("/usr/sbin/not-installed-here");
        assert_eq!(canonical_entry(missing), missing);
    }

    fn exec_of(
        pid: u32,
        generation: Option<u64>,
        image: &str,
        in_container: bool,
    ) -> schema::ExecEvent {
        let mut e = schema::fixtures::exec();
        e.meta.pid = pid;
        e.meta.process_generation = generation;
        e.meta.container = in_container.then(|| schema::ContainerContext {
            id: "abc".into(),
            image: None,
            name: None,
        });
        e.image_path = image.into();
        e
    }

    fn images(execs: &[schema::ExecEvent]) -> ExecImages {
        let mut images = ExecImages::new();
        for e in execs {
            images.record(e);
        }
        images
    }

    /// An allow-list whose `/proc` fallback always fails: only the exec table can allow.
    fn table_only(entry: &str) -> CanaryAllow {
        CanaryAllow::for_test(entry, |_| None)
    }

    #[test]
    fn a_process_whose_exec_was_seen_is_allowed_without_reading_proc() {
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", false)]);
        assert!(table_only("/usr/bin/updatedb").allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn the_exec_table_overrides_what_proc_would_say() {
        let mut seen = images(&[exec_of(10, Some(1), "/tmp/encryptor", false)]);
        let allow =
            CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/usr/bin/updatedb".into()));
        assert!(
            !allow.allows(10, seen.image_of(10, Some(1)).as_ref()),
            "the image the agent saw wins"
        );
    }

    #[test]
    fn a_seen_exec_is_not_trusted_when_proc_shows_the_process_runs_something_else() {
        // The process exec'd an allowed binary, then exec'd `/tmp/payload` and that second
        // event never reached the table: `/proc` is the only witness of the change.
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", false)]);
        let allow = CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/tmp/payload".into()));
        assert!(!allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn a_seen_exec_is_allowed_when_proc_agrees_with_it() {
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", false)]);
        let allow =
            CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/usr/bin/updatedb".into()));
        assert!(allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn an_entry_that_is_read_again_survives_the_eviction_of_newer_ones() {
        let mut seen = ExecImages::with_capacity(3);
        seen.record(&exec_of(1, Some(1), "/usr/bin/updatedb", false));
        seen.record(&exec_of(2, Some(1), "/usr/bin/a", false));
        seen.record(&exec_of(3, Some(1), "/usr/bin/b", false));
        assert!(seen.image_of(1, Some(1)).is_some(), "read: now the newest");
        seen.record(&exec_of(4, Some(1), "/usr/bin/c", false));
        assert!(
            seen.image_of(1, Some(1)).is_some(),
            "pid 2 was the oldest and went, not the one read since"
        );
        assert!(seen.image_of(2, Some(1)).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn an_exec_through_a_link_outside_a_trusted_location_is_not_matched_by_its_name() {
        // `/usr/bin/ls` stands for a real binary in a trusted location; the link to it lives in
        // a temporary directory, which is not one.
        let target = Path::new("/usr/bin/ls");
        if !target.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("updatedb");
        std::os::unix::fs::symlink(target, &link).unwrap();
        let mut config = config_for(&[]);
        config.allow_exe = vec![link.clone()];
        let allow = CanaryAllow::with_resolver(&config, |_| None);
        let mut seen = images(&[exec_of(10, Some(1), &link.to_string_lossy(), false)]);
        assert!(
            !allow.allows(10, seen.image_of(10, Some(1)).as_ref()),
            "the link's own name is user-writable, so it cannot vouch for the process"
        );
        let mut by_target = images(&[exec_of(11, Some(1), "/usr/bin/ls", false)]);
        assert!(
            allow.allows(11, by_target.image_of(11, Some(1)).as_ref()),
            "the resolved path still matches"
        );
    }

    #[test]
    fn a_canary_deleted_while_the_agent_was_down_is_back_after_a_restart() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        start(&config_for(&[dir.path()]), state.path()).unwrap();
        let gone = fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let content = fs::read_to_string(&gone).unwrap();
        fs::remove_file(&gone).unwrap();
        start(&config_for(&[dir.path()]), state.path()).unwrap();
        assert_eq!(
            fs::read_to_string(&gone).unwrap(),
            content,
            "replanted as it was"
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), Kind::ALL.len());
    }

    #[test]
    fn refresh_once_replants_a_deleted_canary_and_leaves_a_replaced_one() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&[dir.path()]);
        start(&config, state.path()).unwrap();
        let seed = load_or_create_seed(state.path()).unwrap();
        let canaries = planned_canaries(&config, &seed);
        fs::remove_file(&canaries[0].path).unwrap();
        fs::write(&canaries[1].path, "the user's own file").unwrap();
        refresh_once(&canaries, &inventory_path(state.path()));
        assert!(canaries[0].path.exists());
        assert_eq!(
            fs::read_to_string(&canaries[1].path).unwrap(),
            "the user's own file"
        );
    }

    #[test]
    fn a_recycled_pid_is_not_taken_for_the_process_that_was_seen() {
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", false)]);
        // Another incarnation of pid 10: the entry is not its, and /proc says nothing.
        assert!(!table_only("/usr/bin/updatedb").allows(10, seen.image_of(10, Some(2)).as_ref()));
    }

    #[test]
    fn an_unstamped_process_is_not_trusted_from_the_table() {
        let mut seen = images(&[exec_of(10, None, "/usr/bin/updatedb", false)]);
        assert!(!table_only("/usr/bin/updatedb").allows(10, seen.image_of(10, None).as_ref()));
    }

    #[test]
    fn a_process_in_a_container_is_not_allowed_even_with_an_allowed_image() {
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", true)]);
        assert!(!table_only("/usr/bin/updatedb").allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn a_relative_exec_never_matches() {
        let mut seen = images(&[exec_of(10, Some(1), "./updatedb", false)]);
        assert!(!table_only("./updatedb").allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn an_exec_through_the_name_the_operator_wrote_matches_a_resolved_entry() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("updatedb.plocate");
        fs::write(&target, b"x").unwrap();
        #[cfg(unix)]
        {
            let link = dir.path().join("updatedb");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            // The sensor reports the path the exec was given: the link's name.
            let as_exec = link.to_string_lossy().into_owned();
            let canonical = fs::canonicalize(&target).unwrap();
            let allow = CanaryAllow {
                exes: vec![canonical],
                as_written: vec![link],
                resolve: |_| None,
            };
            let mut seen = images(&[exec_of(10, Some(1), &as_exec, false)]);
            assert!(allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
        }
    }

    #[test]
    fn a_process_the_agent_never_saw_exec_falls_back_to_proc() {
        let allow =
            CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/usr/bin/updatedb".into()));
        assert!(allow.allows(10, ExecImages::new().image_of(10, Some(1)).as_ref()));
        assert!(allow.allows(10, None));
    }

    #[test]
    fn the_exec_table_is_bounded() {
        let mut images = ExecImages::new();
        for pid in 0..(EXEC_IMAGES as u32 + 100) {
            images.record(&exec_of(pid, Some(1), "/usr/bin/x", false));
        }
        assert!(images.seen.len() <= EXEC_IMAGES);
        assert!(images.seen.evicted() > 0);
    }

    #[test]
    fn an_image_is_absolute_by_its_text_on_every_host() {
        for absolute in [
            "/usr/bin/updatedb",
            "C:\\Windows\\x.exe",
            "c:/x.exe",
            "\\\\host\\share\\x.exe",
        ] {
            assert!(is_absolute_image(absolute), "{absolute}");
        }
        for relative in [
            "",
            "updatedb",
            "./updatedb",
            "../bin/updatedb",
            "bin/updatedb",
            "C:x.exe",
        ] {
            assert!(!is_absolute_image(relative), "{relative}");
        }
    }

    #[test]
    fn no_refresh_thread_without_canary_directories() {
        // An empty config returns before any thread exists: nothing to assert but no panic.
        spawn_refresh(config_for(&[]), PathBuf::from("/nonexistent"));
    }
}
