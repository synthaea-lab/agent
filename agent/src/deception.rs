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
            .map(|exe| canonical_entry(exe))
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
#[cfg(test)]
pub(crate) fn start(config: &config::DeceptionConfig, state_dir: &Path) -> Option<Tripwires> {
    start_with_decoys(config, state_dir).0
}

/// `start`, and the SHA-256 (lowercase hex) of the decoy tokens found **in the canary files on
/// disk** after planting, for the control plane to recognise one when it is presented. Hashes
/// only: a token never leaves the host. Empty when nothing was planted. The tokens are read
/// back from the files, not taken from the plan: a canary planted by an earlier build keeps
/// its old content (`plant` never overwrites), so the plan's token would be one no file holds.
pub(crate) fn start_with_decoys(
    config: &config::DeceptionConfig,
    state_dir: &Path,
) -> (Option<Tripwires>, Vec<String>) {
    let inventory = inventory_path(state_dir);
    if config.canary_dirs.is_empty() {
        retire(&inventory);
        return (None, Vec::new());
    }
    let seed = match load_or_create_seed(state_dir) {
        Ok(seed) => seed,
        Err(error) => {
            tracing::error!(%error, "deception: no seed, no canaries planted");
            return (None, Vec::new());
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
    let canaries = deception::plan(&seed, &placements);
    let present = plant_each_directory(&canaries, &inventory);
    let decoys = decoy_hashes_on_disk(&canaries, &present);
    match Inventory::load(&inventory) {
        Ok(inventory) => (
            Some(Tripwires::from_inventory(&inventory)).filter(|t| !t.is_empty()),
            decoys,
        ),
        Err(error) => {
            tracing::error!(%error, "deception: inventory unreadable, no tripwires");
            (None, decoys)
        }
    }
}

/// SHA-256 of every decoy token that is in the files of `present` (the canaries `plant` wrote
/// or found unchanged), read back from disk. A canary that was skipped (occupied, missing, in
/// a directory that does not exist) contributes nothing, and neither does one planted by an
/// earlier build whose content has no decoy line: registering a token no file holds would
/// only spend one of the 256 slots a host has.
fn decoy_hashes_on_disk(canaries: &[deception::Canary], present: &[PathBuf]) -> Vec<String> {
    let on_disk: Vec<deception::Canary> = canaries
        .iter()
        .filter(|canary| present.contains(&canary.path))
        .filter_map(|canary| {
            let content = fs::read_to_string(&canary.path).ok()?;
            Some(deception::Canary {
                path: canary.path.clone(),
                kind: canary.kind,
                content,
            })
        })
        .collect();
    deception::decoy_tokens(&on_disk)
        .iter()
        .map(|token| deception::sha256_hex(token.as_bytes()))
        .collect()
}

/// Delays between registration attempts, then the last one repeats. A control plane that is
/// down at start is the ordinary case (the agent starts at boot), so this waits it out for
/// about half a day before giving up; the next start tries again.
const REGISTER_DELAYS: [std::time::Duration; 7] = [
    std::time::Duration::from_secs(5),
    std::time::Duration::from_secs(15),
    std::time::Duration::from_secs(60),
    std::time::Duration::from_secs(300),
    std::time::Duration::from_secs(900),
    std::time::Duration::from_secs(1800),
    std::time::Duration::from_secs(3600),
];

/// Most attempts before giving up for this run.
const REGISTER_ATTEMPTS: usize = 12;

/// What came of registering the decoy hashes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Registration {
    /// The control plane has them.
    Registered { attempts: usize },
    /// The control plane refused them and asking again would not change that.
    Refused { attempts: usize },
    /// Still unreachable after every attempt; the next start tries again.
    GaveUp { attempts: usize },
}

/// Whether asking again cannot change the answer: the control plane called the request itself
/// wrong (400 malformed, 409 over the per-agent bound, 413 too large, 422), or it could not be
/// built (serialization, configuration). Everything else is worth the schedule, including
/// what `TransportError::is_retryable` treats as final: a `429` or `408` from the proxy, a
/// `401`/`403` from a proxy hiccup or a certificate not yet in place, a TLS or I/O error. The
/// thread runs once per start and a daemon may not restart for days, so giving up early costs
/// more than a few extra tries.
fn refusal_will_not_change(error: &transport::TransportError) -> bool {
    match error {
        transport::TransportError::ServerError { status, .. } => {
            matches!(*status, 400 | 409 | 413 | 422)
        }
        transport::TransportError::Serialization(_) | transport::TransportError::Config(_) => true,
        _ => false,
    }
}

/// Calls `register` until it succeeds, is refused for good, or `REGISTER_ATTEMPTS` is spent,
/// sleeping `REGISTER_DELAYS` between tries. `sleep` is injected so the schedule is testable.
pub(crate) fn register_with_retry(
    mut register: impl FnMut() -> Result<(), transport::TransportError>,
    mut sleep: impl FnMut(std::time::Duration),
) -> Registration {
    for attempt in 1..=REGISTER_ATTEMPTS {
        match register() {
            Ok(()) => return Registration::Registered { attempts: attempt },
            Err(error) if refusal_will_not_change(&error) => {
                tracing::error!(%error, "deception: the control plane refused the decoy registration");
                return Registration::Refused { attempts: attempt };
            }
            Err(error) => {
                tracing::warn!(%error, attempt, "deception: decoy registration failed, will retry");
                if attempt < REGISTER_ATTEMPTS {
                    sleep(REGISTER_DELAYS[(attempt - 1).min(REGISTER_DELAYS.len() - 1)]);
                }
            }
        }
    }
    Registration::GaveUp {
        attempts: REGISTER_ATTEMPTS,
    }
}

/// Registers `hashes` with the control plane in the background: a detached thread, so the
/// agent's start and its shutdown never wait for it.
pub(crate) fn register_decoys_in_background(
    client: std::sync::Arc<transport::TransportClient>,
    hashes: Vec<String>,
) {
    if hashes.is_empty() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("decoy-register".into())
        .spawn(move || {
            let outcome =
                register_with_retry(|| client.register_decoy_tokens(&hashes), std::thread::sleep);
            tracing::info!(
                ?outcome,
                count = hashes.len(),
                "deception: decoy registration"
            );
        });
    if let Err(error) = spawned {
        tracing::error!(%error, "deception: could not start the decoy registration thread");
    }
}

/// Plants the canaries one directory at a time, so a directory the agent cannot write (the
/// packaged unit's `ProtectSystem=strict` makes most of the host read-only) costs only its
/// own canaries. The plan is made once for every placement: planning per directory would
/// give each the same names.
fn plant_each_directory(canaries: &[deception::Canary], inventory: &Path) -> Vec<PathBuf> {
    let mut by_dir: Vec<(&Path, Vec<deception::Canary>)> = Vec::new();
    for canary in canaries {
        let dir = canary.path.parent().unwrap_or(Path::new(""));
        match by_dir.iter_mut().find(|(d, _)| *d == dir) {
            Some((_, group)) => group.push(canary.clone()),
            None => by_dir.push((dir, vec![canary.clone()])),
        }
    }
    let mut present = Vec::new();
    for (dir, group) in by_dir {
        match deception::plant(&group, inventory) {
            Ok(report) => {
                tracing::info!(
                    dir = %dir.display(),
                    planted = report.planted.len(),
                    unchanged = report.unchanged.len(),
                    skipped = report.skipped.len(),
                    "deception: canaries planted"
                );
                present.extend(report.planted);
                present.extend(report.unchanged);
            }
            Err(error) => tracing::error!(
                dir = %dir.display(),
                %error,
                "deception: planting failed here (is the directory writable by the agent? \
                 the packaged unit needs it in ReadWritePaths, see docs/operations/deception.md)"
            ),
        }
    }
    present
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

    #[test]
    fn the_decoy_hashes_are_the_hashes_of_the_tokens_in_the_planted_files() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (_, hashes) = start_with_decoys(&config_for(&[dir.path()]), state.path());
        // One token in the credentials canary and one in the config canary.
        assert_eq!(hashes.len(), 2);
        let mut on_disk: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .flat_map(|entry| {
                let text = fs::read_to_string(entry.unwrap().path()).unwrap();
                text.split_whitespace()
                    .filter(|w| w.starts_with("syn_dk_"))
                    .map(|t| deception::sha256_hex(t.as_bytes()))
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut sent = hashes;
        on_disk.sort();
        sent.sort();
        assert_eq!(sent, on_disk);
        assert!(
            sent.iter()
                .all(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        );
    }

    #[test]
    fn a_restart_registers_the_same_hashes() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = start_with_decoys(&config_for(&[dir.path()]), state.path()).1;
        let second = start_with_decoys(&config_for(&[dir.path()]), state.path()).1;
        assert_eq!(first, second);
    }

    #[test]
    fn nothing_configured_registers_nothing() {
        let state = tempfile::tempdir().unwrap();
        assert!(
            start_with_decoys(&config_for(&[]), state.path())
                .1
                .is_empty()
        );
    }

    fn network_error() -> transport::TransportError {
        transport::TransportError::Network("connection refused".into())
    }

    #[test]
    fn registration_that_succeeds_at_once_never_sleeps() {
        let mut sleeps = Vec::new();
        let outcome = register_with_retry(|| Ok(()), |d| sleeps.push(d));
        assert_eq!(outcome, Registration::Registered { attempts: 1 });
        assert!(sleeps.is_empty());
    }

    #[test]
    fn an_unreachable_control_plane_is_waited_out_on_the_schedule() {
        let mut failures = 3;
        let mut sleeps = Vec::new();
        let outcome = register_with_retry(
            || {
                if failures > 0 {
                    failures -= 1;
                    Err(network_error())
                } else {
                    Ok(())
                }
            },
            |d| sleeps.push(d),
        );
        assert_eq!(outcome, Registration::Registered { attempts: 4 });
        assert_eq!(sleeps, REGISTER_DELAYS[..3].to_vec());
    }

    #[test]
    fn a_refusal_that_will_not_change_stops_the_attempts() {
        let mut calls = 0;
        let mut slept = false;
        let outcome = register_with_retry(
            || {
                calls += 1;
                Err(transport::TransportError::ServerError {
                    status: 409,
                    message: "at most 256 decoy tokens per agent".into(),
                })
            },
            |_| slept = true,
        );
        assert_eq!(outcome, Registration::Refused { attempts: 1 });
        assert_eq!(calls, 1);
        assert!(!slept);
    }

    #[test]
    fn registration_gives_up_after_the_attempts_with_the_last_delay_repeated() {
        let mut calls = 0;
        let mut sleeps = Vec::new();
        let outcome = register_with_retry(
            || {
                calls += 1;
                Err(network_error())
            },
            |d| sleeps.push(d),
        );
        assert_eq!(
            outcome,
            Registration::GaveUp {
                attempts: REGISTER_ATTEMPTS
            }
        );
        assert_eq!(calls, REGISTER_ATTEMPTS);
        assert_eq!(
            sleeps.len(),
            REGISTER_ATTEMPTS - 1,
            "no sleep after the last try"
        );
        assert_eq!(sleeps.last(), REGISTER_DELAYS.last());
    }

    /// The plan `start_with_decoys` makes for `config`, for the tests that need the paths.
    fn plan_for(config: &config::DeceptionConfig, seed: &Seed) -> Vec<deception::Canary> {
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

    /// Plants the canaries as an earlier build did: same files, no decoy line, inventoried.
    fn plant_without_decoys(config: &config::DeceptionConfig, state: &Path) {
        let seed = load_or_create_seed(state).unwrap();
        let stripped: Vec<deception::Canary> = plan_for(config, &seed)
            .into_iter()
            .map(|mut canary| {
                canary.content = canary
                    .content
                    .lines()
                    .filter(|line| !line.contains("syn_dk_"))
                    .map(|line| format!("{line}\n"))
                    .collect();
                canary
            })
            .collect();
        deception::plant(&stripped, &inventory_path(state)).unwrap();
    }

    #[test]
    fn canaries_planted_by_an_earlier_build_register_no_token_that_no_file_holds() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&[dir.path()]);
        plant_without_decoys(&config, state.path());
        let (tripwires, hashes) = start_with_decoys(&config, state.path());
        assert!(tripwires.is_some(), "the old canaries still watch");
        assert!(
            hashes.is_empty(),
            "the plan's tokens are in no file: {hashes:?}"
        );
    }

    #[test]
    fn a_directory_that_does_not_exist_contributes_no_decoy_hash() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-created");
        let (_, hashes) = start_with_decoys(&config_for(&[dir.path(), &missing]), state.path());
        assert_eq!(
            hashes.len(),
            2,
            "the two tokens of the directory that exists"
        );
    }

    #[test]
    fn a_canary_replaced_by_the_users_own_file_contributes_no_decoy_hash() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&[dir.path()]);
        let seed = load_or_create_seed(state.path()).unwrap();
        let planned = plan_for(&config, &seed);
        let token_canary = planned
            .iter()
            .find(|c| c.content.contains("syn_dk_"))
            .unwrap();
        fs::write(&token_canary.path, "the user's own file").unwrap();
        let (_, hashes) = start_with_decoys(&config, state.path());
        assert_eq!(hashes.len(), 1, "only the other token-carrying canary");
    }

    #[test]
    fn a_file_that_was_not_planted_is_not_read_for_tokens_even_if_it_holds_one() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&[dir.path()]);
        let seed = load_or_create_seed(state.path()).unwrap();
        let planned = plan_for(&config, &seed);
        // Someone's own file sits at a canary's path and happens to contain a token (a copy
        // of one from elsewhere): `plant` skips it as occupied and it is not ours to register.
        let token_canary = planned
            .iter()
            .find(|c| c.content.contains("syn_dk_"))
            .unwrap();
        fs::write(&token_canary.path, &token_canary.content).unwrap();
        let (_, hashes) = start_with_decoys(&config, state.path());
        assert_eq!(
            hashes.len(),
            1,
            "only the token of the canary that was planted"
        );
    }

    #[test]
    fn only_a_refusal_that_will_not_change_stops_the_attempts() {
        let server_error = |status| transport::TransportError::ServerError {
            status,
            message: String::new(),
        };
        for status in [400, 409, 413, 422] {
            assert!(refusal_will_not_change(&server_error(status)), "{status}");
        }
        for status in [401, 403, 404, 408, 429, 500, 502, 503] {
            assert!(!refusal_will_not_change(&server_error(status)), "{status}");
        }
        assert!(!refusal_will_not_change(&network_error()));
        assert!(!refusal_will_not_change(&transport::TransportError::Tls(
            "certificate expired".into()
        )));
        assert!(refusal_will_not_change(&transport::TransportError::Config(
            "no url".into()
        )));
        let bad_json = serde_json::from_str::<u8>("x").unwrap_err();
        assert!(refusal_will_not_change(&transport::TransportError::from(
            bad_json
        )));
    }

    #[test]
    fn a_429_from_the_proxy_is_retried_on_the_schedule() {
        let mut failures = 2;
        let mut sleeps = Vec::new();
        let outcome = register_with_retry(
            || {
                if failures > 0 {
                    failures -= 1;
                    Err(transport::TransportError::ServerError {
                        status: 429,
                        message: "slow down".into(),
                    })
                } else {
                    Ok(())
                }
            },
            |d| sleeps.push(d),
        );
        assert_eq!(outcome, Registration::Registered { attempts: 3 });
        assert_eq!(sleeps, REGISTER_DELAYS[..2].to_vec());
    }
}
