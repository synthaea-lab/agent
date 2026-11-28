//! Who may touch a canary without raising: the operator's allow-list of executables, and
//! the table of exec images it is checked against.
//!
//! Asking the OS about a live process (its executable, its mount namespace) is a platform
//! mechanism the caller provides as a [`ProcessLookup`]; nothing here reads `/proc`.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// How the allow-list asks the OS about a live process.
#[derive(Clone, Copy)]
pub struct ProcessLookup {
    /// The executable behind a pid, as a path that means what the allow-list says, or `None`
    /// when it cannot be resolved (the process exited, no access, another mount namespace).
    pub exe: fn(u32) -> Option<PathBuf>,
    /// Whether a pid is positively in another mount namespace than the agent. Unreadable is
    /// not foreign.
    pub in_foreign_mount_namespace: fn(u32) -> bool,
}

impl ProcessLookup {
    /// A host that answers nothing: only the exec table can allow a process.
    pub const UNAVAILABLE: Self = Self {
        exe: |_| None,
        in_foreign_mount_namespace: |_| false,
    };
}

/// What the agent saw when a process executed: the image the sensor reported, and whether the
/// process runs in a container. Kept per pid by [`ExecImages`], so that allowing a process
/// does not depend on reading `/proc` (which needs `CAP_SYS_PTRACE` for another user's).
#[derive(Clone, Debug)]
pub struct ExecImage {
    path: String,
    /// The process incarnation (`process_generation`) that exec'd it, when the sensor stamps one.
    generation: Option<u64>,
    in_container: bool,
    /// Sensor time of the `exec`, ns. An exec that happened after a touch says nothing about
    /// who made the touch (#81 review): only one at or before it may excuse it.
    timestamp_ns: u64,
}

impl ExecImage {
    /// What the sensor reported for this exec.
    #[must_use]
    pub fn from_exec(exec: &schema::ExecEvent) -> Self {
        Self {
            path: exec.image_path.clone(),
            generation: exec.meta.process_generation,
            in_container: exec.meta.container.is_some(),
            timestamp_ns: exec.meta.timestamp_ns,
        }
    }

    /// Sensor time of the exec, in nanoseconds.
    #[must_use]
    pub fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Whether this is the image of an exec that happened at or before `not_after_ns`.
    #[must_use]
    pub fn precedes(&self, not_after_ns: u64) -> bool {
        self.timestamp_ns <= not_after_ns
    }
}

/// Bounded `pid -> image` table fed by `Exec` events. Newest wins (a process that execs again
/// replaces its entry); eviction is counted by the map and costs a `/proc` fallback.
pub struct ExecImages {
    seen: store::BoundedMap<u32, ExecImage>,
}

/// Most pids remembered. An exec is short-lived state: the oldest are dropped first.
const EXEC_IMAGES: usize = 8192;

impl Default for ExecImages {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecImages {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
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
    pub fn record(&mut self, exec: &schema::ExecEvent) {
        self.seen.insert(exec.meta.pid, ExecImage::from_exec(exec));
    }

    /// The image `pid` was seen to execute, if it was and the entry is of this incarnation:
    /// both stamped and equal. An unstamped side is not enough to tell a recycled pid, so it
    /// is not trusted (the caller falls back to `/proc`). A lookup refreshes the entry's
    /// recency: an allowed process that keeps touching canaries must not be evicted by the
    /// execs of everything else, which would make it look unknown again.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn image_of(&mut self, pid: u32, generation: Option<u64>) -> Option<ExecImage> {
        self.image_of_not_after(pid, generation, u64::MAX)
    }

    /// The image `pid` was seen to execute, but only an exec at or before `not_after_ns` (the time of the touch
    /// being judged) counts: the newest entry of a process that exec'd again *after* the touch
    /// is not what made it, and its earlier image was replaced, so nothing is known.
    pub fn image_of_not_after(
        &mut self,
        pid: u32,
        generation: Option<u64>,
        not_after_ns: u64,
    ) -> Option<ExecImage> {
        let seen = self.seen.get(&pid)?;
        match (seen.generation, generation) {
            (Some(a), Some(b)) if a == b && seen.precedes(not_after_ns) => Some(seen.clone()),
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
pub struct CanaryAllow {
    /// Entries as `/proc/<pid>/exe` shows them (symlinks resolved).
    exes: Vec<PathBuf>,
    /// The same entries as the operator wrote them: an exec through the link's name
    /// (`/usr/bin/updatedb`) is reported as written, not resolved.
    as_written: Vec<PathBuf>,
    resolve: fn(u32) -> Option<PathBuf>,
    /// Whether `pid` is positively in another mount namespace than the agent. Unreadable is
    /// not foreign: that is the "`/proc` says nothing" case, which the exec table may decide.
    foreign_mount_ns: fn(u32) -> bool,
}

impl CanaryAllow {
    /// The allow-list of `allow_exe`, which asks `lookup` about live processes. An entry
    /// outside a trusted system location is dropped with a warning rather than honoured.
    #[must_use]
    pub fn new(allow_exe: &[PathBuf], lookup: ProcessLookup) -> Self {
        let mut exes = Vec::new();
        let mut as_written = Vec::new();
        for written in allow_exe {
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
            resolve: lookup.exe,
            foreign_mount_ns: lookup.in_foreign_mount_namespace,
        }
    }

    /// An allow-list of exactly `exe`, neither resolved nor checked for a trusted location.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn for_test(exe: &str, resolve: fn(u32) -> Option<PathBuf>) -> Self {
        Self {
            exes: vec![PathBuf::from(exe)],
            as_written: vec![PathBuf::from(exe)],
            resolve,
            foreign_mount_ns: |_| false,
        }
    }

    /// The same list, for which every process is in another mount namespace.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn in_foreign_mount_ns_for_test(mut self) -> Self {
        self.foreign_mount_ns = |_| true;
        self
    }

    /// Whether nothing is allowed: the exec table has no use then, and the sink does not fill it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exes.is_empty()
    }

    /// Whether the process `pid` runs an allowed executable. `seen` is what the agent recorded
    /// when this incarnation of the pid executed ([`ExecImages::image_of_not_after`], already checked
    /// against the pid's incarnation), if anything; with none, the `/proc` route decides.
    /// The caller passes a clone and holds no lock: the `/proc` read below can be slow.
    #[must_use]
    pub fn allows(&self, pid: u32, seen: Option<&ExecImage>) -> bool {
        if self.exes.is_empty() {
            return false;
        }
        if let Some(image) = seen {
            // A path string is only as good as the namespace that resolved it: a process that is
            // positively in another mount namespace may have bind-mounted its own binary over a
            // listed one, so the table's `bprm->filename` proves nothing about it. (Unreadable
            // is not foreign: see `foreign_mount_ns`.)
            if image.in_container || (self.foreign_mount_ns)(pid) {
                return false;
            }
            // The table is the image of the last `Exec` the agent recorded for this incarnation.
            // The generation is stamped at fork, not at exec, so it cannot tell that the process
            // exec'd again and that event was shed or arrived late. `/proc`, where the agent can
            // read it, shows the image now: if it names something else the entry is stale and
            // the process is not allowed. Where `/proc` says nothing (no ptrace access) the
            // table decides alone, and that residue is documented. The same weakness applies to a
            // touch held for its `exec` and judged with no image: `/proc` is read when the hold
            // ends, so a pid recycled inside the 500 ms by a process running an allowed image
            // would excuse it (narrow: it needs a pid reuse inside the hold).
            // The string checks go first. A name the table does not list is not a refusal: the
            // exec may have gone through a link (`/bin/updatedb` under usrmerge, a `PATH` lookup)
            // that `/proc` canonicalises, so that process takes the `/proc` route below.
            if self.matches_image(&image.path) {
                return match (self.resolve)(pid) {
                    None => true,
                    Some(exe) => {
                        self.exes.contains(&exe) || is_interpreter_of(&exe, Path::new(&image.path))
                    }
                };
            }
        }
        (self.resolve)(pid).is_some_and(|exe| self.exes.contains(&exe))
    }

    /// Whether `/proc` names an executable for `pid`: false for a process that already exited, a
    /// container's or another user's the agent may not read. Lets the sink tell "not allowed"
    /// from "nothing known yet".
    #[must_use]
    pub fn proc_names_an_exe(&self, pid: u32) -> bool {
        (self.resolve)(pid).is_some()
    }

    /// Whether `allows` refuses this process whatever arrives later: it runs in a container, or
    /// positively in another mount namespace, so no image can excuse it. A touch by such a
    /// process is not worth waiting for an `exec` (`allows` above, the same two conditions).
    #[must_use]
    pub fn refuses_outright(&self, pid: u32, seen: Option<&ExecImage>) -> bool {
        seen.is_some_and(|image| image.in_container) || (self.foreign_mount_ns)(pid)
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

/// Whether `exe`, what `/proc/<pid>/exe` shows, is consistent with a process that exec'd the
/// script `image`. A `#!` script runs as its interpreter, so `/proc` names the interpreter and
/// never the script: without this a listed script would be refused whenever `/proc` is
/// readable and allowed whenever it is not. An `env` shebang (`#!/usr/bin/env python3`) names
/// `env` while `/proc` shows the program `env` found, so the interpreter cannot be told from
/// the file: it is accepted when that program is in a trusted system location. A file that is
/// not a script, or cannot be read, never excuses a difference.
fn is_interpreter_of(exe: &Path, image: &Path) -> bool {
    use std::io::Read as _;
    let mut head = [0u8; 256];
    let Ok(mut file) = fs::File::open(image) else {
        return false;
    };
    let Ok(read) = file.read(&mut head) else {
        return false;
    };
    let Some(line) = head[..read].strip_prefix(b"#!") else {
        return false;
    };
    let line = String::from_utf8_lossy(line.split(|&b| b == b'\n').next().unwrap_or_default())
        .into_owned();
    let Some(interpreter) = line.split_whitespace().next().map(Path::new) else {
        return false;
    };
    // `/proc` is readable here, so an `env` shebang is excused only when the program `env` found
    // (through the process's own `PATH`) sits in a trusted location: a user who runs the script
    // with `PATH=/tmp/x:$PATH` must not get their own interpreter allowed.
    (interpreter.file_name().is_some_and(|name| name == "env")
        && policy::name_exclusion_applies(exe.to_str()))
        || canonical_entry(interpreter) == exe
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup that resolves executables with `exe` and calls no process foreign.
    fn answering(exe: fn(u32) -> Option<PathBuf>) -> ProcessLookup {
        ProcessLookup {
            exe,
            ..ProcessLookup::UNAVAILABLE
        }
    }

    fn allow_of(exes: &[&str], resolve: fn(u32) -> Option<PathBuf>) -> CanaryAllow {
        let allow_exe: Vec<PathBuf> = exes.iter().map(PathBuf::from).collect();
        CanaryAllow::new(&allow_exe, answering(resolve))
    }

    #[test]
    fn a_process_running_an_allowed_system_executable_is_allowed() {
        // A trusted-location path that exists on no host: both the allow list and the
        // resolver keep it literal (`canonical_entry` can't resolve it), so they match the
        // same everywhere. The earlier `/usr/bin/updatedb` made the test depend on the host,
        // where that path is a symlink on plocate boxes (#255). The symlink/canonicalize
        // agreement is covered hermetically by `an_entry_that_is_a_symlink_is_compared_by_its_target`.
        const ALLOWED: &str = "/usr/sbin/synthaea-test-allowed";
        let allow = allow_of(&[ALLOWED], |_| Some(ALLOWED.into()));
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
    fn an_exec_name_the_list_does_not_hold_is_judged_by_what_proc_shows() {
        // The table names `/tmp/encryptor`, which no entry matches, so it cannot vouch for the
        // process; `/proc` shows a listed binary, as on `main`, and decides.
        let mut seen = images(&[exec_of(10, Some(1), "/tmp/encryptor", false)]);
        let allow =
            CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/usr/bin/updatedb".into()));
        assert!(allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn a_seen_exec_is_not_trusted_when_proc_shows_the_process_runs_something_else() {
        // The process exec'd an allowed binary, then exec'd `/tmp/payload` and that second
        // event never reached the table: `/proc` is the only witness of the change.
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", false)]);
        let allow = CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/tmp/payload".into()));
        assert!(!allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    /// A script in a temporary directory with `shebang` as its first line, listed as allowed.
    #[cfg(unix)]
    fn listed_script(shebang: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("backup.sh");
        fs::write(&script, format!("{shebang}\necho ok\n")).unwrap();
        let path = script.to_string_lossy().into_owned();
        (dir, path)
    }

    #[cfg(unix)]
    #[test]
    fn a_listed_script_is_allowed_when_proc_shows_its_interpreter() {
        if !Path::new("/bin/sh").exists() {
            return;
        }
        let (_dir, script) = listed_script("#!/bin/sh");
        let mut seen = images(&[exec_of(10, Some(1), &script, false)]);
        let allow = CanaryAllow::for_test(&script, |_| fs::canonicalize("/bin/sh").ok());
        assert!(
            allow.allows(10, seen.image_of(10, Some(1)).as_ref()),
            "/proc names the interpreter of a script, never the script"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_listed_script_is_not_allowed_when_proc_shows_another_program() {
        let (_dir, script) = listed_script("#!/bin/sh");
        let mut seen = images(&[exec_of(10, Some(1), &script, false)]);
        let allow = CanaryAllow::for_test(&script, |_| Some("/tmp/payload".into()));
        assert!(!allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn an_env_shebang_script_is_allowed_when_proc_shows_a_trusted_interpreter() {
        let (_dir, script) = listed_script("#!/usr/bin/env python3");
        let mut seen = images(&[exec_of(10, Some(1), &script, false)]);
        let allow = CanaryAllow::for_test(&script, |_| Some("/usr/bin/python3.12".into()));
        assert!(allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn an_env_shebang_script_is_not_allowed_when_path_made_env_find_an_untrusted_interpreter() {
        // `PATH=/tmp/x:$PATH ./backup.sh` with their own `/tmp/x/python3`: `/proc` is readable
        // and names the program `env` found, which no trusted location holds.
        let (_dir, script) = listed_script("#!/usr/bin/env python3");
        let mut seen = images(&[exec_of(10, Some(1), &script, false)]);
        let allow = CanaryAllow::for_test(&script, |_| Some("/tmp/x/python3".into()));
        assert!(!allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn a_process_in_another_mount_namespace_is_not_allowed_by_the_exec_table_alone() {
        // `unshare -Urm` and a bind mount over a listed binary: the exec reports exactly the
        // listed string and `/proc` cannot be resolved, but the namespace is positively foreign.
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", false)]);
        let mut allow = table_only("/usr/bin/updatedb");
        allow.foreign_mount_ns = |_| true;
        assert!(!allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn a_process_exec_through_another_name_for_a_listed_binary_is_allowed_by_proc() {
        // Exec'd as `/bin/updatedb` (usrmerge, a `PATH` lookup) while the list holds
        // `/usr/bin/updatedb`: the string check fails, `/proc` canonicalises it and decides.
        let mut seen = images(&[exec_of(10, Some(1), "/bin/updatedb", false)]);
        let allow =
            CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/usr/bin/updatedb".into()));
        assert!(allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn a_process_exec_through_an_unlisted_name_stays_denied_when_proc_agrees() {
        let mut seen = images(&[exec_of(10, Some(1), "/tmp/encryptor", false)]);
        let allow = CanaryAllow::for_test("/usr/bin/updatedb", |_| Some("/tmp/encryptor".into()));
        assert!(!allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[test]
    fn a_deleted_listed_binary_is_denied_even_though_the_table_names_it() {
        let mut seen = images(&[exec_of(10, Some(1), "/usr/bin/updatedb", false)]);
        let allow = CanaryAllow::for_test("/usr/bin/updatedb", |_| {
            Some("/usr/bin/updatedb (deleted)".into())
        });
        assert!(!allow.allows(10, seen.image_of(10, Some(1)).as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_is_not_a_script_never_excuses_a_difference_with_proc() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("updatedb");
        fs::write(&binary, b"\x7fELF not a script").unwrap();
        let path = binary.to_string_lossy().into_owned();
        let mut seen = images(&[exec_of(10, Some(1), &path, false)]);
        let allow = CanaryAllow::for_test(&path, |_| Some("/tmp/payload".into()));
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
        let allow = CanaryAllow::new(std::slice::from_ref(&link), answering(|_| None));
        let mut seen = images(&[exec_of(10, Some(1), &link.to_string_lossy(), false)]);
        assert!(
            !allow.allows(10, seen.image_of(10, Some(1)).as_ref()),
            "the link's own name is user-writable, so it cannot vouch for the process"
        );
        // The kernel reports an exec by its resolved path, and `/usr/bin/ls` may itself be a link:
        // on Ubuntu 26.04 it points into the uutils multicall tree (`/usr/lib/cargo/bin/coreutils`).
        let resolved = fs::canonicalize(target).unwrap();
        let mut by_target = images(&[exec_of(11, Some(1), &resolved.to_string_lossy(), false)]);
        assert!(
            allow.allows(11, by_target.image_of(11, Some(1)).as_ref()),
            "the resolved path still matches"
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
                foreign_mount_ns: |_| false,
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
}
