//! Path-prefix filtering shared by every Linux file-event probe (issue #262): drops
//! high-volume virtual-filesystem/scratch-space paths before they reach the ring
//! buffer.
//!
//! Not a bare prefix list — dropping is conditioned on `(prefix, access intent)`.
//! Issue #325 (the original filter) unconditionally dropped `/proc/`, `/dev/`,
//! `/sys/`, and `/tmp/`, which silently made `check_proc_root_escape` (T1611) and
//! the spawn+connect+filewrite dropper-chain correlation unreachable: `/tmp/`,
//! `/var/tmp/`, and `/dev/shm/` are dropper/payload staging grounds as much as they
//! are noisy scratch space (issue #426). A read-only open there — loading a shared
//! library, `cat`-ing a file — is the noise #325 was written to cut; a write-intent
//! open (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`) or any of
//! delete/rename/chmod/chown/setxattr/removexattr is the payload lifecycle itself,
//! and is never dropped there. `/dev/` (minus `/dev/shm/`, handled above) and
//! `/sys/` are unconditional, unchanged from #325, with one exception: a write-intent open of
//! a cgroup limit file (`memory.max`, `cgroup.freeze`...) is how a security tool is ended or
//! frozen without a signal, and passes ([`is_cgroup_limit_write`], #49).
//!
//! `/proc/` gets the same intent rule as the tmp family, not the unconditional
//! drop #429 originally gave it (review on #429/#426): `/proc/<pid>/root/...` is
//! not the only way to reach a real file through procfs — `/proc/self/root/...`
//! and `/proc/self/cwd/...` resolve through the kernel exactly the same way
//! (`/proc/self/root/etc/cron.d/x` *is* `/etc/cron.d/x`), and `self` isn't
//! numeric, so [`is_proc_pid_root`]'s pid check never recognises it. Special-casing
//! `self` (and `cwd`) would only chase the next alias; conditioning the whole
//! `/proc/` prefix on write intent, like `/tmp/`, closes the class instead: a
//! write/mutation reaching a real path through *any* procfs alias now always
//! passes, and plain reads of procfs pseudo-files (`/proc/self/status`,
//! `/proc/sys/...`) — the volume #325 was written to cut — stay filtered.
//!
//! [`is_filtered_path`] takes plain `(flags: i64, is_mutation: bool)` rather than a
//! payload-carrying `enum` — an earlier version used `enum PathAccess { Open(i64),
//! Mutation }`, which the kernel verifier rejected on `sys_enter_unlink` with `R4
//! !read_ok`: constructing the no-payload `Mutation` variant leaves the enum's
//! `i64`-sized payload slot uninitialised, and passing the enum by value across this
//! function-call boundary reads that whole slot regardless of which variant is live.
//! Harmless on a normal target (the discriminant gates which bytes are ever used);
//! rejected outright by BPF's stricter "no reading uninitialised stack" rule. Two
//! always-initialised primitives sidestep it entirely.
//!
//! No new loops in this file. Everything here is inlined into each of the 14 file
//! programs, so every loop multiplies verifier state across all of them: two small
//! `while`-skip-the-slashes loops (d2f48bc) were enough to push every file program
//! past the 1M-instruction limit on 5.15 (12/26 programs loaded, #429 review). The
//! one existing loop, the pid-digit scan in [`is_proc_pid_root`], was already there
//! and verified; prefer a fail-open early return over another loop.

const O_WRONLY: i64 = 0o1;
const O_RDWR: i64 = 0o2;
const O_CREAT: i64 = 0o100;
const O_TRUNC: i64 = 0o1000;

fn is_write_intent(flags: i64) -> bool {
    flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) != 0
}

/// Whether `path` is `/proc/<pid>/root` or anything under it — a numeric pid
/// segment, nothing else. `no_std`-safe: byte-slice parsing only, no allocation.
///
/// `.get()` throughout, never `path[i]`/`&path[a..b]`: a direct index/range panics
/// (and generates a panic branch) on out-of-bounds, and the `no_std` bpfel target's
/// panic handler is an infinite loop — illegal for the kernel verifier, which
/// rejected `sys_enter_openat` with "last insn is not an exit or jmp" the one time
/// this function used direct indexing. `.get()` returns `Option`, so every path
/// through this function provably terminates. (An earlier iterator-combinator
/// version, `strip_prefix`/`position`/`split_at`/`iter().all`, avoided panics too but
/// verified so slowly probe load never finished within 15s+ on any of this
/// function's 7 call sites — replaced for that, unrelated, reason.)
fn is_proc_pid_root(path: &[u8]) -> bool {
    const PREFIX: &[u8] = b"/proc/";
    let Some(prefix) = path.get(..PREFIX.len()) else {
        return false;
    };
    if prefix != PREFIX {
        return false;
    }

    // The kernel collapses repeated `/`, so `/proc//1//root/etc/shadow` opens the
    // same file as `/proc/1/root/etc/shadow` (#429 review). Skipping the run of
    // slashes takes a loop per separator, and those two loops pushed every file
    // program over the 1M-instruction verifier limit on 5.15. So fail open: a
    // doubled slash at either separator counts as a match. No legitimate program
    // writes these paths, so it costs no volume, and the event reaches
    // `check_proc_root_escape`, which already skips empty segments.
    let mut i = PREFIX.len();
    if matches!(path.get(i), Some(&b'/')) {
        return true;
    }
    let pid_start = i;
    loop {
        let Some(&b) = path.get(i) else {
            return false;
        };
        if b == b'/' {
            break;
        }
        if !b.is_ascii_digit() {
            return false;
        }
        i += 1;
    }
    if i == pid_start {
        return false;
    }
    // path[i] == b'/' here — the pid/root separator.

    let root_start = i + 1;
    if matches!(path.get(root_start), Some(&b'/')) {
        return true;
    }
    const ROOT: &[u8] = b"root";
    let Some(root_slice) = path.get(root_start..root_start + ROOT.len()) else {
        return false;
    };
    if root_slice != ROOT {
        return false;
    }
    matches!(path.get(root_start + ROOT.len()), None | Some(&b'/'))
}

/// Whether `path` is a write to a cgroup control file that ends, freezes or starves the unit it
/// sits in (<https://github.com/synthaea-lab/agent/issues/49>): `memory.max`, `memory.high`,
/// `pids.max` (and any other `*.max`, `cpu.max` included), `cgroup.freeze`, and the cgroup v1
/// `freezer.state` and `memory.*_in_bytes`.
///
/// `echo 1M > .../auditd.service/memory.max` makes the kernel OOM-kill the tool with a
/// `SEND_SIG_PRIV` signal no probe reports, and `echo 1 > cgroup.freeze` sends no signal at all;
/// the file open is the only event either leaves. The match is on the path **tail**, fail-open
/// like [`is_proc_pid_root`]: a few constant compares of at most seven bytes, no loop and no
/// per-name `memcmp`, because this is inlined into the open program and the verifier budget on
/// 5.15 is what bounded the earlier versions of this file. It lets through a few files the rule
/// ignores (`io.max`, `memory.swap.max`); whether the unit is a listed tool is the rule's job
/// (`check_security_tool_cgroup_write`), the probe cannot know the list.
///
/// Only an open with write intent counts, and only `open`/`openat` (`is_mutation` false): the
/// mutation syscalls never name these files in a way that matters, so for them this folds away
/// at compile time and costs the other 13 file programs nothing.
fn is_cgroup_limit_write(path: &[u8], flags: i64, is_mutation: bool) -> bool {
    if is_mutation || !is_write_intent(flags) || !path.starts_with(b"/sys/fs/cgroup/") {
        return false;
    }
    path.ends_with(b".max")
        || path.ends_with(b".high")
        || path.ends_with(b".freeze")
        || path.ends_with(b".state")
        || path.ends_with(b"_bytes")
}

/// Whether a file event on `path` should be dropped before it reaches the ring
/// buffer. `flags` is the raw `open(2)`/`openat(2)` flags for an open-family event;
/// pass `0` together with `is_mutation: true` for the mutation-only syscalls
/// (`unlink`/`rename`/`chmod`/`chown`/`setxattr`/`removexattr`), which have no flags
/// to give and are always write-intent by construction — the path itself already IS
/// the mutation.
#[must_use]
pub fn is_filtered_path(path: &[u8], flags: i64, is_mutation: bool) -> bool {
    if is_proc_pid_root(path) {
        return false;
    }
    if path.starts_with(b"/proc/") {
        return !(is_mutation || is_write_intent(flags));
    }
    if path.starts_with(b"/sys/") {
        // Only a write to a cgroup limit file leaves `/sys/` (see `is_cgroup_limit_write`);
        // every other path under it, and every read, stays dropped.
        return !is_cgroup_limit_write(path, flags, is_mutation);
    }
    if path.starts_with(b"/dev/shm/")
        || path.starts_with(b"/tmp/")
        || path.starts_with(b"/var/tmp/")
    {
        return !(is_mutation || is_write_intent(flags));
    }
    path.starts_with(b"/dev/")
}

#[cfg(all(test, feature = "user"))]
mod tests {
    use super::*;

    #[test]
    fn proc_pid_root_itself_is_never_filtered() {
        assert!(!is_filtered_path(b"/proc/1/root", 0, false));
    }

    #[test]
    fn proc_pid_root_subpath_is_never_filtered() {
        assert!(!is_filtered_path(b"/proc/1/root/etc/shadow", 0, false));
        assert!(!is_filtered_path(b"/proc/4242/root/etc/passwd", 0, true));
    }

    #[test]
    fn proc_pid_rootfs_lookalike_is_not_mistaken_for_root() {
        // "/rootfs" is not the "/root" segment — must not false-positive.
        assert!(is_filtered_path(b"/proc/1/rootfs", 0, false));
    }

    #[test]
    fn proc_pid_without_root_read_only_stays_filtered() {
        assert!(is_filtered_path(b"/proc/1/cmdline", 0, false));
        assert!(is_filtered_path(b"/proc/1/status", 0, false));
    }

    #[test]
    fn proc_write_intent_open_passes() {
        assert!(!is_filtered_path(b"/proc/1/attr/current", O_WRONLY, false));
    }

    #[test]
    fn proc_mutation_always_passes() {
        assert!(!is_filtered_path(b"/proc/1/status", 0, true));
    }

    #[test]
    fn proc_non_numeric_segment_read_only_stays_filtered() {
        assert!(is_filtered_path(b"/proc/self/root", 0, false));
    }

    #[test]
    fn proc_self_root_write_intent_escape_passes() {
        // #429 review: `/proc/self/root/etc/cron.d/x` *is* `/etc/cron.d/x` to the
        // kernel, but `self` isn't numeric so `is_proc_pid_root` never matches it —
        // the write-intent exception (not a `self`-specific carve-out) is what
        // catches this, and the same reasoning covers `/proc/self/cwd/...`.
        assert!(!is_filtered_path(
            b"/proc/self/root/etc/cron.d/evade429",
            O_CREAT | O_TRUNC,
            false
        ));
        assert!(!is_filtered_path(
            b"/proc/self/cwd/evade429",
            O_CREAT | O_TRUNC,
            false
        ));
    }

    #[test]
    fn proc_self_root_mutation_escape_passes() {
        assert!(!is_filtered_path(
            b"/proc/self/root/etc/cron.d/evade429",
            0,
            true
        ));
    }

    #[test]
    fn proc_pid_root_double_slash_is_not_mistaken_for_filtered() {
        // #429 review: the kernel collapses repeated `/`, so
        // `/proc//1//root/etc/shadow` resolves the same as `/proc/1/root/etc/shadow`
        // — `is_proc_pid_root` has to recognise it too, or `check_proc_root_escape`
        // never sees the event the filter already let through unfiltered anyway.
        assert!(!is_filtered_path(b"/proc//1//root/etc/shadow", 0, false));
    }

    #[test]
    fn proc_pid_double_slash_before_root_is_not_filtered() {
        // The second fail-open branch: a single `/` after `/proc`, doubled only
        // at the pid/root separator.
        assert!(!is_filtered_path(b"/proc/1//root/etc/shadow", 0, false));
    }

    #[test]
    fn tmp_write_intent_open_passes() {
        assert!(!is_filtered_path(b"/tmp/payload", O_WRONLY, false));
        assert!(!is_filtered_path(b"/tmp/payload", O_CREAT | O_TRUNC, false));
    }

    #[test]
    fn tmp_read_only_open_stays_filtered() {
        assert!(is_filtered_path(b"/tmp/payload", 0, false));
    }

    #[test]
    fn tmp_mutation_always_passes() {
        assert!(!is_filtered_path(b"/tmp/payload", 0, true));
    }

    #[test]
    fn var_tmp_write_intent_open_passes() {
        assert!(!is_filtered_path(b"/var/tmp/payload", O_CREAT, false));
    }

    #[test]
    fn dev_shm_write_intent_open_passes() {
        assert!(!is_filtered_path(b"/dev/shm/payload", O_RDWR, false));
    }

    #[test]
    fn dev_shm_read_only_open_stays_filtered() {
        assert!(is_filtered_path(b"/dev/shm/payload", 0, false));
    }

    #[test]
    fn dev_outside_shm_is_always_filtered() {
        assert!(is_filtered_path(b"/dev/sda1", O_WRONLY, false));
        assert!(is_filtered_path(b"/dev/sda1", 0, true));
    }

    #[test]
    fn sys_is_filtered_except_a_cgroup_limit_write() {
        assert!(is_filtered_path(b"/sys/kernel/x", O_WRONLY, false));
        assert!(is_filtered_path(b"/sys/kernel/x", 0, true));
        assert!(is_filtered_path(
            b"/sys/class/leds/x/brightness",
            O_WRONLY,
            false
        ));
    }

    #[test]
    fn a_write_open_of_a_cgroup_limit_file_passes() {
        // `echo 1M > memory.max` opens O_WRONLY|O_CREAT|O_TRUNC; a python write is O_WRONLY.
        for path in [
            &b"/sys/fs/cgroup/system.slice/auditd.service/memory.max"[..],
            b"/sys/fs/cgroup/system.slice/auditd.service/memory.high",
            b"/sys/fs/cgroup/system.slice/auditd.service/pids.max",
            b"/sys/fs/cgroup/system.slice/auditd.service/cpu.max",
            b"/sys/fs/cgroup/system.slice/auditd.service/cgroup.freeze",
            b"/sys/fs/cgroup/freezer/system.slice/auditd.service/freezer.state",
            b"/sys/fs/cgroup/memory/system.slice/auditd.service/memory.limit_in_bytes",
            b"/sys/fs/cgroup/memory/system.slice/auditd.service/memory.soft_limit_in_bytes",
        ] {
            for flags in [O_WRONLY, O_RDWR, O_WRONLY | O_CREAT | O_TRUNC] {
                assert!(!is_filtered_path(path, flags, false), "{path:?} {flags:o}");
            }
        }
    }

    #[test]
    fn a_read_of_a_cgroup_limit_file_stays_filtered() {
        for path in [
            &b"/sys/fs/cgroup/system.slice/auditd.service/memory.max"[..],
            b"/sys/fs/cgroup/system.slice/auditd.service/cgroup.freeze",
            b"/sys/fs/cgroup/system.slice/auditd.service/pids.max",
            b"/sys/fs/cgroup/system.slice/auditd.service/memory.events",
        ] {
            assert!(is_filtered_path(path, 0, false), "{path:?}");
        }
    }

    #[test]
    fn other_cgroup_writes_stay_filtered() {
        // systemd moves pids and tunes weights all day: volume, and no stop.
        for path in [
            &b"/sys/fs/cgroup/system.slice/auditd.service/cgroup.procs"[..],
            b"/sys/fs/cgroup/system.slice/auditd.service/cgroup.subtree_control",
            b"/sys/fs/cgroup/system.slice/auditd.service/cpu.weight",
            b"/sys/fs/cgroup/system.slice/auditd.service/memory.oom.group",
            b"/sys/fs/cgroup/system.slice/auditd.service/cgroup.kill",
        ] {
            assert!(is_filtered_path(path, O_WRONLY, false), "{path:?}");
        }
    }

    #[test]
    fn a_limit_file_name_outside_the_cgroup_tree_stays_filtered() {
        assert!(is_filtered_path(
            b"/sys/kernel/mm/memory.max",
            O_WRONLY,
            false
        ));
        assert!(is_filtered_path(
            b"/sys/fs/cgroupx/a.service/memory.max",
            O_WRONLY,
            false
        ));
        assert!(is_filtered_path(b"/sys/fs/cgroup", O_WRONLY, false));
    }

    #[test]
    fn a_mutation_syscall_on_a_cgroup_limit_file_stays_filtered() {
        // unlink/rename/chmod/chown/xattr: not how a limit is set, and they must not pay for it.
        let path = b"/sys/fs/cgroup/system.slice/auditd.service/memory.max";
        assert!(is_filtered_path(path, 0, true));
        assert!(is_filtered_path(path, O_WRONLY, true));
    }

    #[test]
    fn unrelated_paths_are_never_filtered() {
        assert!(!is_filtered_path(b"/etc/passwd", 0, false));
        assert!(!is_filtered_path(
            b"/home/user/.ssh/authorized_keys",
            0,
            true
        ));
    }
}
