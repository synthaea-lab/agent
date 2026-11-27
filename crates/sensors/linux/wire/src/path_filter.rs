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
//! `/sys/` are unconditional, unchanged from #325, with three exceptions, each a way to blind a
//! security tool that leaves no other event (#356):
//! - a write-intent open of a cgroup limit file (`memory.max`, `cgroup.freeze`...), which ends or
//!   freezes a tool without a signal ([`is_cgroup_limit_write`], #49);
//! - a write-intent open of the `AppArmor` `.remove` file, which unloads a confinement profile
//!   ([`is_apparmor_profile_removal`]);
//! - any mutation under bpffs (`/sys/fs/bpf/`), where removing a pin detaches or forgets a
//!   tool's BPF object, this agent's `SIGKILL` attribution included ([`is_bpffs_mutation`]).
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
//! and verified; prefer a fail-open early return over another loop. The single
//! exception is [`may_leave_its_prefix`] (#350): a prefix filter that drops
//! `/dev/../etc/x` is an evasion, and telling a path that leaves its prefix from one
//! that stays takes reading every byte. It runs only on paths the prefixes would drop,
//! and its cost was measured with `verify_probes` before it landed.

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

/// Whether `path` (already known to start with `/sys/`) is a write to a cgroup control file that ends, freezes or starves the unit it
/// sits in (<https://github.com/synthaea-lab/agent/issues/49>): `memory.max`, `memory.high`,
/// `pids.max` (and any other `*.max`, `cpu.max` included), `cgroup.freeze`, and the cgroup v1
/// `freezer.state` and `memory.*_in_bytes`.
///
/// `echo 1M > .../auditd.service/memory.max` makes the kernel OOM-kill the tool with a
/// `SEND_SIG_PRIV` signal no probe reports, and `echo 1 > cgroup.freeze` sends no signal at all;
/// the file open is the only event either leaves. The match is on the path **tail** and does not
/// test for `/sys/fs/cgroup/`: the probe reads the path as the caller wrote it, and the kernel
/// resolves `/sys/fs/../fs/cgroup/...`, `/sys//fs/cgroup/...` and `/sys/./fs/cgroup/...` to the
/// same file, so a literal prefix test is one character from being bypassed. Fail-open
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
    if is_mutation || !is_write_intent(flags) {
        return false;
    }
    path.ends_with(b".max")
        || path.ends_with(b".high")
        || path.ends_with(b".freeze")
        || path.ends_with(b".state")
        || path.ends_with(b"_bytes")
}

/// Whether `path` (already known to start with `/sys/`) is a write of the `AppArmor` profile-removal
/// file, `<securityfs>/apparmor/.remove` (#356): `aa-disable`, `aa-teardown` and
/// `apparmor_parser -R` write a profile name to it, and the profile's confinement is gone with
/// no signal and no exec of the confined tool. Same shape and budget as [`is_cgroup_limit_write`]:
/// one constant tail compare, no `securityfs` prefix test (a non-normalized spelling would step
/// around it), write-intent `open`/`openat` only. `.load` and `.replace` are left filtered: they
/// add or tighten a policy, and `apparmor.service` writes them for every profile at boot.
fn is_apparmor_profile_removal(path: &[u8], flags: i64, is_mutation: bool) -> bool {
    !is_mutation && is_write_intent(flags) && path.ends_with(b"/.remove")
}

/// Whether `path` is an `unlink`/`rename`/`chmod`/`chown`/xattr change under bpffs (#356). A
/// pinned BPF object lives as long as its pin or an open handle: removing the pin of a tool's
/// program detaches it once the tool lets go, and removing this agent's
/// `SIGNAL_TAMPER_LAST` pin before a `SIGKILL` leaves the restarted agent nothing to attribute.
/// bpffs is written only when something is pinned or unpinned, so passing every mutation there
/// costs no volume. Opens stay filtered: a pinned object is reached with `bpf(BPF_OBJ_GET)`, not
/// `open(2)`. A literal prefix, like the other prefix rules here: a non-normalized spelling
/// (`/sys//fs/bpf/...`) is the general prefix-escape question of #350, not this rule's.
fn is_bpffs_mutation(path: &[u8], is_mutation: bool) -> bool {
    is_mutation && path.starts_with(b"/sys/fs/bpf/")
}

/// Whether a file event on `path` should be dropped before it reaches the ring
/// buffer. `flags` is the raw `open(2)`/`openat(2)` flags for an open-family event;
/// pass `0` together with `is_mutation: true` for the mutation-only syscalls
/// (`unlink`/`rename`/`chmod`/`chown`/`setxattr`/`removexattr`), which have no flags
/// to give and are always write-intent by construction — the path itself already IS
/// the mutation.
#[must_use]
pub fn is_filtered_path(path: &[u8], flags: i64, is_mutation: bool) -> bool {
    drops_by_prefix(path, flags, is_mutation)
        && !may_leave_its_prefix(path, u64::from(is_mutation || is_write_intent(flags)))
}

/// Whether the kernel can resolve `path` (already known to start with a filtered prefix)
/// somewhere outside that prefix, judged on its spelling (#350). The prefix rules read the
/// path as the caller wrote it, and the kernel walks it:
///
/// - **`.` and `..` segments.** `/dev/../etc/cron.d/x` is `/etc/cron.d/x`. Reproduced live
///   before this check (Debian 12, 6.1): an open with `O_CREAT`, an `unlink`, a `chmod` and
///   a `rename` through `/dev/..` or `/sys/..` left no event, though each one took effect.
///   Only a segment that is exactly `.` or `..` counts, the end of the path included as a
///   separator (`/dev/..`): a hidden name like `/tmp/.X11-unix/X0` or an `AppImage`'s
///   `/tmp/.mount_x/...` is read all the time, and stays filtered (agent#352 review).
/// - **Repeated `/`.** The kernel collapses them, so `/dev//fd/3/x` must not slip past the
///   alias test below by spelling.
/// - **A path the probe truncated.** The probe reads at most `MAX_PATH_LEN - 1` bytes and the
///   kernel walks the whole string, so a `..` past that point is never seen (agent#352
///   review: repeated sysfs `subsystem` links put the first `..` at byte 265, no privilege
///   needed). A path that fills the buffer passes whatever it holds.
/// - **Descriptor aliases.** `/dev/fd` links to `/proc/self/fd`, and `/dev/stdin`,
///   `/dev/stdout` and `/dev/stderr` to its first three entries. Each entry is a link to
///   whatever that descriptor holds, a directory included. So with `/etc` open as fd 3,
///   `/dev/fd/3/cron.d/x` is `/etc/cron.d/x`, and no `..` is needed. The alias itself
///   (`/dev/fd/63` for a bash process substitution, `/dev/stdin`) stays filtered for a
///   read; a path that continues below it passes for every access.
///
/// Write-intent opens and mutations of the alias itself pass too (`writes` is 1 for them):
/// they reach the descriptor's target.
///
/// Not covered:
/// - a symlink under a filtered prefix. Any user can plant one under `/tmp`, `/var/tmp` or
///   `/dev/shm` and read through it; only root can under `/dev` or `/sys`. Reads through it
///   are dropped. Writes and mutations under the tmp family pass by intent anyway.
/// - a read through a procfs alias that `self` or a pid names: `/proc/self/root/etc/shadow`,
///   `/proc/self/cwd/x`, `/proc/<pid>/fd/3/x`. Telling these from `/proc/self/status` takes
///   more bytes of state per step than the verifier budget left by this scan allows
///   (agent#357; agent#351 is the way to buy it back).
///
/// Telling either apart would take a lookup the probe cannot make, or a budget it does not
/// have: that is the residual risk of a prefix filter.
///
/// This is the one loop the filter adds. It runs only when the prefix rules would drop the
/// path (the `&&` in [`is_filtered_path`]), at most [`crate::MAX_PATH_LEN`] steps over
/// bytes the probe already read, with no nested loop: what `verify_probes` has to fit on
/// 5.14 and 5.15 (see the module comment on #429).
///
/// The body has no branch on the bytes, only arithmetic, and the one branch per step is the
/// bounds check. Every handler in `raw_sys_enter` inlines this, and the verifier walks what
/// follows the loop once per way out of it, while a branch before the loop sends a second
/// state through all of it. So every other test is computed before the loop, without a
/// branch, and combined after it with plain arithmetic. The shapes measured with
/// `verify_probes` before this one was kept are in `docs/sensors/linux/ebpf-probes.md`.
fn may_leave_its_prefix(path: &[u8], writes: u64) -> bool {
    // Computed before the loop and without a branch: the verifier walks what follows the loop
    // once per way out of it, and a branch before it sends a second state through all of it.
    let truncated = at_least(path.len() as u64, crate::MAX_PATH_LEN as u64 - 1);
    let below_fd = starts_with_8(path, *b"/dev/fd/");
    let below_std = starts_with_8(path, *b"/dev/std");
    let mut slashes = 0u64;
    let mut previous_is_slash = 0u64;
    // The segment read so far is exactly `.` / exactly `..`.
    let mut segment_is_dot = 0u64;
    let mut segment_is_dot_dot = 0u64;
    let mut leaves = 0u64;
    let mut i = 0usize;
    while i < crate::MAX_PATH_LEN {
        let Some(&byte) = path.get(i) else {
            break;
        };
        let is_slash = equality_bit(byte, b'/');
        let is_dot = equality_bit(byte, b'.');
        // A `/` closes the segment before it: `.`, `..`, or empty (`//`).
        leaves |= is_slash & (segment_is_dot | segment_is_dot_dot | previous_is_slash);
        segment_is_dot_dot = segment_is_dot & is_dot;
        segment_is_dot = previous_is_slash & is_dot;
        slashes += is_slash;
        previous_is_slash = is_slash;
        i += 1;
    }
    // The end of the path closes the last segment too: `/dev/..` is `/`.
    leaves |= segment_is_dot | segment_is_dot_dot;
    let below_alias = continues_below_a_descriptor_alias(below_fd, below_std, slashes, writes);
    (leaves | truncated | below_alias) != 0
}

/// `/dev/fd/<n>/...` has this many `/`: one more than the alias itself.
const SLASHES_BELOW_FD_ALIAS: u64 = 4;
/// `/dev/stdin/...` (and `stdout`, `stderr`) has this many `/`.
const SLASHES_BELOW_STD_ALIAS: u64 = 3;

/// 1 when a path under a descriptor alias (`below_fd`: `/dev/fd/`, `below_std`: `/dev/std`)
/// reaches the descriptor's target, else 0, without a branch.
///
/// A path that continues below the alias names a file inside the directory the descriptor
/// holds. A write-intent open or a mutation (`writes`) of the alias itself reopens what the
/// descriptor holds: `chmod("/dev/fd/3")` changes the target's mode, and an `O_TRUNC` open
/// rewrites it, even when fd 3 was opened read-only (agent#352 review). Only a read of the
/// alias stays dropped: `cat /dev/stdin` and bash's `/dev/fd/63` are the noise, and a reopened
/// read names a file whose own open was seen or was inherited.
fn continues_below_a_descriptor_alias(
    below_fd: u64,
    below_std: u64,
    slashes: u64,
    writes: u64,
) -> u64 {
    (below_fd & (at_least(slashes, SLASHES_BELOW_FD_ALIAS) | writes))
        | (below_std & (at_least(slashes, SLASHES_BELOW_STD_ALIAS) | writes))
}

/// 1 when `path` starts with the 8 bytes of `prefix`, else 0, with one bounds branch and no
/// branch on the bytes.
fn starts_with_8(path: &[u8], prefix: [u8; 8]) -> u64 {
    let Some(head) = path.get(..8) else {
        return 0;
    };
    let mut differs = 0u64;
    for (byte, wanted) in head.iter().zip(prefix) {
        differs |= u64::from(byte ^ wanted);
    }
    differs.wrapping_sub(1) >> 63
}

/// 1 when `count >= floor`, else 0, without a branch. `count` is at most `MAX_PATH_LEN`, far
/// below the top bit, so `floor - 1 - count` wraps (setting the top bit) exactly when
/// `count >= floor`.
fn at_least(count: u64, floor: u64) -> u64 {
    (floor - 1).wrapping_sub(count) >> 63
}

/// 1 when `byte == wanted`, else 0, without a branch: `byte ^ wanted` is 0 only on a match,
/// and only 0 wraps below zero, which sets the top bit.
fn equality_bit(byte: u8, wanted: u8) -> u64 {
    (u64::from(byte ^ wanted)).wrapping_sub(1) >> 63
}

/// The prefix rules alone, on the path as the caller spelled it.
fn drops_by_prefix(path: &[u8], flags: i64, is_mutation: bool) -> bool {
    if is_proc_pid_root(path) {
        return false;
    }
    if path.starts_with(b"/proc/") {
        return !(is_mutation || is_write_intent(flags));
    }
    if path.starts_with(b"/sys/") {
        // Only the three tamper routes of the module doc leave `/sys/`; every other path under
        // it, and every read, stays dropped.
        return !(is_cgroup_limit_write(path, flags, is_mutation)
            || is_apparmor_profile_removal(path, flags, is_mutation)
            || is_bpffs_mutation(path, is_mutation));
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
    fn sys_is_filtered_except_its_tamper_routes() {
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
        // systemd moves pids and tunes weights all day: volume, and no stop. `cgroup.kill` is
        // filtered on purpose too, although it is the most direct stop: its `SIGKILL` reaches
        // `signal_generate` as `SEND_SIG_NOINFO`, attributed to the writer (`signals.md`), so
        // the signal probe already reports it.
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
    fn a_non_normalized_spelling_of_a_cgroup_limit_file_passes() {
        // The kernel resolves each of these to the same file as the plain path (live on Debian
        // 12, 6.1: the value is applied); the probe must not drop them.
        for path in [
            &b"/sys/fs/../fs/cgroup/system.slice/osqueryd.service/memory.high"[..],
            b"/sys//fs/cgroup/system.slice/osqueryd.service/memory.high",
            b"/sys/./fs/cgroup/system.slice/osqueryd.service/memory.high",
            b"/sys/fs/cgroup/system.slice/osqueryd.service/../osqueryd.service/memory.max",
            b"/sys/fs/cgroup/system.slice/osqueryd.service/cgroup.freeze",
        ] {
            assert!(!is_filtered_path(path, O_WRONLY, false), "{path:?}");
        }
        // A read of the plain spelling stays filtered. The other spellings pass even as reads,
        // since a `.`, `..` or empty segment can leave `/sys` (#350).
        assert!(is_filtered_path(
            b"/sys/fs/cgroup/system.slice/osqueryd.service/cgroup.freeze",
            0,
            false
        ));
    }

    #[test]
    fn a_limit_file_name_elsewhere_under_sys_passes_and_the_rule_decides() {
        // Fail-open by design: the probe cannot tell `/sys/kernel/mm/memory.max` from a cgroup
        // file without the prefix test it no longer has; the rule reads the unit.
        assert!(!is_filtered_path(
            b"/sys/kernel/mm/memory.max",
            O_WRONLY,
            false
        ));
        assert!(is_filtered_path(b"/sys/kernel/mm/memory.max", 0, false));
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
    fn a_mutation_under_bpffs_passes() {
        for path in [
            &b"/sys/fs/bpf/synthaea/signal_tamper_last_v21"[..],
            b"/sys/fs/bpf/falco/prog",
        ] {
            assert!(!is_filtered_path(path, 0, true), "{path:?}");
        }
    }

    #[test]
    fn an_open_under_bpffs_stays_filtered() {
        let path = b"/sys/fs/bpf/synthaea/signal_tamper_last_v21";
        assert!(is_filtered_path(path, 0, false));
        assert!(is_filtered_path(path, O_WRONLY, false));
    }

    #[test]
    fn a_bpffs_lookalike_elsewhere_under_sys_stays_filtered() {
        assert!(is_filtered_path(b"/sys/fs/bpfx/prog", 0, true));
        assert!(is_filtered_path(b"/sys/kernel/bpf/prog", 0, true));
    }

    #[test]
    fn a_write_open_of_apparmors_remove_file_passes() {
        let path = b"/sys/kernel/security/apparmor/.remove";
        for flags in [O_WRONLY, O_RDWR, O_WRONLY | O_TRUNC] {
            assert!(!is_filtered_path(path, flags, false), "{flags:o}");
        }
    }

    #[test]
    fn a_read_or_mutation_of_apparmors_remove_file_stays_filtered() {
        let path = b"/sys/kernel/security/apparmor/.remove";
        assert!(is_filtered_path(path, 0, false));
        assert!(is_filtered_path(path, 0, true));
    }

    #[test]
    fn apparmor_policy_loads_stay_filtered() {
        for path in [
            &b"/sys/kernel/security/apparmor/.load"[..],
            b"/sys/kernel/security/apparmor/.replace",
        ] {
            assert!(is_filtered_path(path, O_WRONLY, false), "{path:?}");
        }
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

    /// Every way a call can name a path, as `(flags, is_mutation)`: a read, a write-intent
    /// open, and a mutation syscall.
    const EVERY_ACCESS: [(i64, bool); 3] = [(0, false), (O_WRONLY | O_CREAT, false), (0, true)];

    #[test]
    fn a_path_that_climbs_out_of_a_filtered_prefix_is_never_filtered() {
        // #350, reproduced live on Debian 12 (6.1): each of these took effect with no event.
        for path in [
            &b"/dev/../etc/cron.d/job"[..],
            b"/sys/../etc/shadow",
            b"/proc/../etc/shadow",
            b"/tmp/../etc/shadow",
            b"/var/tmp/../../etc/shadow",
            b"/dev/shm/../../etc/shadow",
            b"/dev/x/../../var/log/auth.log",
            b"/sys/kernel/../../usr/bin/tool",
        ] {
            for (flags, is_mutation) in EVERY_ACCESS {
                assert!(
                    !is_filtered_path(path, flags, is_mutation),
                    "{path:?} flags={flags:o} mutation={is_mutation}"
                );
            }
        }
    }

    #[test]
    fn a_dot_or_empty_segment_under_a_filtered_prefix_is_never_filtered() {
        // `.` and `//` keep the path where it is, but they defeat the alias test below by
        // spelling, so they pass like `..`.
        for path in [
            &b"/dev/./fd/3/cron.d/job"[..],
            b"/dev//fd/3/cron.d/job",
            b"/sys/./kernel/x",
            b"/dev/.",
            b"/dev/..",
            b"/tmp/x/..",
        ] {
            for (flags, is_mutation) in EVERY_ACCESS {
                assert!(!is_filtered_path(path, flags, is_mutation), "{path:?}");
            }
        }
    }

    #[test]
    fn a_hidden_name_under_a_filtered_prefix_stays_filtered() {
        // agent#352 review: X11's socket directory and an AppImage's mount are read all the
        // time. Only a segment that is exactly `.` or `..` moves the path.
        for path in [
            &b"/tmp/.X11-unix/X0"[..],
            b"/tmp/.mount_abc/usr/lib/libx.so",
            b"/dev/.hidden",
            b"/tmp/..x",
            b"/tmp/.../x",
            b"/tmp/x.",
        ] {
            assert!(is_filtered_path(path, 0, false), "{path:?}");
        }
    }

    #[test]
    fn a_path_below_a_descriptor_alias_is_never_filtered() {
        // With a directory open as fd 3 (or as stdin), these name a file inside it.
        for path in [
            &b"/dev/fd/3/cron.d/job"[..],
            b"/dev/fd/3/",
            b"/dev/stdin/shadow",
            b"/dev/stdout/x",
            b"/dev/stderr/x",
        ] {
            for (flags, is_mutation) in EVERY_ACCESS {
                assert!(!is_filtered_path(path, flags, is_mutation), "{path:?}");
            }
        }
    }

    const DESCRIPTOR_ALIASES: [&[u8]; 4] =
        [b"/dev/fd/63", b"/dev/stdin", b"/dev/stdout", b"/dev/stderr"];

    #[test]
    fn a_read_of_a_descriptor_alias_itself_stays_filtered() {
        // bash's process substitution opens `/dev/fd/63`; reading stdin through its name is
        // common.
        for path in DESCRIPTOR_ALIASES {
            assert!(is_filtered_path(path, 0, false), "{path:?}");
        }
    }

    #[test]
    fn a_write_or_mutation_of_a_descriptor_alias_itself_is_never_filtered() {
        // agent#352 review: `chmod("/dev/fd/N")` set the target's mode, and an `O_WRONLY|O_TRUNC`
        // open of it rewrote the target, fd N having been opened read-only.
        for path in DESCRIPTOR_ALIASES {
            assert!(
                !is_filtered_path(path, O_WRONLY | O_TRUNC, false),
                "{path:?}"
            );
            assert!(!is_filtered_path(path, 0, true), "{path:?}");
        }
    }

    #[test]
    fn the_plain_noise_the_filter_exists_for_stays_filtered() {
        for path in [
            &b"/dev/null"[..],
            b"/dev/pts/3",
            b"/dev/urandom",
            b"/sys/class/net/lo/uevent",
            b"/sys/devices/system/cpu/online",
        ] {
            for (flags, is_mutation) in EVERY_ACCESS {
                assert!(is_filtered_path(path, flags, is_mutation), "{path:?}");
            }
        }
        for path in [
            &b"/proc/1/status"[..],
            b"/tmp/cache",
            b"/var/tmp/x",
            b"/dev/shm/x",
        ] {
            assert!(is_filtered_path(path, 0, false), "{path:?}");
        }
    }

    #[test]
    fn a_dot_inside_a_name_is_not_a_dot_segment() {
        // Only a `.` right after a `/` counts: `libc.so.6` and `cpu0.1` keep their noise
        // filtered.
        assert!(is_filtered_path(b"/sys/devices/cpu0.1/uevent", 0, false));
        assert!(is_filtered_path(b"/tmp/lib.so.6", 0, false));
    }

    /// The rule `may_leave_its_prefix` implements, with plain comparisons: what the
    /// branchless version is checked against.
    fn leaves_by_bytes(path: &[u8]) -> bool {
        let slash_at = |i: usize| path.get(i) == Some(&b'/');
        // Every segment that follows a `/`, up to the next `/` or the end; a trailing `/`
        // closes no segment.
        let dot_or_empty_segment = (1..path.len()).filter(|&i| slash_at(i - 1)).any(|start| {
            let end = (start..path.len())
                .find(|&i| slash_at(i))
                .unwrap_or(path.len());
            matches!(&path[start..end], b"." | b"..") || (end == start && end < path.len())
        });
        let slash_from = |start: usize| (start..path.len()).any(slash_at);
        dot_or_empty_segment
            || path.len() >= crate::MAX_PATH_LEN - 1
            || (path.starts_with(b"/dev/fd/") && slash_from(8))
            || (path.starts_with(b"/dev/std") && slash_from(5))
    }

    #[test]
    fn the_branchless_scan_agrees_with_the_plain_rule_on_every_short_path() {
        // Every string of up to 9 bytes over `/`, `.` and `a`, after each prefix that matters:
        // every segment of up to three dots, a `//` at every offset, and every count of
        // slashes past an alias.
        let alphabet = *b"/.a";
        for prefix in [
            &b""[..],
            b"/dev/",
            b"/dev/fd/",
            b"/dev/std",
            b"/sys/kernel/",
        ] {
            for len in 0..=9u32 {
                for n in 0..3usize.pow(len) {
                    let mut path = prefix.to_vec();
                    let mut rest = n;
                    for _ in 0..len {
                        path.push(alphabet[rest % 3]);
                        rest /= 3;
                    }
                    assert_eq!(
                        may_leave_its_prefix(&path, 0),
                        leaves_by_bytes(&path),
                        "{path:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_branchless_prefix_test_matches_starts_with() {
        for path in [
            &b""[..],
            b"/dev/fd",
            b"/dev/fd/",
            b"/dev/fd/3",
            b"/dev/fe/3",
            b"/dev/stdin",
            b"/dev/st",
            b"_dev/fd/",
        ] {
            for prefix in [*b"/dev/fd/", *b"/dev/std"] {
                assert_eq!(
                    starts_with_8(path, prefix),
                    u64::from(path.starts_with(&prefix)),
                    "{path:?}"
                );
            }
        }
    }

    #[test]
    fn the_branchless_threshold_matches_the_comparison_for_every_probe_count() {
        for count in 0..=crate::MAX_PATH_LEN as u64 {
            for floor in [3, 4] {
                assert_eq!(at_least(count, floor), u64::from(count >= floor), "{count}");
            }
        }
    }

    #[test]
    fn the_branchless_byte_test_matches_equality_for_every_byte() {
        for byte in 0..=u8::MAX {
            for wanted in *b"/." {
                assert_eq!(
                    equality_bit(byte, wanted),
                    u64::from(byte == wanted),
                    "{byte}"
                );
            }
        }
    }

    /// The longest path the probe hands the filter: `bpf_probe_read_user_str_bytes` into a
    /// `MAX_PATH_LEN` buffer keeps one byte for the terminating NUL.
    const PROBE_PATH_MAX: usize = crate::MAX_PATH_LEN - 1;

    /// `/dev/` + filler + `tail`, `len` bytes in all.
    fn path_under_dev(len: usize, tail: &[u8]) -> std::vec::Vec<u8> {
        let mut path = b"/dev/".to_vec();
        path.resize(len - tail.len(), b'a');
        path.extend_from_slice(tail);
        path
    }

    #[test]
    fn a_dot_dot_ending_the_longest_unfilled_path_is_seen() {
        let path = path_under_dev(PROBE_PATH_MAX - 1, b"/..");
        assert!(!is_filtered_path(&path, 0, true));
    }

    #[test]
    fn a_plain_path_one_byte_short_of_the_probe_buffer_stays_filtered() {
        let path = path_under_dev(PROBE_PATH_MAX - 1, b"");
        assert!(is_filtered_path(&path, 0, true));
        assert!(is_filtered_path(&path, 0, false));
    }

    #[test]
    fn a_path_that_fills_the_probe_buffer_is_never_filtered() {
        // agent#352 review: repeated sysfs `subsystem` links reach a `..` past byte 255, which
        // the probe never reads, and the kernel resolves it out of `/sys`. Unprivileged; an
        // append through that spelling landed under `/var/tmp`.
        let mut spelled = b"/sys/bus/cpu".to_vec();
        for _ in 0..11 {
            spelled.extend_from_slice(b"/devices/cpu0/subsystem");
        }
        spelled.extend_from_slice(b"/../../../var/tmp/x");
        let seen = &spelled[..PROBE_PATH_MAX];
        assert!(
            !seen.windows(2).any(|pair| pair == b"/."),
            "the probe sees no dot segment"
        );
        for (flags, is_mutation) in EVERY_ACCESS {
            assert!(
                !is_filtered_path(seen, flags, is_mutation),
                "flags={flags:o}"
            );
        }
        assert!(!is_filtered_path(
            &path_under_dev(PROBE_PATH_MAX, b""),
            0,
            false
        ));
    }
}
