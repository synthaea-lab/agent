#![no_std]
//! # sensor-linux-wire
//!
//! The ring-buffer ABI between the eBPF probes (`../ebpf`, `bpfel-unknown-none`) and
//! the userspace loader (`../userspace`): fixed-size `repr(C)` structs written by the
//! kernel side and read back with `read_unaligned` on the user side. Both crates must
//! be built from the same revision — this is an internal ABI, not a stable format.
//!
//! These types are deliberately NOT the agent's event model: the loader normalizes
//! them into `schema` types. The fixed limits below are wire/kernel constraints (the
//! eBPF stack is 512 bytes and events are built in place on it), not product limits —
//! truncation at these bounds is a sensor property reported by conformance.
//! `ExecEvent` is built in a `PerCpuArray` because `image` alone already exceeds the
//! stack budget.

// The "user" feature (userspace loader + uprobes sensor) brings std in for the
// shared decode helpers at the bottom; the eBPF build stays pure no_std.
#[cfg(feature = "user")]
extern crate std;

/// Bumped on every layout-affecting change to the structs below. Not a wire header
/// (ring-buffer items carry none) — a build-time tripwire: the userspace loader
/// `const _`-asserts the value it was compiled against, so an ebpf/userspace version
/// skew fails the build instead of misreading bytes at runtime.
///
/// - v1: initial exec/open/connect structs.
/// - v2: `ExecEvent` gains `image`/`image_len` (authoritative image path from the
///   tracepoint, issue #111) and `pcomm` (parent name from the fork-lineage map,
///   issue #53). `cmdline` is unchanged (`mm->arg_*` blob).
/// - v3: `ExecEvent` drops `cmdline`/`cmdline_len` — argv is read from
///   `/proc/<pid>/cmdline` by the userspace loader (issue #152), so the probe no
///   longer touches a `task_struct`/`mm_struct` frozen offset at all.
/// - v4: `EventMeta` gains `cgroup_id` (`bpf_get_current_cgroup_id()`, captured at
///   probe time, issue #204) — closes the drain-time `/proc` exit race for
///   container attribution: the userspace loader resolves it against cgroupfs
///   instead of `/proc/<pid>/cgroup`, which no longer needs the pid to still exist.
/// - v5: `TlsCaptureEvent` and `ReadlineInputEvent` added for uprobes (issue #90).
///   TLS capture budgeted at 256 bytes (first N bytes of plaintext), readline at
///   512 bytes (full interactive command line).
/// - v6: `FileWriteEvent`, `FileDeleteEvent`, `FileRenameEvent` added (issue #262).
///   `FileWriteEvent` carries no path — `write(2)`/`pwrite64(2)` take a file
///   descriptor, not a path, and this codebase resolves no `fd`→path mapping
///   (kernel-side `d_path`/`bpf_d_path` nor a userspace `/proc/<pid>/fd/<n>`
///   lookup); it is a volume/frequency signal (burst-write detection), not a
///   per-write path trail. `FileDeleteEvent`/`FileRenameEvent` read real path
///   arguments straight off the syscall, same as `FileOpenEvent`.
/// - v7: `SocketBindEvent` added (issue #263) — `bind(2)` only. Same
///   family-filtered (`AF_INET`/`AF_INET6`) sockaddr read as `ConnectEvent`;
///   `listen(2)` (no address, just `fd`+`backlog`) and `accept(2)`/`accept4(2)`
///   (needs a `sys_exit` probe to read the kernel-filled peer address — a new
///   probe shape this crate doesn't have yet) are deliberately deferred.
/// - v8: `FileChmodEvent`/`FileChownEvent` added (issue #262 Phase 2) —
///   `chmod(2)`/`fchmodat(2)` and `chown(2)`/`lchown(2)`/`fchownat(2)`. All five
///   read a real path argument, unlike `FileWriteEvent`. `fchmod(2)`/`fchown(2)`
///   (fd-only, no path) are deferred the same way `write(2)`'s fd-only shape was
///   handled: a future addition, not a silent gap.
/// - v9: `UdpSendEvent` added (issue #263 Phase 2) — `sendto(2)` only, same
///   family-filtered sockaddr read as `ConnectEvent`/`SocketBindEvent`, plus the
///   caller's requested payload size. `recvfrom(2)` is deliberately NOT captured:
///   its source-address output parameter is only populated by the kernel after the
///   syscall returns, the same `sys_exit_*` probe shape `accept`/`accept4` need and
///   this crate doesn't have yet. `send(2)` (no destination arg) is also not
///   captured — glibc issues it as `sendto(fd, buf, len, flags, NULL, 0)`, which
///   this probe's null-address check already skips, same as `connect`/`bind`.
pub const WIRE_VERSION: u32 = 9;

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 256;
/// Budget for TLS plaintext capture (first N bytes). Chosen to fit comfortably
/// in a ring-buffer event with metadata while staying under 512 bytes total.
pub const MAX_TLS_CAPTURE: usize = 256;
/// Budget for readline input capture (full command line). Interactive shell
/// commands rarely exceed this length; longer inputs are truncated at capture time.
pub const MAX_READLINE_INPUT: usize = 512;

/// Metadata common to every wire event: identity of the emitting process.
/// `uid`/`gid` come from `bpf_get_current_uid_gid()` (low/high 32 bits).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventMeta {
    pub pid: u32,
    /// Parent PID (`real_parent->tgid`). Since issue #53 this comes from the
    /// `PROC_LINEAGE` fork-tracking map (`sched_process_fork` + `/proc` priming), not
    /// a frozen-offset `task_struct` walk — `0` when the parent forked before the
    /// probe attached and priming missed it.
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `bpf_ktime_get_ns()`: nanoseconds since boot (monotonic), NOT epoch — the
    /// loader adds the boot-to-epoch offset during normalization.
    pub timestamp_ns: u64,
    pub comm: [u8; TASK_COMM_LEN],
    /// `bpf_get_current_cgroup_id()`, captured at probe time, not resolved lazily
    /// against `/proc` at drain time (issue #204) — the userspace loader maps this
    /// to a container id by inode against cgroupfs. `0` if the helper failed.
    pub cgroup_id: u64,
}

/// Process execution (`sched:sched_process_exec`, success only).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub meta: EventMeta,
    /// Authoritative executed-image path: the kernel's `bprm->filename`, read from the
    /// `sched_process_exec` tracepoint's `__data_loc filename` field. NOT `argv[0]`,
    /// which the caller sets freely (`execve("/tmp/x", {"/usr/bin/sshd"}, …)`).
    /// `\0`-terminated, truncated at `MAX_PATH_LEN` (a sensor property).
    pub image: [u8; MAX_PATH_LEN],
    pub image_len: u16,
    /// Parent short name at exec time, from the `PROC_LINEAGE` map. Empty when the
    /// parent forked before the probe attached and `/proc` priming missed it.
    pub pcomm: [u8; TASK_COMM_LEN],
}

/// Value of the `PROC_LINEAGE` fork-tracking map: a pid's parent identity, captured
/// from `sched:sched_process_fork` (`parent_pid`/`parent_comm` tracepoint fields — no
/// `task_struct` offsets) or primed from `/proc/<pid>/stat` at startup. Replaces the
/// per-kernel frozen-offset `real_parent->tgid` walk that returned garbage off the
/// binding kernel (issue #53). Also written from userspace, so the layout is shared.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LineageEntry {
    pub ppid: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// File open (`syscalls:sys_enter_openat`). `path` is the raw path passed by the
/// caller, not resolved against `dfd` (known limitation, documented in the probe).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    pub meta: EventMeta,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
    pub flags: u32,
}

/// File write (`syscalls:sys_enter_write`/`sys_enter_pwrite64`). No path: `write(2)`
/// takes a file descriptor, and this sensor resolves no fd→path mapping (see the
/// `WIRE_VERSION` v6 changelog above) — a volume/frequency signal for burst-write
/// detection (ransomware, mass tampering), not a per-write path trail.
/// `bytes_requested` is the caller's `count` argument, read at syscall entry — the
/// actual bytes written (the syscall's return value) is not observed here.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileWriteEvent {
    pub meta: EventMeta,
    pub fd: u32,
    pub bytes_requested: u64,
}

/// File delete (`syscalls:sys_enter_unlink`/`sys_enter_unlinkat`). `path` is the raw
/// path passed by the caller, not resolved against `dfd` — same known limitation as
/// `FileOpenEvent::path`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileDeleteEvent {
    pub meta: EventMeta,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
}

/// File rename (`syscalls:sys_enter_rename`/`sys_enter_renameat`/
/// `sys_enter_renameat2`). Both `old_path`/`new_path` are raw caller-supplied paths,
/// not resolved against `olddfd`/`newdfd` — same known limitation as
/// `FileOpenEvent::path`. The classic ransomware signal (`document.docx` →
/// `document.docx.encrypted`) lives entirely in `new_path`'s suffix, no fd
/// resolution needed to see it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameEvent {
    pub meta: EventMeta,
    pub old_path: [u8; MAX_PATH_LEN],
    pub old_path_len: u16,
    pub new_path: [u8; MAX_PATH_LEN],
    pub new_path_len: u16,
}

/// File permission change (`syscalls:sys_enter_chmod`/`sys_enter_fchmodat`, issue #262
/// Phase 2). `path` is the raw path passed by the caller, not resolved against `dfd` —
/// same known limitation as `FileOpenEvent::path`. `fchmod(2)` (fd-only) is deferred.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileChmodEvent {
    pub meta: EventMeta,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
    /// The requested mode bits (`umode_t`), truncated to 32 bits — the tracepoint
    /// promotes it to 8 bytes on the wire but only the low 16 bits are ever
    /// meaningful (permission bits plus setuid/setgid/sticky).
    pub mode: u32,
}

/// File ownership change (`syscalls:sys_enter_chown`/`sys_enter_lchown`/
/// `sys_enter_fchownat`, issue #262 Phase 2). `path` is the raw path passed by the
/// caller, not resolved against `dfd` — same known limitation as
/// `FileOpenEvent::path`. `fchown(2)` (fd-only) is deferred. `uid`/`gid` of
/// `(uid_t)-1`/`(gid_t)-1` (i.e. `u32::MAX`) mean "leave unchanged" per `chown(2)`'s
/// own semantics — passed through as-is, not specially interpreted here.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileChownEvent {
    pub meta: EventMeta,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
    pub uid: u32,
    pub gid: u32,
}

/// Outbound network connection (`syscalls:sys_enter_connect`, `AF_INET/AF_INET6` only).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub meta: EventMeta,
    /// Raw bytes of `sin_addr` in memory order — not a native-endian integer, to
    /// avoid the byte-reversal bug observed in real conditions on 2026-08-13
    /// (127.0.0.11 displayed as "11.0.0.127").
    pub daddr_v4: [u8; 4],
    pub daddr_v6: [u8; 16],
    pub dport: u16,
    pub is_ipv6: bool,
}

/// Socket bind (`syscalls:sys_enter_bind`, `AF_INET/AF_INET6` only, issue #263) — a
/// discrete, real-time trace of a process claiming a local address, same
/// family-filtered sockaddr shape as [`ConnectEvent`]. Distinct from
/// `schema::ListenPortEvent`, which is a periodic poll snapshot (`sensor-linux-netlink`)
/// — this fires once, at the moment of the `bind(2)` call itself, and does not imply
/// `listen(2)` followed (a UDP socket, or a TCP socket bound but never listened,
/// binds too).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketBindEvent {
    pub meta: EventMeta,
    pub laddr_v4: [u8; 4],
    pub laddr_v6: [u8; 16],
    pub lport: u16,
    pub is_ipv6: bool,
}

/// Outbound UDP datagram (`syscalls:sys_enter_sendto`, `AF_INET`/`AF_INET6` only,
/// issue #263 Phase 2). Same family-filtered sockaddr read as `ConnectEvent`, plus
/// the caller's requested payload size (`len`, read at syscall entry — not the
/// syscall's return value, so a short send still reports the requested size, same
/// convention as `FileWriteEvent::bytes_requested`). `recvfrom(2)` is deliberately
/// not captured — see this file's `WIRE_VERSION` v8 changelog.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpSendEvent {
    pub meta: EventMeta,
    pub daddr_v4: [u8; 4],
    pub daddr_v6: [u8; 16],
    pub dport: u16,
    pub is_ipv6: bool,
    pub size: u32,
}

/// TLS plaintext capture (uprobes on `SSL_read`/`SSL_write`, issue #90).
/// Captures the first `MAX_TLS_CAPTURE` bytes of plaintext before encryption
/// (`SSL_write`) or after decryption (`SSL_read`) for C2 beacon detection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsCaptureEvent {
    pub meta: EventMeta,
    /// 0 = read (post-decryption), 1 = write (pre-encryption).
    pub direction: u8,
    /// 0 = OpenSSL, 1 = `BoringSSL`, 2 = `GnuTLS`. Identifies which library was probed.
    pub lib_type: u8,
    /// Actual bytes captured (may be less than `MAX_TLS_CAPTURE` if the buffer
    /// passed to `SSL_read`/`SSL_write` was shorter).
    pub bytes_len: u32,
    /// First N bytes of the plaintext buffer. Budget: 256 bytes.
    pub data: [u8; MAX_TLS_CAPTURE],
}

/// Readline input capture (uprobes on bash/zsh readline, issue #90).
/// Captures interactive shell commands at typing time, including shell builtins
/// that never trigger execve (cd, export, alias, etc.).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadlineInputEvent {
    pub meta: EventMeta,
    /// 0 = bash, 1 = zsh. Identifies which shell was probed.
    pub shell_type: u8,
    /// Actual input length (may be less than `MAX_READLINE_INPUT` if truncated).
    pub input_len: u32,
    /// Full command line input. Budget: 512 bytes.
    pub input: [u8; MAX_READLINE_INPUT],
}

/// Decodes a fixed comm buffer: NUL-terminated, kernel-truncated to 15 bytes — a
/// sensor property (reported by conformance), not a schema limit. Shared by the
/// eBPF loader and the uprobes sensor, which carried identical copies before.
#[cfg(feature = "user")]
#[must_use]
pub fn comm_str(comm: &[u8; TASK_COMM_LEN]) -> std::string::String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    std::string::String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Difference between the epoch clock and `CLOCK_MONOTONIC` (which the probes
/// stamp events with, `bpf_ktime_get_ns`), computed once at sensor startup so
/// normalization can turn probe timestamps into epoch nanoseconds. `0` (plus a
/// warning) if the monotonic clock cannot be read — timestamps then stay
/// monotonic-based rather than the sensor failing.
///
/// Lives here because the two sensor crates each carried a copy and the copies
/// drifted once already (unchecked vs. saturating arithmetic).
#[cfg(all(feature = "user", target_os = "linux"))]
#[must_use]
pub fn boot_epoch_offset_ns() -> u64 {
    let epoch_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain FFI call writing into a valid stack-owned timespec.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        tracing::warn!("clock_gettime(CLOCK_MONOTONIC) failed — timestamps stay monotonic");
        return 0;
    }
    let monotonic_ns = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    epoch_ns.saturating_sub(monotonic_ns)
}

#[cfg(all(test, feature = "user"))]
mod helper_tests {
    use super::*;

    #[test]
    fn comm_str_stops_at_the_nul_terminator() {
        let mut buf = [0u8; TASK_COMM_LEN];
        buf[..4].copy_from_slice(b"bash");
        assert_eq!(comm_str(&buf), "bash");
    }

    #[test]
    fn comm_str_handles_a_full_unterminated_buffer() {
        let buf = [b'x'; TASK_COMM_LEN];
        assert_eq!(comm_str(&buf), "x".repeat(TASK_COMM_LEN));
    }

    #[test]
    fn comm_str_replaces_non_utf8_instead_of_failing() {
        // A process can prctl(PR_SET_NAME) itself to arbitrary bytes.
        let mut buf = [0u8; TASK_COMM_LEN];
        buf[0] = 0xFF;
        buf[1] = b'a';
        assert_eq!(comm_str(&buf), "\u{FFFD}a");
    }
}
