//! Changes to what a process is allowed to do: credentials, capabilities, namespaces.

use super::*;

/// `prctl(2)` option: drop a capability from the calling thread's bounding set
/// (`arg` is the capability number). Irreversible for the thread.
pub const PR_CAPBSET_DROP: u32 = 24;

/// `prctl(2)` option: set the calling thread's securebits (`arg` is the
/// `SECBIT_*` bitmask, e.g. `SECBIT_NOROOT`, `SECBIT_NO_SETUID_FIXUP`, and the
/// `*_LOCKED` bits that make them permanent).
pub const PR_SET_SECUREBITS: u32 = 28;

/// Capability-model tampering via `prctl(2)` (issue #457, from #266): the two
/// options that change *which privileges a process tree can ever hold*,
/// [`PR_SET_SECUREBITS`] and [`PR_CAPBSET_DROP`]. Filtered at the source — every
/// other `prctl` option (dozens, some very hot, e.g. `PR_SET_NAME`) never reaches
/// this event stream (see `sensor-linux-wire::PrctlEvent`'s doc). Legitimate
/// users exist (systemd's `CapabilityBoundingSet=`, container runtimes dropping
/// their bounding set at start), so this is telemetry for the detection layer to
/// interpret, not a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrctlEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Raw `prctl` option: always [`PR_SET_SECUREBITS`] or [`PR_CAPBSET_DROP`];
    /// not decoded to a name here, same "sensor reports, detection interprets"
    /// split as [`BpfEvent::cmd`].
    pub option: u32,
    /// The option's `arg2`: the `SECBIT_*` mask for [`PR_SET_SECUREBITS`], the
    /// capability number for [`PR_CAPBSET_DROP`].
    pub arg: u64,
}

/// Which user/group identity syscall produced an [`IdentityChangeEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityChangeKind {
    /// `setuid(2)`: real/effective uid.
    SetUid,
    /// `setgid(2)`: real/effective gid.
    SetGid,
    /// `setresuid(2)`: real, effective and saved uid.
    SetResUid,
    /// `setresgid(2)`: real, effective and saved gid.
    SetResGid,
    /// `setfsuid(2)`: filesystem uid.
    SetFsUid,
    /// `setfsgid(2)`: filesystem gid.
    SetFsGid,
}

/// User/group identity change (issue #266): `setuid(2)`/`setgid(2)`/
/// `setresuid(2)`/`setresgid(2)`/`setfsuid(2)`/`setfsgid(2)`. The
/// SUID-binary-abuse and privilege-drop/escalation primitive — a process
/// requesting uid/gid 0 after starting as an unprivileged user is the
/// canonical exploit-success signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityChangeEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Which identity-changing syscall ran.
    pub kind: IdentityChangeKind,
    /// The requested id — the single argument for [`IdentityChangeKind::SetUid`]/
    /// [`IdentityChangeKind::SetGid`]/[`IdentityChangeKind::SetFsUid`]/
    /// [`IdentityChangeKind::SetFsGid`], or the "real" argument for the
    /// `SetRes*` kinds.
    pub real: u32,
    /// [`IdentityChangeKind::SetResUid`]/[`IdentityChangeKind::SetResGid`]'s
    /// "effective" argument only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<u32>,
    /// [`IdentityChangeKind::SetResUid`]/[`IdentityChangeKind::SetResGid`]'s
    /// "saved" argument only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<u32>,
}

/// Linux capability set change (issue #266): `capset(2)`. Each set is the full
/// 64-bit capability mask (bit N = capability N) since v29 (#457): the low 32
/// bits alone missed `CAP_PERFMON` (38), `CAP_BPF` (39) and
/// `CAP_CHECKPOINT_RESTORE` (40), which is what loading eBPF without full
/// `CAP_SYS_ADMIN` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapSetEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The target process. `0` means "the calling process itself" — this is
    /// `capset(2)`'s own documented meaning for pid 0, not an absent value,
    /// so it stays a plain `u32` rather than `Option<u32>`.
    pub target_pid: u32,
    /// Effective capability set, as a bitmask.
    pub effective: u64,
    /// Permitted capability set, as a bitmask.
    pub permitted: u64,
    /// Inheritable capability set, as a bitmask.
    pub inheritable: u64,
}

/// Which namespace syscall produced a [`NamespaceEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceSyscall {
    /// `setns(2)`: join an existing namespace.
    SetNs,
    /// `unshare(2)`: detach into a new namespace.
    Unshare,
}

/// Namespace manipulation (issue #266): `setns(2)` — the container-escape
/// primitive, joining a host namespace from inside a container — and
/// `unshare(2)`, creating a new namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Which syscall changed the namespace.
    pub syscall: NamespaceSyscall,
    /// [`NamespaceSyscall::SetNs`]'s fd argument (an open `/proc/[pid]/ns/*`
    /// file). Absent for [`NamespaceSyscall::Unshare`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    /// `setns(2)`'s `nstype` (a single `CLONE_NEW*` constant, or `0` for
    /// "any"), or `unshare(2)`'s `flags` (a bitmask of one or more
    /// `CLONE_NEW*` bits) — not decoded to constant names here, same
    /// "sensor reports, detection interprets" split as `PtraceEvent::request`.
    pub flags: u32,
}
