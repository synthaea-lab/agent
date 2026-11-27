//! Who did it and where: the fields every event carries.

use super::*;

/// Identity of the user a process runs as, per platform.
///
/// A bare `uid: u32` cannot represent Windows (audit finding F-3: SYSTEM spawning
/// `cmd.exe` and a standard user doing the same were the same event). `Unknown` is for
/// sensors that genuinely cannot attribute (they should say so in their capabilities,
/// not fabricate a value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "os", rename_all = "snake_case")]
pub enum User {
    /// A Unix account.
    Unix {
        /// Numeric user id.
        uid: u32,
        /// Numeric group id.
        gid: u32,
    },
    /// A Windows account.
    Windows {
        /// String SID (e.g. `S-1-5-18`).
        sid: String,
        /// Integrity level RID (e.g. 0x2000 medium, 0x3000 high, 0x4000 system),
        /// when the sensor can read the token.
        integrity_level: Option<u32>,
    },
    /// The sensor cannot attribute a user.
    Unknown,
}

/// Metadata common to every event: identity of the emitting process.
///
/// A source that cannot name an actor leaves the parts it cannot fill empty (for example `pid` 0
/// or [`User::Unknown`]); the doc on each event type says which parts, and what `meta` names
/// instead where the event has no acting process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMeta {
    /// Process id of the emitting process.
    pub pid: u32,
    /// Parent PID — essential for most detections (process-tree rules).
    pub ppid: u32,
    /// Account the emitting process runs as.
    pub user: User,
    /// Nanoseconds since the UNIX epoch. Sensors normalize their platform clock
    /// (boot-relative eBPF timestamps, ETW FILETIME) before emitting.
    pub timestamp_ns: u64,
    /// Short process name (Linux `comm`, image basename elsewhere). Unbounded here;
    /// platform truncation (e.g. the kernel's 15 bytes for `comm`) is a sensor
    /// property reported by conformance, not a schema limit.
    pub comm: String,
    /// Container the emitting process runs in, when the sensor can attribute one.
    /// `None` on macOS, on bare-metal/VM Linux processes, and on Windows host
    /// processes (Windows attributes process-isolated containers only, from the
    /// ETW sensor, <https://github.com/synthaea-lab/agent/issues/39>) — this is not a Kubernetes pod/namespace context (out of
    /// scope, issue #80), just the container runtime's own identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerContext>,
    /// Opaque stamp of this incarnation of `pid`, for telling a recycled pid from
    /// the process a cache remembers (#519). Only **equality between two events
    /// that carry the same `pid`** means anything: it is not a timestamp, not
    /// comparable across pids, and not stable across agent restarts (the Linux
    /// sensor assigns it at `sched_process_fork`, or from `/proc` for a process
    /// that predates the agent; the Windows sensor reports the kernel's process
    /// sequence number, #725). `None` when the sensor has no such stamp (macOS)
    /// or could not read it; a consumer must then treat the pid
    /// as unchanged, never as new.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_generation: Option<u64>,
    /// [`Self::process_generation`] of `ppid`, as the sensor recorded it when `pid`
    /// forked. A cache keyed on the parent's pid needs the parent's incarnation, not
    /// the child's. Same meaning and same `None` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_generation: Option<u64>,
}

/// Identity of the container a process runs in, resolved from its cgroup on Linux
/// (issue #80) and from its server silo on Windows (<https://github.com/synthaea-lab/agent/issues/39>).
///
/// `id` is the only field a sensor can fill today (cgroup path parsing alone on
/// Linux, the Host Compute Service on Windows; no daemon call). `image`/`name` need a cached lookup against the Docker/containerd
/// socket — deliberately left as a follow-up so this attribution foundation doesn't
/// block on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerContext {
    /// Full container id, as it appears in the cgroup path (64 hex chars for
    /// Docker/containerd) — not truncated to the 12-char short id, so it stays a
    /// stable join key for a later Docker/containerd socket lookup. On Windows,
    /// the Host Compute Service's compute-system id (the same Docker/containerd
    /// id), or `silo:<n>` (the server silo id) until the service has named the
    /// container: still a container, just not yet a joinable one.
    pub id: String,
    /// Image reference (e.g. `nginx:1.27`). `None` until the socket lookup lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Container name, as assigned by the runtime. `None` until the socket lookup
    /// lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
