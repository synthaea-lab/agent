//! # schema
//!
//! The platform boundary of the agent: the normalized event model shared by every
//! sensor, the rule engine, the correlator, and the ML feature extractors, plus the
//! [`sensor`] contract every platform sensor implements.
//!
//! ## Semi-frozen API
//!
//! Every crate in the workspace depends on this one. Changes to public types ripple
//! everywhere and need explicit justification in review — prefer additive changes
//! (new fields with serde defaults, new [`Event`] variants) over reshaping what exists.
//!
//! **Every serialization-visible change bumps [`SCHEMA_VERSION`]** and adds a full
//! `tests/fixtures/v<N>/` snapshot (existing fixture files are never edited) — no
//! exception for additive changes, even though they don't break a Rust reader on
//! this crate's current types. This resolves issue #114 (closed): a change is
//! "visible" in three ways, and all three bump the version the same way —
//!
//! 1. **New optional field** on an existing type (e.g. [`EventMeta::container`],
//!    #169, v9 → v10) — non-breaking for a Rust reader (`#[serde(default)]`), but
//!    a non-Rust consumer (the server, a SIEM export) that snapshots the field set
//!    it deserializes still sees a change.
//! 2. **New [`Event`] variant** (e.g. `Event::Auth`, #94, v12 → v13) — non-breaking
//!    for a Rust reader too ([`Event`] is `#[non_exhaustive]`, forcing a wildcard
//!    match arm), but it changes the closed set of `"type"` tag values a consumer
//!    keying on that tag can see, the same concern as case 1.
//! 3. **Removal, rename, or type change** — breaking outright, bumps for the
//!    obvious reason.
//!
//! Bumping on 1 and 2 costs nothing (the version is metadata, not a compatibility
//! gate — old fixtures keep deserializing under new types, see
//! `tests/v1_compat.rs`) and buys every consumer an honest signal of "this shape
//! didn't exist before v*N*", which not bumping would silently hide. See
//! `docs/architecture/event-schema.md` for the full contract and worked examples.
//!
//! Not every change to this crate is a schema change: reusing bits within an
//! *existing* field (e.g. [`FLAG_PERSISTENCE_ARTIFACT`]) adds no new shape, so it
//! does not bump [`SCHEMA_VERSION`] — see that constant's doc comment. Nor is this
//! the same contract as a sensor's own wire ABI (e.g. `sensor-linux-wire`'s
//! `WIRE_VERSION`, bumped independently for #204): that governs the eBPF-to-
//! userspace struct layout on one platform, never this crate's public JSON model.
//!
//! ## What this crate is not
//!
//! Not the wire format. Sensors normalize their platform's native representation into
//! these types; fixed-size `repr(C)` structs for the eBPF ring buffer live with the
//! Linux sensor pair (`sensors/linux`), ETW layouts with `sensors/windows/etw`. The
//! old iteration let the eBPF wire format (fixed 256-byte buffers, `TASK_COMM_LEN`)
//! define the shared model; that is deliberately undone here — command lines and paths
//! are unbounded owned strings (Windows encoded-PowerShell command lines run to
//! kilobytes), and user identity is per-platform instead of a bare Unix uid.

use serde::{Deserialize, Serialize};

pub mod detection;
#[cfg(feature = "test-fixtures")]
pub mod fixtures;
pub mod sensor;
pub mod time;

/// Version of the serialized event model. Bumped on any serialization-visible change,
/// together with a new golden-fixture directory (see crate docs).
///
/// Bumped 12 → 13 for [`Event::Auth`] (#94): a new enum variant is a new possible
/// `"type"` tag value, which counts as serialization-visible per the rule above —
/// even though it breaks nothing for readers of *old* data (see `tests/v1_compat.rs`,
/// which pins that `tests/fixtures/v1/*.json`, frozen and never edited, still
/// deserialize under the current `Event` type). `tests/fixtures/v13/` is a full
/// snapshot (every golden fixture, not only the new `Auth` ones), matching the
/// precedent already established by versions 2 through 12. Originally claimed as
/// 10 → 11 while this branch was open; rebased to 13 once #189 (`NetworkFlow`,
/// 11 → 12) merged into `main` first — same coordination note as ADR-0005.
///
/// Bumped 13 → 14 for [`Event::TlsCapture`] and [`Event::ReadlineInput`] (#90):
/// two new enum variants for uprobes-based TLS plaintext capture and shell readline
/// input capture. Same serialization-visible reasoning as v13 above.
///
/// Bumped 14 → 15 for [`Event::FileWrite`], [`Event::FileDelete`], and
/// [`Event::FileRename`] (#262): three new enum variants for Linux
/// write/delete/rename telemetry. Same serialization-visible reasoning as v13/v14.
///
/// Bumped 15 → 16 for [`Event::SocketBind`] (#263): one new enum variant for
/// discrete, real-time `bind(2)` telemetry on Linux. Same reasoning as v13-v15.
pub const SCHEMA_VERSION: u32 = 16;

/// Marker set on [`FileOpenEvent::flags`] by `sensor-windows-eventlog` when it
/// reports a Windows **service install** as a persistence artifact (event 7045, "A
/// service was installed in the system" — ATT&CK T1543.003) rather than a real file
/// operation. `rules::check_service_persistence` requires this exact value before
/// applying a suspicious-path filter — see that function's doc for why: applying the
/// filter to the whole Windows file stream unfiltered would alert on every legitimate
/// AppData/Temp write (browser updates, Electron apps, installers...).
///
/// A distinct bit from [`FLAG_PERSISTENCE_TASK_ARTIFACT`] (not shared): the two
/// techniques (T1543.003 vs T1053.005) must not both fire off a single event.
/// `disposition_to_flags` (`sensor-windows`) only ever produces `O_WRONLY` (0o1) /
/// `O_CREAT` (0o100), so this high bit never collides with a real disposition value.
///
/// Not a serialization-visible schema change (no new field, no new [`Event`]
/// variant — `flags` already exists and is already an opaque, per-platform `u32`),
/// so this does not bump [`SCHEMA_VERSION`]. Pragmatic solution, not the final one:
/// see `docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md` for the
/// full rationale and the option of a dedicated `Persistence`/`Registry` event
/// family once the schema needs one for other reasons too.
pub const FLAG_PERSISTENCE_ARTIFACT: u32 = 0x1000_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Windows **scheduled task**
/// creation (event 4698, "A scheduled task was created" — ATT&CK T1053.005) rather
/// than a service (T1543.003). See `check_scheduled_task_persistence` (`rules`) and
/// `docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md`.
pub const FLAG_PERSISTENCE_TASK_ARTIFACT: u32 = 0x2000_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Windows **local account
/// creation** (event 4720, "A user account was created" — ATT&CK T1136.001) rather
/// than a service (T1543.003) or scheduled task (T1053.005). See
/// `check_account_creation_persistence` (`rules`) and
/// `docs/adr/0004-windows-persistence-detection-via-eventlog-polling.md`.
///
/// Scoped to local SAM accounts on this host: domain account creation (4720 on the
/// domain controller) is out of scope for a userland EDR on member/standalone
/// machines — the sensor never observes it. A `computer` account creation (4741) is
/// a distinct technique (T1136.002) and would take its own bit if we add it later.
pub const FLAG_PERSISTENCE_ACCOUNT_ARTIFACT: u32 = 0x0800_0000;

/// Same principle as [`FLAG_PERSISTENCE_ARTIFACT`], for a Linux **systemd unit**
/// observed starting for the first time since the agent started (ATT&CK T1543.002
/// — Create or Modify System Process: Systemd Service, the Linux sibling of
/// T1543.003) rather than a Windows service. Set by `sensor-linux-journal`'s
/// `persistence::UnitPersistenceTracker` (issue #93), the Linux side of the same
/// "reuse `FileOpenEvent` + a flag" shape rather than a new `Event` variant —
/// see `sensor-linux-journal::auth`'s module doc for why a Linux-only lifecycle
/// shape was deliberately not invented while this decision was open.
///
/// Not the same signal as Windows' 7045: journald's `JOB_TYPE=start`/
/// `JOB_RESULT=done` fires on every start of a unit, install or routine restart
/// alike, unlike the Service Control Manager which only writes 7045 once, at
/// actual registration. This flag is therefore only a "first start observed by
/// this agent process" approximation, not a true install signal — see the
/// tracker's own doc for the full caveat (an agent restart forgets what it had
/// already seen).
///
/// `FileOpenEvent::path` and `FileOpenEvent::meta::comm` both carry the unit name
/// (`sshd.service`) — journald's job-completion record has no image-path
/// equivalent to Windows' 7045, so there is no separate field to put there.
///
/// A distinct bit from every other `FLAG_PERSISTENCE_*` constant, so no two
/// techniques cross-fire off a single event.
pub const FLAG_PERSISTENCE_SYSTEMD_ARTIFACT: u32 = 0x4000_0000;

/// Identity of the user a process runs as, per platform.
///
/// A bare `uid: u32` cannot represent Windows (audit finding F-3: SYSTEM spawning
/// `cmd.exe` and a standard user doing the same were the same event). `Unknown` is for
/// sensors that genuinely cannot attribute (they should say so in their capabilities,
/// not fabricate a value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "os", rename_all = "snake_case")]
pub enum User {
    Unix {
        uid: u32,
        gid: u32,
    },
    Windows {
        /// String SID (e.g. `S-1-5-18`).
        sid: String,
        /// Integrity level RID (e.g. 0x2000 medium, 0x3000 high, 0x4000 system),
        /// when the sensor can read the token.
        integrity_level: Option<u32>,
    },
    Unknown,
}

/// Metadata common to every event: identity of the emitting process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMeta {
    pub pid: u32,
    /// Parent PID — essential for most detections (process-tree rules).
    pub ppid: u32,
    pub user: User,
    /// Nanoseconds since the UNIX epoch. Sensors normalize their platform clock
    /// (boot-relative eBPF timestamps, ETW FILETIME) before emitting.
    pub timestamp_ns: u64,
    /// Short process name (Linux `comm`, image basename elsewhere). Unbounded here;
    /// platform truncation (e.g. the kernel's 15 bytes for `comm`) is a sensor
    /// property reported by conformance, not a schema limit.
    pub comm: String,
    /// Container the emitting process runs in, when the sensor can attribute one.
    /// `None` on every platform without container support (Windows, macOS) and on
    /// bare-metal/VM Linux processes — this is not a Kubernetes pod/namespace context
    /// (out of scope, issue #80), just the container runtime's own identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerContext>,
}

/// Identity of the container a process runs in, resolved from its cgroup (issue #80).
///
/// `id` is the only field a Linux sensor can fill today (cgroup path parsing alone,
/// no daemon call). `image`/`name` need a cached lookup against the Docker/containerd
/// socket — deliberately left as a follow-up so this attribution foundation doesn't
/// block on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerContext {
    /// Full container id, as it appears in the cgroup path (64 hex chars for
    /// Docker/containerd) — not truncated to the 12-char short id, so it stays a
    /// stable join key for a later Docker/containerd socket lookup.
    pub id: String,
    /// Image reference (e.g. `nginx:1.27`). `None` until the socket lookup lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Container name, as assigned by the runtime. `None` until the socket lookup
    /// lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Process execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEvent {
    pub meta: EventMeta,
    /// Full path of the executed image, as the platform reports it (normalized to a
    /// drive-letter path on Windows — audit F-5).
    pub image_path: String,
    /// The command line as one string, unbounded (audit F-1/F-4: this field is what
    /// the base64 rule, encoded-PowerShell Sigma rules, and the ML cmdline features
    /// evaluate — it must never be a truncated placeholder for the image path).
    pub cmdline: String,
    /// Argument vector where the platform provides one (Unix execve). Empty on
    /// platforms that only have a flat command line (Windows); consumers fall back
    /// to [`ExecEvent::cmdline`].
    pub argv: Vec<String>,
    /// Parent process short name, captured by the sensor *at exec time*. Lineage is a
    /// first-class detection input (parent→child transition rarity, ancestry
    /// features — see "Behavior over time" in `docs/detection/ml.md`); sensors that
    /// can attribute the parent fill this rather than leaving consumers to join on
    /// `meta.ppid` later, which races against pid reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_comm: Option<String>,
    /// Full image path of the parent, where the platform resolves it (ETW and
    /// `EndpointSecurity` provide it; eBPF may only have the parent `comm`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_image_path: Option<String>,
    /// SHA-256 of the executed image, filled by the agent's enrichment stage (not by
    /// sensors) — the join key for IOC hash matching and fleet-level correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Code-signature verdict for the executed image, filled by enrichment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl ExecEvent {
    /// The command line in the one canonical form the ML cmdline scorer and its
    /// training pipeline agree on: `argv` tokens joined (and terminated) by NUL.
    ///
    /// This is deliberately **not** [`ExecEvent::cmdline`]: sensors are free to put a
    /// display/Sigma-friendly string there (the Linux userspace sensor space-joins
    /// argv), and the cmdline feature extractor splits tokens on NUL — feeding it a
    /// space-joined string silently collapses `token_count` to 1 and inflates
    /// `max_token_length`. Every ML consumer (`ml::features::cmdline`, the agent's
    /// scorer wiring, `synthaea_ml`) must build its input from here.
    ///
    /// Fallback when `argv` is empty (Windows/ETW has only a flat command line):
    /// [`ExecEvent::cmdline`] verbatim, as one token. Mirror of
    /// `synthaea_ml.data.canonical.ml_cmdline_from_record`.
    #[must_use]
    pub fn ml_cmdline(&self) -> String {
        if self.argv.is_empty() {
            return self.cmdline.clone();
        }
        let mut s = String::with_capacity(self.cmdline.len() + self.argv.len());
        for tok in &self.argv {
            s.push_str(tok);
            s.push('\0');
        }
        s
    }
}

/// Code-signature verdict (Authenticode on Windows, codesign on macOS; Linux has no
/// standard equivalent and reports `Unsupported`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signature {
    /// Signed and the chain verified.
    Valid,
    /// Signed but verification failed (broken chain, revoked, tampered).
    Invalid,
    /// No signature present.
    Unsigned,
    /// The platform has no signature scheme, or verification errored.
    Unsupported,
}

/// File open/create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpenEvent {
    pub meta: EventMeta,
    pub path: String,
    /// Platform-native open/access flags (Linux `open(2)` flags, Windows create
    /// dispositions). Rules match primarily on `path`; flag interpretation is
    /// per-platform and documented by each sensor.
    pub flags: u32,
}

/// File write (issue #262).
///
/// ## ⚠️ Critical Limitation: No Path Included
///
/// This event carries **no path** — only `(pid, fd, bytes_requested)`. `write(2)` and
/// `pwrite64(2)` operate on file descriptors, not paths, and the Linux sensor resolves
/// no fd→path mapping (neither kernel-side `bpf_d_path`/LSM hooks nor userspace
/// `/proc/<pid>/fd/<n>` lookup — see `sensor-linux-wire::FileWriteEvent`'s version
/// history for rationale).
///
/// **This is a volume/frequency signal** for burst-write detection (ransomware, mass
/// tampering, log destruction), not a per-write path trail. To correlate a write with
/// a file path, detection rules must join to a recent [`FileOpenEvent`] on
/// `(meta.pid, fd)`.
///
/// ## Detection Correlation Pattern
///
/// ```rust,ignore
/// // Pseudo-code example: correlate FileOpen → FileWrite
/// match event {
///     Event::FileOpen(open) => {
///         // Store (pid, fd) → path mapping
///         state.track_fd(open.meta.pid, open.fd, open.path.clone());
///     }
///     Event::FileWrite(write) => {
///         // Look up path from prior FileOpen
///         if let Some(path) = state.get_path(write.meta.pid, write.fd) {
///             // Now you can detect: "wrote 1MB to /etc/passwd"
///             check_suspicious_write(path, write.bytes_requested);
///         }
///     }
///     Event::FileClose(_) => {
///         // Clean up fd tracking to bound memory
///     }
/// }
/// ```
///
/// See `docs/detection/file-activity-patterns.md` for full worked examples including
/// ransomware burst-write + mass-rename correlation.
///
/// ## Performance Notes
///
/// `write(2)` is one of the hottest syscalls in the system. Current implementation:
/// - Captures **every** write syscall (no size filtering)
/// - Expected rate: 10-1000+ events/sec under normal load, 10K+/sec under heavy I/O
/// - No built-in sampling or backpressure (Phase 1 implementation)
///
/// Future work (issue #262 Phase 2):
/// - Add min-size filter (e.g., skip writes < 4KB)
/// - Consider sampling under sustained high-volume
/// - Add `writev(2)`, `pwrite64(2)`, `pwritev(2)` coverage (currently only `write(2)`)
///
/// ## Syscall Coverage
///
/// Phase 1 (current): `write(2)` only
/// Phase 2 (deferred): `writev`, `pwrite64`, `pwritev`, `pwritev2`
///
/// Rationale for deferral: `write(2)` covers the common case; vectored/positioned
/// writes are used by databases and async I/O but add complexity (multiple fd/offset
/// pairs per syscall). Added once the Phase 1 signal proves useful and performance
/// characteristics are understood.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteEvent {
    pub meta: EventMeta,
    /// The file descriptor written to, in the writing process's own fd table —
    /// meaningful only paired with `meta.pid`, and reused across the process's
    /// lifetime like any fd.
    pub fd: u32,
    /// The caller's requested byte count (`write(2)`'s `count` argument), read at
    /// syscall entry — not the syscall's return value, so a short write or a
    /// failed call still reports the requested size.
    pub bytes_requested: u64,
}

/// File delete (issue #262): `unlink(2)`/`unlinkat(2)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeleteEvent {
    pub meta: EventMeta,
    pub path: String,
}

/// File rename (issue #262): `rename(2)`/`renameat(2)`/`renameat2(2)`. The classic
/// ransomware signal (`invoice.pdf` → `invoice.pdf.locked`) lives entirely in
/// `new_path`'s suffix relative to `old_path`'s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRenameEvent {
    pub meta: EventMeta,
    pub old_path: String,
    pub new_path: String,
}

/// Socket bind (issue #263): `bind(2)`, `AF_INET`/`AF_INET6` only — a discrete,
/// real-time trace of a process claiming a local address (backdoor/reverse-shell
/// listener detection: `/bin/bash` binding a port is a strong signal on its own).
///
/// Distinct from [`ListenPortEvent`], which is a periodic poll snapshot from
/// `sensor-linux-netlink`: this fires once, at the `bind(2)` call itself, and does
/// NOT imply `listen(2)` followed — a UDP socket, or a TCP socket bound but never
/// listened, binds too. `listen(2)`/`accept(2)` are deliberately not captured yet
/// (see `sensor-linux-wire::SocketBindEvent`'s doc for why).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketBindEvent {
    pub meta: EventMeta,
    pub local_addr: core::net::IpAddr,
    pub local_port: u16,
}

/// DNS resolution — the query name and answer, joined to the resolving process.
///
/// Emitted on EID 3008 (`QueryCompleted`) of the Microsoft-Windows-DNS-Client
/// provider. Gives the exact domain a process tried to resolve and what it got
/// back — the primary join key for domain IOC matching and beacon-frequency
/// analysis. EID 3006 (`QueryStarted`) is not emitted: without the answer it is
/// noise; a successful resolution always produces a 3008.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryEvent {
    pub meta: EventMeta,
    /// The queried domain name, as the OS received it from the application.
    pub query: String,
    /// DNS record type (1 = A, 28 = AAAA, 5 = CNAME, ...).
    pub qtype: u32,
    /// Resolved addresses / CNAME chain, semicolon-separated as the provider
    /// emits them (e.g. `"type:1 172.67.143.127;"`). `None` on NXDOMAIN or when
    /// the provider returns an empty string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Win32 status code (0 = success, 9003 = NXDOMAIN, ...).
    pub status: u32,
}

/// WMI activity — query execution (EID 23) or method invocation (EID 24) from the
/// Microsoft-Windows-WMI-Activity provider.
///
/// Covers T1047 (`Win32_Process.Create` via WMI) and WMI-based reconnaissance
/// (`SELECT * FROM Win32_Process`). Exactly one of `query` or `method` is `Some`
/// depending on the event ID; the other is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WmiActivityEvent {
    pub meta: EventMeta,
    /// WMI namespace (e.g. `ROOT\\CIMv2`).
    pub namespace: String,
    /// WQL query string for EID 23 (`ExecQuery`). `None` for EID 24.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Method invocation for EID 24, formatted as `ClassName.MethodName`
    /// (e.g. `Win32_Process.Create`). `None` for EID 23.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// `PowerShell` script block logged by EID 4104 of the Microsoft-Windows-PowerShell
/// provider.
///
/// The provider decodes `base64 -EncodedCommand` payloads before logging — this
/// event sees the plain-text script regardless of obfuscation, making it the
/// primary signal for encoded-PowerShell detections (T1059.001, T1027).
///
/// Large scripts are split across multiple ETW records. Each fragment shares the
/// same `script_block_id`; reassemble by ordering on `(script_block_id,
/// message_number)`. Single-record scripts have `message_number = message_total = 1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptBlockEvent {
    pub meta: EventMeta,
    /// Opaque identifier shared by all fragments of the same script block.
    pub script_block_id: String,
    /// Source file path when the script was loaded from disk; `None` for
    /// interactive / inline invocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Decoded script text for this fragment.
    pub text: String,
    /// 1-based fragment index. Equal to `message_total` when the script fits in
    /// one ETW record.
    pub message_number: u32,
    /// Total number of fragments for this script block.
    pub message_total: u32,
}

/// Image (DLL or EXE) loaded into a process address space.
///
/// Emitted on EID 5 of the Microsoft-Windows-Kernel-Process provider, which is
/// already subscribed for process start/end events. Covers DLL hijacking, side-loading,
/// `LOLBin` chains (e.g. `wscript.exe` → `scrobj.dll`), and AMSI bypass via patching
/// (first seen as a load of `amsi.dll` into an unexpected process).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageLoadEvent {
    pub meta: EventMeta,
    /// Full path of the loaded image, normalized to drive-letter form (same
    /// normalization as [`ExecEvent::image_path`], audit F-5).
    pub image_path: String,
}

/// Registry value write — the primary signal for persistence and configuration
/// manipulation detections.
///
/// Emitted on EID 4 (`RegSetValueKey`) of the Microsoft-Windows-Kernel-Registry
/// provider. Only write operations are captured; reads (EID 2 `RegOpenKey`) are
/// high-volume noise with almost no detection value at this tier.
///
/// Key path is normalized from NT registry format (`\REGISTRY\MACHINE\...`) to
/// the familiar Win32 hive prefix (`HKLM\...`) by the sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySetEvent {
    pub meta: EventMeta,
    /// Normalized registry key path (e.g. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).
    pub key: String,
    /// Name of the value being written. Empty string means the default value `(Default)`.
    pub value_name: String,
    /// Registry data type (`1=REG_SZ`, `2=REG_EXPAND_SZ`, `3=REG_BINARY`, `4=REG_DWORD`, ...).
    pub data_type: u32,
    /// String representation of the value data for `REG_SZ` / `REG_EXPAND_SZ` types.
    /// `None` for binary or DWORD types where string decoding is not meaningful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// In-memory .NET assembly load — the primary signal for execute-assembly /
/// fileless .NET injection (T1620, T1055).
///
/// Emitted on EID 154 (`AssemblyLoad`) of the `Microsoft-Windows-DotNETRuntime`
/// provider, filtered to dynamic (in-memory) assemblies only (`flags & 0x2 != 0`).
/// File-backed assemblies are high-volume noise with low detection value at this
/// tier — they are dropped at the sensor, not forwarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyLoadEvent {
    pub meta: EventMeta,
    /// Fully qualified assembly name (e.g. `MyPayload, Version=0.0.0.0, ...`).
    pub assembly_name: String,
    /// Assembly load flags from the runtime (`0x2` = dynamic/in-memory,
    /// `0x8` = collectible). In-memory loads always have bit `0x2` set.
    pub flags: u32,
}

/// SMB client connection to a remote server (EID 30704 of
/// `Microsoft-Windows-SMBClient`).
///
/// Fires when the SMB redirector establishes a TCP connection to a remote
/// server. Primary signal for lateral movement via SMB (T1021.002 —
/// Remote Services: SMB/Windows Admin Shares).
///
/// EID 30702 (failed connection) is not emitted — only successful connections
/// have detection value at this tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmbConnectEvent {
    pub meta: EventMeta,
    /// Server name as the SMB client resolved it (e.g. `\\WIN-TARGET` or `\\192.168.1.10`).
    pub server_name: String,
}

/// UDP datagram sent — the primary signal for DNS-tunneling and C2-over-UDP detection.
///
/// Emitted on EID 14 (`UDPSend` IPv4) of the Microsoft-Windows-Kernel-Network
/// provider, which is already subscribed for TCP connect/send events. IPv6 UDP
/// is not captured at this tier (field layout differs; add EID 18 separately if needed).
///
/// Note: UDP is stateless — unlike TCP connects there is no dedup filter, so
/// high-volume UDP flows (QUIC, media) may produce many events. Rules matching
/// on this type should aggregate on `(pid, daddr, dport)` before alerting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpSendEvent {
    pub meta: EventMeta,
    /// Destination address (IPv4 only at this tier).
    pub daddr: core::net::IpAddr,
    pub dport: u16,
    /// UDP payload size in bytes. Useful for detecting large DNS queries (tunneling)
    /// and volumetric anomalies — normal DNS queries are under 512 bytes.
    pub size: u32,
}

/// A TCP socket found listening, from a periodic socket-table snapshot rather than a
/// discrete `bind`/`listen()` syscall trace (Linux: `NETLINK_SOCK_DIAG`, issue #92 —
/// a probe-free source that runs where eBPF/ETW cannot, or as a redundant cross-check
/// alongside them).
///
/// `meta.timestamp_ns` is when the snapshot was taken, not when the socket actually
/// started listening — a snapshot can only observe "listening as of now", so a
/// short-lived listener between two polls is invisible to this source (the polling
/// cadence is a caller decision, not a schema concern). Detection value is in the
/// series across snapshots (listen-port drift: a new port appearing that wasn't there
/// last poll), not any single event in isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenPortEvent {
    pub meta: EventMeta,
    pub local_addr: core::net::IpAddr,
    pub local_port: u16,
}

/// Direction of TLS data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsDirection {
    /// Data read from network (post-decryption).
    Read,
    /// Data written to network (pre-encryption).
    Write,
}

/// TLS library type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsLibraryType {
    /// OpenSSL library.
    OpenSsl,
    /// `BoringSSL` library (Google's fork of OpenSSL).
    BoringSsl,
    /// `GnuTLS` library.
    GnuTls,
}

/// Shell type for readline capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellType {
    Bash,
    Zsh,
}

/// TLS plaintext capture — first N bytes of data before encryption or after
/// decryption (issue #90).
///
/// Emitted by Linux uprobes on `SSL_read`/`SSL_write` and `GnuTLS` equivalents.
/// Captures HTTP headers, initial TLS handshake bytes, and other plaintext that
/// would otherwise be invisible to network monitoring. Primary signal for C2
/// beacon detection and exfiltration analysis.
///
/// Note: This is sensitive data — the plaintext may contain credentials, tokens,
/// or PII. Sensors apply a byte budget (`MAX_TLS_CAPTURE = 256` in the wire format);
/// longer buffers are truncated at capture time. Configuration must allow operators
/// to disable this capture or apply process/library allowlists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsCaptureEvent {
    pub meta: EventMeta,
    /// Direction of data flow (read = inbound/decrypted, write = outbound/encrypted).
    pub direction: TlsDirection,
    /// TLS library that was probed.
    pub lib_type: TlsLibraryType,
    /// Captured plaintext bytes. May be binary data (not UTF-8). Consumers should
    /// handle encoding errors gracefully when treating this as text.
    pub data: Vec<u8>,
}

/// Interactive shell command capture — commands typed at a shell prompt that may
/// not trigger execve (issue #90).
///
/// Emitted by Linux uprobes on bash/zsh readline functions. Captures shell builtins
/// (`cd`, `export`, `alias`) and interactive commands that do not spawn child processes.
/// Complements `ExecEvent` for complete shell activity visibility.
///
/// Note: Multi-line commands are captured as typed (newlines included). Command
/// history navigation (up-arrow) triggers multiple readline events; deduplication
/// is the consumer's responsibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadlineInputEvent {
    pub meta: EventMeta,
    /// Shell type (bash or zsh).
    pub shell_type: ShellType,
    /// Full command line as typed by the user. UTF-8 validated by the sensor.
    pub input: String,
}

/// Outbound network connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectEvent {
    pub meta: EventMeta,
    /// Destination address, v4 or v6 (audit F-7: v6 is first-class, not an unset flag).
    pub daddr: core::net::IpAddr,
    pub dport: u16,
}

/// Conntrack flow accounting — bytes/packets transferred over a tracked connection,
/// the beacon-detection volume feature a point-in-time [`ConnectEvent`] can't carry
/// (Linux: `NETLINK_NETFILTER`/`ctnetlink`, issue #92).
///
/// A conntrack dump entry carries no PID of its own — this event only exists because
/// the sensor joined the flow's tuple against a concurrent `sock_diag` snapshot to
/// attribute it (see `sensor-linux-netlink`'s `normalize::conntrack_flow_events_for`);
/// a flow the join couldn't attribute (already closed, owned by another user's
/// unreadable `/proc/<pid>/fd`) produces no event at all rather than one with
/// fabricated metadata, same discipline as [`ListenPortEvent`].
///
/// `bytes_*`/`packets_*` are `None` when the kernel's
/// `net.netfilter.nf_conntrack_acct` accounting is disabled (the default) — a flow
/// with `None` counters is still worth an event (its address/port/protocol alone),
/// just without volume data. `meta.timestamp_ns` is the poll time, not flow start —
/// same "snapshot, not a discrete trace" caveat as [`ListenPortEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFlowEvent {
    pub meta: EventMeta,
    /// This host's side of the attributed socket (see the join doc above) — the
    /// stable per-flow identity a poll-based source needs: unlike a discrete
    /// `connect()` trace, the same live flow reappears on every conntrack poll
    /// while it's open, so a consumer counting "connections" must key on
    /// `local_port` (plus `daddr`/`dport`) to tell a repeated poll of one
    /// long-lived flow apart from N distinct connections (issue #92 beacon
    /// wiring — a naive per-poll counter would otherwise alert on any ordinary
    /// long-lived connection, e.g. SSH, simply for staying open past 3 polls).
    pub local_port: u16,
    /// The peer address, from this host's perspective — whichever side of the
    /// flow's tuple isn't the locally-attributed socket (see the join doc above).
    pub daddr: core::net::IpAddr,
    pub dport: u16,
    /// IP protocol number (`IPPROTO_TCP` = 6; the only value this source currently
    /// attributes — see the sensor crate doc for why UDP isn't joined yet).
    pub protocol: u8,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub packets_sent: Option<u64>,
    pub packets_received: Option<u64>,
}

/// Health status of a single sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorHealth {
    /// Sensor name (e.g. "linux-ebpf", "windows-etw").
    pub name: String,
    /// Cumulative pulse count since agent start (heartbeat counter).
    pub pulse_count: u64,
    /// Whether the sensor is currently considered silent (no pulses in deadline).
    pub silent: bool,
}

/// Periodic agent health beacon — self-diagnostics emitted to the control plane.
///
/// Emitted at a fixed cadence (default 30s) so the server can detect silent agents
/// (an agent that stops beaconing is as suspicious as one that stops sending events).
/// Does not carry event payloads — only aggregate counters and status flags.
///
/// Note: Unlike telemetry events, `HealthBeacon` has no `EventMeta` (no originating
/// process). Consumers must handle this variant specially in pattern matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthBeacon {
    /// Nanoseconds since the UNIX epoch.
    pub timestamp_ns: u64,
    /// Agent version string (e.g. "0.1.0").
    pub agent_version: String,
    /// Health status of each loaded sensor.
    pub sensors: Vec<SensorHealth>,
    /// Total bytes currently in the event spool (upload backlog).
    pub spool_bytes: u64,
    /// Cumulative records dropped from spool due to byte cap.
    pub spool_dropped: u64,
    /// Cumulative events dropped from enrichment queue (backpressure).
    pub enrich_dropped: u64,
}

/// A logon/authentication outcome, or a privileged-session assignment — shared
/// across platforms per #94: Windows Security-log logons (events 4624/4625/4648/
/// 4672, `sensor-windows-eventlog`) and Linux authentication (sshd accept/failure,
/// `su`/`sudo`, PAM sessions — `sensor-linux-journal`, not yet implemented) both
/// normalize into this one shape rather than each inventing its own type. See
/// `docs/adr/0005-windows-logon-events-shared-auth-event-type.md`.
///
/// Deliberately narrower than either platform's native audit record: only the
/// fields a cross-platform lateral-movement/privilege-escalation rule can
/// actually use today. Platform-only detail that doesn't generalize (a Windows
/// `LogonType` code, a Linux PAM service name) is left out rather than added
/// speculatively — extend when a rule needs it, per this crate's additive-only
/// discipline (see the top-level docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEvent {
    /// Identity of the process that reported the logon (e.g. Windows
    /// `winlogon.exe`/`lsass.exe`, the logon subsystem — not necessarily the
    /// account's own process). This is a session/auth-subsystem event, not a
    /// process-lifecycle one; `meta.user` is who is *performing* the action
    /// (the already-logged-on caller for `ExplicitCredentials`/
    /// `PrivilegedSession`), which is not the same as `target_user` below.
    pub meta: EventMeta,
    pub outcome: AuthOutcome,
    pub kind: AuthKind,
    /// The account being authenticated as/into — Windows `TargetUserName`
    /// (`DOMAIN\user` or a local account name), Linux the PAM/sshd target user.
    /// Deliberately distinct from `meta.user`: for `ExplicitCredentials` and
    /// `PrivilegedSession` the two differ by design — that difference is the
    /// whole signal.
    pub target_user: String,
    /// Windows `TargetUserSid`, when the platform resolves one. `None` on Linux
    /// (no SID concept) and when Windows itself could not resolve the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user_sid: Option<String>,
    /// Origin address, when the platform reports one for this kind of logon
    /// (network/RDP logons, SSH) — absent for local console/service/batch
    /// logons, which is itself meaningful (do not fabricate a loopback address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<core::net::IpAddr>,
    /// Opaque platform status/result code, kept for forensic completeness
    /// (Windows hex `Status`/`SubStatus` — e.g. the substatus that tells a wrong
    /// password apart from an already-locked-out account) — not interpreted by
    /// rules, which match on `outcome`/`kind` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
}

/// Whether an [`AuthEvent`] represents a successful or failed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthOutcome {
    Success,
    Failure,
}

/// What kind of authentication/session action an [`AuthEvent`] represents.
/// Coarse by design — see each variant for how Windows event IDs and (once
/// implemented) the Linux journal facilities map onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// A new logon session was created (Windows event 4624; Linux sshd
    /// `Accepted ...`/a PAM session open).
    Logon,
    /// A logon attempt failed (Windows event 4625; Linux sshd `Failed
    /// password ...`/a PAM authentication failure).
    LogonFailure,
    /// Credentials for an account other than the current session's were
    /// explicitly supplied (Windows event 4648 — a classic RunAs/lateral-movement
    /// signal; Linux `su`/`sudo -u other-user`).
    ExplicitCredentials,
    /// Special/elevated privileges were assigned to a logon session (Windows
    /// event 4672, typically alongside a 4624 for administrative accounts; Linux
    /// a successful `sudo`).
    PrivilegedSession,
}

/// The normalized event envelope.
///
/// `#[non_exhaustive]`: new telemetry categories (registry, DNS, image load, ...) are
/// added as variants without breaking sinks — consumers must have a fall-through arm
/// and treat unknown categories as "not for me".
///
/// Note: Control-plane messages like [`HealthBeacon`] are NOT part of this enum.
/// They flow through a separate channel at the transport layer to avoid polluting
/// the telemetry pipeline with non-process events.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Exec(ExecEvent),
    FileOpen(FileOpenEvent),
    Connect(ConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistrySet(RegistrySetEvent),
    ImageLoad(ImageLoadEvent),
    ScriptBlock(ScriptBlockEvent),
    WmiActivity(WmiActivityEvent),
    AssemblyLoad(AssemblyLoadEvent),
    SmbConnect(SmbConnectEvent),
    UdpSend(UdpSendEvent),
    Auth(AuthEvent),
    ListenPort(ListenPortEvent),
    NetworkFlow(NetworkFlowEvent),
    TlsCapture(TlsCaptureEvent),
    ReadlineInput(ReadlineInputEvent),
    FileWrite(FileWriteEvent),
    FileDelete(FileDeleteEvent),
    FileRename(FileRenameEvent),
    SocketBind(SocketBindEvent),
}

impl Event {
    /// Returns the process metadata common to all telemetry events.
    ///
    /// Deliberately exhaustive (no wildcard arm): every new [`Event`] variant must
    /// add its own arm here, so a missing one is a compile error rather than a
    /// silently-wrong fallback.
    #[must_use]
    pub fn meta(&self) -> &EventMeta {
        match self {
            Event::Exec(e) => &e.meta,
            Event::FileOpen(e) => &e.meta,
            Event::Connect(e) => &e.meta,
            Event::DnsQuery(e) => &e.meta,
            Event::RegistrySet(e) => &e.meta,
            Event::ImageLoad(e) => &e.meta,
            Event::ScriptBlock(e) => &e.meta,
            Event::WmiActivity(e) => &e.meta,
            Event::AssemblyLoad(e) => &e.meta,
            Event::SmbConnect(e) => &e.meta,
            Event::UdpSend(e) => &e.meta,
            Event::Auth(e) => &e.meta,
            Event::ListenPort(e) => &e.meta,
            Event::NetworkFlow(e) => &e.meta,
            Event::TlsCapture(e) => &e.meta,
            Event::ReadlineInput(e) => &e.meta,
            Event::FileWrite(e) => &e.meta,
            Event::FileDelete(e) => &e.meta,
            Event::FileRename(e) => &e.meta,
            Event::SocketBind(e) => &e.meta,
            // No wildcard arm, on purpose: #[non_exhaustive] has no effect inside
            // the defining crate, so a new variant without its arm here is a
            // compile error — the reminder the doc comment above promises.
        }
    }
}
