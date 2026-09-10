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
//! Any change visible in serialization bumps [`SCHEMA_VERSION`] and adds a new
//! `tests/fixtures/v<N>/` directory; existing fixture files are never edited.
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
pub mod sensor;

/// Version of the serialized event model. Bumped on any serialization-visible change,
/// together with a new golden-fixture directory (see crate docs).
pub const SCHEMA_VERSION: u32 = 10;

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

/// Outbound network connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectEvent {
    pub meta: EventMeta,
    /// Destination address, v4 or v6 (audit F-7: v6 is first-class, not an unset flag).
    pub daddr: core::net::IpAddr,
    pub dport: u16,
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

/// The normalized event envelope.
///
/// `#[non_exhaustive]`: new telemetry categories (registry, DNS, image load, ...) are
/// added as variants without breaking sinks — consumers must have a fall-through arm
/// and treat unknown categories as "not for me".
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
    /// Agent health beacon (no originating process — control-plane diagnostic).
    HealthBeacon(HealthBeacon),
}

impl Event {
    /// Returns the process metadata for telemetry events.
    ///
    /// # Panics
    ///
    /// Panics if called on `Event::HealthBeacon`, which has no originating process.
    /// Use [`Event::meta_opt`] if you need to handle all variants safely.
    #[must_use]
    pub fn meta(&self) -> &EventMeta {
        self.meta_opt()
            .expect("meta() called on Event::HealthBeacon — use meta_opt() instead")
    }

    /// Returns the process metadata if this is a telemetry event, or `None` for
    /// control-plane messages like `HealthBeacon`.
    #[must_use]
    pub fn meta_opt(&self) -> Option<&EventMeta> {
        match self {
            Event::Exec(e) => Some(&e.meta),
            Event::FileOpen(e) => Some(&e.meta),
            Event::Connect(e) => Some(&e.meta),
            Event::DnsQuery(e) => Some(&e.meta),
            Event::RegistrySet(e) => Some(&e.meta),
            Event::ImageLoad(e) => Some(&e.meta),
            Event::ScriptBlock(e) => Some(&e.meta),
            Event::WmiActivity(e) => Some(&e.meta),
            Event::AssemblyLoad(e) => Some(&e.meta),
            Event::SmbConnect(e) => Some(&e.meta),
            Event::UdpSend(e) => Some(&e.meta),
            Event::HealthBeacon(_) => None,
            // Non-exhaustive: new telemetry categories reach existing sinks without
            // a breaking change — consumers match variants they understand and
            // ignore the rest.
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Returns `true` if this is a control-plane message (e.g. `HealthBeacon`)
    /// rather than a telemetry event from a process.
    #[must_use]
    pub fn is_control_message(&self) -> bool {
        matches!(self, Event::HealthBeacon(_))
    }
}
