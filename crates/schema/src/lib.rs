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
pub const SCHEMA_VERSION: u32 = 2;

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

/// Outbound network connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectEvent {
    pub meta: EventMeta,
    /// Destination address, v4 or v6 (audit F-7: v6 is first-class, not an unset flag).
    pub daddr: core::net::IpAddr,
    pub dport: u16,
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
}

impl Event {
    #[must_use]
    pub fn meta(&self) -> &EventMeta {
        match self {
            Event::Exec(e) => &e.meta,
            Event::FileOpen(e) => &e.meta,
            Event::Connect(e) => &e.meta,
            Event::DnsQuery(e) => &e.meta,
            // Non-exhaustive: new telemetry categories reach existing sinks without
            // a breaking change — consumers match variants they understand and
            // ignore the rest.
            #[allow(unreachable_patterns)]
            _ => unreachable!("all Event variants must be covered by meta()"),
        }
    }
}
