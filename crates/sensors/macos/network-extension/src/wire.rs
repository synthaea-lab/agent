//! The extension↔agent wire protocol: newline-delimited JSON records the
//! Swift system extension (see `extension/`) writes over the local socket and
//! this crate's receiver reads.
//!
//! JSON rather than a fixed `repr(C)` layout (the `sensor-linux-wire`
//! approach) deliberately: the two sides are different languages built by
//! different toolchains (`swiftc` vs `cargo`) with independent release
//! timing — a self-describing, versioned format degrades additively instead
//! of corrupting on skew. Volume is far below the eBPF ring buffer's, so the
//! serialization cost is irrelevant here.
//!
//! Versioning follows the same discipline as `sensor-linux-wire`'s
//! `WIRE_VERSION`, independent of `schema::SCHEMA_VERSION`: bump on any
//! change a deployed extension could disagree with; the receiver skips (and
//! counts) records with an unknown `v` rather than guessing.

use serde::{Deserialize, Serialize};

/// Version of this wire protocol. The Swift side writes it into every
/// record's `v` field (`extension/EventPipe.swift` must match).
pub const WIRE_VERSION: u32 = 1;

/// Direction of a filtered flow, from the endpoint's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Outbound,
    Inbound,
}

/// One record from the extension. `serde(tag = "kind")` so unknown kinds from
/// a newer extension fail the line's parse (skipped + counted), never the
/// stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NeRecord {
    /// A new socket flow observed by `NEFilterDataProvider`, reported at
    /// flow-establishment time (the `ConnectEvent`-shaped fact).
    Flow {
        v: u32,
        /// Nanoseconds since the UNIX epoch, taken by the extension.
        ts_ns: u64,
        /// Pid from the flow's source-app audit token.
        pid: u32,
        /// Executable path resolved from the pid, when the extension could.
        #[serde(default)]
        process_path: Option<String>,
        direction: FlowDirection,
        /// Remote address literal (v4 or v6).
        remote_addr: String,
        remote_port: u16,
        /// Local port, when known (0 when the provider had not bound yet).
        #[serde(default)]
        local_port: u16,
        /// IP protocol number (6 tcp, 17 udp).
        protocol: u8,
    },
    /// Flow accounting at flow close — bytes transferred, the
    /// `NetworkFlowEvent`-shaped fact.
    FlowStats {
        v: u32,
        ts_ns: u64,
        pid: u32,
        #[serde(default)]
        process_path: Option<String>,
        remote_addr: String,
        remote_port: u16,
        #[serde(default)]
        local_port: u16,
        protocol: u8,
        bytes_sent: u64,
        bytes_received: u64,
    },
    /// A DNS query/response pair observed by `NEDNSProxyProvider`.
    Dns {
        v: u32,
        ts_ns: u64,
        pid: u32,
        #[serde(default)]
        process_path: Option<String>,
        /// The queried name.
        query: String,
        /// DNS record type (1 = A, 28 = AAAA, ...).
        qtype: u32,
        /// Answers, semicolon-separated literals, when the response carried
        /// any (same shape as the Windows DNS-Client provider's field).
        #[serde(default)]
        result: Option<String>,
        /// DNS RCODE (0 = NOERROR, 3 = NXDOMAIN, ...).
        rcode: u32,
    },
}

impl NeRecord {
    /// The record's wire version.
    #[must_use]
    pub fn version(&self) -> u32 {
        match self {
            NeRecord::Flow { v, .. } | NeRecord::FlowStats { v, .. } | NeRecord::Dns { v, .. } => {
                *v
            }
        }
    }
}
