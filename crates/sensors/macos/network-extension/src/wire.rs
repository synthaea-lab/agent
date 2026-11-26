//! The extension-to-agent wire protocol: newline-delimited JSON records.
//!
//! JSON rather than a `repr(C)` layout because the two sides are built by
//! different toolchains and released independently, so a skew skips records
//! instead of corrupting them. Bump [`WIRE_VERSION`] (independent of
//! `schema::SCHEMA_VERSION`) on any change a deployed extension could
//! disagree with; the receiver skips and counts records with another `v`.

use serde::{Deserialize, Serialize};

/// Version of this wire protocol. The Swift side writes it into every
/// record's `v` field (`extension/EventPipe.swift` must match).
pub const WIRE_VERSION: u32 = 1;

/// Direction of a filtered flow, from the endpoint's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    /// The endpoint opened the flow.
    Outbound,
    /// The flow arrived at the endpoint.
    Inbound,
}

/// One record from the extension. `serde(tag = "kind")` so unknown kinds from
/// a newer extension fail the line's parse (skipped + counted), never the
/// stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
///
/// Every record carries the wire version `v`, a timestamp `ts_ns`, and the `pid` the extension
/// attributed (0 when the flow had no audit token). The shared fields are documented on
/// [`NeRecord::Flow`]; the other variants repeat the names and mean the same.
pub enum NeRecord {
    /// A new socket flow observed by `NEFilterDataProvider`, reported at
    /// flow-establishment time (the `ConnectEvent`-shaped fact).
    Flow {
        /// Wire version the extension wrote; the receiver skips a record whose `v` is not
        /// [`WIRE_VERSION`].
        v: u32,
        /// Nanoseconds since the UNIX epoch, taken by the extension.
        ts_ns: u64,
        /// Pid from the flow's source-app audit token.
        pid: u32,
        /// Executable path resolved from the pid, when the extension could.
        #[serde(default)]
        process_path: Option<String>,
        /// Whether the endpoint opened the flow or received it.
        direction: FlowDirection,
        /// Remote address literal (v4 or v6).
        remote_addr: String,
        /// Remote port, 0 when the extension could not parse the endpoint's port.
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
        /// See [`NeRecord::Flow`].
        v: u32,
        /// When the flow closed, not when it opened.
        ts_ns: u64,
        /// See [`NeRecord::Flow`].
        pid: u32,
        /// See [`NeRecord::Flow`].
        #[serde(default)]
        process_path: Option<String>,
        /// See [`NeRecord::Flow`].
        remote_addr: String,
        /// See [`NeRecord::Flow`].
        remote_port: u16,
        /// See [`NeRecord::Flow`].
        #[serde(default)]
        local_port: u16,
        /// See [`NeRecord::Flow`].
        protocol: u8,
        /// Bytes the endpoint sent over the flow (`bytesOutboundCount`).
        bytes_sent: u64,
        /// Bytes the endpoint received over the flow (`bytesInboundCount`).
        bytes_received: u64,
    },
    /// A DNS query/response pair observed by `NEDNSProxyProvider`.
    Dns {
        /// See [`NeRecord::Flow`].
        v: u32,
        /// When the response arrived.
        ts_ns: u64,
        /// See [`NeRecord::Flow`].
        pid: u32,
        /// See [`NeRecord::Flow`].
        #[serde(default)]
        process_path: Option<String>,
        /// The queried name, empty when the question did not parse.
        query: String,
        /// DNS record type (1 = A, 28 = AAAA, ...), 0 when the question did not parse.
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
