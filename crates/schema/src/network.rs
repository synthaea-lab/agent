//! Sockets, connections, flows, name resolution and the protocols carried over them.

use super::*;

/// Socket bind (issue #263): `bind(2)`, `AF_INET`/`AF_INET6` only — a discrete,
/// real-time trace of a process claiming a local address (backdoor/reverse-shell
/// listener detection: `/bin/bash` binding a port is a strong signal on its own).
///
/// Distinct from [`ListenPortEvent`], which is a periodic poll snapshot from
/// `sensor-linux-netlink`: this fires once, at the `bind(2)` call itself, and does
/// NOT imply `listen(2)` followed — a UDP socket, or a TCP socket bound but never
/// listened, binds too. See [`SocketListenEvent`] for the `listen(2)` counterpart
/// and [`SocketAcceptEvent`] for the `accept(2)`/`accept4(2)` counterpart (see
/// `sensor-linux-wire::SocketBindEvent`'s doc for why).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketBindEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Local address the socket is bound to.
    pub local_addr: core::net::IpAddr,
    /// Local port the socket is bound to.
    pub local_port: u16,
}

/// Socket listen (issue #263 Phase 2): `listen(2)` — a discrete, real-time trace of
/// a process transitioning a bound socket into the listening state
/// (backdoor/reverse-shell listener detection, same rationale as
/// [`SocketBindEvent`]).
///
/// `listen(2)`'s own arguments carry no address, only `fd`+`backlog` — the sensor
/// correlates this event's `(pid, fd)` against a prior `bind(2)` it observed.
/// `local_addr`/`local_port` are `None` when no matching `bind()` was seen (the
/// probe attached after it happened, or the caller relied on the kernel's implicit
/// ephemeral-port bind at `listen()` time) rather than reporting a wrong or zeroed
/// address as if it were real.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketListenEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Local address of the listening socket, when the sensor resolved it.
    pub local_addr: Option<core::net::IpAddr>,
    /// Local port of the listening socket, when the sensor resolved it.
    pub local_port: Option<u16>,
    /// The caller's requested backlog — a small value (e.g. 1) on an otherwise
    /// unremarkable listener can itself be a signal.
    pub backlog: u32,
}

/// Socket accept (issue #263 Phase 2): `accept(2)`/`accept4(2)` completing — a
/// discrete, real-time trace of a listening socket accepting a new connection,
/// carrying the PEER's address (the connecting client), not the local one. Only
/// emitted on success — a failed `accept()` has no peer to report. See
/// `sensor-linux-wire::SocketAcceptEvent`'s doc for the `sys_enter`/`sys_exit`
/// correlation this event depends on (the peer address doesn't exist until the
/// kernel-side call returns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketAcceptEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The listening socket's fd (`accept`/`accept4`'s first argument).
    pub listen_fd: u32,
    /// The newly accepted connection's fd (`accept`/`accept4`'s return value).
    pub accepted_fd: u32,
    /// Remote address of the accepted connection.
    pub peer_addr: core::net::IpAddr,
    /// Remote port of the accepted connection.
    pub peer_port: u16,
}

/// Socket creation (issue #263): `socket(2)` — context rather than an address.
/// `bind`/`connect`/`accept` all tell you WHERE a socket talked; this tells you
/// WHAT it was made as, before any of that happens. Not filtered to
/// `AF_INET`/`AF_INET6` like its siblings: an `AF_PACKET` or `SOCK_RAW` creation
/// (packet capture, spoofed-source tooling, a port scanner) is exactly the signal
/// this event exists to carry, and those families have no `bind`/`connect`
/// sockaddr `SocketBindEvent`/`ConnectEvent` would ever see. The one exclusion is
/// `AF_UNIX` (local IPC — systemd, journald, D-Bus, every Unix-domain client):
/// pure volume with no `bind`/`connect`-shaped risk and no current consumer
/// (#714 review). Only emitted on success — a failed `socket()` created nothing
/// to report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketCreateEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// `AF_INET` (2), `AF_INET6` (10), `AF_PACKET` (17), `AF_NETLINK` (16), ...
    pub domain: i32,
    /// `SOCK_STREAM` (1), `SOCK_DGRAM` (2), `SOCK_RAW` (3), ... with
    /// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` masked off by the sensor.
    pub socket_type: i32,
    /// Protocol argument of `socket(2)` (`0` selects the default for the type).
    pub protocol: i32,
    /// The new file descriptor (`socket(2)`'s return value).
    pub fd: u32,
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
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The queried domain name, as the OS received it from the application.
    pub query: String,
    /// DNS record type (1 = A, 28 = AAAA, 5 = CNAME, ...).
    pub qtype: u32,
    /// Existing provider result kept for compatibility; Linux `getaddrinfo`
    /// sets it to the first resolved address. `None` on lookup failure or when
    /// the provider returns no result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Resolved IP addresses in resolver order. Empty for producers that do not
    /// expose an answer set and for failed lookups. Repeated addresses are removed
    /// while preserving their first appearance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<String>,
    /// True when the producer's bounded answer collection omitted further entries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub results_truncated: bool,
    /// Win32 status code (0 = success, 9003 = NXDOMAIN, ...).
    pub status: u32,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

/// An LDAP search a process sent, from EID 30 of the
/// Microsoft-Windows-LDAP-Client provider (#364): the directory-reconnaissance
/// fingerprint an endpoint can see. Kerberoasting / AS-REP roasting start with
/// a search for roastable accounts, and SharpHound-style collection is a burst
/// of wide searches from one process; the ticket requests themselves are only
/// visible on a domain controller.
///
/// Emitted when the request is actually sent (lab, 2026-10-02: a search to a
/// listener that never answers is logged, a failed connect is not). `meta` is
/// the requesting process (`wldap32` runs in-process). Windows-only, same
/// posture as [`WmiActivityEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapSearchEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The search filter as sent (RFC 4515 text).
    pub filter: String,
    /// The search base distinguished name.
    pub base_dn: String,
    /// Search scope: 0 base object, 1 one level, 2 whole subtree.
    pub scope: u32,
    /// Attributes requested; empty means "all".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<String>,
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
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Server name as the SMB client resolved it (e.g. `\\WIN-TARGET` or `\\192.168.1.10`).
    pub server_name: String,
}

/// What a [`BitsJobEvent`] reports about its job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitsJobState {
    /// A file (remote URL → local path) was added to the job: the download
    /// is requested.
    FileAdded,
    /// The job transferred everything.
    Completed,
    /// The job was cancelled.
    Cancelled,
    /// A transfer stopped on an error; [`BitsJobEvent::hresult`] says which.
    TransferError,
}

/// A Background Intelligent Transfer Service job (#284, T1197) from
/// `Microsoft-Windows-Bits-Client`.
///
/// BITS does the network I/O from its own service (`svchost.exe`), so the
/// connect and DNS events never name the process that asked for the download.
/// This event does: `meta` is the job's client, the process that added the
/// file (or cancelled the job). For a completion or a transfer error, which
/// BITS reports from the service, it is the client that added the job's file.
///
/// One event per job state the sensor forwards, all sharing `job_id`; a
/// completion or a cancellation is one event per file of the job. Files
/// fetched from Microsoft update hosts are filtered at the sensor, see
/// `sensor-windows`; the job's owner is not a filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitsJobEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// The job GUID, braces included, as BITS writes it.
    pub job_id: String,
    /// The job's display name, chosen by the client
    /// (`bitsadmin /transfer <name>`, `Start-BitsTransfer -DisplayName`).
    pub job_title: String,
    /// State of the job this event reports.
    pub state: BitsJobState,
    /// The remote URL of the file this event is about.
    pub url: String,
    /// Where BITS writes that file.
    pub local_path: String,
    /// Bytes the job transferred so far, when the record reports it: a job
    /// total, repeated on each file's event of a multi-file job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_transferred: Option<u64>,
    /// The failing HRESULT of a [`BitsJobState::TransferError`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hresult: Option<u32>,
}

/// UDP datagram sent — the primary signal for DNS-tunneling and C2-over-UDP detection.
///
/// Emitted on EIDs 42 (UDP v4 send) and 58 (UDP v6 send) of the
/// Microsoft-Windows-Kernel-Network provider on Windows.
///
/// Note: UDP is stateless — unlike TCP connects there is no dedup filter, so
/// high-volume UDP flows (QUIC, media) may produce many events. Rules matching
/// on this type should aggregate on `(pid, daddr, dport)` before alerting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpSendEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Destination address.
    pub daddr: core::net::IpAddr,
    /// Destination port of the datagram.
    pub dport: u16,
    /// UDP payload size in bytes. Useful for detecting large DNS queries (tunneling)
    /// and volumetric anomalies — normal DNS queries are under 512 bytes.
    pub size: u32,
}

/// UDP datagram received (`recvfrom(2)`, Linux, issue #263) — the inbound
/// counterpart of [`UdpSendEvent`], carrying the sender's address. Emitted only
/// when the kernel reported a source address (a connected-socket `recv(2)` has
/// none), and only on success. `size` is the bytes actually received, not the
/// buffer length requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpRecvEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Sender's address (the remote end of the datagram).
    pub peer_addr: core::net::IpAddr,
    /// Sender's port.
    pub peer_port: u16,
    /// Bytes actually received in the datagram.
    pub size: u32,
}

/// IP protocol number for TCP, the `IPPROTO_TCP` of `<netinet/in.h>` — shared so
/// [`ListenPortEvent::protocol`]/[`NetworkFlowEvent::protocol`] callers across the
/// agent and sensor crates stamp and compare the same value instead of each
/// carrying its own `6` literal, where a typo would make a baseline key that
/// silently never matches (<https://github.com/synthaea-lab/agent/issues/40> review).
pub const IPPROTO_TCP: u8 = 6;

/// IP protocol number for UDP, the `IPPROTO_UDP` of `<netinet/in.h>` — see
/// [`IPPROTO_TCP`].
pub const IPPROTO_UDP: u8 = 17;

/// A TCP or UDP socket found bound/listening, from a periodic socket-table snapshot
/// rather than a discrete `bind`/`listen()` syscall trace (Linux: `NETLINK_SOCK_DIAG`,
/// issue #92 — a probe-free source that runs where eBPF/ETW cannot, or as a redundant
/// cross-check alongside them).
///
/// `meta.timestamp_ns` is when the snapshot was taken, not when the socket actually
/// started listening — a snapshot can only observe "listening as of now", so a
/// short-lived listener between two polls is invisible to this source (the polling
/// cadence is a caller decision, not a schema concern). Detection value is in the
/// series across snapshots (listen-port drift: a new port appearing that wasn't there
/// last poll), not any single event in isolation.
///
/// `protocol` is the IP protocol number, same convention as [`NetworkFlowEvent::protocol`]
/// (`IPPROTO_TCP` = 6, `IPPROTO_UDP` = 17, <https://github.com/synthaea-lab/agent/issues/40>), and is part of every consumer's
/// dedup/baseline key: a UDP listener and a TCP listener on the same port are different
/// shapes, not a collision — `udp/53` and `tcp/53` are two different services with no
/// reason to share a baseline entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenPortEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Local address the socket listens on.
    pub local_addr: core::net::IpAddr,
    /// Local port the socket listens on.
    pub local_port: u16,
    /// Defaults to `IPPROTO_TCP` on a record that predates this field (spooled
    /// events, server storage, the ML corpus): every collector was TCP-only
    /// before <https://github.com/synthaea-lab/agent/issues/40>, so that's what an un-stamped record actually was.
    #[serde(default = "default_listen_port_protocol")]
    pub protocol: u8,
}

/// `IPPROTO_TCP` — the default for `ListenPortEvent::protocol` on a record from
/// before this field existed.
fn default_listen_port_protocol() -> u8 {
    IPPROTO_TCP
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
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Direction of data flow (read = inbound/decrypted, write = outbound/encrypted).
    pub direction: TlsDirection,
    /// TLS library that was probed.
    pub lib_type: TlsLibraryType,
    /// Captured plaintext bytes. May be binary data (not UTF-8). Consumers should
    /// handle encoding errors gracefully when treating this as text.
    pub data: Vec<u8>,
}

/// Outbound network connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectEvent {
    /// The acting process; see [`EventMeta`].
    pub meta: EventMeta,
    /// Destination address, v4 or v6 (audit F-7: v6 is first-class, not an unset flag).
    pub daddr: core::net::IpAddr,
    /// Destination port of the connection.
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
    /// The acting process; see [`EventMeta`].
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
    /// Destination port of the flow.
    pub dport: u16,
    /// IP protocol number (`IPPROTO_TCP` = 6; the only value this source currently
    /// attributes — see the sensor crate doc for why UDP isn't joined yet).
    pub protocol: u8,
    /// Bytes sent by the local side over the flow, when the source reports them.
    pub bytes_sent: Option<u64>,
    /// Bytes received by the local side over the flow, when the source reports them.
    pub bytes_received: Option<u64>,
    /// Packets sent by the local side over the flow, when the source reports them.
    pub packets_sent: Option<u64>,
    /// Packets received by the local side over the flow, when the source reports them.
    pub packets_received: Option<u64>,
}
