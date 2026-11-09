//! Command and Control (TA0011): unusual outbound from a service, encrypted DNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use schema::{ConnectEvent, detection::Severity};

use crate::{
    Alert,
    exclusions::{SERVICE_COMM_PREFIXES, SERVICE_COMMS},
};

/// Outbound ports [`check_service_unusual_outbound`] (T1071, issue #478)
/// treats as routine for a web/DB service process, so only a connection to
/// something else fires. Deliberately its own list, not
/// [`crate::exclusions::STANDARD_PORTS`] (a different rule — BEACON — a
/// different process population, calibrated separately): 80/443/8080/8443/
/// 8000 cover a web app calling out to an HTTP(S) API or self-update
/// endpoint, the rest are the backend services these processes routinely
/// dial out to on a multi-tier deployment — MySQL/MariaDB (3306), `PostgreSQL`
/// (5432), Redis (6379), Memcached (11211), Elasticsearch (9200), `MongoDB`
/// (27017). Without these, an ordinary php-fpm-to-Redis-on-a-different-host
/// connection would fire this rule — uncalibrated against fleet traffic
/// otherwise (first cut, 2026-09-28).
const SERVICE_OUTBOUND_STANDARD_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 8000, 3306, 5432, 6379, 11211, 9200, 27017,
];

/// T1071 — Application Layer Protocol: a web or database service process
/// connecting outbound to a port outside its routine set (issue #478, Level
/// 1). Unlike `NetworkState::check_beacon` (repeated connections, a threshold +
/// window), this fires on a *single* connection: these specific service
/// accounts have such a narrow legitimate outbound footprint that even one
/// connection outside it is a strong post-exploitation signal — a reverse
/// shell after a web exploit, or (per the issue) `mysqld`/`mariadbd`, which
/// almost never have a legitimate reason to connect out at all.
///
/// Loopback destinations are excluded outright: a web app dialing a
/// same-host backend (Redis, a local API, Postgres over a Unix-mapped TCP
/// port) is the overwhelming majority of "unusual port from these
/// processes" traffic in practice, and a real exfil/C2 destination is never
/// loopback — it has to leave the host to be useful to an attacker.
#[must_use]
pub(crate) fn check_service_unusual_outbound(event: &ConnectEvent) -> Option<Alert> {
    let comm = event.meta.comm.as_str();
    let is_service =
        SERVICE_COMMS.contains(&comm) || SERVICE_COMM_PREFIXES.iter().any(|p| comm.starts_with(p));
    if !is_service {
        return None;
    }
    // Unspecified (`0.0.0.0` / `::`) is not a destination either: postgres's
    // startup `connect()` to `0.0.0.0:65535` / `:::65535` (its stats-collector
    // self-probe) fired this on a bare start (#498 review). On Linux it means
    // "this host", same as loopback.
    if event.daddr.is_loopback()
        || event.daddr.is_unspecified()
        || SERVICE_OUTBOUND_STANDARD_PORTS.contains(&event.dport)
    {
        return None;
    }
    Some(Alert {
        technique: "T1071",
        severity: Severity::Medium,
        message: format!(
            "pid={} comm={comm}: outbound connection to {}:{} — port outside this service's \
             routine set, possible reverse shell after exploitation",
            event.meta.pid, event.daddr, event.dport,
        ),
    })
}

/// DNS-over-TLS's reserved port (RFC 7858) — essentially no other common traffic
/// uses it, so any connection here is already unusual regardless of destination.
const DOT_PORT: u16 = 853;

/// HTTPS's port, which DNS-over-HTTPS (`DoH`) rides on indistinguishably from
/// ordinary traffic at the connection level — this rule only treats it as `DoH`
/// when the destination is also one of [`KNOWN_DOH_RESOLVERS`].
const HTTPS_PORT: u16 = 443;

/// Processes expected to speak encrypted DNS directly, so a connection from one
/// of them to [`DOT_PORT`] or a [`KNOWN_DOH_RESOLVERS`] address is routine, not a
/// signal: the host's own stub resolver (which may speak `DoT` upstream), and
/// browsers (several ship `DoH` on by default and dial it themselves rather than
/// through the OS resolver). Comparing against `comm` case-insensitively covers
/// both the bare Linux/macOS name and the Windows `.exe` form.
const DOH_DOT_EXPECTED_COMMS: &[&str] = &[
    "systemd-resolved",
    "mDNSResponder",
    "firefox",
    "firefox-esr",
    "firefox.exe",
    "chrome",
    "chrome.exe",
    "chromium",
    "chromium-browser",
    "brave",
    "brave.exe",
    "opera",
    "opera.exe",
    "msedge",
    "msedge.exe",
];

/// Known public `DoH` resolver addresses: Cloudflare, Google, Quad9, OpenDNS/Cisco
/// — the handful of providers the pre-built resolver profiles in Firefox/Chrome
/// ship with, so also the ones a C2 implant reusing a well-known endpoint (to
/// blend into "normal" `DoH` traffic rather than running its own) is most likely
/// to pick. Deliberately short and not exhaustive: a private/enterprise `DoH`
/// endpoint, a self-hosted one, or a public provider not on this list is a real
/// gap this rule accepts, the same unbounded-tail trade-off ADR-0028 documents
/// for `policy`'s interpreter blocklist — this is detection content, meant to be
/// widened as real `DoH` C2 traffic is observed, not a complete inventory.
const KNOWN_DOH_RESOLVERS: &[IpAddr] = &[
    // Cloudflare (1.1.1.1)
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
    // Google Public DNS
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
    // Quad9
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009)),
    // OpenDNS / Cisco
    IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
    IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
];

/// T1071.004 — Application Layer Protocol: DNS, the encrypted-transport case
/// (issue #458 Phase 2, point 5): a non-browser, non-resolver process connecting
/// to DNS-over-TLS's reserved port, or to a well-known public `DoH` resolver on
/// 443. Both are legitimate ways to resolve names, but neither is something an
/// arbitrary process has an ordinary reason to do directly — the OS resolver
/// (`systemd-resolved`, `mDNSResponder`) or the browser already does it for
/// everything else on the host. A process doing its own encrypted DNS is doing
/// so specifically to keep its queries out of plaintext UDP/53 — the same
/// visibility gap a C2 implant or exfil tool wants, whether or not this
/// particular connection turns out to be one.
///
/// Correlator content over the existing `ConnectEvent`, not new telemetry, per
/// the issue's own note — `DnsQuery`'s `getaddrinfo` uprobe (#397) cannot see
/// resolution a process does inside its own TLS session instead of calling libc.
#[must_use]
pub(crate) fn check_doh_dot_connection(event: &ConnectEvent) -> Option<Alert> {
    let comm = event.meta.comm.as_str();
    if DOH_DOT_EXPECTED_COMMS
        .iter()
        .any(|&n| comm.eq_ignore_ascii_case(n))
    {
        return None;
    }
    let (protocol, port) = if event.dport == DOT_PORT {
        ("DNS-over-TLS", DOT_PORT)
    } else if event.dport == HTTPS_PORT && KNOWN_DOH_RESOLVERS.contains(&event.daddr) {
        ("DNS-over-HTTPS", HTTPS_PORT)
    } else {
        return None;
    };
    Some(Alert {
        technique: "T1071.004",
        severity: Severity::Low,
        message: format!(
            "pid={} comm={comm}: connection to {}:{port} — {protocol} from a process that \
             is not the system resolver or a browser, possibly DNS queries kept off plaintext \
             UDP/53 to evade monitoring",
            event.meta.pid, event.daddr,
        ),
    })
}
