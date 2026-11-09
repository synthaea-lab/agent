//! The network rules of [`crate::RuleState`]: BEACON over connects and conntrack flows,
//! SCAN-SPREAD and SCAN-VERTICAL, EGRESS-VOLUME and EGRESS-DOMAIN, and the ARCHIVE-EXFIL
//! chain, with the sliding history each one keeps.

use std::net::IpAddr;

use schema::{
    ConnectEvent, DnsQueryEvent, FileOpenEvent, FileWriteEvent, NetworkFlowEvent,
    detection::Severity,
};
use store::BoundedMap;

use crate::{
    Alert,
    egressdomain::{self, DomainClass},
    exclusions::{
        ARCHIVE_EGRESS_WINDOW_NS, ARCHIVE_READ_WINDOW_NS, ARCHIVE_STAGED_BYTES, ARCHIVE_SUFFIXES,
        BEACON_THRESHOLD, BEACON_WINDOW_NS, BROWSERS, DNS_CLASS_WINDOW_NS, EGRESS_BYTES_THRESHOLD,
        EGRESS_CLASSED_BYTES_THRESHOLD, EGRESS_DOMAIN_BROWSER_COMMS, EGRESS_WINDOW_NS,
        SCAN_SPREAD_THRESHOLD, SCAN_SPREAD_WINDOW_NS, SCAN_VERTICAL_THRESHOLD,
        SCAN_VERTICAL_WINDOW_NS, STANDARD_PORTS,
    },
    has_write_intent,
    sliding::{FlowPortDedup, SlidingCounter, SlidingDistinct, SlidingSum},
    state::{COUNTER_CAP, PidFact, same_incarnation},
};

/// One (comm, daddr) EGRESS-VOLUME entry: the bytes sent inside the window and when
/// the last alert fired (one alert per window, as `SlidingCounter::try_alert`).
#[derive(Default)]
struct EgressVolume {
    sum: SlidingSum,
    last_alert_ns: Option<u64>,
    /// The last EGRESS-DOMAIN alert for this entry, kept apart from `last_alert_ns` so that
    /// one finding does not hide the other.
    last_class_alert_ns: Option<u64>,
}

/// A storage or paste service a pid resolved, and the address its lookup returned
/// (EGRESS-DOMAIN). Keyed by (pid, address) in `NetworkState::dns_class`.
struct DnsClassSighting {
    generation: Option<u64>,
    class: DomainClass,
    /// The name the process asked for, kept for the alert message.
    domain: String,
    timestamp_ns: u64,
}

/// The archive a pid has open for writing (ARCHIVE-EXFIL).
struct ArchiveWriter {
    generation: Option<u64>,
    path: String,
    bytes: u64,
}

/// A staged archive a pid has read (ARCHIVE-EXFIL).
struct ArchiveReader {
    generation: Option<u64>,
    path: String,
    read_ns: u64,
    alerted: bool,
}

/// True when `path` ends in one of [`ARCHIVE_SUFFIXES`] (case-insensitive).
fn is_archive_name(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ARCHIVE_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// True for an address a remote party can be at: not loopback, private, link-local,
/// multicast, unspecified, or an IPv4 broadcast/unique-local equivalent.
fn is_public_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // 100.64.0.0/10, carrier-grade NAT (also Tailscale): an overlay, not the internet
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7 unique-local, fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// The sliding history of the network rules. Every table is LRU-bounded by [`COUNTER_CAP`].
pub(crate) struct NetworkState {
    /// (comm, daddr, dport) → sliding counter for BEACON (T1071 Windows). LRU-bounded.
    beacon: BoundedMap<(String, String, u16), SlidingCounter>,
    /// Same key as `beacon` → which local ports have already counted toward it —
    /// only consulted by [`Self::on_network_flow`] (a poll-based source, see
    /// [`FlowPortDedup`]'s doc); `on_connect`'s discrete syscall trace needs no
    /// dedup, each `ConnectEvent` already is one real connection attempt.
    beacon_flow_dedup: BoundedMap<(String, String, u16), FlowPortDedup>,
    /// (pid, dport) → sliding distinct-destination counter for SCAN-SPREAD
    /// (T1046/T1210, issue #465). LRU-bounded.
    scan_spread: BoundedMap<(u32, u16), SlidingDistinct<IpAddr>>,
    /// (pid, daddr) → distinct destination ports, for SCAN-VERTICAL (T1046, #378).
    /// LRU-bounded.
    scan_vertical: BoundedMap<(u32, IpAddr), SlidingDistinct<u16>>,
    /// (comm, daddr, dport, `local_port`) → the `bytes_sent` of the last poll of that
    /// flow, for EGRESS-VOLUME (T1041/T1048, #380). Conntrack counters are cumulative
    /// per flow, so only the difference between two polls is new volume. LRU-bounded.
    egress_flow_last: BoundedMap<(String, IpAddr, u16, u16), u64>,
    /// (comm, daddr) → bytes sent inside the sliding window, for EGRESS-VOLUME. The
    /// key leaves the port out on purpose: an exfiltration split over many connections
    /// to one host is the shape to catch. LRU-bounded.
    egress_volume: BoundedMap<(String, IpAddr), EgressVolume>,
    /// (pid, address) → the storage or paste service that pid resolved to that address, for
    /// EGRESS-DOMAIN (T1567, #380). Only a lookup of a listed service is recorded, so the
    /// history grows with those, not with all DNS; LRU-bounded like every other table.
    dns_class: BoundedMap<(u32, IpAddr), DnsClassSighting>,
    /// pid → the archive it opened for writing and the bytes it has written since, for
    /// ARCHIVE-EXFIL (T1560/T1041, #380). `FileWriteEvent` carries no path, so the bytes
    /// are everything the pid writes (any fd): an archiver's output dominates them, a
    /// chatty process that also opens a `.gz` would overcount (a stated gap). LRU-bounded.
    archive_writers: BoundedMap<u32, ArchiveWriter>,
    /// Path of a staged archive → when it crossed [`ARCHIVE_STAGED_BYTES`]. LRU-bounded.
    staged_archives: BoundedMap<String, u64>,
    /// pid → the staged archive it read, until it connects out. LRU-bounded.
    archive_readers: BoundedMap<u32, ArchiveReader>,
}

impl NetworkState {
    pub(crate) fn new() -> Self {
        Self {
            beacon: BoundedMap::new(COUNTER_CAP),
            beacon_flow_dedup: BoundedMap::new(COUNTER_CAP),
            scan_spread: BoundedMap::new(COUNTER_CAP),
            scan_vertical: BoundedMap::new(COUNTER_CAP),
            egress_flow_last: BoundedMap::new(COUNTER_CAP),
            egress_volume: BoundedMap::new(COUNTER_CAP),
            dns_class: BoundedMap::new(COUNTER_CAP),
            archive_writers: BoundedMap::new(COUNTER_CAP),
            staged_archives: BoundedMap::new(COUNTER_CAP),
            archive_readers: BoundedMap::new(COUNTER_CAP),
        }
    }

    /// The network rules of a `ConnectEvent`: BEACON, SCAN-SPREAD, SCAN-VERTICAL and the last
    /// link of ARCHIVE-EXFIL, in that order.
    pub(crate) fn on_connect(&mut self, event: &ConnectEvent) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_beacon(event).into_iter().collect();
        alerts.extend(self.check_scan_spread(event));
        alerts.extend(self.check_scan_vertical(event));
        alerts.extend(self.check_archive_egress(&event.meta, event.daddr));
        alerts
    }

    /// The rules of a conntrack `NetworkFlowEvent`: BEACON (see [`Self::check_beacon_flow`]),
    /// EGRESS-VOLUME and EGRESS-DOMAIN, and the last link of ARCHIVE-EXFIL. `images` is the
    /// pid → exec-time image table that EGRESS-DOMAIN's browser exclusion reads.
    pub(crate) fn on_network_flow(
        &mut self,
        event: &NetworkFlowEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.check_beacon_flow(event).into_iter().collect();
        alerts.extend(self.check_egress_volume(event, images));
        alerts.extend(self.check_archive_egress(&event.meta, event.daddr));
        alerts
    }

    /// Shared BEACON exclusions (T1071/T1041) — same filter regardless of which
    /// telemetry source observed the connection.
    ///
    /// pid=4 (Windows System) is excluded by the caller, not here: `NetworkFlowEvent`
    /// (Linux-only, no Windows equivalent) never needs that check, so it stays
    /// specific to [`Self::check_beacon`].
    fn beacon_excluded(comm: &str, daddr: IpAddr, dport: u16) -> bool {
        // Known limitation: neither ConnectEvent nor NetworkFlowEvent carries an
        // image path, so the browser exclusion stays name-only here — the
        // correlator's exec-time masquerade tracking covers the rename bypass at
        // the correlation layer.
        if BROWSERS.iter().any(|&n| comm.eq_ignore_ascii_case(n)) {
            return true;
        }
        if STANDARD_PORTS.contains(&dport) {
            return true;
        }
        // `0.0.0.0:65535` / `:::65535` is no remote peer: it's the address-selection
        // probe sshd-session and sshd-auth run with a `connect()` on every login, which
        // crossed the 3-in-60s threshold on a lab VM with three SSH logins in a minute
        // (2026-09-29, #525). Only on that port: a connect to `0.0.0.0:<port>` reaches
        // the local host like `127.0.0.1:<port>`, which still counts, so the rest must
        // count too or a local-relay beacon could hide behind the unspecified address
        // (#536).
        if policy::is_address_selection_probe(daddr, dport) {
            return true;
        }
        // IPv4 multicast (224.0.0.0/4) and broadcast (last octet = 255): legitimate
        // network traffic emitted in a loop by system services (mDNS, SSDP, Spotify…),
        // never C2.
        if let IpAddr::V4(v4) = daddr {
            let o = v4.octets();
            if o[0] >= 224 || o[3] == 255 {
                return true;
            }
        }
        false
    }

    /// Records one occurrence toward the (comm, daddr, dport) BEACON counter and
    /// returns an alert once the threshold is crossed — the counting/alerting core
    /// shared by [`Self::check_beacon`] and [`Self::check_beacon_flow`], which
    /// differ only in what counts as "one occurrence" (see the latter's doc).
    fn record_beacon(
        &mut self,
        pid: u32,
        comm: &str,
        daddr: IpAddr,
        dport: u16,
        ts: u64,
    ) -> Option<Alert> {
        let daddr = daddr.to_string();
        let key = (comm.to_string(), daddr.clone(), dport);
        let entry = self.beacon.get_or_insert_with(key, SlidingCounter::default);
        let count = entry.record(ts, BEACON_WINDOW_NS);
        if count >= BEACON_THRESHOLD && entry.try_alert(ts, BEACON_WINDOW_NS) {
            return Some(Alert {
                technique: "T1071/T1041",
                severity: Severity::High,
                message: format!(
                    "pid={pid} comm={comm} → {daddr}:{dport} | {count}x in {}s — suspected beaconing",
                    BEACON_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// T1071/T1041 — repeated connections to the same destination on a non-standard
    /// port (C2 beaconing). Browsers excluded (repeated outbound traffic = normal
    /// behavior).
    fn check_beacon(&mut self, event: &ConnectEvent) -> Option<Alert> {
        // pid=4 = Windows System process: constantly emits low-level network traffic
        // (NetBIOS, SMB…) — never C2, guaranteed false positive.
        if event.meta.pid == 4 {
            return None;
        }
        if Self::beacon_excluded(&event.meta.comm, event.daddr, event.dport) {
            return None;
        }
        self.record_beacon(
            event.meta.pid,
            &event.meta.comm,
            event.daddr,
            event.dport,
            event.meta.timestamp_ns,
        )
    }

    /// SCAN-SPREAD (T1046/T1210, issue #465): many distinct destinations, one
    /// port, in a short window — a live Mirai detonation (309 connections to
    /// 300+ distinct IPs on port 23 in ~30s, default-credential telnet
    /// spread) produced no dedicated alert; `check_beacon`'s repeated-*same*-
    /// destination shape is the mirror image and structurally can't catch
    /// this. Keyed by (pid, dport): counts distinct `daddr`, not raw
    /// connection count, so a busy client hammering one server (BEACON's own
    /// shape, not this one) doesn't also cross this threshold.
    ///
    /// Deliberately not gated by `beacon_excluded`'s `STANDARD_PORTS` (22,
    /// 23, 3389, …-style ports are exactly what credential-spray/lateral-
    /// movement traffic targets — excluding them here would blind the rule
    /// to the exact case that motivated it) or by name (comm is spoofable,
    /// same reasoning the rest of this file gives elsewhere). Only pid=4
    /// (Windows System) is excluded, same guaranteed-false-positive reason
    /// as `check_beacon`. No other exclusions yet — none of BEACON's own
    /// carry over cleanly to a distinct-destination shape, and none has been
    /// calibrated against a real false positive here; the plausible one (a
    /// mail relay or monitoring agent fanning out to many hosts on one port
    /// in a burst) is left for a live capture to confirm, not guessed at.
    fn check_scan_spread(&mut self, event: &ConnectEvent) -> Option<Alert> {
        if event.meta.pid == 4 {
            return None;
        }
        let key = (event.meta.pid, event.dport);
        let ts = event.meta.timestamp_ns;
        let entry = self
            .scan_spread
            .get_or_insert_with(key, SlidingDistinct::default);
        let distinct = entry.record(event.daddr, ts, SCAN_SPREAD_WINDOW_NS);
        if distinct >= SCAN_SPREAD_THRESHOLD && entry.try_alert(ts, SCAN_SPREAD_WINDOW_NS) {
            return Some(Alert {
                technique: "T1046/T1210",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} contacted {distinct} distinct destinations on port {} in \
                     {}s — suspected scan/spread burst",
                    event.meta.pid,
                    event.meta.comm,
                    event.dport,
                    SCAN_SPREAD_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// SCAN-VERTICAL (T1046, #378): many distinct ports on one host from one pid in a short
    /// window, the vertical mirror of [`Self::check_scan_spread`] (many hosts, one port). A
    /// TCP connect scan of a target; the horizontal rule cannot see it, as it keys on the
    /// port. Loopback destinations are not counted (see [`SCAN_VERTICAL_THRESHOLD`]). Only
    /// pid 4 (Windows System) is excluded, as in SCAN-SPREAD.
    fn check_scan_vertical(&mut self, event: &ConnectEvent) -> Option<Alert> {
        if event.meta.pid == 4 || event.daddr.is_loopback() || event.daddr.is_unspecified() {
            return None;
        }
        let ts = event.meta.timestamp_ns;
        let entry = self
            .scan_vertical
            .get_or_insert_with((event.meta.pid, event.daddr), SlidingDistinct::default);
        let distinct = entry.record(event.dport, ts, SCAN_VERTICAL_WINDOW_NS);
        if distinct >= SCAN_VERTICAL_THRESHOLD && entry.try_alert(ts, SCAN_VERTICAL_WINDOW_NS) {
            return Some(Alert {
                technique: "T1046",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} contacted {distinct} distinct ports on {} in {}s — \
                     suspected port scan",
                    event.meta.pid,
                    event.meta.comm,
                    event.daddr,
                    SCAN_VERTICAL_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        None
    }

    /// T1071/T1041 via conntrack polling (issue #92) — same rule as
    /// [`Self::check_beacon`], fed by a periodic flow snapshot instead of a discrete
    /// `connect()` trace. This is the "probe-free" source `sensor-linux-netlink`
    /// exists for: it produces the same alert where eBPF/ETW cannot run, or as a
    /// redundant cross-check alongside them.
    ///
    /// A poll-based source re-reports the *same* open flow on every poll — unlike
    /// `ConnectEvent`, one `NetworkFlowEvent` is not one connection attempt. Without
    /// deduping, an ordinary long-lived connection (SSH, a websocket) still open on
    /// its 3rd poll inside the window would false-positive BEACON on its own.
    /// [`FlowPortDedup`] keyed by `local_port` — this host's stable identity for one
    /// flow's lifetime — only lets a given flow count once per window; a real beacon
    /// (N distinct short-lived connections, N distinct local ports) still crosses
    /// the threshold exactly as `check_beacon` would.
    fn check_beacon_flow(&mut self, event: &NetworkFlowEvent) -> Option<Alert> {
        if Self::beacon_excluded(&event.meta.comm, event.daddr, event.dport) {
            return None;
        }
        let key = (
            event.meta.comm.clone(),
            event.daddr.to_string(),
            event.dport,
        );
        let ts = event.meta.timestamp_ns;
        let dedup = self
            .beacon_flow_dedup
            .get_or_insert_with(key, FlowPortDedup::default);
        if !dedup.is_new(event.local_port, ts, BEACON_WINDOW_NS) {
            return None;
        }
        self.record_beacon(
            event.meta.pid,
            &event.meta.comm,
            event.daddr,
            event.dport,
            ts,
        )
    }

    /// Remembers that this pid resolved a listed storage or paste service to these addresses,
    /// for [`Self::check_egress_volume`] to join with the volume it later sends there.
    pub(crate) fn on_dns_query(&mut self, event: &DnsQueryEvent) {
        let Some(class) = egressdomain::classify_domain(&event.query) else {
            return;
        };
        if event.status != 0 {
            return;
        }
        let Some(result) = event.result.as_deref() else {
            return;
        };
        for address in egressdomain::resolved_addresses(result) {
            self.dns_class.insert(
                (event.meta.pid, address),
                DnsClassSighting {
                    generation: event.meta.process_generation,
                    class,
                    domain: event.query.to_ascii_lowercase(),
                    timestamp_ns: event.meta.timestamp_ns,
                },
            );
        }
    }

    /// ARCHIVE-EXFIL, first link: a pid that opens an archive-named file for writing starts
    /// counting its written bytes; a pid that opens a **staged** archive (see
    /// [`Self::record_archive_write`]) without write intent, within [`ARCHIVE_READ_WINDOW_NS`]
    /// of its staging, becomes a reader waiting for a connection. The writer itself is not a
    /// reader: extracting what it just wrote is not a hand-off.
    pub(crate) fn record_archive_open(&mut self, event: &FileOpenEvent) {
        let pid = event.meta.pid;
        let ts = event.meta.timestamp_ns;
        if has_write_intent(event.flags) {
            if is_archive_name(&event.path) {
                // A new write open of the path starts a new archive: a staging from an
                // earlier run (a nightly job rewriting `home.tar.gz`) must not outlive it,
                // or the read window would be measured from the first night forever.
                self.staged_archives.remove(&event.path);
                self.archive_writers.insert(
                    pid,
                    ArchiveWriter {
                        generation: event.meta.process_generation,
                        path: event.path.clone(),
                        bytes: 0,
                    },
                );
            }
            return;
        }
        let Some(&staged_ns) = self.staged_archives.peek(&event.path) else {
            return;
        };
        if ts.saturating_sub(staged_ns) > ARCHIVE_READ_WINDOW_NS {
            return;
        }
        if self.archive_writers.peek(&pid).is_some_and(|w| {
            w.path == event.path && same_incarnation(w.generation, event.meta.process_generation)
        }) {
            return;
        }
        self.archive_readers.insert(
            pid,
            ArchiveReader {
                generation: event.meta.process_generation,
                path: event.path.clone(),
                read_ns: ts,
                alerted: false,
            },
        );
    }

    /// ARCHIVE-EXFIL, second link: the bytes the writer pid writes after opening the archive.
    /// Crossing [`ARCHIVE_STAGED_BYTES`] stages it, once.
    pub(crate) fn record_archive_write(&mut self, event: &FileWriteEvent) {
        let Some(writer) = self.archive_writers.get_mut(&event.meta.pid) else {
            return;
        };
        if !same_incarnation(writer.generation, event.meta.process_generation) {
            return;
        }
        writer.bytes = writer.bytes.saturating_add(event.bytes_requested);
        if writer.bytes >= ARCHIVE_STAGED_BYTES {
            // The staging time is the last write past the threshold, not the first: a job
            // that keeps writing for hours is finished when it stops, and the read window
            // counts from there.
            let path = writer.path.clone();
            self.staged_archives.insert(path, event.meta.timestamp_ns);
        }
    }

    /// ARCHIVE-EXFIL (T1560/T1041, #380) — the chain: a pid wrote an archive of at least
    /// [`ARCHIVE_STAGED_BYTES`], **another** pid read that file, and that reader then
    /// connected to a public address within [`ARCHIVE_EGRESS_WINDOW_NS`]. One alert per
    /// reader. Medium, not higher: a backup job that archives and then uploads to an object
    /// store is exactly this shape, and no allowlist of such jobs exists yet (it needs a
    /// lab capture of the host's own backups). Gaps, stated: a stream that never touches a
    /// file (`tar | ssh`), an archive named without one of [`ARCHIVE_SUFFIXES`], and a
    /// sender that is not the reader (a file handed over by a pipe or a copy).
    ///
    /// False positives beyond the backup job, from the shape itself: the reader is any
    /// process that opens the file without write intent, and any public connection from that
    /// pid inside the window completes the chain, with no link between the bytes read and the
    /// destination. A long-lived daemon (an antivirus scanner, an indexer, a sync client) that
    /// touches the archive and later makes an unrelated connection alerts. Open, connect and
    /// flow events arrive from separate rings, so a connection stamped just before the open
    /// can be ordered after it; the window absorbs that.
    fn check_archive_egress(&mut self, meta: &schema::EventMeta, daddr: IpAddr) -> Option<Alert> {
        if !is_public_address(daddr) {
            return None;
        }
        let reader = self.archive_readers.get_mut(&meta.pid)?;
        if reader.alerted
            || !same_incarnation(reader.generation, meta.process_generation)
            || meta.timestamp_ns.saturating_sub(reader.read_ns) > ARCHIVE_EGRESS_WINDOW_NS
        {
            return None;
        }
        reader.alerted = true;
        Some(Alert {
            technique: "T1560/T1041",
            severity: Severity::Medium,
            message: format!(
                "pid={} comm={} read the staged archive {} and connected to {}",
                meta.pid, meta.comm, reader.path, daddr,
            ),
        })
    }

    /// EGRESS-VOLUME (T1041/T1048, #380) — a process name that sends more than
    /// [`EGRESS_BYTES_THRESHOLD`] to one public address inside
    /// [`EGRESS_WINDOW_NS`], summed over all its connections to that address.
    ///
    /// Conntrack counters are cumulative per flow and a poll-based source re-reports
    /// a live flow every cycle, so the volume of one poll is the difference with the
    /// previous poll of the same flow. **The first poll of a flow only sets its
    /// baseline** and adds nothing: a flow already open when the agent started carries
    /// the history of its whole life, and counting it would alert on any long SSH or
    /// backup session at startup. The cost is named: a transfer that starts and ends
    /// between two polls of a brand-new flow is not counted; a sustained one is, from
    /// its second poll.
    ///
    /// Inert without volume data: `bytes_sent` is `None` unless the host enabled
    /// `net.netfilter.nf_conntrack_acct` (off by default, see [`NetworkFlowEvent`]), so
    /// silence here does not mean nothing was sent. Private, loopback, link-local,
    /// multicast and unspecified peers are excluded: a backup to the local network is
    /// not the signal this rule looks for. No name exclusion list yet, for the reason
    /// given at [`EGRESS_BYTES_THRESHOLD`].
    ///
    /// **EGRESS-DOMAIN (T1567, #380)** reads the same sum. When the pid itself resolved a listed
    /// storage or paste service to this address ([`Self::on_dns_query`],
    /// [`Self::resolved_service`]), the lower [`EGRESS_CLASSED_BYTES_THRESHOLD`] applies and the
    /// alert names the technique of the class (T1567.002 or T1567.003) and the domain. It is
    /// **dormant on a default host**: it needs `nf_conntrack_acct` for the volume *and* a DNS
    /// source for the lookup (the Linux `getaddrinfo` probe is opt-in, `UprobesConfig::with_dns_enabled`).
    /// Without the lookup the generic threshold above is all there is. Only the first address of a
    /// Linux lookup is recorded, so a connection to another address of the same answer is not
    /// joined (the Windows provider lists them all).
    fn check_egress_volume(
        &mut self,
        event: &NetworkFlowEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Vec<Alert> {
        let Some(sent) = event.bytes_sent else {
            return Vec::new();
        };
        if !is_public_address(event.daddr) {
            return Vec::new();
        }
        let flow = (
            event.meta.comm.clone(),
            event.daddr,
            event.dport,
            event.local_port,
        );
        let previous = self.egress_flow_last.get(&flow).copied();
        self.egress_flow_last.insert(flow, sent);
        // First poll of the flow: baseline only. A counter that went down is a new
        // flow on a reused local port: its whole value is new volume.
        let delta = match previous {
            None => return Vec::new(),
            Some(last) if sent >= last => sent - last,
            Some(_) => sent,
        };
        if delta == 0 {
            return Vec::new();
        }
        let ts = event.meta.timestamp_ns;
        let class = self.resolved_service(event, images);
        let entry = self.egress_volume.get_or_insert_with(
            (event.meta.comm.clone(), event.daddr),
            EgressVolume::default,
        );
        let total = entry.sum.add(ts, delta, EGRESS_WINDOW_NS);
        let mut alerts = Vec::new();
        let recently =
            |last: Option<u64>| last.is_some_and(|t| ts.saturating_sub(t) < EGRESS_WINDOW_NS);
        if let Some((class, domain)) = class
            && total >= EGRESS_CLASSED_BYTES_THRESHOLD
            && !recently(entry.last_class_alert_ns)
        {
            entry.last_class_alert_ns = Some(ts);
            alerts.push(Alert {
                technique: class.technique(),
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} sent {}MB to {} ({domain}, a {} service) in {}s — possible \
                     exfiltration to a web service",
                    event.meta.pid,
                    event.meta.comm,
                    total / (1024 * 1024),
                    event.daddr,
                    class.label(),
                    EGRESS_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        if total >= EGRESS_BYTES_THRESHOLD && !recently(entry.last_alert_ns) {
            entry.last_alert_ns = Some(ts);
            alerts.push(Alert {
                technique: "T1041/T1048",
                severity: Severity::Medium,
                message: format!(
                    "pid={} comm={} sent {}MB to {} in {}s — possible exfiltration over the \
                     network",
                    event.meta.pid,
                    event.meta.comm,
                    total / (1024 * 1024),
                    event.daddr,
                    EGRESS_WINDOW_NS / 1_000_000_000,
                ),
            });
        }
        alerts
    }

    /// EGRESS-DOMAIN's join key: the storage or paste service this very pid resolved to the
    /// flow's address, within [`DNS_CLASS_WINDOW_NS`], unless the pid is a browser (see
    /// [`EGRESS_DOMAIN_BROWSER_COMMS`]). The class comes from the process's own lookup because
    /// the address alone is shared with every other site behind the same CDN. A sighting
    /// recorded for another incarnation of the pid (a recycled number) is not an answer.
    fn resolved_service(
        &self,
        event: &NetworkFlowEvent,
        images: &BoundedMap<u32, PidFact>,
    ) -> Option<(DomainClass, String)> {
        let sighting = self.dns_class.peek(&(event.meta.pid, event.daddr))?;
        let ts = event.meta.timestamp_ns;
        if ts.saturating_sub(sighting.timestamp_ns) > DNS_CLASS_WINDOW_NS
            || matches!(
                (sighting.generation, event.meta.process_generation),
                (Some(recorded), Some(current)) if recorded != current
            )
        {
            return None;
        }
        let image = PidFact::current(images, event.meta.pid, event.meta.process_generation);
        let is_browser = EGRESS_DOMAIN_BROWSER_COMMS.contains(&event.meta.comm.as_str())
            && policy::name_exclusion_applies(image);
        (!is_browser).then(|| (sighting.class, sighting.domain.clone()))
    }
}
