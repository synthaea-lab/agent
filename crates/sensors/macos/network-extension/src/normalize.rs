//! Maps wire records ([`crate::wire::NeRecord`]) into `schema` events — all
//! three shapes already exist, so this sensor adds **no** schema variants:
//!
//! - `Flow` → [`schema::ConnectEvent`] (the discrete fact the BEACON rule and
//!   the correlator key on — `(comm, daddr, dport)`);
//! - `FlowStats` → [`schema::NetworkFlowEvent`] (volume, the beacon feature a
//!   point-in-time connect can't carry — same split as the Linux
//!   conntrack source);
//! - `Dns` → [`schema::DnsQueryEvent`] (the domain↔process join key), with
//!   process attribution NE's DNS proxy gives that the Windows provider
//!   documents wanting.
//!
//! Inbound flows are deliberately mapped to `ConnectEvent` too — the schema
//! shape carries the remote peer either way, and an inbound connection to an
//! unexpected local service is exactly the lateral-movement signal the
//! coverage matrix promises ("inbound + outbound"). The direction currently
//! rides in which port field is the remote one; a dedicated direction field
//! is additive schema work if a rule ever needs it explicitly.

use schema::{ConnectEvent, DnsQueryEvent, Event, EventMeta, NetworkFlowEvent, User};

use crate::wire::NeRecord;

/// Short process name from the extension's resolved path.
fn comm_from_path(path: Option<&str>) -> String {
    let path = path.unwrap_or("");
    path.rsplit('/').next().unwrap_or(path).to_string()
}

fn meta(ts_ns: u64, pid: u32, process_path: Option<&str>) -> EventMeta {
    EventMeta {
        pid,
        // The audit token carries no ppid; lineage joins happen on pid
        // against the ES exec stream (same reasoning as the other
        // subsystem-report sensors).
        ppid: 0,
        // NEFilterFlow's audit token could carry uid/gid; the extension does
        // not forward them yet — honest Unknown until it does (wire v2).
        user: User::Unknown,
        timestamp_ns: ts_ns,
        comm: comm_from_path(process_path),
        container: None,
    }
}

/// Maps one wire record to its schema event. `None` when the remote address
/// doesn't parse as a literal (the extension only ever sends literals; a
/// disagreement means version skew — skip, never fabricate).
#[must_use]
pub fn normalize(record: &NeRecord) -> Option<Event> {
    match record {
        NeRecord::Flow {
            ts_ns,
            pid,
            process_path,
            remote_addr,
            remote_port,
            ..
        } => Some(Event::Connect(ConnectEvent {
            meta: meta(*ts_ns, *pid, process_path.as_deref()),
            daddr: remote_addr.parse().ok()?,
            dport: *remote_port,
        })),
        NeRecord::FlowStats {
            v: _,
            ts_ns,
            pid,
            process_path,
            remote_addr,
            remote_port,
            local_port,
            protocol,
            bytes_sent,
            bytes_received,
        } => Some(Event::NetworkFlow(NetworkFlowEvent {
            meta: meta(*ts_ns, *pid, process_path.as_deref()),
            local_port: *local_port,
            daddr: remote_addr.parse().ok()?,
            dport: *remote_port,
            protocol: *protocol,
            bytes_sent: Some(*bytes_sent),
            bytes_received: Some(*bytes_received),
            // NE reports bytes, not packet counts.
            packets_sent: None,
            packets_received: None,
        })),
        NeRecord::Dns {
            v: _,
            ts_ns,
            pid,
            process_path,
            query,
            qtype,
            result,
            rcode,
        } => Some(Event::DnsQuery(DnsQueryEvent {
            meta: meta(*ts_ns, *pid, process_path.as_deref()),
            query: query.clone(),
            qtype: *qtype,
            result: result.clone().filter(|r| !r.is_empty()),
            // DnsQueryEvent::status is the platform's status word; on macOS
            // this sensor reports the DNS RCODE (0 = NOERROR, 3 = NXDOMAIN).
            status: *rcode,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{FlowDirection, WIRE_VERSION};

    #[test]
    fn flow_maps_to_connect_with_attribution() {
        let record = NeRecord::Flow {
            v: WIRE_VERSION,
            ts_ns: 1_790_000_000_000_000_000,
            pid: 4242,
            process_path: Some("/usr/bin/curl".into()),
            direction: FlowDirection::Outbound,
            remote_addr: "203.0.113.7".into(),
            remote_port: 443,
            local_port: 52344,
            protocol: 6,
        };
        let Some(Event::Connect(connect)) = normalize(&record) else {
            panic!("must map to Event::Connect");
        };
        assert_eq!(connect.meta.pid, 4242);
        assert_eq!(connect.meta.comm, "curl");
        assert_eq!(
            connect.daddr,
            "203.0.113.7".parse::<core::net::IpAddr>().unwrap()
        );
        assert_eq!(connect.dport, 443);
    }

    #[test]
    fn ipv6_flows_are_first_class() {
        let record = NeRecord::Flow {
            v: WIRE_VERSION,
            ts_ns: 0,
            pid: 1,
            process_path: None,
            direction: FlowDirection::Outbound,
            remote_addr: "2001:db8::7".into(),
            remote_port: 443,
            local_port: 0,
            protocol: 6,
        };
        assert!(matches!(
            normalize(&record),
            Some(Event::Connect(c)) if c.daddr.is_ipv6()
        ));
    }

    #[test]
    fn flow_stats_map_to_network_flow_volume() {
        let record = NeRecord::FlowStats {
            v: WIRE_VERSION,
            ts_ns: 1_790_000_000_000_000_000,
            pid: 4242,
            process_path: Some("/usr/bin/curl".into()),
            remote_addr: "203.0.113.7".into(),
            remote_port: 443,
            local_port: 52344,
            protocol: 6,
            bytes_sent: 1234,
            bytes_received: 56789,
        };
        let Some(Event::NetworkFlow(flow)) = normalize(&record) else {
            panic!("must map to Event::NetworkFlow");
        };
        assert_eq!(flow.bytes_sent, Some(1234));
        assert_eq!(flow.bytes_received, Some(56789));
        assert_eq!(flow.local_port, 52344);
        assert_eq!(flow.packets_sent, None, "NE reports bytes, not packets");
    }

    #[test]
    fn dns_maps_with_process_attribution_and_rcode() {
        let record = NeRecord::Dns {
            v: WIRE_VERSION,
            ts_ns: 1_790_000_000_000_000_000,
            pid: 4242,
            process_path: Some("/Users/mal/.hidden/payload".into()),
            query: "beacon.example.test".into(),
            qtype: 1,
            result: Some("203.0.113.7;".into()),
            rcode: 0,
        };
        let Some(Event::DnsQuery(dns)) = normalize(&record) else {
            panic!("must map to Event::DnsQuery");
        };
        assert_eq!(dns.query, "beacon.example.test");
        assert_eq!(dns.meta.comm, "payload");
        assert_eq!(dns.status, 0);
    }

    #[test]
    fn nxdomain_keeps_empty_result_as_none() {
        let record = NeRecord::Dns {
            v: WIRE_VERSION,
            ts_ns: 0,
            pid: 1,
            process_path: None,
            query: "nxdomain.test".into(),
            qtype: 1,
            result: Some(String::new()),
            rcode: 3,
        };
        assert!(matches!(
            normalize(&record),
            Some(Event::DnsQuery(d)) if d.result.is_none() && d.status == 3
        ));
    }

    #[test]
    fn unparseable_remote_address_skips_rather_than_fabricates() {
        let record = NeRecord::Flow {
            v: WIRE_VERSION,
            ts_ns: 0,
            pid: 1,
            process_path: None,
            direction: FlowDirection::Outbound,
            remote_addr: "not-an-address".into(),
            remote_port: 443,
            local_port: 0,
            protocol: 6,
        };
        assert_eq!(normalize(&record), None);
    }
}
