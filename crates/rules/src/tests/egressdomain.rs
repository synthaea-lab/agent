//! EGRESS-DOMAIN (#380, T1567): the volume a process sends to an address that its own DNS lookup
//! resolved from a storage or paste service.

use schema::DnsQueryEvent;

use super::*;

const MIB: u64 = 1024 * 1024;
const SEC: u64 = 1_000_000_000;
const PASTE_IP: [u8; 4] = [104, 20, 67, 143];
const PID: u32 = 300;

fn lookup(pid: u32, query: &str, result: Option<&str>, at_s: u64) -> DnsQueryEvent {
    let mut event = DnsQueryEvent {
        query: query.to_string(),
        result: result.map(str::to_string),
        status: 0,
        ..schema::fixtures::dns_query()
    };
    event.meta = meta();
    event.meta.pid = pid;
    event.meta.timestamp_ns = at_s * SEC;
    event
}

fn flow(pid: u32, comm: &str, port: u16, daddr: [u8; 4], sent: u64, at_s: u64) -> NetworkFlowEvent {
    NetworkFlowEvent {
        bytes_sent: Some(sent),
        ..network_flow_event_full(pid, comm, port, daddr, 443, at_s * SEC)
    }
}

/// A state where `PID` resolved `query` to `PASTE_IP` at t=0 and opened a flow (the baseline poll
/// adds nothing).
fn after_lookup(query: &str) -> RuleState {
    let mut state = RuleState::new();
    state.on_dns_query(&lookup(PID, query, Some("104.20.67.143"), 0));
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 0, 1))
            .is_empty()
    );
    state
}

fn techniques(alerts: &[crate::Alert]) -> Vec<&'static str> {
    alerts.iter().map(|a| a.technique).collect()
}

#[test]
fn a_paste_service_upload_over_the_threshold_alerts_with_the_domain() {
    let mut state = after_lookup("pastebin.com");
    // 10 MiB: below the 25 MiB classed threshold.
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 10 * MIB, 5))
            .is_empty()
    );
    // 30 MiB in total: over it, far below the generic 512 MiB.
    let alerts = state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 10));
    assert_eq!(techniques(&alerts), ["T1567.003"]);
    assert!(
        alerts[0].message.contains("pastebin.com"),
        "{}",
        alerts[0].message
    );
    assert!(alerts[0].message.contains("30MB"), "{}", alerts[0].message);
}

#[test]
fn a_cloud_storage_upload_is_tagged_as_cloud_storage() {
    let mut state = after_lookup("content.dropboxapi.com");
    let alerts = state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 40 * MIB, 5));
    assert_eq!(techniques(&alerts), ["T1567.002"]);
    assert!(
        alerts[0].message.contains("content.dropboxapi.com"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn alerts_once_per_window_and_again_after_it() {
    let mut state = after_lookup("pastebin.com");
    assert_eq!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 5))
            .len(),
        1
    );
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 60 * MIB, 10))
            .is_empty()
    );
    // The window is ten minutes: a later burst alerts again.
    let alerts = state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 120 * MIB, 700));
    assert_eq!(techniques(&alerts), ["T1567.003"]);
}

#[test]
fn no_lookup_means_only_the_generic_threshold_applies() {
    // The same upload to the same address with no DNS source: a 30 MiB send alerts nothing...
    let mut state = RuleState::new();
    state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 0, 1));
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 5))
            .is_empty()
    );
    // ...and 600 MiB still raises the generic EGRESS-VOLUME finding, never the classed one.
    let alerts = state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 600 * MIB, 10));
    assert_eq!(techniques(&alerts), ["T1041/T1048"]);
}

#[test]
fn another_process_resolving_the_service_does_not_class_this_process_flow() {
    // A storage service shares its addresses with every site behind the same CDN: only the
    // sending pid's own lookup counts.
    let mut state = RuleState::new();
    state.on_dns_query(&lookup(PID + 1, "pastebin.com", Some("104.20.67.143"), 0));
    state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 0, 1));
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 5))
            .is_empty()
    );
}

#[test]
fn a_lookup_of_an_unlisted_name_or_a_failed_or_empty_one_classes_nothing() {
    for (query, result, status) in [
        ("example.com", Some("104.20.67.143"), 0),
        ("pastebin.com", None, 0),
        ("pastebin.com", Some("104.20.67.143"), 9003),
        ("pastebin.com", Some("not an address"), 0),
        ("notpastebin.com", Some("104.20.67.143"), 0),
    ] {
        let mut state = RuleState::new();
        let mut event = lookup(PID, query, result, 0);
        event.status = status;
        state.on_dns_query(&event);
        state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 0, 1));
        assert!(
            state
                .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 5))
                .is_empty(),
            "{query} {result:?} {status}"
        );
    }
}

#[test]
fn a_flow_to_another_address_of_the_answer_is_not_joined() {
    // Only the first address of a Linux lookup is recorded: a connection to a second one is a
    // known miss, written in the rule's doc.
    let mut state = RuleState::new();
    state.on_dns_query(&lookup(PID, "pastebin.com", Some("104.20.67.143"), 0));
    let other = [104, 20, 68, 143];
    state.on_network_flow(&flow(PID, "curl", 50000, other, 0, 1));
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, other, 30 * MIB, 5))
            .is_empty()
    );
}

#[test]
fn the_windows_answer_list_classes_every_address_in_it() {
    let mut state = RuleState::new();
    state.on_dns_query(&lookup(
        PID,
        "pastebin.com",
        Some("type:5 cdn.example.net;type:1 104.20.67.143;type:1 104.20.68.143;"),
        0,
    ));
    for daddr in [[104, 20, 67, 143], [104, 20, 68, 143]] {
        state.on_network_flow(&flow(PID, "curl", 50000, daddr, 0, 1));
        let alerts = state.on_network_flow(&flow(PID, "curl", 50000, daddr, 30 * MIB, 5));
        assert_eq!(techniques(&alerts), ["T1567.003"], "{daddr:?}");
    }
}

#[test]
fn a_lookup_older_than_the_window_no_longer_classes_the_address() {
    let mut state = RuleState::new();
    state.on_dns_query(&lookup(PID, "pastebin.com", Some("104.20.67.143"), 0));
    // The flow appears two hours after the lookup.
    state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 0, 7200));
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 7205))
            .is_empty()
    );
}

#[test]
fn a_recycled_pid_does_not_inherit_the_lookup_of_the_process_that_held_it() {
    let mut state = RuleState::new();
    let mut event = lookup(PID, "pastebin.com", Some("104.20.67.143"), 0);
    event.meta.process_generation = Some(1);
    state.on_dns_query(&event);
    let mut baseline = flow(PID, "curl", 50000, PASTE_IP, 0, 1);
    baseline.meta.process_generation = Some(2);
    state.on_network_flow(&baseline);
    let mut grown = flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 5);
    grown.meta.process_generation = Some(2);
    assert!(state.on_network_flow(&grown).is_empty());
}

#[test]
fn a_private_peer_is_never_classed() {
    let mut state = RuleState::new();
    state.on_dns_query(&lookup(PID, "pastebin.com", Some("10.1.2.3"), 0));
    state.on_network_flow(&flow(PID, "curl", 50000, [10, 1, 2, 3], 0, 1));
    assert!(
        state
            .on_network_flow(&flow(PID, "curl", 50000, [10, 1, 2, 3], 30 * MIB, 5))
            .is_empty()
    );
}

#[test]
fn a_browser_from_the_system_directories_uploading_to_storage_does_not_alert() {
    let mut state = RuleState::new();
    let exec = ExecEvent {
        image_path: "/opt/google/chrome/chrome".to_string(),
        ..exec_event_full(PID, 1, "chrome", "", 0)
    };
    state.on_exec(&exec);
    state.on_dns_query(&lookup(PID, "drive.google.com", Some("104.20.67.143"), 0));
    state.on_network_flow(&flow(PID, "chrome", 50000, PASTE_IP, 0, 1));
    assert!(
        state
            .on_network_flow(&flow(PID, "chrome", 50000, PASTE_IP, 30 * MIB, 5))
            .is_empty()
    );
}

#[test]
fn a_binary_called_chrome_run_from_tmp_is_not_excluded() {
    // The name-keyed exclusion is gated on the image (CLAUDE.md): a rename in /tmp inherits
    // nothing.
    let mut state = RuleState::new();
    let exec = ExecEvent {
        image_path: "/tmp/chrome".to_string(),
        ..exec_event_full(PID, 1, "chrome", "", 0)
    };
    state.on_exec(&exec);
    state.on_dns_query(&lookup(PID, "drive.google.com", Some("104.20.67.143"), 0));
    state.on_network_flow(&flow(PID, "chrome", 50000, PASTE_IP, 0, 1));
    let alerts = state.on_network_flow(&flow(PID, "chrome", 50000, PASTE_IP, 30 * MIB, 5));
    assert_eq!(techniques(&alerts), ["T1567.002"]);
}

#[test]
fn the_classed_and_the_generic_findings_are_independent() {
    let mut state = after_lookup("pastebin.com");
    assert_eq!(
        techniques(&state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 30 * MIB, 5))),
        ["T1567.003"]
    );
    // Crossing the generic threshold afterwards still raises it: the classed alert did not
    // consume its window.
    let alerts = state.on_network_flow(&flow(PID, "curl", 50000, PASTE_IP, 600 * MIB, 10));
    assert_eq!(techniques(&alerts), ["T1041/T1048"]);
}

#[test]
fn the_sighting_history_is_bounded_and_an_evicted_pid_is_forgotten() {
    let mut state = RuleState::new();
    for pid in 0..=(COUNTER_CAP as u32) {
        state.on_dns_query(&lookup(
            10_000 + pid,
            "pastebin.com",
            Some("104.20.67.143"),
            0,
        ));
    }
    // The oldest entry was shed: its pid's flow is no longer classed. The newest still is.
    let upload = |state: &mut RuleState, pid: u32| {
        state.on_network_flow(&flow(pid, "curl", 50000, PASTE_IP, 0, 1));
        state.on_network_flow(&flow(pid, "curl", 50000, PASTE_IP, 30 * MIB, 5))
    };
    assert!(upload(&mut state, 10_000).is_empty());
    assert_eq!(upload(&mut state, 10_000 + COUNTER_CAP as u32).len(), 1);
}
