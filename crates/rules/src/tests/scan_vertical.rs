//! SCAN-VERTICAL (T1046, #378): many distinct ports on one host from one pid. The cases
//! that must stay quiet matter as much as the scan: one host's few ports, many hosts on one
//! port (SCAN-SPREAD's shape), loopback, a slow client.

use super::*;
use crate::{
    Alert, Severity,
    exclusions::{SCAN_VERTICAL_THRESHOLD, SCAN_VERTICAL_WINDOW_NS},
};

const MS: u64 = 1_000_000;

/// The `T1046` alerts (the vertical rule's own tag; SCAN-SPREAD's is `T1046/T1210`).
fn vertical(alerts: Vec<Alert>) -> Vec<Alert> {
    alerts
        .into_iter()
        .filter(|a| a.technique == "T1046")
        .collect()
}

/// `ports` connects from `pid` to `host`, one every 10 ms.
fn scan(state: &mut RuleState, pid: u32, host: [u8; 4], ports: std::ops::Range<u16>) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for (i, port) in ports.enumerate() {
        alerts.extend(state.on_connect(&connect_event_full(
            pid,
            "scanner",
            host,
            port,
            i as u64 * 10 * MS,
        )));
    }
    vertical(alerts)
}

#[test]
fn many_ports_on_one_host_alert_once() {
    let mut state = RuleState::new();
    let alerts = scan(&mut state, 700, [10, 0, 0, 5], 1000..1100);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert!(
        alerts[0].message.contains("10.0.0.5"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn a_client_using_a_handful_of_ports_on_one_host_does_not_alert() {
    let mut state = RuleState::new();
    assert!(
        scan(
            &mut state,
            700,
            [10, 0, 0, 5],
            1000..(1000 + SCAN_VERTICAL_THRESHOLD as u16 - 1)
        )
        .is_empty()
    );
}

#[test]
fn one_port_hammered_is_not_a_port_scan() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..200u64 {
        alerts.extend(state.on_connect(&connect_event_full(
            700,
            "app",
            [10, 0, 0, 5],
            443,
            i * 10 * MS,
        )));
    }
    assert!(vertical(alerts).is_empty());
}

#[test]
fn many_hosts_on_one_port_is_scan_spread_not_scan_vertical() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..60u8 {
        alerts.extend(state.on_connect(&connect_event_full(
            700,
            "bot",
            [10, 0, 1, i],
            23,
            u64::from(i) * 10 * MS,
        )));
    }
    assert!(vertical(alerts.clone()).is_empty());
    assert!(
        alerts.iter().any(|a| a.technique == "T1046/T1210"),
        "{alerts:?}"
    );
}

#[test]
fn a_few_ports_on_each_of_many_hosts_does_not_alert() {
    // 10 ports on each of 6 hosts: 60 connects, never 20 ports on one host.
    let mut state = RuleState::new();
    for host in 0..6u8 {
        assert!(scan(&mut state, 700, [10, 0, 2, host], 2000..2010).is_empty());
    }
}

#[test]
fn loopback_is_not_counted() {
    // A single-host stack connects to many local ports by design.
    let mut state = RuleState::new();
    assert!(scan(&mut state, 700, [127, 0, 0, 1], 3000..3100).is_empty());
}

#[test]
fn a_slow_client_outside_the_window_does_not_alert() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..60u64 {
        // One new port every window: never more than two in flight.
        alerts.extend(state.on_connect(&connect_event_full(
            700,
            "app",
            [10, 0, 0, 5],
            4000 + i as u16,
            i * SCAN_VERTICAL_WINDOW_NS,
        )));
    }
    assert!(vertical(alerts).is_empty());
}

#[test]
fn the_ports_of_two_processes_are_not_added_together() {
    let mut state = RuleState::new();
    let mut alerts = scan(&mut state, 700, [10, 0, 0, 5], 5000..5015);
    alerts.extend(scan(&mut state, 701, [10, 0, 0, 5], 6000..6015));
    assert!(alerts.is_empty());
}

#[test]
fn the_windows_system_process_is_excluded() {
    let mut state = RuleState::new();
    assert!(scan(&mut state, 4, [10, 0, 0, 5], 7000..7100).is_empty());
}

#[test]
fn the_state_stays_bounded_under_many_targets() {
    // One connect to each of far more (pid, host) pairs than the map holds.
    let mut state = RuleState::new();
    for i in 0..(crate::state::COUNTER_CAP as u32 + 1_000) {
        let alerts = state.on_connect(&connect_event_full(
            800 + i,
            "app",
            [10, (i >> 8) as u8, i as u8, 9],
            8000,
            u64::from(i % 5),
        ));
        assert!(vertical(alerts).is_empty());
    }
}
