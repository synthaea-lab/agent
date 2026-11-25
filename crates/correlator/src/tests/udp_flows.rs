//! The UDP flow gate (#253 review): at most one `UdpSend` per flow per second on the
//! bus, the rest counted, and a datagram as the network leg of the spawn rules.

use super::*;

const SECOND_NS: u64 = 1_000_000_000;
const PID: u32 = 4321;

fn udp_sends_on_bus(engine: &CorrelationEngine) -> usize {
    engine
        .bus()
        .events_for_pid(PID, None)
        .filter(|event| matches!(event, Event::UdpSend(_)))
        .count()
}

#[test]
fn a_udp_burst_within_a_second_puts_one_datagram_on_the_bus_and_counts_the_rest() {
    let mut engine = CorrelationEngine::new();
    for datagram in 0..1_000 {
        engine.on_event(udp_send_to(PID, SECOND_NS + datagram * 1_000, 443));
    }

    assert_eq!(udp_sends_on_bus(&engine), 1);
    assert_eq!(engine.udp_send_shedding().repeats_suppressed, 999);
}

#[test]
fn each_destination_of_a_process_is_its_own_flow() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(udp_send_to(PID, SECOND_NS, 53));
    engine.on_event(udp_send_to(PID, 2 * SECOND_NS, 443));

    assert_eq!(udp_sends_on_bus(&engine), 2);
    assert_eq!(engine.udp_send_shedding().repeats_suppressed, 0);
}

#[test]
fn a_flow_still_active_a_second_later_is_admitted_again() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(udp_send_to(PID, SECOND_NS, 443));
    engine.on_event(udp_send_to(PID, SECOND_NS + SECOND_NS / 2, 443));
    engine.on_event(udp_send_to(PID, 2 * SECOND_NS, 443));

    assert_eq!(udp_sends_on_bus(&engine), 2);
    assert_eq!(engine.udp_send_shedding().repeats_suppressed, 1);
}

#[test]
fn a_datagram_late_in_the_window_still_pairs_with_a_later_payload_write() {
    let mut engine = CorrelationEngine::with_window(Duration::from_secs(60));
    engine.on_event(udp_send_to(PID, SECOND_NS, 4444));
    engine.on_event(udp_send_to(PID, 60 * SECOND_NS, 4444));

    let alerts = engine.on_event(file_write_event(PID, 61 * SECOND_NS + SECOND_NS / 2));

    assert!(
        alerts.iter().any(|alert| alert.technique == "T1105"),
        "the throwaway datagram left the window, the one sent at 60 s has not"
    );
}

#[test]
fn a_spawned_process_sending_a_udp_datagram_alerts_spawn_and_connect() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(exec_event(PID, SECOND_NS));

    let alerts = engine.on_event(udp_send_to(PID, 2 * SECOND_NS, 53));

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059/T1071");
}

#[test]
fn a_udp_datagram_and_a_payload_write_alert_staging() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(udp_send_to(PID, SECOND_NS, 4444));

    let alerts = engine.on_event(file_write_event(PID, 2 * SECOND_NS));

    assert!(alerts.iter().any(|alert| alert.technique == "T1105"));
}
