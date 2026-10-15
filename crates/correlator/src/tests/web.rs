//! Web request + web-server shell pairing (#478, ADR-0022): `Event::HttpRequest` from
//! an access log, joined to a shell spawned by a web server by time, in either order.

use proptest::prelude::*;
use schema::{HttpEvidence, HttpRequestEvent, HttpSignature};

use super::*;

const SEC: u64 = 1_000_000_000;

fn request(ts_ns: u64) -> Event {
    Event::HttpRequest(HttpRequestEvent {
        meta: meta_full(0, 0, "http-access-log", ts_ns),
        client: Some("203.0.113.9".parse().unwrap()),
        method: Some("GET".into()),
        path: "/up/s.php".into(),
        param_names: vec!["cmd".into()],
        status: 200,
        signature: HttpSignature::WebshellLike,
        evidence: Some(HttpEvidence {
            param: "cmd".into(),
            value: "SECRET-VALUE-whoami".into(),
        }),
        ..schema::fixtures::http_request()
    })
}

fn shell_under(parent: &str, pid: u32, ts_ns: u64) -> Event {
    Event::Exec(ExecEvent {
        meta: meta_full(pid, 500, "sh", ts_ns),
        image_path: "/usr/bin/sh".into(),
        parent_comm: Some(parent.into()),
        ..schema::fixtures::exec()
    })
}

fn web_alerts(alerts: &[crate::CorrelationAlert]) -> Vec<&crate::CorrelationAlert> {
    alerts
        .iter()
        .filter(|a| a.technique == "T1505.003")
        .collect()
}

#[test]
fn request_then_shell_alerts_once() {
    let mut engine = CorrelationEngine::new();
    assert!(engine.on_event(request(102 * SEC)).is_empty());
    assert!(web_alerts(&engine.on_event(shell_under("php-fpm8.3", 700, 101 * SEC))).is_empty());
    let alerts = engine.advance_time(104 * SEC);
    let web = web_alerts(&alerts);
    assert_eq!(web.len(), 1, "{alerts:?}");
    assert!(
        web[0].message.contains("WebshellLike"),
        "{}",
        web[0].message
    );
    assert!(web[0].message.contains("/up/s.php"));
    assert!(web[0].message.contains("203.0.113.9"));
    assert!(web[0].message.contains("param=cmd"));
    // A later request near the same shell does not alert for it again.
    assert!(web_alerts(&engine.on_event(request(103 * SEC))).is_empty());
}

#[test]
fn shell_then_request_alerts_when_the_log_line_arrives() {
    // The log line is written after the request ends, so the shell it caused comes
    // first and the line is read a few seconds later.
    let mut engine = CorrelationEngine::new();
    let early = engine.on_event(shell_under("nginx", 800, 100 * SEC));
    assert!(web_alerts(&early).is_empty(), "no request seen yet");
    let late = engine.on_event(request(101 * SEC));
    assert!(
        web_alerts(&late).is_empty(),
        "the grace period is still open"
    );
    let alerts = engine.advance_time(103 * SEC);
    assert_eq!(web_alerts(&alerts).len(), 1, "{alerts:?}");
}

#[test]
fn the_matched_value_never_reaches_the_alert() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(102 * SEC));
    engine.on_event(shell_under("apache2", 700, 101 * SEC));
    let alerts = engine.advance_time(104 * SEC);
    for a in &alerts {
        assert!(!a.message.contains("SECRET-VALUE"), "{}", a.message);
    }
}

#[test]
fn a_shell_under_another_parent_does_not_pair() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(102 * SEC));
    let alerts = engine.on_event(shell_under("sshd-session", 700, 101 * SEC));
    assert!(web_alerts(&alerts).is_empty());
}

#[test]
fn a_request_alone_is_not_a_case_but_a_shell_without_a_request_expires_generically() {
    let mut engine = CorrelationEngine::new();
    assert!(web_alerts(&engine.on_event(request(100 * SEC))).is_empty());
    let mut engine = CorrelationEngine::new();
    let alerts = engine.on_event(shell_under("nginx", 700, 100 * SEC));
    assert!(web_alerts(&alerts).is_empty());
    let expired_alerts = engine.advance_time(103 * SEC);
    let expired = web_alerts(&expired_alerts);
    assert_eq!(expired.len(), 1);
    assert!(
        expired[0]
            .message
            .contains("no matching access-log request")
    );
}

#[test]
fn an_old_request_is_not_named_after_the_grace_period() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(100 * SEC));
    let alerts = engine.on_event(shell_under("nginx", 700, 300 * SEC));
    assert!(web_alerts(&alerts).is_empty());
    let expired_alerts = engine.advance_time(303 * SEC);
    let expired = web_alerts(&expired_alerts);
    assert_eq!(expired.len(), 1);
    assert!(
        expired[0]
            .message
            .contains("no matching access-log request")
    );
    assert!(!expired[0].message.contains("/up/s.php"));
}

#[test]
fn a_request_creates_no_belief_for_the_pid_zero_pseudo_process() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(100 * SEC));
    assert!(engine.belief_for_entity(0, "http-access-log").is_none());
    assert!(engine.belief_for_pid(0).is_none());
}

#[test]
fn each_shell_gets_its_own_alert() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(101 * SEC));
    engine.on_event(shell_under("php-fpm", 700, 100 * SEC));
    engine.on_event(request(102 * SEC));
    engine.on_event(shell_under("php-fpm", 701, 101 * SEC));
    let all_alerts = engine.advance_time(104 * SEC);
    let alerts = web_alerts(&all_alerts);
    assert_eq!(alerts.len(), 2);
}

#[test]
fn requests_with_equal_read_timestamps_use_a_stable_tiebreaker() {
    // One poll stamps a burst with the same instant; the chosen request must not depend
    // on the order in which those records reach the correlator.
    let mut engine = CorrelationEngine::new();
    let probe = Event::HttpRequest(HttpRequestEvent {
        signature: HttpSignature::SqlInjection,
        path: "/index.php".into(),
        ..match request(102 * SEC) {
            Event::HttpRequest(r) => r,
            _ => unreachable!(),
        }
    });
    engine.on_event(probe);
    engine.on_event(request(102 * SEC));
    engine.on_event(shell_under("nginx", 900, 101 * SEC));
    let alerts = engine.advance_time(104 * SEC);
    let web = web_alerts(&alerts);
    assert_eq!(web.len(), 1, "{alerts:?}");
    assert!(
        web[0].message.contains("SqlInjection"),
        "{}",
        web[0].message
    );
    assert!(web[0].message.contains("/index.php"), "{}", web[0].message);
}

#[test]
fn requests_arriving_while_a_shell_is_pending_use_the_stable_tiebreaker() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(shell_under("nginx", 907, 101 * SEC));
    engine.on_event(request(102 * SEC));
    let probe = Event::HttpRequest(HttpRequestEvent {
        signature: HttpSignature::SqlInjection,
        path: "/index.php".into(),
        ..match request(102 * SEC) {
            Event::HttpRequest(r) => r,
            _ => unreachable!(),
        }
    });
    engine.on_event(probe);

    let alerts = engine.advance_time(104 * SEC);
    let web = web_alerts(&alerts);
    assert_eq!(web.len(), 1, "{alerts:?}");
    assert!(web[0].message.contains("SqlInjection"));
    assert!(web[0].message.contains("/index.php"));
}

#[test]
fn post_shell_request_is_selected_even_when_an_older_request_is_present() {
    // The older access-log record is unrelated; the one read after the shell is eligible.
    let mut engine = CorrelationEngine::new();
    let older = Event::HttpRequest(HttpRequestEvent {
        signature: HttpSignature::SqlInjection,
        path: "/uploads/c99.php".into(),
        status: 404,
        ..match request(89 * SEC) {
            Event::HttpRequest(r) => r,
            _ => unreachable!(),
        }
    });
    engine.on_event(older);
    engine.on_event(shell_under("nginx", 900, 100 * SEC));
    engine.on_event(request(101 * SEC));
    let alerts = engine.advance_time(103 * SEC);
    let web = web_alerts(&alerts);
    assert_eq!(web.len(), 1, "{alerts:?}");
    assert!(
        web[0].message.contains("WebshellLike"),
        "{}",
        web[0].message
    );
    assert!(web[0].message.contains("1s after"), "{}", web[0].message);
    assert!(web[0].message.contains("/up/s.php"), "{}", web[0].message);
    assert!(!web[0].message.contains("/uploads/c99.php"));
}

#[test]
fn a_request_after_the_grace_window_is_not_paired() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(shell_under("nginx", 902, 100 * SEC));
    let late = engine.on_event(request(103 * SEC + 1));
    let web = web_alerts(&late);
    assert_eq!(web.len(), 2, "generic alert followed by completion");
    assert!(web[0].message.contains("no matching access-log request"));
    assert!(web[1].message.contains("late access-log request read"));
    assert!(web[1].message.contains("/up/s.php"));
    assert!(web[1].message.contains("unverified"), "{}", web[1].message);
}

#[test]
fn a_late_access_log_completes_a_generic_alert_with_the_original_shell() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(shell_under("nginx", 903, 100 * SEC));
    let generic = engine.advance_time(103 * SEC);
    assert_eq!(web_alerts(&generic).len(), 1);
    assert!(web_alerts(&generic)[0].trigger_event.is_some());

    let completion = engine.on_event(request(100 * SEC + 90 * SEC));
    let web = web_alerts(&completion);
    assert_eq!(web.len(), 1);
    assert!(web[0].message.contains("late access-log request read"));
    assert!(web[0].message.contains("/up/s.php"));
    assert_eq!(web[0].trigger_event.as_ref().unwrap().meta().pid, 903);
}

#[test]
fn a_request_at_the_late_completion_deadline_is_included() {
    let mut engine = CorrelationEngine::new();
    let now = schema::time::now_ns();
    let shell_ns = now.saturating_sub(300 * SEC);
    engine.on_event(shell_under("nginx", 905, shell_ns));
    let generic = engine.advance_time(now);
    assert_eq!(web_alerts(&generic).len(), 1);

    let completion = engine.on_event(request(now));
    let web = web_alerts(&completion);
    assert_eq!(web.len(), 1);
    assert!(web[0].message.contains("late access-log request read"));
}

#[test]
fn a_request_beyond_the_late_completion_deadline_is_ignored() {
    let mut engine = CorrelationEngine::new();
    let now = schema::time::now_ns();
    let shell_ns = now.saturating_sub(10 * SEC);
    engine.on_event(shell_under("nginx", 906, shell_ns));
    let generic = engine.advance_time(now);
    assert_eq!(web_alerts(&generic).len(), 1);

    let too_late = engine.on_event(request(shell_ns + 300 * SEC + 1));
    assert!(web_alerts(&too_late).is_empty());
}

#[test]
fn a_future_shell_timestamp_cannot_fast_forward_the_grace_watermark() {
    let mut engine = CorrelationEngine::new();
    let wall_now = schema::time::now_ns();
    let future_shell = wall_now.saturating_add(120 * SEC);
    let alerts = engine.on_event(shell_under("nginx", 904, future_shell));
    assert!(web_alerts(&alerts).is_empty());
    assert!(web_alerts(&engine.advance_time(wall_now.saturating_add(600 * SEC))).is_empty());
}

#[test]
fn pending_web_shell_state_is_bounded() {
    let mut engine = CorrelationEngine::new();
    let now = schema::time::now_ns();
    for i in 0..256 {
        engine.on_event(shell_under("nginx", 10_000 + i, now));
    }
    assert_eq!(engine.web_shell_shedding().pending_overflow, 0);
    let overflow = engine.on_event(shell_under("nginx", 20_000, now));
    assert_eq!(web_alerts(&overflow).len(), 1);
    assert_eq!(
        engine.web_shell_shedding().pending_overflow,
        1,
        "the overflow is counted, not only logged"
    );
}

#[test]
fn a_late_window_that_closes_without_a_request_is_counted() {
    let mut engine = CorrelationEngine::new();
    let now = schema::time::now_ns();
    let shell_ns = now.saturating_sub(400 * SEC);
    engine.on_event(shell_under("nginx", 907, shell_ns));
    assert_eq!(
        web_alerts(&engine.advance_time(shell_ns + 10 * SEC)).len(),
        1
    );
    assert_eq!(engine.web_shell_shedding().late_window_expired, 0);
    assert!(web_alerts(&engine.advance_time(now)).is_empty());
    assert_eq!(engine.web_shell_shedding().late_window_expired, 1);
}

#[test]
fn requests_pushed_out_of_the_recent_ring_are_counted() {
    let mut engine = CorrelationEngine::new();
    let now = schema::time::now_ns();
    for i in 0..512 {
        engine.on_event(request(now - 1_000 * SEC + i));
    }
    assert_eq!(engine.web_shell_shedding().requests_evicted, 0);
    engine.on_event(request(now - 1_000 * SEC + 600));
    assert_eq!(engine.web_shell_shedding().requests_evicted, 1);
}

#[test]
fn duplicate_shell_events_do_not_queue_two_alerts() {
    let mut engine = CorrelationEngine::new();
    let shell = shell_under("nginx", 20_001, 100 * SEC);
    assert!(web_alerts(&engine.on_event(shell.clone())).is_empty());
    assert!(web_alerts(&engine.on_event(shell)).is_empty());

    let alerts = engine.advance_time(103 * SEC);
    assert_eq!(web_alerts(&alerts).len(), 1, "{alerts:?}");
}

#[test]
fn a_new_shell_timestamp_for_the_same_pid_is_not_suppressed_as_a_duplicate() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(shell_under("nginx", 20_002, 100 * SEC));
    assert_eq!(web_alerts(&engine.advance_time(103 * SEC)).len(), 1);

    assert!(web_alerts(&engine.on_event(shell_under("nginx", 20_002, 101 * SEC))).is_empty());
    assert_eq!(web_alerts(&engine.advance_time(104 * SEC)).len(), 1);
}

#[test]
fn completed_shell_contexts_release_the_bounded_pending_capacity() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(shell_under("nginx", 20_003, 100 * SEC));
    assert_eq!(web_alerts(&engine.advance_time(103 * SEC)).len(), 1);
    assert_eq!(web_alerts(&engine.on_event(request(104 * SEC))).len(), 1);

    for i in 0..256 {
        let alerts = engine.on_event(shell_under("nginx", 30_000 + i, 200 * SEC));
        assert!(web_alerts(&alerts).is_empty(), "queue overflowed at {i}");
    }
}

proptest! {
    #[test]
    fn selected_request_is_independent_of_shell_and_log_delivery_order(
        shell_ns in 100 * SEC..1_000_000 * SEC,
        offset in 0..3 * SEC,
    ) {
        let request_ns = shell_ns + offset;
        let shell = shell_under("nginx", 901, shell_ns);
        let request = request(request_ns);
        let mut shell_first = CorrelationEngine::new();
        shell_first.on_event(shell.clone());
        shell_first.on_event(request.clone());
        let first_alerts = shell_first.advance_time(shell_ns + 3 * SEC);
        let selected_first = web_alerts(&first_alerts);

        let mut request_first = CorrelationEngine::new();
        request_first.on_event(request);
        request_first.on_event(shell);
        let second_alerts = request_first.advance_time(shell_ns + 3 * SEC);
        let selected_second = web_alerts(&second_alerts);

        prop_assert_eq!(selected_first.len(), 1);
        prop_assert_eq!(selected_second.len(), 1);
        prop_assert_eq!(&selected_first[0].message, &selected_second[0].message);
        prop_assert!(selected_first[0].message.contains("/up/s.php"));
    }
}
