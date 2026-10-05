//! Web request + web-server shell pairing (#478, ADR-0022): `Event::HttpRequest` from
//! an access log, joined to a shell spawned by a web server by time, in either order.

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
    assert!(engine.on_event(request(100 * SEC)).is_empty());
    let alerts = engine.on_event(shell_under("php-fpm8.3", 700, 101 * SEC));
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
    assert!(web_alerts(&engine.on_event(request(102 * SEC))).is_empty());
}

#[test]
fn shell_then_request_alerts_when_the_log_line_arrives() {
    // The log line is written after the request ends, so the shell it caused comes
    // first and the line is read a few seconds later.
    let mut engine = CorrelationEngine::new();
    let early = engine.on_event(shell_under("nginx", 800, 100 * SEC));
    assert!(web_alerts(&early).is_empty(), "no request seen yet");
    let alerts = engine.on_event(request(103 * SEC));
    assert_eq!(web_alerts(&alerts).len(), 1, "{alerts:?}");
}

#[test]
fn the_matched_value_never_reaches_the_alert() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(100 * SEC));
    let alerts = engine.on_event(shell_under("apache2", 700, 101 * SEC));
    for a in &alerts {
        assert!(!a.message.contains("SECRET-VALUE"), "{}", a.message);
    }
}

#[test]
fn a_shell_under_another_parent_does_not_pair() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(100 * SEC));
    let alerts = engine.on_event(shell_under("sshd-session", 700, 101 * SEC));
    assert!(web_alerts(&alerts).is_empty());
}

#[test]
fn a_request_or_a_web_shell_alone_is_not_a_case() {
    let mut engine = CorrelationEngine::new();
    assert!(web_alerts(&engine.on_event(request(100 * SEC))).is_empty());
    let mut engine = CorrelationEngine::new();
    let alerts = engine.on_event(shell_under("nginx", 700, 100 * SEC));
    assert!(web_alerts(&alerts).is_empty());
}

#[test]
fn a_request_older_than_the_window_does_not_pair() {
    let mut engine = CorrelationEngine::new();
    engine.on_event(request(100 * SEC));
    let alerts = engine.on_event(shell_under("nginx", 700, 300 * SEC));
    assert!(web_alerts(&alerts).is_empty());
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
    engine.on_event(request(100 * SEC));
    let first = engine.on_event(shell_under("php-fpm", 700, 101 * SEC));
    let second = engine.on_event(shell_under("php-fpm", 701, 102 * SEC));
    assert_eq!(web_alerts(&first).len(), 1);
    assert_eq!(web_alerts(&second).len(), 1);
}

#[test]
fn requests_read_in_one_poll_pair_with_the_last_one_in_the_log() {
    // One poll reads a burst and stamps all of it with the same instant, so only the
    // order says which request came last.
    let mut engine = CorrelationEngine::new();
    let probe = Event::HttpRequest(HttpRequestEvent {
        signature: HttpSignature::SqlInjection,
        path: "/index.php".into(),
        ..match request(100 * SEC) {
            Event::HttpRequest(r) => r,
            _ => unreachable!(),
        }
    });
    engine.on_event(probe);
    engine.on_event(request(100 * SEC));
    let alerts = engine.on_event(shell_under("nginx", 900, 101 * SEC));
    let web = web_alerts(&alerts);
    assert_eq!(web.len(), 1, "{alerts:?}");
    assert!(
        web[0].message.contains("WebshellLike"),
        "{}",
        web[0].message
    );
    assert!(web[0].message.contains("/up/s.php"), "{}", web[0].message);
}

#[test]
fn two_requests_at_the_same_distance_pair_with_the_one_before_the_shell() {
    // 5 s before and 5 s after: only the earlier one can have started the shell.
    let mut engine = CorrelationEngine::new();
    let before = Event::HttpRequest(HttpRequestEvent {
        signature: HttpSignature::SqlInjection,
        path: "/index.php".into(),
        ..match request(95 * SEC) {
            Event::HttpRequest(r) => r,
            _ => unreachable!(),
        }
    });
    engine.on_event(before);
    engine.on_event(request(105 * SEC));
    let alerts = engine.on_event(shell_under("nginx", 900, 100 * SEC));
    let web = web_alerts(&alerts);
    assert_eq!(web.len(), 1, "{alerts:?}");
    assert!(
        web[0].message.contains("SqlInjection"),
        "{}",
        web[0].message
    );
    assert!(web[0].message.contains("/index.php"), "{}", web[0].message);
}
