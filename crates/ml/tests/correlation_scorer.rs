//! Inference parity seam for T2: `ml::CorrelationScorer` (Rust feature extraction
//! from an `EventBus`, then `ort`) must reproduce the scores the training-side
//! runtime produces (Python feature extraction through onnxruntime), pinned by
//! `ml/tests/fixtures/correlation_scorer_golden.jsonl` and its
//! `gen_correlation_scorer_fixture.py` generator.
//!
//! The counterpart of `scorer.rs` for the correlation model: `features_golden`
//! pins the vector, this pins the score the shipped runtime computes from a window
//! of events — including the `MIN_EVENT_COUNT` gate, where the scorer returns
//! `None` and the model is never asked.

use std::{net::Ipv4Addr, time::Duration};

use correlator::EventBus;
use ml::CorrelationScorer;
use schema::{ConnectEvent, Event, EventMeta, ExecEvent, FileOpenEvent, User};
use serde_json::Value;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scorer() -> CorrelationScorer {
    let model = std::fs::read(fixture_path("correlation_scorer.onnx")).unwrap();
    CorrelationScorer::from_onnx_bytes(&model).expect("fixture model must load")
}

fn meta(pid: u32, ts_ns: u64) -> EventMeta {
    EventMeta {
        pid,
        ppid: 0,
        user: User::Unix { uid: 0, gid: 0 },
        timestamp_ns: ts_ns,
        comm: "proc".into(),
    }
}

/// Build an `Event` from one golden event object (same schema as
/// `synthaea_ml.features.correlation`: `type` in exec/connect/fileopen, `pid`,
/// `ts_ns`, plus `daddr_v4`/`dport` or `flags`).
fn event_from_json(e: &Value) -> Event {
    let pid = e["pid"].as_u64().unwrap() as u32;
    let ts = e["ts_ns"].as_u64().unwrap();
    match e["type"].as_str().unwrap() {
        "exec" => Event::Exec(ExecEvent {
            meta: meta(pid, ts),
            image_path: String::new(),
            cmdline: String::new(),
            argv: vec![],
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
        }),
        "connect" => {
            let o = e["daddr_v4"].as_array().unwrap();
            let addr = Ipv4Addr::new(
                o[0].as_u64().unwrap() as u8,
                o[1].as_u64().unwrap() as u8,
                o[2].as_u64().unwrap() as u8,
                o[3].as_u64().unwrap() as u8,
            );
            Event::Connect(ConnectEvent {
                meta: meta(pid, ts),
                daddr: addr.into(),
                dport: e["dport"].as_u64().unwrap() as u16,
            })
        }
        "fileopen" => Event::FileOpen(FileOpenEvent {
            meta: meta(pid, ts),
            path: String::new(),
            flags: e["flags"].as_u64().unwrap() as u32,
        }),
        other => panic!("unknown golden event type {other:?}"),
    }
}

fn golden_lines() -> Vec<Value> {
    std::fs::read_to_string(fixture_path("correlation_scorer_golden.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("invalid golden line"))
        .collect()
}

#[test]
fn scores_match_onnxruntime_reference() {
    let mut scorer = scorer();
    // f32 inference vs the f32 golden: only rounding should differ.
    const TOL: f32 = 1e-5;
    let mut scored = 0;
    let mut gated = 0;
    for row in golden_lines() {
        let pid = row["pid"].as_u64().unwrap() as u32;
        // A fresh, wide window per case: the fixture never relies on eviction.
        let mut bus = EventBus::new(Duration::from_secs(24 * 3600));
        for e in row["events"].as_array().unwrap() {
            bus.push(event_from_json(e));
        }
        let got = scorer.score(&bus, pid).unwrap();
        match row["score"].as_f64() {
            None => {
                assert!(
                    got.is_none(),
                    "pid {pid}: expected gated (None), got {got:?}",
                );
                gated += 1;
            }
            Some(expected) => {
                let got = got.expect("expected a score, scorer gated");
                assert!(
                    (got - expected as f32).abs() <= TOL,
                    "score drifted for pid {pid}: ort={got} reference={expected}",
                );
                scored += 1;
            }
        }
    }
    // Guardrail: a truncated or mis-pathed golden file must not pass silently.
    assert!(
        scored >= 4,
        "suspicious golden file: only {scored} scored cases"
    );
    assert!(
        gated >= 1,
        "golden file should exercise the gate at least once"
    );
}

#[test]
fn score_explained_agrees_with_score_and_attributes() {
    let mut scorer = scorer();
    for row in golden_lines() {
        if row["score"].is_null() {
            continue;
        }
        let pid = row["pid"].as_u64().unwrap() as u32;
        let mut bus = EventBus::new(Duration::from_secs(24 * 3600));
        for e in row["events"].as_array().unwrap() {
            bus.push(event_from_json(e));
        }
        let bare = scorer.score(&bus, pid).unwrap().unwrap();
        let explained = scorer.score_explained(&bus, pid, 3).unwrap().unwrap();
        assert_eq!(
            bare, explained.value,
            "explained score must equal bare score"
        );
        assert!(explained.attributions.len() <= 3);
        for w in explained.attributions.windows(2) {
            assert!(w[0].contribution.abs() >= w[1].contribution.abs());
        }
        for a in &explained.attributions {
            assert!(
                ml::features::correlation::FEATURE_NAMES.contains(&a.feature.as_str()),
                "unknown feature {:?}",
                a.feature,
            );
        }
    }
}

#[test]
fn gate_returns_none_before_the_model_runs() {
    let mut scorer = scorer();
    let mut bus = EventBus::new(Duration::from_secs(3600));
    bus.push(event_from_json(
        &serde_json::json!({"type":"exec","pid":42,"ts_ns":0}),
    ));
    bus.push(event_from_json(
        &serde_json::json!({"type":"connect","pid":42,"ts_ns":1_000_000_000,"daddr_v4":[1,1,1,1],"dport":53}),
    ));
    // Two events < MIN_EVENT_COUNT.
    assert!(scorer.score(&bus, 42).unwrap().is_none());
    assert!(scorer.score_explained(&bus, 42, 3).unwrap().is_none());
}

#[test]
fn wrong_feature_arity_is_rejected() {
    // The cmdline scorer model is 9 features — loading it as a correlation scorer
    // (8 features) must fail at load, not mis-score silently.
    let model = std::fs::read(fixture_path("cmdline_scorer.onnx")).unwrap();
    assert!(CorrelationScorer::from_onnx_bytes(&model).is_err());
}

#[test]
fn garbage_model_fails_closed() {
    assert!(CorrelationScorer::from_onnx_bytes(b"not a model").is_err());
}
