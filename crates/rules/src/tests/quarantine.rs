//! T1204.002 — a file carrying a download-provenance mark (`FileQuarantine`)
//! executed within the window (#365). Platform-neutral: the same join serves
//! macOS quarantine xattrs and Windows `Zone.Identifier` streams. Gated on the
//! image's signature (#441): resolved here as the agent's enrichment worker
//! would.

use schema::{ExecEvent, FileQuarantineEvent, Signature};

use super::meta;
use crate::{Alert, ImageSignature, RuleState, exclusions::QUARANTINE_EXEC_WINDOW_NS};

const DOWNLOAD: &str = r"C:\Users\u\Downloads\invoice.exe";

fn mark(path: &str, timestamp_ns: u64) -> FileQuarantineEvent {
    FileQuarantineEvent {
        meta: schema::EventMeta {
            timestamp_ns,
            comm: "msedge.exe".into(),
            ..meta()
        },
        path: path.into(),
        agent: Some("msedge.exe".into()),
        origin_url: Some("https://example.test/invoice.exe".into()),
        ..schema::fixtures::file_quarantine()
    }
}

fn run(image_path: &str, timestamp_ns: u64) -> ExecEvent {
    ExecEvent {
        meta: schema::EventMeta {
            pid: 4242,
            timestamp_ns,
            comm: "invoice.exe".into(),
            ..meta()
        },
        image_path: image_path.into(),
        ..schema::fixtures::exec()
    }
}

const AUTHENTICODE_UNSIGNED: ImageSignature = ImageSignature {
    verdict: Some(Signature::Unsigned),
    chain_verified: true,
};

/// The exec as the agent sees it: `on_exec`'s alerts, plus the gated ones
/// resolved with `signature`.
fn exec_with(state: &mut RuleState, event: &ExecEvent, signature: ImageSignature) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = state
        .on_exec_signature_gated(event)
        .and_then(|gated| gated.resolve(signature))
        .into_iter()
        .collect();
    alerts.extend(state.on_exec(event));
    alerts
}

/// An unsigned image on Windows: what every pre-#441 test here assumed.
fn exec(state: &mut RuleState, event: &ExecEvent) -> Vec<Alert> {
    exec_with(state, event, AUTHENTICODE_UNSIGNED)
}

#[test]
fn marked_download_executed_within_the_window_alerts_with_its_origin() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alerts = exec(&mut state, &run(DOWNLOAD, 90_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1204.002");
    assert!(
        alerts[0]
            .message
            .contains("https://example.test/invoice.exe")
    );
    assert!(alerts[0].message.contains("msedge.exe"));
    assert!(alerts[0].message.contains("90.0s"));
}

#[test]
fn path_match_ignores_case() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alerts = exec(&mut state, &run(&DOWNLOAD.to_uppercase(), 1));
    assert_eq!(alerts.len(), 1);
}

#[test]
fn exec_past_the_window_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(exec(&mut state, &run(DOWNLOAD, QUARANTINE_EXEC_WINDOW_NS + 1)).is_empty());
}

#[test]
fn unmarked_file_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(exec(&mut state, &run(r"C:\Windows\System32\notepad.exe", 1)).is_empty());
}

#[test]
fn rerunning_the_same_download_alerts_once() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert_eq!(exec(&mut state, &run(DOWNLOAD, 1)).len(), 1);
    assert!(exec(&mut state, &run(DOWNLOAD, 2)).is_empty());
}

#[test]
fn a_fresh_mark_on_the_same_path_alerts_again() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert_eq!(exec(&mut state, &run(DOWNLOAD, 1)).len(), 1);
    state.on_file_quarantine(&mark(DOWNLOAD, 10));
    assert_eq!(exec(&mut state, &run(DOWNLOAD, 11)).len(), 1);
}

#[test]
fn mark_without_recorded_urls_still_joins() {
    // A raced read of the stream reports the mark alone — still a download.
    let mut state = RuleState::new();
    state.on_file_quarantine(&FileQuarantineEvent {
        path: DOWNLOAD.into(),
        ..schema::fixtures::file_quarantine()
    });
    let alerts = exec(&mut state, &run(DOWNLOAD, 1));
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("origin: unrecorded"));
}

#[test]
fn a_signed_installer_run_does_not_alert() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let signed = ImageSignature {
        verdict: Some(Signature::Valid),
        chain_verified: true,
    };
    assert!(exec_with(&mut state, &run(DOWNLOAD, 1), signed).is_empty());
}

#[test]
fn an_unsigned_download_says_so() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alerts = exec(&mut state, &run(DOWNLOAD, 1));
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0].message.ends_with("[unsigned]"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn an_invalid_signature_alerts() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let tampered = ImageSignature {
        verdict: Some(Signature::Invalid),
        chain_verified: true,
    };
    let alerts = exec_with(&mut state, &run(DOWNLOAD, 1), tampered);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.ends_with("[signature invalid]"));
}

#[test]
fn a_valid_signature_without_chain_verification_still_alerts() {
    // macOS: `Valid` includes ad-hoc signatures, which every arm64 binary has.
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark("/Users/u/Downloads/tool", 0));
    let ad_hoc = ImageSignature {
        verdict: Some(Signature::Valid),
        chain_verified: false,
    };
    let alerts = exec_with(&mut state, &run("/Users/u/Downloads/tool", 1), ad_hoc);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("chain not verified"));
}

#[test]
fn a_lost_signature_verdict_still_alerts() {
    for verdict in [None, Some(Signature::Unsupported)] {
        let mut state = RuleState::new();
        state.on_file_quarantine(&mark(DOWNLOAD, 0));
        let unknown = ImageSignature {
            verdict,
            chain_verified: true,
        };
        let alerts = exec_with(&mut state, &run(DOWNLOAD, 1), unknown);
        assert_eq!(alerts.len(), 1, "{verdict:?}");
        assert!(alerts[0].message.ends_with("[signature not verified]"));
    }
}

#[test]
fn a_caller_that_cannot_wait_gets_the_unverified_alert() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alert = state
        .on_exec_signature_gated(&run(DOWNLOAD, 1))
        .expect("the join matches")
        .unverified();
    assert_eq!(alert.technique, "T1204.002");
    assert!(alert.message.ends_with("[signature not verified]"));
}

#[test]
fn on_exec_alone_no_longer_raises_the_download_join() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(state.on_exec(&run(DOWNLOAD, 1)).is_empty());
}
