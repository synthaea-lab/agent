//! T1204.002 — a file carrying a download-provenance mark (`FileQuarantine`)
//! executed within the window (#365). Platform-neutral: the same join serves
//! macOS quarantine xattrs and Windows `Zone.Identifier` streams.

use schema::{ExecEvent, FileQuarantineEvent};

use super::meta;
use crate::{RuleState, exclusions::QUARANTINE_EXEC_WINDOW_NS};

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

#[test]
fn marked_download_executed_within_the_window_alerts_with_its_origin() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alerts = state.on_exec(&run(DOWNLOAD, 90_000_000_000));
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
    let alerts = state.on_exec(&run(&DOWNLOAD.to_uppercase(), 1));
    assert_eq!(alerts.len(), 1);
}

#[test]
fn exec_past_the_window_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(
        state
            .on_exec(&run(DOWNLOAD, QUARANTINE_EXEC_WINDOW_NS + 1))
            .is_empty()
    );
}

#[test]
fn unmarked_file_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(
        state
            .on_exec(&run(r"C:\Windows\System32\notepad.exe", 1))
            .is_empty()
    );
}

#[test]
fn rerunning_the_same_download_alerts_once() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert_eq!(state.on_exec(&run(DOWNLOAD, 1)).len(), 1);
    assert!(state.on_exec(&run(DOWNLOAD, 2)).is_empty());
}

#[test]
fn a_fresh_mark_on_the_same_path_alerts_again() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert_eq!(state.on_exec(&run(DOWNLOAD, 1)).len(), 1);
    state.on_file_quarantine(&mark(DOWNLOAD, 10));
    assert_eq!(state.on_exec(&run(DOWNLOAD, 11)).len(), 1);
}

#[test]
fn mark_without_recorded_urls_still_joins() {
    // A raced read of the stream reports the mark alone — still a download.
    let mut state = RuleState::new();
    state.on_file_quarantine(&FileQuarantineEvent {
        path: DOWNLOAD.into(),
        ..schema::fixtures::file_quarantine()
    });
    let alerts = state.on_exec(&run(DOWNLOAD, 1));
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("origin: unrecorded"));
}
