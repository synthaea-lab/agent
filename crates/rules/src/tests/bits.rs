//! T1197 — a file a BITS job downloaded, executed within the window (#284).

use schema::{BitsJobEvent, BitsJobState, EventMeta, ExecEvent, User};

use super::meta;
use crate::{RuleState, exclusions::BITS_EXEC_WINDOW_NS};

const PAYLOAD: &str = r"C:\Users\u\AppData\Local\Temp\p.exe";
const MIN: u64 = 60_000_000_000;

fn windows_meta(pid: u32, comm: &str, timestamp_ns: u64) -> EventMeta {
    EventMeta {
        pid,
        timestamp_ns,
        comm: comm.into(),
        user: User::Windows {
            sid: "S-1-5-21-0-0-0-1000".into(),
            integrity_level: None,
        },
        ..meta()
    }
}

fn job(state: BitsJobState, timestamp_ns: u64) -> BitsJobEvent {
    BitsJobEvent {
        meta: windows_meta(6412, "bitsadmin.exe", timestamp_ns),
        job_id: "{c40080ab-6fe4-418a-8ba6-c271c5298f18}".into(),
        job_title: "update".into(),
        state,
        url: "https://example.test/payload.exe".into(),
        local_path: PAYLOAD.into(),
        ..schema::fixtures::bits_job()
    }
}

fn run(image_path: &str, timestamp_ns: u64) -> ExecEvent {
    ExecEvent {
        meta: windows_meta(4242, "p.exe", timestamp_ns),
        image_path: image_path.into(),
        ..schema::fixtures::exec()
    }
}

#[test]
fn executing_a_bits_downloaded_file_alerts() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::FileAdded, 0));
    state.on_bits_job(&job(BitsJobState::Completed, 2_000_000_000));
    let alerts = state.on_exec(&run(PAYLOAD, 5_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1197");
    let message = &alerts[0].message;
    assert!(message.contains("3.0s earlier"), "{message}");
    assert!(
        message.contains(r#"BITS job "update" of pid=6412 comm=bitsadmin.exe"#),
        "{message}"
    );
    assert!(
        message.contains("url: https://example.test/payload.exe"),
        "{message}"
    );
}

#[test]
fn the_window_runs_from_the_completion() {
    // A slow transfer: the file only exists once the job completes.
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::FileAdded, 0));
    state.on_bits_job(&job(BitsJobState::Completed, 30 * MIN));
    assert_eq!(state.on_exec(&run(PAYLOAD, 35 * MIN)).len(), 1);
}

#[test]
fn exec_past_the_window_stays_silent() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::Completed, 0));
    assert!(
        state
            .on_exec(&run(PAYLOAD, BITS_EXEC_WINDOW_NS + 1))
            .is_empty()
    );
}

#[test]
fn rerunning_the_download_alerts_once() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::Completed, 0));
    assert_eq!(state.on_exec(&run(PAYLOAD, 1)).len(), 1);
    assert!(state.on_exec(&run(PAYLOAD, 2)).is_empty());
}

#[test]
fn a_late_completion_record_does_not_rearm_an_alerted_download() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::FileAdded, 0));
    assert_eq!(state.on_exec(&run(PAYLOAD, 1)).len(), 1);
    state.on_bits_job(&job(BitsJobState::Completed, 2));
    assert!(state.on_exec(&run(PAYLOAD, 3)).is_empty());
}

#[test]
fn a_new_job_for_the_same_path_rearms_it() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::Completed, 0));
    assert_eq!(state.on_exec(&run(PAYLOAD, 1)).len(), 1);
    state.on_bits_job(&job(BitsJobState::FileAdded, 2));
    assert_eq!(state.on_exec(&run(PAYLOAD, 3)).len(), 1);
}

#[test]
fn a_cancelled_job_leaves_nothing_to_join() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::FileAdded, 0));
    state.on_bits_job(&job(BitsJobState::Cancelled, 1));
    assert!(state.on_exec(&run(PAYLOAD, 2)).is_empty());
}

#[test]
fn a_transfer_error_keeps_the_download_pending() {
    // BITS retries on its own; the retried transfer completes the same file.
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::FileAdded, 0));
    state.on_bits_job(&job(BitsJobState::TransferError, 1));
    assert_eq!(state.on_exec(&run(PAYLOAD, 2)).len(), 1);
}

#[test]
fn the_path_join_ignores_case() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::Completed, 0));
    assert_eq!(
        state
            .on_exec(&run(r"c:\users\U\appdata\local\temp\P.EXE", 1))
            .len(),
        1
    );
}

#[test]
fn another_file_does_not_join() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::Completed, 0));
    assert!(
        state
            .on_exec(&run(r"C:\Windows\System32\whoami.exe", 1))
            .is_empty()
    );
}

fn job_b(state: BitsJobState, timestamp_ns: u64) -> BitsJobEvent {
    BitsJobEvent {
        job_id: "{0000000b-0000-0000-0000-000000000000}".into(),
        url: "https://example.test/decoy".into(),
        ..job(state, timestamp_ns)
    }
}

#[test]
fn cancelling_another_job_for_the_same_path_keeps_the_payload_armed() {
    // #577 review: job A downloads the payload, job B targets the same path
    // and is cancelled. BITS only discards B's temporary file.
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::FileAdded, 0));
    state.on_bits_job(&job(BitsJobState::Completed, 1));
    state.on_bits_job(&job_b(BitsJobState::FileAdded, 2));
    state.on_bits_job(&job_b(BitsJobState::Cancelled, 3));
    let alerts = state.on_exec(&run(PAYLOAD, 4));
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0]
            .message
            .contains("url: https://example.test/payload.exe"),
        "the completed download keeps its attribution: {}",
        alerts[0].message
    );
}

#[test]
fn cancelling_a_partial_download_of_another_pending_job_keeps_the_newer_one() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::FileAdded, 0));
    state.on_bits_job(&job_b(BitsJobState::FileAdded, 1));
    state.on_bits_job(&job(BitsJobState::Cancelled, 2));
    assert_eq!(state.on_exec(&run(PAYLOAD, 3)).len(), 1);
}

#[test]
fn another_jobs_completion_over_an_alerted_download_alerts_again() {
    let mut state = RuleState::new();
    state.on_bits_job(&job(BitsJobState::Completed, 0));
    assert_eq!(state.on_exec(&run(PAYLOAD, 1)).len(), 1);
    state.on_bits_job(&job_b(BitsJobState::Completed, 2));
    assert_eq!(state.on_exec(&run(PAYLOAD, 3)).len(), 1);
}
