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
