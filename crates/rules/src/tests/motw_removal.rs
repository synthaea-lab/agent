//! T1553.005 — a file whose mark-of-the-web was removed (`FileDelete` of its
//! `:Zone.Identifier` stream: `Unblock-File`, `Remove-Item -Stream`) executed
//! within the window (#442).

use schema::{EventMeta, ExecEvent, FileDeleteEvent, FileQuarantineEvent, User};

use super::meta;
use crate::{RuleState, exclusions::QUARANTINE_EXEC_WINDOW_NS};

const DOWNLOAD: &str = r"C:\Users\u\Downloads\invoice.exe";

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

fn delete(meta: EventMeta, path: &str) -> FileDeleteEvent {
    let mut event = schema::fixtures::file_delete();
    event.meta = meta;
    event.path = path.into();
    event
}

fn unblock(stream_path: &str, timestamp_ns: u64) -> FileDeleteEvent {
    delete(
        windows_meta(777, "powershell.exe", timestamp_ns),
        stream_path,
    )
}

fn run(image_path: &str, timestamp_ns: u64) -> ExecEvent {
    ExecEvent {
        meta: windows_meta(4242, "invoice.exe", timestamp_ns),
        image_path: image_path.into(),
        ..schema::fixtures::exec()
    }
}

fn stream(host: &str) -> String {
    format!("{host}:Zone.Identifier")
}

#[test]
fn executing_a_file_after_its_mark_was_removed_alerts() {
    let mut state = RuleState::new();
    assert!(
        state
            .on_file_delete(&unblock(&stream(DOWNLOAD), 0))
            .is_empty()
    );
    let alerts = state.on_exec(&run(DOWNLOAD, 30_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1553.005");
    let message = &alerts[0].message;
    assert!(
        message.contains("removed by pid=777 comm=powershell.exe"),
        "{message}"
    );
    assert!(message.contains("30.0s"), "{message}");
    assert!(message.contains("origin: unrecorded"), "{message}");
}

#[test]
fn removing_a_mark_alone_does_not_alert() {
    // `Unblock-File` over a downloaded module tree is routine.
    let mut state = RuleState::new();
    for i in 0..50 {
        let host = format!(r"C:\Users\u\Documents\WindowsPowerShell\Modules\M\f{i}.ps1");
        assert!(state.on_file_delete(&unblock(&stream(&host), i)).is_empty());
    }
}

#[test]
fn the_data_stream_type_suffix_and_case_are_ignored() {
    let mut state = RuleState::new();
    state.on_file_delete(&unblock(
        r"c:\users\u\downloads\INVOICE.EXE:zone.identifier:$DATA",
        0,
    ));
    assert_eq!(state.on_exec(&run(DOWNLOAD, 1)).len(), 1);
}

#[test]
fn the_origin_url_is_quoted_when_the_mark_was_seen() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&FileQuarantineEvent {
        meta: windows_meta(10, "msedge.exe", 0),
        path: DOWNLOAD.into(),
        origin_url: Some("https://example.test/invoice.exe".into()),
        ..schema::fixtures::file_quarantine()
    });
    state.on_file_delete(&unblock(&stream(DOWNLOAD), 1));
    let alerts = state.on_exec(&run(DOWNLOAD, 2));
    // Marked, then unmarked, then run: both techniques, one alert each.
    let techniques: Vec<_> = alerts.iter().map(|a| a.technique).collect();
    assert_eq!(techniques, ["T1204.002", "T1553.005"]);
    assert!(
        alerts[1]
            .message
            .contains("origin: https://example.test/invoice.exe")
    );
}

#[test]
fn exec_past_the_window_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_delete(&unblock(&stream(DOWNLOAD), 0));
    assert!(
        state
            .on_exec(&run(DOWNLOAD, QUARANTINE_EXEC_WINDOW_NS + 1))
            .is_empty()
    );
}

#[test]
fn rerunning_the_unblocked_file_alerts_once() {
    let mut state = RuleState::new();
    state.on_file_delete(&unblock(&stream(DOWNLOAD), 0));
    assert_eq!(state.on_exec(&run(DOWNLOAD, 1)).len(), 1);
    assert!(state.on_exec(&run(DOWNLOAD, 2)).is_empty());
}

#[test]
fn deleting_the_file_itself_or_another_stream_is_not_a_mark_removal() {
    let mut state = RuleState::new();
    for path in [
        DOWNLOAD.to_string(),
        format!("{DOWNLOAD}:SmartScreen"),
        ":Zone.Identifier".to_string(),
        r"C:\Users\u\Downloads\:Zone.Identifier".to_string(),
    ] {
        state.on_file_delete(&unblock(&path, 0));
    }
    assert!(state.on_exec(&run(DOWNLOAD, 1)).is_empty());
}

#[test]
fn a_unix_delete_named_like_a_stream_is_ignored() {
    let mut state = RuleState::new();
    state.on_file_delete(&delete(meta(), "/tmp/x:Zone.Identifier"));
    assert!(
        state
            .on_exec(&ExecEvent {
                meta: meta(),
                image_path: "/tmp/x".into(),
                ..schema::fixtures::exec()
            })
            .is_empty()
    );
}
