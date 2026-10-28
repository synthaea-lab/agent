//! T1070.006 — explicit Windows file timestamp requests.

use schema::{EventMeta, FileSetTimeEvent, User, detection::Severity};

use crate::evaluate_file_set_time;

fn event() -> FileSetTimeEvent {
    FileSetTimeEvent {
        meta: EventMeta {
            pid: 42,
            user: User::Windows {
                sid: String::new(),
                integrity_level: None,
            },
            comm: String::new(),
            ..schema::fixtures::meta()
        },
        path: r"C:\Users\u\invoice.docx".into(),
        last_write_time: Some(132_537_600_000_000_000),
        ..schema::fixtures::file_set_time()
    }
}

#[test]
fn explicit_time_set_is_medium_without_a_process_name_exclusion() {
    let mut event = event();
    event.meta.comm = "vssadmin.exe".into();
    let alerts = evaluate_file_set_time(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1070.006");
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert!(alerts[0].message.contains(&event.path));
}

#[test]
fn unchanged_and_automatic_timestamp_fields_do_not_alert() {
    for time in [0, -1, -2] {
        let mut event = event();
        event.creation_time = Some(time);
        event.last_write_time = None;
        assert!(evaluate_file_set_time(&event).is_empty(), "time {time}");
    }
}

#[test]
fn any_explicit_timestamp_field_alerts() {
    for field in 0..4 {
        let mut event = event();
        event.creation_time = None;
        event.last_access_time = None;
        event.last_write_time = None;
        event.change_time = None;
        match field {
            0 => event.creation_time = Some(1),
            1 => event.last_access_time = Some(1),
            2 => event.last_write_time = Some(1),
            _ => event.change_time = Some(1),
        }
        assert_eq!(evaluate_file_set_time(&event).len(), 1, "field {field}");
    }
}
