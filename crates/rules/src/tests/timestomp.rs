//! T1070.006 — explicit file timestamp requests (Windows minifilter, Linux `inode_setattr`).

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
fn explicit_time_set_is_low_without_a_process_name_exclusion() {
    let mut event = event();
    event.meta.comm = "vssadmin.exe".into();
    let alerts = evaluate_file_set_time(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1070.006");
    assert_eq!(alerts[0].severity, Severity::Low);
    assert!(alerts[0].message.contains(&event.path));
    assert!(!alerts[0].message.contains("vssadmin"));
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

/// Linux (#1036): the `inode_setattr` hook reports a Unix process with a real `comm`, and
/// only the times the caller chose are set.
fn linux_event(comm: &str) -> FileSetTimeEvent {
    FileSetTimeEvent {
        meta: EventMeta {
            pid: 4242,
            user: User::Unix { uid: 0, gid: 0 },
            comm: comm.into(),
            ..schema::fixtures::meta()
        },
        path: "/var/log/auth.log".into(),
        creation_time: None,
        last_access_time: None,
        last_write_time: Some(129_067_776_000_000_000),
        change_time: None,
    }
}

#[test]
fn linux_explicit_mtime_alerts_low_and_names_the_process() {
    let alerts = evaluate_file_set_time(&linux_event("touch"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1070.006");
    assert_eq!(alerts[0].severity, Severity::Low);
    assert!(
        alerts[0].message.contains("comm=touch"),
        "{}",
        alerts[0].message
    );
    assert!(alerts[0].message.contains("/var/log/auth.log"));
}

#[test]
fn linux_package_managers_unpacking_files_do_not_alert() {
    for comm in ["rpm", "dpkg", "dnf", "apt-get", "pacman", "unattended-upgr"] {
        assert!(
            evaluate_file_set_time(&linux_event(comm)).is_empty(),
            "{comm}"
        );
    }
}

#[test]
fn linux_a_process_that_only_looks_like_a_package_manager_still_alerts() {
    // Exact `comm` match, not a prefix or substring.
    for comm in ["rpmbuild-evil", "dnf.sh", "ndpkg", ""] {
        assert_eq!(
            evaluate_file_set_time(&linux_event(comm)).len(),
            1,
            "{comm:?}"
        );
    }
}

#[test]
fn linux_a_request_with_no_chosen_time_does_not_alert() {
    let mut event = linux_event("touch");
    event.last_write_time = None;
    assert!(evaluate_file_set_time(&event).is_empty());
}
