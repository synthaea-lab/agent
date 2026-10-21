//! T1564.004 — Hide Artifacts: NTFS File Attributes. A write-intent open on an
//! alternate data stream (#136 ADS slice 1).

use schema::{EventMeta, FileOpenEvent, O_CREAT, O_WRONLY, User};

use crate::check_alternate_data_stream_write;

fn open(path: &str, flags: u32) -> FileOpenEvent {
    let mut event = FileOpenEvent {
        path: path.into(),
        flags,
        ..schema::fixtures::file_open()
    };
    event.meta.user = User::Windows {
        sid: "S-1-5-21-0-0-0-1000".into(),
        integrity_level: None,
    };
    event
}

fn unix_open(path: &str, flags: u32) -> FileOpenEvent {
    FileOpenEvent {
        meta: EventMeta {
            user: User::Unix {
                uid: 1000,
                gid: 1000,
            },
            ..schema::fixtures::file_open().meta
        },
        path: path.into(),
        flags,
    }
}

#[test]
fn writing_a_named_stream_alerts() {
    let alert = check_alternate_data_stream_write(&open(r"C:\Users\u\notes.txt:hidden", O_WRONLY))
        .expect("named stream write should alert");
    assert_eq!(alert.technique, "T1564.004");
    assert_eq!(alert.severity, schema::detection::Severity::Medium);
    assert!(alert.message.contains("\"hidden\""), "{}", alert.message);
    assert!(alert.message.contains("notes.txt"), "{}", alert.message);
}

#[test]
fn creating_a_named_stream_alerts() {
    assert!(
        check_alternate_data_stream_write(&open(
            r"C:\ProgramData\svc.dat:payload",
            O_WRONLY | O_CREAT
        ))
        .is_some()
    );
}

#[test]
fn a_zone_identifier_write_does_not_alert() {
    // Every browser/mail client/Explorer marks a download this way — #365/#439
    // already track this stream specifically; it is not a new signal here.
    assert!(
        check_alternate_data_stream_write(&open(
            r"C:\Users\u\Downloads\invoice.exe:Zone.Identifier",
            O_WRONLY | O_CREAT,
        ))
        .is_none()
    );
}

#[test]
fn the_zone_identifier_exclusion_is_case_insensitive_and_ignores_the_type_tag() {
    assert!(
        check_alternate_data_stream_write(&open(
            r"c:\users\u\downloads\invoice.exe:zone.identifier:$DATA",
            O_WRONLY,
        ))
        .is_none()
    );
}

#[test]
fn a_unix_colon_in_a_file_name_does_not_alert() {
    // A colon is ordinary in a Linux/macOS file name (a timestamp, a log
    // name) and must not be read as an NTFS stream on a host that has none
    // (#943 review).
    for path in [
        "/tmp/backup-2026-10-21T10:30:00.tar.gz",
        "/tmp/build:cache",
        "/var/log/app:error.log",
    ] {
        assert!(
            check_alternate_data_stream_write(&unix_open(path, O_WRONLY | O_CREAT)).is_none(),
            "{path}"
        );
    }
}

#[test]
fn the_files_own_unnamed_stream_opened_explicitly_does_not_alert() {
    // `file.txt::$DATA` names the file's own default stream, not a hidden
    // one — the colon here is a type-tag separator with an empty stream
    // name, not a real stream (#943 review).
    assert!(
        check_alternate_data_stream_write(&open(r"C:\Temp\file.txt::$DATA", O_WRONLY)).is_none()
    );
}

#[test]
fn a_plain_file_write_does_not_alert() {
    assert!(check_alternate_data_stream_write(&open(r"C:\Temp\plain.txt", O_WRONLY)).is_none());
}

#[test]
fn a_read_only_open_does_not_alert_even_with_a_stream_path() {
    // The sensor itself never emits a read-only open as a `FileOpenEvent`
    // (`flags == 0` is filtered before dispatch), but the check stays correct
    // on its own in case a future caller ever passes one through directly.
    assert!(check_alternate_data_stream_write(&open(r"C:\Temp\f.txt:odd", 0)).is_none());
}

#[test]
fn a_bare_stream_with_no_base_name_does_not_alert() {
    // Same malformed shapes `motw_removal` already treats as not a real stream.
    for path in [
        r":odd".to_string(),
        r"C:\Users\u\Downloads\:odd".to_string(),
    ] {
        assert!(
            check_alternate_data_stream_write(&open(&path, O_WRONLY)).is_none(),
            "{path}"
        );
    }
}

#[test]
fn a_trailing_colon_with_nothing_after_it_does_not_alert() {
    assert!(check_alternate_data_stream_write(&open(r"C:\Temp\f.txt:", O_WRONLY)).is_none());
}

#[test]
fn the_drive_letter_colon_alone_is_not_a_stream() {
    assert!(check_alternate_data_stream_write(&open(r"C:\Temp\plain.txt", O_WRONLY)).is_none());
}
