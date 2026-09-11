//! Sink tests. The hostile-string cases carry over from the old `jsonl.rs` tests:
//! a process can rename itself arbitrarily (`prctl(PR_SET_NAME, ...)` on Linux), so
//! comm/cmdline containing quotes, backslashes, or control bytes must still produce
//! valid JSON lines — `serde_json`'s job now, asserted here rather than assumed.

use schema::{Event, EventMeta, ExecEvent, FileOpenEvent, User, sensor::EventSink};

use super::*;

fn exec_event(comm: &str, cmdline: &str) -> Event {
    Event::Exec(ExecEvent {
        meta: EventMeta {
            pid: 1234,
            ppid: 1,
            user: User::Unix { uid: 0, gid: 0 },
            timestamp_ns: 42,
            comm: comm.to_string(),
            container: None,
        },
        image_path: String::new(),
        cmdline: cmdline.to_string(),
        argv: vec![],
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
    })
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn events_round_trip_through_the_file() {
    let dir = std::env::temp_dir().join(format!("sinks-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let _ = std::fs::remove_file(&path);

    let sink = JsonlEventSink::open(&path).unwrap();
    let events = [
        exec_event("bash", "curl -o /tmp/x https://example.test/x"),
        Event::FileOpen(FileOpenEvent {
            meta: EventMeta {
                pid: 1,
                ppid: 0,
                user: User::Unknown,
                timestamp_ns: 43,
                comm: "cron".into(),
                container: None,
            },
            path: "/etc/cron.d/job".into(),
            flags: 0o101,
        }),
    ];
    for e in &events {
        sink.on_event(e.clone());
    }
    assert_eq!(sink.count(), 2);

    let lines = read_lines(&path);
    assert_eq!(lines.len(), 2);
    for (line, original) in lines.iter().zip(&events) {
        let back: Event = serde_json::from_str(line).unwrap();
        assert_eq!(&back, original);
    }
}

#[test]
fn hostile_comm_and_cmdline_stay_valid_json() {
    // prctl-renamed comm with a quote; cmdline with NUL argv separators and an ANSI
    // escape — all must parse back with a strict JSON parser, unchanged.
    let cases = [
        exec_event(r#"evil"name"#, "ls\0-la"),
        exec_event("a\\b", "a\tb\rc\n\x1b[0m"),
    ];
    for event in cases {
        let line = serde_json::to_string(&event).unwrap();
        assert!(!line.contains('\n'), "one line per event: {line:?}");
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back, event);
    }
}

#[test]
fn writer_appends_across_reopens() {
    let dir = std::env::temp_dir().join(format!("sinks-test-append-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("alerts.ndjson");
    let _ = std::fs::remove_file(&path);

    let record = |n: u64| AlertRecord {
        timestamp_ns: n,
        technique: "T1105".into(),
        message: "test".into(),
    };
    {
        let w = JsonlWriter::open(&path).unwrap();
        w.write(&record(1));
    }
    {
        let w = JsonlWriter::open(&path).unwrap();
        w.write(&record(2));
    }
    let lines = read_lines(&path);
    assert_eq!(lines.len(), 2, "append mode must not truncate");
    let last: AlertRecord = serde_json::from_str(&lines[1]).unwrap();
    assert_eq!(last.timestamp_ns, 2);
}

#[test]
fn torn_tail_is_repaired_on_reopen() {
    // A crash mid-write leaves a line without its newline; reopening must not fuse
    // the next record onto it.
    let path = std::env::temp_dir().join(format!("sinks-torn-{}.ndjson", std::process::id()));
    std::fs::write(&path, b"{\"torn\":tru").unwrap();
    let w = JsonlWriter::open(&path).unwrap();
    w.write(&serde_json::json!({"ok": 1}));
    drop(w);
    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "torn tail and new record must be separate lines"
    );
    assert!(serde_json::from_str::<serde_json::Value>(lines[1]).is_ok());
    std::fs::remove_file(&path).ok();
}
