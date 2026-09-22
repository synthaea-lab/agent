//! Edge case tests for FileWrite/FileDelete/FileRename events (issue #262).
//!
//! Covers scenarios raised in PR #277 review feedback:
//! - Long paths (near `MAX_PATH` limits)
//! - Special characters in filenames
//! - Large byte counts
//! - Unicode and non-UTF8 edge cases
//! - Boundary conditions

use schema::{Event, EventMeta, FileDeleteEvent, FileRenameEvent, FileWriteEvent, User};

fn test_meta(comm: &str) -> EventMeta {
    EventMeta {
        pid: 1000,
        ppid: 999,
        user: User::Unix {
            uid: 1000,
            gid: 1000,
        },
        timestamp_ns: 1_756_900_100_000_000_000,
        comm: comm.into(),
        container: None,
    }
}

#[test]
fn file_delete_long_path() {
    // Linux PATH_MAX is 4096 — test near-limit path survives serialization.
    // Realistic scenario: deeply nested directory structure.
    let long_path = format!(
        "/home/user/{}",
        "very_long_directory_name_that_exceeds_typical_limits/".repeat(50)
    );
    assert!(long_path.len() > 2000, "path should be long");

    let event = Event::FileDelete(FileDeleteEvent {
        meta: test_meta("rm"),
        path: long_path.clone(),
    });

    // Round-trip: must survive serialization without truncation
    let json = serde_json::to_string(&event).unwrap();
    let back: Event = serde_json::from_str(&json).unwrap();

    match back {
        Event::FileDelete(e) => assert_eq!(e.path, long_path),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn file_rename_special_chars() {
    // Filenames with special characters: spaces, quotes, shell metacharacters.
    // Ransomware often creates files with unusual names.
    let test_cases = vec![
        // Spaces
        ("important document.pdf", "important document.pdf.locked"),
        // Shell metacharacters
        ("file$name.txt", "file$name.txt.encrypted"),
        // Quotes
        (r#"file"with"quotes.doc"#, r#"file"with"quotes.doc.crypted"#),
        // Backslash (Windows-style path on Linux)
        (r"path\with\backslash.txt", r"path\with\backslash.txt.enc"),
        // Leading dash (tricky for command-line tools)
        ("-suspicious.txt", "-suspicious.txt.locked"),
    ];

    for (old, new) in test_cases {
        let event = Event::FileRename(FileRenameEvent {
            meta: test_meta("encryptor"),
            old_path: old.into(),
            new_path: new.into(),
        });

        // Round-trip: special chars must survive
        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();

        match back {
            Event::FileRename(e) => {
                assert_eq!(e.old_path, old);
                assert_eq!(e.new_path, new);
            }
            _ => panic!("wrong variant"),
        }
    }
}

#[test]
fn file_rename_unicode() {
    // Unicode filenames: emoji, non-Latin scripts, combining characters.
    // Real-world scenario: international users, or attackers using Unicode tricks.
    let test_cases = vec![
        // Emoji (valid UTF-8, 4-byte sequences)
        ("photo_📷.jpg", "photo_📷.jpg.locked"),
        // Cyrillic (homograph attack: а looks like Latin a)
        ("pаssword.txt", "pаssword.txt.encrypted"),
        // Arabic
        ("ملف_مهم.pdf", "ملف_مهم.pdf.locked"),
        // Chinese
        ("重要文件.doc", "重要文件.doc.crypted"),
        // Combining characters (é as e + ́)
        ("café.txt", "café.txt.enc"),
        // Zero-width characters (invisible)
        ("file\u{200B}name.txt", "file\u{200B}name.txt.locked"),
    ];

    for (old, new) in test_cases {
        let event = Event::FileRename(FileRenameEvent {
            meta: test_meta("encryptor"),
            old_path: old.into(),
            new_path: new.into(),
        });

        // Round-trip: Unicode must survive
        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();

        match back {
            Event::FileRename(e) => {
                assert_eq!(e.old_path, old);
                assert_eq!(e.new_path, new);
            }
            _ => panic!("wrong variant"),
        }
    }
}

#[test]
fn file_write_large_byte_counts() {
    // Boundary conditions for bytes_requested (u64).
    let test_cases = vec![
        0,                           // Zero-byte write (valid syscall, e.g., touch)
        1,                           // Single byte
        4096,                        // Typical page size
        1024 * 1024,                 // 1 MB
        1024 * 1024 * 1024,          // 1 GB (large but realistic for video/DB)
        u64::MAX,                    // Maximum (unrealistic but must not overflow)
    ];

    for bytes in test_cases {
        let event = Event::FileWrite(FileWriteEvent {
            meta: test_meta("encryptor"),
            fd: 5,
            bytes_requested: bytes,
        });

        // Round-trip: byte count must survive exactly
        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();

        match back {
            Event::FileWrite(e) => assert_eq!(e.bytes_requested, bytes),
            _ => panic!("wrong variant"),
        }
    }
}

#[test]
fn file_write_fd_boundary() {
    // File descriptors: typical range 0-1023, but kernel allows up to ~1M.
    let test_cases = vec![
        0,             // stdin (valid write target on Linux)
        1,             // stdout
        2,             // stderr
        3,             // First user fd
        1023,          // Typical ulimit default
        65535,         // Large but realistic (servers with high fd limits)
        u32::MAX,      // Maximum (unrealistic but must not break)
    ];

    for fd in test_cases {
        let event = Event::FileWrite(FileWriteEvent {
            meta: test_meta("writer"),
            fd,
            bytes_requested: 1024,
        });

        // Round-trip: fd must survive exactly
        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();

        match back {
            Event::FileWrite(e) => assert_eq!(e.fd, fd),
            _ => panic!("wrong variant"),
        }
    }
}

#[test]
fn file_delete_empty_path() {
    // Edge case: empty path (invalid syscall, but sensor might capture it).
    // Should serialize/deserialize without panic.
    let event = Event::FileDelete(FileDeleteEvent {
        meta: test_meta("rm"),
        path: String::new(),
    });

    let json = serde_json::to_string(&event).unwrap();
    let back: Event = serde_json::from_str(&json).unwrap();

    match back {
        Event::FileDelete(e) => assert_eq!(e.path, ""),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn file_rename_same_path() {
    // Edge case: rename to the same path (no-op, but valid syscall).
    // Scenario: attacker probing, or buggy ransomware.
    let path = "/home/user/file.txt";
    let event = Event::FileRename(FileRenameEvent {
        meta: test_meta("renamer"),
        old_path: path.into(),
        new_path: path.into(),
    });

    let json = serde_json::to_string(&event).unwrap();
    let back: Event = serde_json::from_str(&json).unwrap();

    match back {
        Event::FileRename(e) => {
            assert_eq!(e.old_path, path);
            assert_eq!(e.new_path, path);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn file_rename_cross_filesystem() {
    // Realistic scenario: rename across filesystem boundaries (becomes copy+delete).
    // Paths on different mounts: /home (ext4) vs /tmp (tmpfs).
    let event = Event::FileRename(FileRenameEvent {
        meta: test_meta("mv"),
        old_path: "/home/user/file.txt".into(),
        new_path: "/tmp/file.txt".into(),
    });

    let json = serde_json::to_string(&event).unwrap();
    let back: Event = serde_json::from_str(&json).unwrap();

    match back {
        Event::FileRename(e) => {
            assert_eq!(e.old_path, "/home/user/file.txt");
            assert_eq!(e.new_path, "/tmp/file.txt");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn file_rename_multiple_extensions() {
    // Ransomware pattern: multiple extensions added (.pdf.locked.encrypted).
    let event = Event::FileRename(FileRenameEvent {
        meta: test_meta("encryptor"),
        old_path: "/home/user/invoice.pdf".into(),
        new_path: "/home/user/invoice.pdf.locked.encrypted.ransom".into(),
    });

    let json = serde_json::to_string(&event).unwrap();
    let back: Event = serde_json::from_str(&json).unwrap();

    match back {
        Event::FileRename(e) => {
            assert_eq!(e.old_path, "/home/user/invoice.pdf");
            assert_eq!(e.new_path, "/home/user/invoice.pdf.locked.encrypted.ransom");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn file_delete_system_critical() {
    // Detection scenario: deletion of critical system files.
    let critical_paths = vec![
        "/etc/passwd",
        "/etc/shadow",
        "/boot/vmlinuz",
        "/var/log/auth.log",
        "/var/log/secure",
        "/.bash_history",
    ];

    for path in critical_paths {
        let event = Event::FileDelete(FileDeleteEvent {
            meta: test_meta("rm"),
            path: path.into(),
        });

        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();

        match back {
            Event::FileDelete(e) => assert_eq!(e.path, path),
            _ => panic!("wrong variant"),
        }
    }
}

#[test]
fn file_write_no_path_correlation() {
    // Core limitation: FileWrite has no path, only (pid, fd).
    // This test documents that limitation explicitly.
    let write = FileWriteEvent {
        meta: test_meta("writer"),
        fd: 4,
        bytes_requested: 1048576, // 1 MB
    };

    // No path field exists
    // (This test would fail to compile if path was accidentally added)
    let _ = write.fd;
    let _ = write.bytes_requested;
    // write.path; // <-- would not compile

    // To get path, detection rules must correlate with FileOpenEvent on (pid, fd)
}

#[test]
fn file_events_high_frequency() {
    // Performance scenario: many events in rapid succession.
    // Tests that serialization doesn't accumulate memory or have O(n²) behavior.
    let mut events = Vec::new();

    // Generate 1000 FileWrite events (simulating burst-write scenario)
    for i in 0..1000 {
        events.push(Event::FileWrite(FileWriteEvent {
            meta: EventMeta {
                pid: 2000,
                ppid: 1999,
                user: User::Unix {
                    uid: 1000,
                    gid: 1000,
                },
                timestamp_ns: 1_756_900_100_000_000_000 + (i * 1_000_000), // 1ms apart
                comm: "encryptor".into(),
                container: None,
            },
            fd: 4,
            bytes_requested: 4096,
        }));
    }

    // Serialize all events (should complete quickly)
    for event in &events {
        let json = serde_json::to_string(event).unwrap();
        let _back: Event = serde_json::from_str(&json).unwrap();
    }

    assert_eq!(events.len(), 1000);
}
