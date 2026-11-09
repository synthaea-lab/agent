//! #1129: a process can put any bit in the `flags` it passes to `open`/`openat` (the kernel ignores
//! the unknown ones) and the probe reads them unfiltered. The Linux normalizer masks them to the real
//! open(2) flags, so none of the synthetic `FLAG_*` bits that the rules read as a sensor's own can
//! come from a process. This test is here, not in `sensor-linux`, because it needs both the
//! normalizer and `rules`, and a sensor crate may depend only on `schema`.
#![cfg(target_os = "linux")]

use schema::{Event, O_RDWR, SYNTHETIC_FLAGS};
use sensor_linux::normalize::file_open;
use sensor_linux_wire as wire;

fn probe_open(flags: u32, path: &[u8]) -> schema::FileOpenEvent {
    let mut comm = [0u8; wire::TASK_COMM_LEN];
    comm[..5].copy_from_slice(b"forge");
    let mut buf = [0u8; wire::MAX_PATH_LEN];
    buf[..path.len()].copy_from_slice(path);
    let event = wire::FileOpenEvent {
        meta: wire::EventMeta {
            pid: 42,
            ppid: 7,
            uid: 1000,
            gid: 1000,
            timestamp_ns: 1_000,
            comm,
            cgroup_id: 0,
            process_generation: 0,
            parent_generation: 0,
        },
        path: buf,
        path_len: path.len() as u16,
        flags,
    };
    let Event::FileOpen(e) = file_open(&event, 0, None) else {
        panic!("wrong variant")
    };
    e
}

#[test]
fn a_probe_open_with_a_synthetic_bit_raises_no_alert() {
    for flag in SYNTHETIC_FLAGS {
        for path in [&b"/etc/hostname"[..], &b"/tmp/forge-persist"[..]] {
            let e = probe_open(flag | O_RDWR, path);
            assert_eq!(e.flags & flag, 0, "{flag:#x} survived the normalizer");
            let alerts = rules::evaluate_file_open(&e);
            assert!(
                alerts.is_empty(),
                "forged {flag:#x} on {} raised {alerts:?}",
                e.path
            );
        }
    }
}

#[test]
fn every_synthetic_bit_together_raises_no_alert() {
    let all = SYNTHETIC_FLAGS.iter().fold(0, |a, f| a | f);
    let e = probe_open(all | O_RDWR, b"/etc/hostname");
    assert_eq!(e.flags, O_RDWR);
    assert!(rules::evaluate_file_open(&e).is_empty());
}
