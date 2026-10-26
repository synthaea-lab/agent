//! T1006 — mounted raw-volume opens.

use schema::{RawVolumeOpenEvent, User, detection::Severity};

use crate::evaluate_raw_volume_open;

fn event(desired_access: u32) -> RawVolumeOpenEvent {
    RawVolumeOpenEvent {
        meta: EventMeta {
            pid: 42,
            user: User::Unknown,
            comm: String::new(),
            ..schema::fixtures::meta()
        },
        volume: r"\Device\HarddiskVolume3".into(),
        desired_access,
    }
}

use schema::EventMeta;

#[test]
fn write_capable_volume_open_is_medium_and_preserves_requested_mask() {
    let mut event = event(0x0000_0002);
    event.meta.comm = "vssadmin.exe".into();
    let alerts = evaluate_raw_volume_open(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1006");
    assert_eq!(alerts[0].severity, Severity::Medium);
    assert!(alerts[0].message.contains(&event.volume));
    assert!(alerts[0].message.contains("0x00000002"));
}

#[test]
fn each_explicit_write_capability_is_medium() {
    for mask in [0x0000_0002, 0x0000_0004, 0x4000_0000, 0x1000_0000] {
        let alerts = evaluate_raw_volume_open(&event(mask));
        assert_eq!(alerts.len(), 1, "mask {mask:#010x}");
        assert_eq!(alerts[0].severity, Severity::Medium);
    }
}

#[test]
fn read_capability_and_maximum_allowed_are_low() {
    for mask in [0x0000_0001, 0x8000_0000, 0x0200_0000] {
        let alerts = evaluate_raw_volume_open(&event(mask));
        assert_eq!(alerts.len(), 1, "mask {mask:#010x}");
        assert_eq!(alerts[0].severity, Severity::Low);
    }
}

#[test]
fn metadata_only_access_does_not_alert() {
    for mask in [0, 0x0000_0080, 0x0002_0000, 0x0010_0000] {
        assert!(
            evaluate_raw_volume_open(&event(mask)).is_empty(),
            "mask {mask:#010x}"
        );
    }
}
