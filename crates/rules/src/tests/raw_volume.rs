//! T1006 — mounted raw-volume opens.

use schema::{EventMeta, RawVolumeOpenEvent, User, detection::Severity};

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
    // #1007 review (SherlockOmss): the mask used to only cover FILE_WRITE_DATA,
    // FILE_APPEND_DATA, GENERIC_WRITE and GENERIC_ALL, so FILE_WRITE_EA,
    // FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC and WRITE_OWNER each alerted on
    // nothing even though every one of them can modify the volume or its own
    // protection.
    for mask in [
        0x0000_0002, // FILE_WRITE_DATA
        0x0000_0004, // FILE_APPEND_DATA
        0x0000_0010, // FILE_WRITE_EA
        0x0000_0100, // FILE_WRITE_ATTRIBUTES
        0x0001_0000, // DELETE
        0x0004_0000, // WRITE_DAC
        0x0008_0000, // WRITE_OWNER
        0x4000_0000, // GENERIC_WRITE
        0x1000_0000, // GENERIC_ALL
    ] {
        let alerts = evaluate_raw_volume_open(&event(mask));
        assert_eq!(alerts.len(), 1, "mask {mask:#010x}");
        assert_eq!(alerts[0].severity, Severity::Medium, "mask {mask:#010x}");
    }
}

#[test]
fn maximum_allowed_is_medium_not_low() {
    // #1007 review (SherlockOmss): MAXIMUM_ALLOWED resolves to whatever the
    // caller's token grants, and a caller able to open a raw volume at all
    // already needs an elevated privilege -- bucketing it with plain read
    // capabilities as Low understated it.
    let alerts = evaluate_raw_volume_open(&event(0x0200_0000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::Medium);
}

#[test]
fn pure_read_capability_is_low() {
    for mask in [0x0000_0001, 0x8000_0000] {
        let alerts = evaluate_raw_volume_open(&event(mask));
        assert_eq!(alerts.len(), 1, "mask {mask:#010x}");
        assert_eq!(alerts[0].severity, Severity::Low, "mask {mask:#010x}");
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
