use super::*;
use crate::payload::test_fields::{Fields, Value, text_value, utf16};

const HKCU: &str = r"\REGISTRY\USER\S-1-5-21-1-2-3-1001";
const HKCU_OBJECT: u64 = 0xffff_c08a_0000_1000;
const RUN_OBJECT: u64 = 0xffff_c08a_0000_2000;
const REG_SZ: u32 = 1;

fn keys() -> RegistryKeys {
    RegistryKeys::new(64)
}

/// A successful EID 1/2 record of the manifest's template.
fn opened(key_object: u64, base_object: u64, base_name: &str, relative_name: &str) -> Fields {
    Fields::of(&[
        ("BaseObject", Value::Pointer(base_object)),
        ("KeyObject", Value::Pointer(key_object)),
        ("Status", Value::U32(0)),
        ("Disposition", Value::U32(1)),
        ("BaseName", text_value(base_name)),
        ("RelativeName", text_value(relative_name)),
    ])
}

fn closed(key_object: u64) -> Fields {
    Fields::of(&[
        ("KeyObject", Value::Pointer(key_object)),
        ("Status", Value::U32(0)),
        ("KeyName", text_value("")),
    ])
}

/// An EID 5 record as a live Windows 11 26300 session delivers it: no `KeyName`, no data.
fn written(key_object: u64) -> Fields {
    Fields::of(&[
        ("KeyObject", Value::Pointer(key_object)),
        ("Status", Value::U32(0)),
        ("Type", Value::U32(REG_SZ)),
        ("KeyName", text_value("")),
        ("ValueName", text_value("updater")),
        ("CapturedData", Value::Bytes(Vec::new())),
    ])
}

fn path_of_write(keys: &mut RegistryKeys, key_object: u64) -> Option<String> {
    keys.on_record(RegistryOperation::SetValue, &written(key_object))
        .map(|keyed| keyed.key_path)
}

#[test]
fn the_event_id_filter_is_exactly_the_ids_read() {
    for event_id in 0..=u16::MAX {
        assert_eq!(
            RegistryOperation::EVENT_IDS.contains(&event_id),
            RegistryOperation::from_id(event_id).is_some(),
            "EID {event_id}"
        );
    }
}

#[test]
fn a_write_through_a_key_opened_by_absolute_name_has_that_path() {
    let mut keys = keys();
    keys.on_record(RegistryOperation::Open, &opened(HKCU_OBJECT, 0, "", HKCU));

    assert_eq!(path_of_write(&mut keys, HKCU_OBJECT).as_deref(), Some(HKCU));
}

#[test]
fn a_key_created_relative_to_an_open_key_is_joined_to_its_path() {
    let mut keys = keys();
    keys.on_record(RegistryOperation::Open, &opened(HKCU_OBJECT, 0, "", HKCU));
    keys.on_record(
        RegistryOperation::Create,
        &opened(
            RUN_OBJECT,
            HKCU_OBJECT,
            "",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
    );

    let keyed = keys
        .on_record(RegistryOperation::SetValue, &written(RUN_OBJECT))
        .expect("resolved write");

    assert_eq!(
        keyed.key_path,
        format!(r"{HKCU}\Software\Microsoft\Windows\CurrentVersion\Run")
    );
    assert_eq!(keyed.write.value_name, "updater");
}

#[test]
fn a_base_name_the_kernel_wrote_is_used_without_the_table() {
    let mut keys = keys();
    keys.on_record(
        RegistryOperation::Open,
        &opened(RUN_OBJECT, HKCU_OBJECT, HKCU, "Software"),
    );

    assert_eq!(
        path_of_write(&mut keys, RUN_OBJECT),
        Some(format!(r"{HKCU}\Software"))
    );
}

#[test]
fn reopening_a_key_by_an_empty_relative_name_is_the_base_key() {
    let mut keys = keys();
    keys.on_record(RegistryOperation::Open, &opened(HKCU_OBJECT, 0, "", HKCU));
    keys.on_record(
        RegistryOperation::Open,
        &opened(RUN_OBJECT, HKCU_OBJECT, "", ""),
    );

    assert_eq!(path_of_write(&mut keys, RUN_OBJECT).as_deref(), Some(HKCU));
}

#[test]
fn a_write_naming_its_key_keeps_that_name() {
    let mut keys = keys();
    let mut write = written(RUN_OBJECT);
    write.0.insert("KeyName", text_value(HKCU));

    assert_eq!(
        keys.on_record(RegistryOperation::SetValue, &write)
            .map(|keyed| keyed.key_path)
            .as_deref(),
        Some(HKCU)
    );
    assert_eq!(keys.unresolved_writes(), 0);
}

#[test]
fn a_write_through_an_unknown_key_object_is_counted_not_emitted() {
    let mut keys = keys();

    assert_eq!(path_of_write(&mut keys, RUN_OBJECT), None);
    assert_eq!(keys.unresolved_writes(), 1);
}

#[test]
fn a_closed_key_object_is_forgotten() {
    let mut keys = keys();
    keys.on_record(RegistryOperation::Open, &opened(HKCU_OBJECT, 0, "", HKCU));
    keys.on_record(RegistryOperation::Close, &closed(HKCU_OBJECT));

    assert_eq!(path_of_write(&mut keys, HKCU_OBJECT), None);
    assert_eq!(keys.unresolved_writes(), 1);
}

#[test]
fn an_open_relative_to_an_unknown_base_forgets_what_its_key_object_was() {
    let mut keys = keys();
    keys.on_record(RegistryOperation::Open, &opened(RUN_OBJECT, 0, "", HKCU));
    keys.on_record(
        RegistryOperation::Open,
        &opened(RUN_OBJECT, HKCU_OBJECT, "", "Software"),
    );

    assert_eq!(path_of_write(&mut keys, RUN_OBJECT), None);
}

#[test]
fn a_failed_open_records_nothing() {
    let mut keys = keys();
    let mut failed = opened(HKCU_OBJECT, 0, "", HKCU);
    failed.0.insert("Status", Value::U32(0xc000_0034));
    keys.on_record(RegistryOperation::Open, &failed);

    assert_eq!(path_of_write(&mut keys, HKCU_OBJECT), None);
}

#[test]
fn a_resolved_write_becomes_an_event_under_its_win32_key_with_its_value() {
    let mut keys = keys();
    keys.on_record(RegistryOperation::Open, &opened(HKCU_OBJECT, 0, "", HKCU));
    let mut write = written(HKCU_OBJECT);
    write
        .0
        .insert("CapturedData", Value::Bytes(utf16("C:\\evil.exe\0")));

    let event = keys
        .on_record(RegistryOperation::SetValue, &write)
        .expect("resolved write")
        .into_event(schema::fixtures::meta());

    assert_eq!(event.key, r"HKU\S-1-5-21-1-2-3-1001");
    assert_eq!(event.value_name, "updater");
    assert_eq!(event.data_type, REG_SZ);
    assert_eq!(event.data.as_deref(), Some("C:\\evil.exe"));
}

#[test]
fn the_table_stays_within_its_cap_under_unclosed_opens() {
    let mut keys = RegistryKeys::new(8);
    for key_object in 1..=1_000 {
        keys.on_record(RegistryOperation::Open, &opened(key_object, 0, "", HKCU));
    }

    assert!(keys.paths.len() <= 8);
    assert!(keys.paths.evicted() > 0);
}
