use super::*;
use crate::payload::test_fields::{Fields, Value, text_value, utf16};

const HKCU: &str = r"\REGISTRY\USER\S-1-5-21-1-2-3-1001";
const HKCU_OBJECT: u64 = 0xffff_c08a_0000_1000;
const RUN_OBJECT: u64 = 0xffff_c08a_0000_2000;
const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const REG_SZ: u32 = 1;
const WRITER: u32 = 4242;
const NOISY_PROCESS: u32 = 666;

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

fn open(keys: &mut RegistryKeys, pid: u32, record: &Fields) {
    keys.on_record(RegistryOperation::Open, pid, record);
}

fn write_through(keys: &mut RegistryKeys, key_object: u64) -> KeyedWrite {
    keys.on_record(RegistryOperation::SetValue, WRITER, &written(key_object))
        .expect("a value write is always returned")
}

fn key_of_write(keys: &mut RegistryKeys, key_object: u64) -> KeyName {
    write_through(keys, key_object).key
}

fn absolute(path: &str) -> KeyName {
    KeyName::Absolute(path.to_owned())
}

fn below_unknown_key(relative_name: &str) -> KeyName {
    KeyName::BelowUnknownKey(relative_name.to_owned())
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
    open(&mut keys, WRITER, &opened(HKCU_OBJECT, 0, "", HKCU));

    assert_eq!(key_of_write(&mut keys, HKCU_OBJECT), absolute(HKCU));
}

#[test]
fn a_key_created_relative_to_an_open_key_is_joined_to_its_path() {
    let mut keys = keys();
    open(&mut keys, WRITER, &opened(HKCU_OBJECT, 0, "", HKCU));
    keys.on_record(
        RegistryOperation::Create,
        WRITER,
        &opened(RUN_OBJECT, HKCU_OBJECT, "", RUN),
    );

    let keyed = write_through(&mut keys, RUN_OBJECT);

    assert_eq!(keyed.key, absolute(&format!(r"{HKCU}\{RUN}")));
    assert_eq!(keyed.write.value_name, "updater");
}

#[test]
fn a_base_name_the_kernel_wrote_is_used_without_the_table() {
    let mut keys = keys();
    open(
        &mut keys,
        WRITER,
        &opened(RUN_OBJECT, HKCU_OBJECT, HKCU, "Software"),
    );

    assert_eq!(
        key_of_write(&mut keys, RUN_OBJECT),
        absolute(&format!(r"{HKCU}\Software"))
    );
}

#[test]
fn reopening_a_key_by_an_empty_relative_name_is_the_base_key() {
    let mut keys = keys();
    open(&mut keys, WRITER, &opened(HKCU_OBJECT, 0, "", HKCU));
    open(&mut keys, WRITER, &opened(RUN_OBJECT, HKCU_OBJECT, "", ""));

    assert_eq!(key_of_write(&mut keys, RUN_OBJECT), absolute(HKCU));
}

#[test]
fn a_write_naming_its_key_keeps_that_name() {
    let mut keys = keys();
    let mut write = written(RUN_OBJECT);
    write.0.insert("KeyName", text_value(HKCU));

    let keyed = keys
        .on_record(RegistryOperation::SetValue, WRITER, &write)
        .expect("a value write");

    assert_eq!(keyed.key, absolute(HKCU));
    assert_eq!(keys.shedding.unresolved_writes.get(), 0);
}

#[test]
fn a_write_through_a_root_handle_opened_before_the_session_is_emitted_with_its_key_unresolved() {
    // advapi caches HKEY_CURRENT_USER per process: a process that opened it before the
    // session opens Run relative to a key object the table never saw (#252 review).
    let mut keys = keys();
    open(&mut keys, WRITER, &opened(RUN_OBJECT, HKCU_OBJECT, "", RUN));

    let event = write_through(&mut keys, RUN_OBJECT).into_event(schema::fixtures::meta());

    assert_eq!(
        event.key,
        RegistryKey::Unresolved {
            relative_name: RUN.to_owned()
        }
    );
    assert_eq!(event.value_name, "updater");
    assert_eq!(keys.shedding.unresolved_writes.get(), 1);
}

#[test]
fn a_key_opened_below_an_unresolved_key_keeps_the_whole_known_name() {
    let mut keys = keys();
    open(
        &mut keys,
        WRITER,
        &opened(HKCU_OBJECT, 0xdead, "", r"Software\Microsoft"),
    );
    open(
        &mut keys,
        WRITER,
        &opened(RUN_OBJECT, HKCU_OBJECT, "", r"Windows\CurrentVersion\Run"),
    );

    assert_eq!(key_of_write(&mut keys, RUN_OBJECT), below_unknown_key(RUN));
}

#[test]
fn a_write_through_an_unknown_key_object_is_emitted_unresolved_and_counted() {
    let mut keys = keys();

    assert_eq!(key_of_write(&mut keys, RUN_OBJECT), below_unknown_key(""));
    assert_eq!(keys.shedding.unresolved_writes.get(), 1);
}

#[test]
fn a_closed_key_object_is_forgotten() {
    let mut keys = keys();
    open(&mut keys, WRITER, &opened(HKCU_OBJECT, 0, "", HKCU));
    keys.on_record(RegistryOperation::Close, WRITER, &closed(HKCU_OBJECT));

    assert_eq!(key_of_write(&mut keys, HKCU_OBJECT), below_unknown_key(""));
    assert!(keys.entries_by_opener.is_empty());
}

#[test]
fn an_open_relative_to_an_unknown_base_replaces_what_its_key_object_was() {
    let mut keys = keys();
    open(&mut keys, WRITER, &opened(RUN_OBJECT, 0, "", HKCU));
    open(
        &mut keys,
        WRITER,
        &opened(RUN_OBJECT, HKCU_OBJECT, "", "Software"),
    );

    assert_eq!(
        key_of_write(&mut keys, RUN_OBJECT),
        below_unknown_key("Software")
    );
    assert_eq!(keys.entries_held_by(WRITER), 1);
}

#[test]
fn a_failed_open_records_nothing() {
    let mut keys = keys();
    let mut failed = opened(HKCU_OBJECT, 0, "", HKCU);
    failed.0.insert("Status", Value::U32(0xc000_0034));
    open(&mut keys, WRITER, &failed);

    assert_eq!(key_of_write(&mut keys, HKCU_OBJECT), below_unknown_key(""));
}

#[test]
fn a_resolved_write_becomes_an_event_under_its_win32_key_with_its_value() {
    let mut keys = keys();
    open(&mut keys, WRITER, &opened(HKCU_OBJECT, 0, "", HKCU));
    let mut write = written(HKCU_OBJECT);
    write
        .0
        .insert("CapturedData", Value::Bytes(utf16("C:\\evil.exe\0")));

    let event = keys
        .on_record(RegistryOperation::SetValue, WRITER, &write)
        .expect("a value write")
        .into_event(schema::fixtures::meta());

    assert_eq!(
        event.key,
        RegistryKey::Resolved {
            path: r"HKU\S-1-5-21-1-2-3-1001".to_owned()
        }
    );
    assert_eq!(event.value_name, "updater");
    assert_eq!(event.data_type, REG_SZ);
    assert_eq!(event.data.as_deref(), Some("C:\\evil.exe"));
}

#[test]
fn a_long_key_name_is_cut_to_the_bound_on_a_character_boundary_and_counted() {
    let mut keys = keys();
    let deep = format!(r"{HKCU}\{}", "é".repeat(MAX_KEY_NAME_BYTES));
    open(&mut keys, WRITER, &opened(HKCU_OBJECT, 0, "", &deep));

    let KeyName::Absolute(path) = key_of_write(&mut keys, HKCU_OBJECT) else {
        panic!("an absolute open stays absolute when cut");
    };

    assert!(path.len() <= MAX_KEY_NAME_BYTES && path.len() > MAX_KEY_NAME_BYTES - 2);
    assert!(deep.starts_with(&path));
    assert_eq!(keys.shedding.names_truncated.get(), 1);
}

#[test]
fn the_table_stays_within_its_cap_under_unclosed_opens() {
    let mut keys = RegistryKeys::new(8);
    for key_object in 1..=1_000u64 {
        let pid = u32::try_from(key_object % 50).expect("small pid");
        open(&mut keys, pid, &opened(key_object, 0, "", HKCU));
    }

    assert!(keys.names.len() <= 8);
    assert!(keys.names.evicted() > 0);
    assert_eq!(
        keys.entries_by_opener.values().sum::<usize>(),
        keys.names.len()
    );
}

#[test]
fn one_process_opening_keys_without_closing_them_does_not_evict_another_process_s_key() {
    let mut keys = keys();
    open(&mut keys, WRITER, &opened(RUN_OBJECT, 0, "", HKCU));
    for key_object in 1..=1_000 {
        open(&mut keys, NOISY_PROCESS, &opened(key_object, 0, "", HKCU));
    }

    assert_eq!(key_of_write(&mut keys, RUN_OBJECT), absolute(HKCU));
    assert!(keys.entries_held_by(NOISY_PROCESS) <= keys.share);
    assert!(
        keys.shedding.evicted.get() > 0,
        "its own keys are evicted, counted"
    );
}
