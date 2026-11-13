#![cfg(windows)]
//! Kernel-Registry, as the sensor enables it (`SetValueKey` keyword only), delivers a value
//! write as EID 5 with the key's NT path, the value name, its type and its data. Until #91
//! the sensor read EID 4, which is `QueryKey`, as the write.

use std::{
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ferrisetw::{
    EventRecord, parser::Parser, provider::Provider, schema_locator::SchemaLocator,
    trace::UserTrace,
};

const KERNEL_REGISTRY_GUID: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
const SET_VALUE_KEY_KEYWORD: u64 = 0x100;
const SET_VALUE_KEY_EVENT: u16 = 5;
const REG_SZ: u32 = 1;

#[derive(Debug)]
struct Write {
    event_id: u16,
    key_name: String,
    value_name: String,
    value_type: u32,
    captured_data: Vec<u8>,
}

/// Deletes the probe key, written under the user's own hive, whatever the test's outcome.
struct ProbeKey(String);

impl Drop for ProbeKey {
    fn drop(&mut self) {
        let _ = Command::new("reg").args(["delete", &self.0, "/f"]).output();
    }
}

#[test]
#[ignore = "requires an elevated Windows process to enable Microsoft-Windows-Kernel-Registry"]
fn a_value_write_arrives_as_set_value_key_with_its_key_value_and_data() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let marker = format!("synthaea-reg-probe-{}-{unique}", std::process::id());
    let writes = Arc::new(Mutex::new(Vec::new()));
    let callback_writes = Arc::clone(&writes);
    let callback_marker = marker.clone();
    let provider = Provider::by_guid(KERNEL_REGISTRY_GUID)
        .any(SET_VALUE_KEY_KEYWORD)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let key_name: String = parser.try_parse("KeyName").unwrap_or_default();
            if !key_name.contains(&callback_marker) {
                return;
            }
            let write = Write {
                event_id: record.event_id(),
                key_name,
                value_name: parser.try_parse("ValueName").unwrap_or_default(),
                value_type: parser.try_parse("Type").unwrap_or(0),
                captured_data: parser.try_parse("CapturedData").unwrap_or_default(),
            };
            if let Ok(mut writes) = callback_writes.lock() {
                writes.push(write);
            }
        })
        .build();

    let trace = UserTrace::new()
        .named(format!("{marker}-session"))
        .enable(provider)
        .start_and_process()
        .expect("start a real-time Kernel-Registry ETW session");
    thread::sleep(Duration::from_millis(500));

    let key = ProbeKey(format!(r"HKCU\Software\{marker}"));
    let status = Command::new("reg")
        .args([
            "add", &key.0, "/v", "probe", "/t", "REG_SZ", "/d", "harmless", "/f",
        ])
        .status()
        .expect("run reg.exe");
    assert!(status.success(), "reg add failed: {status}");
    thread::sleep(Duration::from_secs(2));
    trace.stop().expect("stop the ETW test session");

    let writes = writes.lock().expect("writes poisoned");
    let write = writes
        .iter()
        .find(|write| write.value_name == "probe")
        .unwrap_or_else(|| panic!("no write of the probe value; saw {writes:?}"));
    assert_eq!(write.event_id, SET_VALUE_KEY_EVENT, "{write:?}");
    assert!(
        write.key_name.starts_with(r"\REGISTRY\USER\"),
        "KeyName is not the key's NT path: {write:?}"
    );
    assert_eq!(write.value_type, REG_SZ, "{write:?}");
    let data: Vec<u16> = write
        .captured_data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .collect();
    assert_eq!(
        String::from_utf16_lossy(&data).trim_end_matches('\0'),
        "harmless",
        "{write:?}"
    );
    assert!(
        writes
            .iter()
            .all(|write| write.event_id == SET_VALUE_KEY_EVENT),
        "the SetValueKey keyword let other operations through: {writes:?}"
    );
}
