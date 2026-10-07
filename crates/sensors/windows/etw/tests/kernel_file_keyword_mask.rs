#![cfg(windows)]

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ferrisetw::{EventRecord, provider::Provider, schema_locator::SchemaLocator, trace::UserTrace};

const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const EXPECTED_EVENT_IDS: [u16; 3] = [12, 26, 30];

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires an elevated Windows process to enable Microsoft-Windows-Kernel-File"]
fn kernel_file_keyword_mask_respects_the_requested_event_ids() {
    let mask = std::env::var("SYNTHAEA_KERNEL_FILE_MASK")
        .ok()
        .map(|value| {
            u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
                .expect("SYNTHAEA_KERNEL_FILE_MASK must be hexadecimal")
        })
        .unwrap_or(0x1480);
    let pid = std::process::id();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let session_name = format!("synthaea-kf-mask-{pid}-{unique}");
    let observed = Arc::new(Mutex::new(BTreeSet::new()));
    let callback_ids = Arc::clone(&observed);
    let provider = Provider::by_guid(KERNEL_FILE_GUID)
        .any(mask)
        .level(5)
        .add_callback(move |record: &EventRecord, _schema: &SchemaLocator| {
            if record.process_id() != pid {
                return;
            }
            let Ok(mut ids) = callback_ids.lock() else {
                return;
            };
            ids.insert(record.event_id());
        })
        .build();

    eprintln!("KERNEL_FILE_MASK_SESSION={session_name}");
    let trace = UserTrace::new()
        .named(session_name)
        .enable(provider)
        .start_and_process()
        .expect("start a real-time Kernel-File ETW session");

    thread::sleep(Duration::from_millis(500));
    let root = TestDirectory(std::env::temp_dir().join(format!("synthaea-kf-mask-{pid}-{unique}")));
    fs::create_dir(&root.0).expect("create the test directory");
    let original = root.0.join("created.bin");
    let renamed = root.0.join("renamed.bin");
    let mut file = File::create(&original).expect("create a file in the test directory");
    file.write_all(b"harmless kernel-file keyword probe")
        .expect("write harmless test bytes");
    drop(file);
    let _ = fs::read(&original).expect("read the harmless test file");
    fs::rename(&original, &renamed).expect("rename the harmless test file");
    fs::remove_file(&renamed).expect("delete the harmless test file");
    fs::remove_dir(&root.0).expect("remove the empty test directory");
    thread::sleep(Duration::from_secs(2));

    trace.stop().expect("stop the ETW test session");

    let observed = observed.lock().expect("event ID set poisoned").clone();
    let expected: BTreeSet<_> = EXPECTED_EVENT_IDS.into_iter().collect();
    let missing: Vec<_> = expected.difference(&observed).copied().collect();
    let unexpected: Vec<_> = observed.difference(&expected).copied().collect();
    assert!(
        missing.is_empty(),
        "mask validation failed: missing expected Kernel-File IDs {missing:?}; observed {observed:?}, mask 0x{mask:x}"
    );
    assert!(
        unexpected.is_empty(),
        "mask validation failed: unexpected Kernel-File IDs {unexpected:?}; observed {observed:?}, mask 0x{mask:x}"
    );
}
