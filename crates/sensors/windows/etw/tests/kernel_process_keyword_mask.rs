#![cfg(windows)]

//! Real-session check of the Kernel-Process keyword mask (#726, #727).
//!
//! `process_provider` asks for the process and image keywords only (`0x50`), so that
//! thread start/stop (EID 3/4, keyword THREAD `0x20`) never reach the callback. The unit
//! test of the mask table compares it with literals it also contains; this test starts
//! a real session with the requested mask and looks at which ids actually arrive for a
//! workload it controls: a short-lived child process (process start, image loads,
//! process stop) and a few threads of its own.

use std::{
    collections::BTreeSet,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ferrisetw::{
    EventRecord, parser::Parser, provider::Provider, schema_locator::SchemaLocator,
    trace::UserTrace,
};

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
/// `ProcessStart`, `ProcessStop`, `ImageLoad`: what the agent needs from this provider.
const REQUIRED_EVENT_IDS: [u16; 3] = [1, 2, 5];
/// `ThreadStart`, `ThreadStop`: what the mask must keep out.
const THREAD_EVENT_IDS: [u16; 2] = [3, 4];

/// The process an event is about: the `ProcessID` field when the schema has one (the
/// header pid of a process stop or an image load is not the process they describe),
/// otherwise the header pid.
fn subject_pid(record: &EventRecord, locator: &SchemaLocator) -> u32 {
    locator
        .event_schema(record)
        .ok()
        .and_then(|schema| {
            let parser = Parser::create(record, &schema);
            parser.try_parse::<u32>("ProcessID").ok()
        })
        .unwrap_or_else(|| record.process_id())
}

#[test]
#[ignore = "requires an elevated Windows process to enable Microsoft-Windows-Kernel-Process"]
fn kernel_process_keyword_mask_respects_the_requested_event_ids() {
    let mask = std::env::var("SYNTHAEA_KERNEL_PROCESS_MASK")
        .ok()
        .map(|value| {
            u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
                .expect("SYNTHAEA_KERNEL_PROCESS_MASK must be hexadecimal")
        })
        .unwrap_or(0x50);
    let pid = std::process::id();
    let child_pid = Arc::new(AtomicU32::new(0));
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let session_name = format!("synthaea-kp-mask-{pid}-{unique}");
    let observed = Arc::new(Mutex::new(BTreeSet::new()));
    let callback_ids = Arc::clone(&observed);
    let callback_child = Arc::clone(&child_pid);
    let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .any(mask)
        // Same as the agent's `process_provider`, which leaves ferrisetw's default (5).
        .level(5)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let subject = subject_pid(record, locator);
            let child = callback_child.load(Ordering::Relaxed);
            if subject != pid && (child == 0 || subject != child) {
                return;
            }
            if let Ok(mut ids) = callback_ids.lock() {
                ids.insert(record.event_id());
            }
        })
        .build();

    eprintln!("KERNEL_PROCESS_MASK_SESSION={session_name}");
    let trace = UserTrace::new()
        .named(session_name)
        .enable(provider)
        .start_and_process()
        .expect("start a real-time Kernel-Process ETW session");

    thread::sleep(Duration::from_millis(500));
    // Harmless workload: a child that prints the Windows version and exits (process
    // start, its image loads, process stop), and a few short-lived threads of our own.
    let mut child = Command::new("cmd.exe")
        .args(["/c", "ver"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start the harmless child process");
    child_pid.store(child.id(), Ordering::Relaxed);
    for _ in 0..8 {
        thread::spawn(|| thread::sleep(Duration::from_millis(5)))
            .join()
            .expect("join a short-lived test thread");
    }
    child.wait().expect("wait for the harmless child process");
    thread::sleep(Duration::from_secs(2));

    trace.stop().expect("stop the ETW test session");

    let observed = observed.lock().expect("event ID set poisoned").clone();
    let missing: Vec<_> = REQUIRED_EVENT_IDS
        .into_iter()
        .filter(|id| !observed.contains(id))
        .collect();
    let unexpected: Vec<_> = THREAD_EVENT_IDS
        .into_iter()
        .filter(|id| observed.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "mask validation failed: missing expected Kernel-Process IDs {missing:?}; observed {observed:?}, mask 0x{mask:x}"
    );
    assert!(
        unexpected.is_empty(),
        "mask validation failed: unexpected Kernel-Process thread IDs {unexpected:?}; observed {observed:?}, mask 0x{mask:x}"
    );
}
