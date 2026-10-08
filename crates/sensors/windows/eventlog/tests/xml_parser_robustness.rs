//! Hostile-input and resource-bound checks for the public, substring-based XML helpers.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    time::{Duration, Instant},
};

use sensor_windows_eventlog::xml::{
    decode_task_definition, expand_applocker_path, extract_between, parse_account_created_block,
    parse_applocker_event, parse_code_integrity_event, parse_defender_event,
    parse_local_session_event, parse_logon_block, parse_remote_connection_event,
    parse_scheduled_task_block, parse_scheduled_task_update_block, parse_service_install_block,
    parse_task_scheduler_op_registered_block, split_event_blocks, task_actions,
    task_actions_display, task_definition_relative_path, task_leaf_name, unescape_xml_entities,
};

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct ThreadCountingAllocator;

#[global_allocator]
static ALLOCATOR: ThreadCountingAllocator = ThreadCountingAllocator;

fn record_allocation(size: usize) {
    let _ = TRACK_ALLOCATIONS.try_with(|active| {
        if active.get() {
            let _ = ALLOCATED_BYTES.try_with(|total| total.set(total.get().saturating_add(size)));
        }
    });
}

// SAFETY: all allocation operations delegate unchanged to `System`; the thread-local
// counter only observes requested sizes and never touches the allocated memory.
unsafe impl GlobalAlloc for ThreadCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated using the original layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record_allocation(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated using the original layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record_allocation(layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: delegated with the original pointer, layout, and requested size.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            record_allocation(new_size);
        }
        new_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: delegated with the original pointer and layout.
        unsafe { System.dealloc(ptr, layout) };
    }
}

struct AllocationTracking;

impl AllocationTracking {
    fn start() -> Self {
        ALLOCATED_BYTES.with(|total| total.set(0));
        TRACK_ALLOCATIONS.with(|active| active.set(true));
        Self
    }

    fn stop(self) -> usize {
        TRACK_ALLOCATIONS.with(|active| active.set(false));
        ALLOCATED_BYTES.with(Cell::get)
    }
}

impl Drop for AllocationTracking {
    fn drop(&mut self) {
        TRACK_ALLOCATIONS.with(|active| active.set(false));
    }
}

const LOGON: &str = "<Event xmlns='x'><System><EventID>4625</EventID><EventRecordID>77</EventRecordID><Execution ProcessID='12'/><TimeCreated SystemTime='2026-01-02T03:04:05Z'/></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='TargetUserSid'>S-1-5-21-1-2-3-1001</Data><Data Name='IpAddress'>198.51.100.7</Data></EventData></Event>";
const LOCAL: &str = "<Event xmlns='x'><System><EventID>21</EventID><EventRecordID>78</EventRecordID><Execution ProcessID='13'/><TimeCreated SystemTime='2026-01-02T03:04:05Z'/></System><UserData><EventXML><User>LAB\\alice</User><SessionID>3</SessionID><Address>198.51.100.8</Address></EventXML></UserData></Event>";
const REMOTE: &str = "<Event xmlns='x'><System><EventID>1149</EventID><EventRecordID>79</EventRecordID><Execution ProcessID='14'/><TimeCreated SystemTime='2026-01-02T03:04:05Z'/></System><UserData><EventXML><Param1>alice</Param1><Param2>LAB</Param2><Param3>198.51.100.9</Param3></EventXML></UserData></Event>";

fn assert_no_panic<T>(label: &str, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| panic!("parser panicked on {label}"))
}

fn assert_repeatable<T: std::fmt::Debug>(label: &str, f: impl Fn() -> T) {
    let first = assert_no_panic(label, &f);
    let second = assert_no_panic(label, f);
    assert_eq!(format!("{first:?}"), format!("{second:?}"), "{label}");
}

fn measure_large_parser<T: std::fmt::Debug>(label: &str, input: &str, parse: impl Fn(&str) -> T) {
    let tracking = AllocationTracking::start();
    let started = Instant::now();
    let first = black_box(parse(black_box(input)));
    let elapsed = started.elapsed();
    let allocated = tracking.stop();
    assert_eq!(format!("{first:?}"), format!("{:?}", parse(input)));
    assert!(
        allocated <= input.len() * 8 + 4096,
        "{label} allocated {allocated} bytes for {} input bytes",
        input.len()
    );
    assert!(elapsed < Duration::from_secs(5), "{label} took {elapsed:?}");
    eprintln!("1 MiB XML parser timing: {label} {elapsed:?}, {allocated} allocated bytes");
}

#[test]
fn every_ascii_byte_prefix_of_real_shaped_events_is_handled_deterministically() {
    for (event, parser) in [(LOGON, 0), (LOCAL, 1), (REMOTE, 2)] {
        assert!(event.is_ascii());
        for end in 0..=event.len() {
            let prefix = &event[..end];
            match parser {
                0 => assert_repeatable("truncated logon", || parse_logon_block(prefix)),
                1 => assert_repeatable("truncated local session", || {
                    parse_local_session_event(prefix)
                }),
                _ => assert_repeatable("truncated remote session", || {
                    parse_remote_connection_event(prefix)
                }),
            }
            let blocks = assert_no_panic("event splitter", || split_event_blocks(prefix));
            assert!(blocks.len() <= 1);
        }
    }
}

#[test]
fn hostile_xml_and_cut_utf8_never_panic_and_results_repeat() {
    let mut cases = vec![
        "<Event><EventData>".to_string(),
        "<Event><A><B></A></Event>".to_string(),
        "<Event><A>unclosed".to_string(),
        "<Event><Data Name='TargetUserSid'>S-1--999999999999999999999</Data></Event>".to_string(),
        "<Event><Data Name='IpAddress'>999.999.999.999</Data></Event>".to_string(),
        "<Event><Data Name='IpAddress'>[::::]:port</Data></Event>".to_string(),
        "<Event><Data Name='TargetUserName'>a\0b</Data><Data Name=\"IpAddress\">x'y\"z</Data></Event>".to_string(),
        "<Event><Data Name='TargetUserSid'>first</Data><Data Name='TargetUserSid'>second</Data></Event>".to_string(),
        "<Event><TimeCreated SystemTime='2026-01-02T03:04:05Z\"'/></Event>".to_string(),
        "<Event><TimeCreated SystemTime=\"2026-01-02T03:04:05Z'/></Event>".to_string(),
        "<Event><Data Name='x'>\u{202e}admin</Data></Event>".to_string(),
    ];
    let unicode = REMOTE.replace("alice", "élodie");
    for end in 0..unicode.len() {
        let prefix = String::from_utf8_lossy(&unicode.as_bytes()[..end]).into_owned();
        cases.push(prefix);
    }

    for input in cases {
        assert_repeatable("hostile logon", || parse_logon_block(&input));
        assert_repeatable("hostile local session", || {
            parse_local_session_event(&input)
        });
        assert_repeatable("hostile remote session", || {
            parse_remote_connection_event(&input)
        });
        assert_repeatable("hostile account-created", || {
            parse_account_created_block(&input)
        });
        assert_repeatable("hostile scheduled task", || {
            parse_scheduled_task_block(&input)
        });
        assert_repeatable("hostile scheduled-task update", || {
            parse_scheduled_task_update_block(&input)
        });
        assert_repeatable("hostile AppLocker", || parse_applocker_event(&input));
        assert_repeatable("hostile Defender", || parse_defender_event(&input));
        assert_repeatable("hostile code integrity", || {
            parse_code_integrity_event(&input)
        });
        assert_repeatable("hostile task scheduler", || {
            parse_task_scheduler_op_registered_block(&input)
        });
        assert_repeatable("hostile service install", || {
            parse_service_install_block(&input)
        });
        assert_no_panic("extract_between", || extract_between(&input, "<A>", "</A>"));
        assert_no_panic("entity unescape", || unescape_xml_entities(&input));
        assert_no_panic("task actions", || task_actions(&input));
        assert_no_panic("task action display", || task_actions_display(&input));
        assert_no_panic("task leaf", || task_leaf_name(&input));
        assert_no_panic("task path", || task_definition_relative_path(&input));
        assert_no_panic("task definition decode", || {
            decode_task_definition(input.as_bytes())
        });
        assert_no_panic("AppLocker expansion", || {
            expand_applocker_path(&input, |_| None)
        });
        let _ = assert_no_panic("IP parsing", || input.parse::<IpAddr>());
    }
}

#[test]
fn megabyte_inputs_stay_linear_in_allocations_and_complete_promptly() {
    let megabyte = "7".repeat(1_000_000);
    let logon = LOGON.replace("alice", &megabyte);
    let local = LOCAL.replace("LAB\\alice", &megabyte);
    let remote = REMOTE.replace("alice", &megabyte);

    measure_large_parser("logon", &logon, parse_logon_block);
    measure_large_parser("local session", &local, parse_local_session_event);
    measure_large_parser("remote session", &remote, parse_remote_connection_event);
}
