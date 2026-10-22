//! STAGING-DIR (T1074.001, #380): many reads of user data, then creates in one staging
//! directory, by the same pid.

use super::*;
use crate::exclusions::{
    STAGING_READ_DIRS, STAGING_READ_FILES, STAGING_WINDOW_NS, STAGING_WRITE_FILES,
};

const SEC: u64 = 1_000_000_000;
const COPY: &str = "cp";
const CREATE: u32 = O_WRONLY | O_CREAT;

fn read_user_files(state: &mut RuleState, pid: u32, files: u32, dirs: u32, start_ns: u64) -> u64 {
    let mut ts = start_ns;
    for i in 0..files {
        let path = format!("/home/alice/Documents/d{}/f{i}.docx", i % dirs);
        state.on_file_open(&file_open_event_full(pid, COPY, &path, O_RDONLY, ts));
        ts += SEC / 100;
    }
    ts
}

/// Creates `files` files in `dir` and returns every alert raised, with the timestamp after.
fn create_in(
    state: &mut RuleState,
    pid: u32,
    dir: &str,
    files: u32,
    start_ns: u64,
) -> (Vec<crate::Alert>, u64) {
    let mut alerts = Vec::new();
    let mut ts = start_ns;
    for i in 0..files {
        let path = format!("{dir}/f{i}.bin");
        alerts.extend(state.on_file_open(&file_open_event_full(pid, COPY, &path, CREATE, ts)));
        ts += SEC / 100;
    }
    (alerts, ts)
}

fn staging(alerts: &[crate::Alert]) -> Vec<&crate::Alert> {
    alerts
        .iter()
        .filter(|a| a.technique == "T1074.001")
        .collect()
}

#[test]
fn a_sweep_of_user_files_copied_into_one_hidden_temp_dir_alerts_once() {
    let mut state = RuleState::new();
    let ts = read_user_files(
        &mut state,
        10,
        STAGING_READ_FILES,
        STAGING_READ_DIRS as u32,
        0,
    );
    let (alerts, _) = create_in(&mut state, 10, "/tmp/.stash", STAGING_WRITE_FILES + 20, ts);
    let found = staging(&alerts);
    assert_eq!(found.len(), 1, "{alerts:?}");
    assert_eq!(found[0].severity, schema::detection::Severity::Medium);
    assert!(
        found[0].message.contains("/tmp/.stash"),
        "{}",
        found[0].message
    );
}

#[test]
fn reads_and_creates_interleaved_as_a_copy_loop_alert() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    let mut ts = 0;
    for i in 0..STAGING_READ_FILES {
        let src = format!("/home/alice/Pictures/d{}/p{i}.jpg", i % 12);
        state.on_file_open(&file_open_event_full(10, COPY, &src, O_RDONLY, ts));
        let dst = format!("/var/tmp/out/p{i}.jpg");
        alerts.extend(state.on_file_open(&file_open_event_full(10, COPY, &dst, CREATE, ts + 1)));
        ts += SEC / 10;
    }
    assert_eq!(staging(&alerts).len(), 1, "{alerts:?}");
}

#[test]
fn reads_below_the_file_or_directory_threshold_do_not_alert() {
    let mut few_files = RuleState::new();
    let ts = read_user_files(&mut few_files, 10, STAGING_READ_FILES - 1, 12, 0);
    let (alerts, _) = create_in(&mut few_files, 10, "/tmp/x", STAGING_WRITE_FILES + 5, ts);
    assert!(staging(&alerts).is_empty(), "{alerts:?}");

    // A build of one tree: many files, few directories.
    let mut few_dirs = RuleState::new();
    let ts = read_user_files(&mut few_dirs, 10, STAGING_READ_FILES + 50, 3, 0);
    let (alerts, _) = create_in(&mut few_dirs, 10, "/tmp/x", STAGING_WRITE_FILES + 5, ts);
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn creates_below_the_threshold_or_spread_over_directories_do_not_alert() {
    let mut state = RuleState::new();
    let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
    let (alerts, ts) = create_in(&mut state, 10, "/tmp/x", STAGING_WRITE_FILES - 1, ts);
    assert!(staging(&alerts).is_empty(), "{alerts:?}");

    let mut spread = RuleState::new();
    let mut ts2 = read_user_files(&mut spread, 10, STAGING_READ_FILES, 12, 0);
    for d in 0..10 {
        let (alerts, next) = create_in(&mut spread, 10, &format!("/tmp/dir{d}"), 10, ts2);
        assert!(staging(&alerts).is_empty(), "{alerts:?}");
        ts2 = next;
    }
    let _ = ts;
}

#[test]
fn files_created_straight_in_a_temp_root_or_an_ordinary_directory_do_not_alert() {
    for dir in [
        "/tmp",
        "/var/tmp",
        "/home/alice/Documents/copy",
        "/srv/share",
    ] {
        let mut state = RuleState::new();
        let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
        let (alerts, _) = create_in(&mut state, 10, dir, STAGING_WRITE_FILES + 5, ts);
        assert!(staging(&alerts).is_empty(), "{dir}: {alerts:?}");
    }
}

#[test]
fn a_hidden_directory_in_the_profile_stages_but_a_cache_or_git_store_does_not() {
    let mut state = RuleState::new();
    let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
    let (alerts, _) = create_in(
        &mut state,
        10,
        "/home/alice/.stash",
        STAGING_WRITE_FILES,
        ts,
    );
    assert_eq!(staging(&alerts).len(), 1, "{alerts:?}");

    for dir in [
        "/home/alice/.cache/thumbs",
        "/home/alice/proj/.git/objects/ab",
    ] {
        let mut state = RuleState::new();
        let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
        let (alerts, _) = create_in(&mut state, 10, dir, STAGING_WRITE_FILES + 5, ts);
        assert!(staging(&alerts).is_empty(), "{dir}: {alerts:?}");
    }
}

#[test]
fn reads_of_configuration_and_system_files_are_not_user_data() {
    let mut state = RuleState::new();
    let mut ts = 0;
    for i in 0..(STAGING_READ_FILES + 20) {
        let path = if i % 2 == 0 {
            format!("/home/alice/.config/d{}/c{i}.json", i % 12)
        } else {
            format!("/usr/share/d{}/f{i}", i % 12)
        };
        state.on_file_open(&file_open_event_full(10, COPY, &path, O_RDONLY, ts));
        ts += SEC / 100;
    }
    let (alerts, _) = create_in(&mut state, 10, "/tmp/.stash", STAGING_WRITE_FILES + 5, ts);
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn a_write_open_of_a_user_file_is_not_a_read() {
    let mut state = RuleState::new();
    let mut ts = 0;
    for i in 0..(STAGING_READ_FILES + 20) {
        let path = format!("/home/alice/Documents/d{}/f{i}.txt", i % 12);
        state.on_file_open(&file_open_event_full(10, "editor", &path, CREATE, ts));
        ts += SEC / 100;
    }
    let (alerts, _) = create_in(&mut state, 10, "/tmp/.stash", STAGING_WRITE_FILES + 5, ts);
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn a_create_without_o_creat_is_not_a_new_staged_file() {
    let mut state = RuleState::new();
    let mut ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
    let mut alerts = Vec::new();
    for i in 0..(STAGING_WRITE_FILES + 5) {
        let path = format!("/tmp/.stash/f{i}.bin");
        alerts.extend(state.on_file_open(&file_open_event_full(10, COPY, &path, O_WRONLY, ts)));
        ts += SEC / 100;
    }
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn the_reader_and_the_creator_must_be_the_same_pid() {
    let mut state = RuleState::new();
    let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
    let (alerts, _) = create_in(&mut state, 11, "/tmp/.stash", STAGING_WRITE_FILES + 5, ts);
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn reads_older_than_the_window_do_not_count() {
    let mut state = RuleState::new();
    let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
    let (alerts, _) = create_in(
        &mut state,
        10,
        "/tmp/.stash",
        STAGING_WRITE_FILES + 5,
        ts + STAGING_WINDOW_NS + SEC,
    );
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn a_reused_pid_does_not_inherit_the_reads_or_the_creates_of_the_previous_process() {
    let mut state = RuleState::new();
    let mut ts = 0;
    for i in 0..STAGING_READ_FILES {
        let path = format!("/home/alice/Documents/d{}/f{i}.docx", i % 12);
        let mut event = file_open_event_full(10, COPY, &path, O_RDONLY, ts);
        event.meta.process_generation = Some(1);
        state.on_file_open(&event);
        ts += SEC / 100;
    }
    let mut alerts = Vec::new();
    for i in 0..(STAGING_WRITE_FILES + 5) {
        let path = format!("/tmp/.stash/f{i}.bin");
        let mut event = file_open_event_full(10, COPY, &path, CREATE, ts);
        event.meta.process_generation = Some(2);
        alerts.extend(state.on_file_open(&event));
        ts += SEC / 100;
    }
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn windows_paths_stage_through_the_user_temp_directory() {
    let mut state = RuleState::new();
    let mut ts = 0;
    for i in 0..STAGING_READ_FILES {
        let path = format!("C:\\Users\\carol\\Documents\\d{}\\f{i}.docx", i % 12);
        state.on_file_open(&file_open_event_full(
            10,
            "robocopy.exe",
            &path,
            O_RDONLY,
            ts,
        ));
        ts += SEC / 100;
    }
    let mut alerts = Vec::new();
    for i in 0..STAGING_WRITE_FILES {
        let path = format!("C:\\Users\\carol\\AppData\\Local\\Temp\\x\\f{i}.bin");
        alerts.extend(state.on_file_open(&file_open_event_full(
            10,
            "robocopy.exe",
            &path,
            CREATE,
            ts,
        )));
        ts += SEC / 100;
    }
    assert_eq!(staging(&alerts).len(), 1, "{alerts:?}");
}

#[test]
fn a_second_burst_after_the_window_alerts_again() {
    let mut state = RuleState::new();
    let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
    let (first, ts) = create_in(&mut state, 10, "/tmp/.stash", STAGING_WRITE_FILES, ts);
    assert_eq!(staging(&first).len(), 1);
    let next = ts + STAGING_WINDOW_NS + SEC;
    let ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, next);
    let (second, _) = create_in(&mut state, 10, "/tmp/.stash", STAGING_WRITE_FILES, ts);
    assert_eq!(staging(&second).len(), 1, "{second:?}");
}

#[test]
fn the_read_history_is_bounded_and_an_evicted_pid_loses_it() {
    let mut state = RuleState::new();
    let mut ts = read_user_files(&mut state, 10, STAGING_READ_FILES, 12, 0);
    // More busier pids than the map holds push pid 10 out.
    for pid in 1_000..(1_000 + crate::exclusions::STAGING_PID_CAP as u32 + 10) {
        let path = format!("/home/alice/Documents/other/{pid}.txt");
        state.on_file_open(&file_open_event_full(pid, "app", &path, O_RDONLY, ts));
        ts += 1;
    }
    let (alerts, _) = create_in(&mut state, 10, "/tmp/.stash", STAGING_WRITE_FILES + 5, ts);
    assert!(staging(&alerts).is_empty(), "{alerts:?}");

    // A pid that is still in the map alerts.
    let last = 1_000 + crate::exclusions::STAGING_PID_CAP as u32 + 9;
    let ts = read_user_files(&mut state, last, STAGING_READ_FILES, 12, ts);
    let (alerts, _) = create_in(&mut state, last, "/tmp/.stash", STAGING_WRITE_FILES, ts);
    assert_eq!(staging(&alerts).len(), 1, "{alerts:?}");
}

fn open_gen(pid: u32, generation: u64, path: &str, flags: u32, ts: u64) -> FileOpenEvent {
    let mut event = file_open_event_full(pid, COPY, path, flags, ts);
    event.meta.process_generation = Some(generation);
    event
}

#[test]
fn a_reused_pid_that_reads_the_rest_does_not_complete_the_previous_process_reads() {
    let mut state = RuleState::new();
    let mut ts = 0;
    // The first process read one file short of the threshold; the next process under the same
    // pid reads a single more: the two never add up.
    for i in 0..(STAGING_READ_FILES - 1) {
        let path = format!("/home/alice/Documents/d{}/f{i}.docx", i % 12);
        state.on_file_open(&open_gen(10, 1, &path, O_RDONLY, ts));
        ts += SEC / 100;
    }
    state.on_file_open(&open_gen(
        10,
        2,
        "/home/alice/Documents/d0/last.docx",
        O_RDONLY,
        ts,
    ));
    let mut alerts = Vec::new();
    for i in 0..(STAGING_WRITE_FILES + 5) {
        let path = format!("/tmp/.stash/f{i}.bin");
        alerts.extend(state.on_file_open(&open_gen(10, 2, &path, CREATE, ts)));
        ts += SEC / 100;
    }
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn a_reused_pid_does_not_add_its_creates_to_the_previous_process_in_the_same_directory() {
    let mut state = RuleState::new();
    let mut ts = 0;
    for i in 0..(STAGING_WRITE_FILES - 1) {
        let path = format!("/tmp/.stash/old{i}.bin");
        state.on_file_open(&open_gen(10, 1, &path, CREATE, ts));
        ts += SEC / 100;
    }
    for i in 0..STAGING_READ_FILES {
        let path = format!("/home/alice/Documents/d{}/f{i}.docx", i % 12);
        state.on_file_open(&open_gen(10, 2, &path, O_RDONLY, ts));
        ts += SEC / 100;
    }
    let alerts = state.on_file_open(&open_gen(10, 2, "/tmp/.stash/new.bin", CREATE, ts));
    assert!(staging(&alerts).is_empty(), "{alerts:?}");
}

#[test]
fn a_reused_pid_that_sweeps_after_a_short_lived_process_still_alerts() {
    let mut state = RuleState::new();
    let mut ts = 0;
    state.on_file_open(&open_gen(
        10,
        1,
        "/home/alice/Documents/d0/a.docx",
        O_RDONLY,
        ts,
    ));
    ts += SEC;
    for i in 0..STAGING_READ_FILES {
        let path = format!("/home/alice/Documents/d{}/f{i}.docx", i % 12);
        state.on_file_open(&open_gen(10, 2, &path, O_RDONLY, ts));
        ts += SEC / 100;
    }
    let mut alerts = Vec::new();
    for i in 0..STAGING_WRITE_FILES {
        let path = format!("/tmp/.stash/f{i}.bin");
        alerts.extend(state.on_file_open(&open_gen(10, 2, &path, CREATE, ts)));
        ts += SEC / 100;
    }
    assert_eq!(staging(&alerts).len(), 1, "{alerts:?}");
}
