//! T1486 mass rename, fed the way the Windows minifilter feeds it (#136 milestone 2c,
//! #853 and #857): backslash paths with a drive letter, and an event that carries the
//! pid and nothing else (`comm` empty, `ppid` 0, `User::Unknown`; see
//! `sensor_windows_minifilter::events::to_event`). The rule itself is platform-neutral;
//! these pin that the Windows shapes reach it and are counted the way they should be.

use super::*;

/// A rename as the minifilter reports it: only the pid, the time and the two paths.
fn minifilter_rename(pid: u32, old_path: &str, new_path: &str, ts: u64) -> schema::FileRenameEvent {
    let mut event = file_rename_event_full(pid, "", old_path, new_path, ts);
    event.meta.ppid = 0;
    event.meta.user = schema::User::Unknown;
    event.executable_path = None;
    event
}

/// `count` renames by one pid, one every 100 ms, `C:\Users\alice\Documents\f{i}.docx` to
/// `f{i}.docx` plus `suffix`.
fn documents_burst(pid: u32, count: u32, suffix: &str) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..count {
        alerts.extend(state.on_file_rename(&minifilter_rename(
            pid,
            &format!(r"C:\Users\alice\Documents\f{i}.docx"),
            &format!(r"C:\Users\alice\Documents\f{i}.docx{suffix}"),
            u64::from(i) * 100_000_000,
        )));
    }
    alerts
}

#[test]
fn an_encryption_pass_over_windows_paths_alerts_once_per_pid() {
    let alerts = documents_burst(4_242, RANSOMWARE_RENAME_THRESHOLD, ".locked");
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].technique, "T1486");
    assert_eq!(alerts[0].severity, crate::Severity::Critical);
    assert!(
        alerts[0].message.contains("pid=4242"),
        "{}",
        alerts[0].message
    );
    assert!(
        alerts[0].message.contains(r"C:\Users\alice\Documents\f"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn one_rename_short_of_the_threshold_does_not_alert() {
    let alerts = documents_burst(4_242, RANSOMWARE_RENAME_THRESHOLD - 1, ".locked");
    assert!(alerts.is_empty(), "{alerts:?}");
}

#[test]
fn moving_each_file_to_another_drive_with_the_suffix_appended_alerts() {
    // `appended_suffix` reads the file names when the directories differ (#512); the
    // directories here differ by drive as well, and the separator is a backslash.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&minifilter_rename(
            4_242,
            &format!(r"C:\Users\alice\Documents\f{i}.docx"),
            &format!(r"D:\stash\f{i}.docx.locked"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn a_numeric_rotation_suffix_on_windows_paths_is_not_ransomware() {
    // `app.log` to `app.log.1`: the rotation filter reads the suffix, not the path style.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&minifilter_rename(
            4_242,
            &format!(r"C:\ProgramData\app\app{i}.log"),
            &format!(r"C:\ProgramData\app\app{i}.log.1"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert!(alerts.is_empty(), "{alerts:?}");
}

#[test]
fn renames_spread_over_several_pids_are_not_summed() {
    // The minifilter gives no parent, so there is no per-parent bucket to sum them in:
    // `ppid` 0 is the "unknown" bucket the rule deliberately never keys on.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&minifilter_rename(
            5_000 + i,
            &format!(r"C:\Users\alice\Documents\f{i}.docx"),
            &format!(r"C:\Users\alice\Documents\f{i}.docx.locked"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert!(alerts.is_empty(), "{alerts:?}");
}

#[test]
fn a_burst_slower_than_the_window_does_not_alert() {
    // One rename per second: 20 of them take 19 s, past the 5 s window.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&minifilter_rename(
            4_242,
            &format!(r"C:\Users\alice\Documents\f{i}.docx"),
            &format!(r"C:\Users\alice\Documents\f{i}.docx.locked"),
            u64::from(i) * 1_000_000_000,
        )));
    }
    assert!(alerts.is_empty(), "{alerts:?}");
}
