//! AGENT-PIN-REMOVED and APPARMOR-PROFILE-REMOVED (T1562.001, #356): the two tamper routes the
//! Linux path filter now lets out of `/sys/`.

use schema::detection::Severity;

use super::*;
use crate::{Alert, evaluate_file_delete, evaluate_file_open};

const O_WRONLY: u32 = 0o1;

fn pin_removal_alerts(path: &str) -> Vec<Alert> {
    evaluate_file_delete(&file_delete_event_full(4242, "rm", path, 1))
        .into_iter()
        .filter(|alert| alert.technique == "T1562.001")
        .collect()
}

fn apparmor_alerts(path: &str, flags: u32) -> Vec<Alert> {
    evaluate_file_open(&file_open_event(path, flags))
        .into_iter()
        .filter(|alert| alert.technique == "T1562.001")
        .collect()
}

#[test]
fn removing_the_agents_tamper_pin_alerts_high() {
    let alerts = pin_removal_alerts("/sys/fs/bpf/synthaea/signal_tamper_last_v21");

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::High);
    assert!(alerts[0].message.contains("pid=4242 comm=rm"));
}

#[test]
fn any_entry_of_the_agents_pin_directory_counts() {
    assert_eq!(
        pin_removal_alerts("/sys/fs/bpf/synthaea/some_future_map").len(),
        1
    );
}

#[test]
fn a_non_normalized_or_proc_root_spelling_of_the_pin_alerts() {
    for path in [
        "/sys//fs/bpf/./synthaea/signal_tamper_last_v21",
        "/sys/fs/bpf/x/../synthaea/signal_tamper_last_v21",
        "/proc/self/root/sys/fs/bpf/synthaea/signal_tamper_last_v21",
    ] {
        assert_eq!(pin_removal_alerts(path).len(), 1, "{path}");
    }
}

#[test]
fn a_relative_removal_of_the_tamper_pin_alerts_on_its_name() {
    for path in ["signal_tamper_last_v21", "synthaea/signal_tamper_last_v21"] {
        assert_eq!(pin_removal_alerts(path).len(), 1, "{path}");
    }
}

#[test]
fn removing_other_bpffs_pins_or_the_directory_lookalikes_stays_silent() {
    for path in [
        "/sys/fs/bpf/falco/prog",
        "/sys/fs/bpf/synthaea",
        "/sys/fs/bpf/synthaea-other/signal",
        "/tmp/synthaea/x",
        "relative/other_file",
    ] {
        assert!(pin_removal_alerts(path).is_empty(), "{path}");
    }
}

#[test]
fn a_write_to_apparmors_remove_file_alerts_medium() {
    let alerts = apparmor_alerts("/sys/kernel/security/apparmor/.remove", O_WRONLY);

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::Medium);
}

#[test]
fn a_non_normalized_spelling_of_apparmors_remove_file_alerts() {
    for path in [
        "/sys//kernel/security/./apparmor/.remove",
        "/sys/kernel/security/apparmor/x/../.remove",
        "apparmor/.remove",
    ] {
        assert_eq!(apparmor_alerts(path, O_WRONLY).len(), 1, "{path}");
    }
}

#[test]
fn reading_apparmors_remove_file_or_loading_a_profile_stays_silent() {
    assert!(apparmor_alerts("/sys/kernel/security/apparmor/.remove", 0).is_empty());
    for path in [
        "/sys/kernel/security/apparmor/.load",
        "/sys/kernel/security/apparmor/.replace",
        "/home/user/.remove",
    ] {
        assert!(apparmor_alerts(path, O_WRONLY).is_empty(), "{path}");
    }
}
