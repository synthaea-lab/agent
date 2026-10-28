//! POLICY-DENIAL-DRIFT on `AppLocker` and WDAC denials (#796): one alert per file, not per
//! rule collection.

use schema::detection::Severity;

use super::*;

fn applocker(collection: &str, path: &str, enforced: bool) -> PolicyDenialEvent {
    PolicyDenialEvent {
        action: Some("execute".into()),
        object_path: Some(path.into()),
        ..policy_denial_event_full("applocker", None, None, Some(collection), enforced)
    }
}

fn wdac(process: &str, path: &str, scenario: &str, enforced: bool) -> PolicyDenialEvent {
    PolicyDenialEvent {
        action: Some("load".into()),
        object_path: Some(path.into()),
        ..policy_denial_event_full("wdac", Some(process), None, Some(scenario), enforced)
    }
}

#[test]
fn a_new_applocker_file_alerts_and_the_same_file_again_does_not() {
    let mut state = RuleState::new();
    let first = state.on_policy_denial(&applocker("EXE", r"C:\Users\x\evil.exe", true));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].technique, "T1562");
    assert!(first[0].message.contains(r"C:\Users\x\evil.exe"));
    assert!(first[0].message.contains("EXE"));
    assert!(first[0].message.contains("execute"));
    assert!(first[0].message.contains("enforced=true"));
    assert!(
        state
            .on_policy_denial(&applocker("EXE", r"C:\Users\x\evil.exe", true))
            .is_empty()
    );
}

#[test]
fn applocker_path_case_does_not_make_a_new_shape() {
    // `FullFilePath` and an expanded `FilePath` report one file in different cases.
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_policy_denial(&applocker("EXE", r"C:\Users\x\EVIL.EXE", true))
            .len(),
        1
    );
    assert!(
        state
            .on_policy_denial(&applocker("EXE", r"C:\USERS\X\evil.exe", true))
            .is_empty()
    );
}

#[test]
fn two_applocker_files_of_one_collection_both_alert() {
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_policy_denial(&applocker("EXE", r"C:\a\one.exe", true))
            .len(),
        1
    );
    assert_eq!(
        state
            .on_policy_denial(&applocker("EXE", r"C:\a\two.exe", true))
            .len(),
        1
    );
}

#[test]
fn one_applocker_file_in_two_collections_alerts_twice() {
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_policy_denial(&applocker("EXE", r"C:\a\x.dll", true))
            .len(),
        1
    );
    assert_eq!(
        state
            .on_policy_denial(&applocker("DLL", r"C:\a\x.dll", true))
            .len(),
        1
    );
}

#[test]
fn applocker_audit_is_low_and_enforced_is_medium() {
    let mut state = RuleState::new();
    let audit = state.on_policy_denial(&applocker("EXE", r"C:\a\audit.exe", false));
    let blocked = state.on_policy_denial(&applocker("EXE", r"C:\a\blocked.exe", true));
    assert_eq!(audit[0].severity, Severity::Low);
    assert!(audit[0].message.contains("enforced=false"));
    assert_eq!(blocked[0].severity, Severity::Medium);
}

#[test]
fn wdac_is_keyed_by_process_file_and_scenario() {
    let mut state = RuleState::new();
    let loader = r"\Device\HarddiskVolume3\Windows\System32\svchost.exe";
    let other = r"\Device\HarddiskVolume3\Tools\runner.exe";
    let file = r"\Device\HarddiskVolume3\Temp\x.dll";
    assert_eq!(
        state
            .on_policy_denial(&wdac(loader, file, "user-mode", true))
            .len(),
        1
    );
    // Same triple in other cases: not new.
    assert!(
        state
            .on_policy_denial(&wdac(
                &loader.to_uppercase(),
                &file.to_uppercase(),
                "user-mode",
                true
            ))
            .is_empty()
    );
    // Another loading process, or the other scenario: each a new shape.
    assert_eq!(
        state
            .on_policy_denial(&wdac(other, file, "user-mode", true))
            .len(),
        1
    );
    assert_eq!(
        state
            .on_policy_denial(&wdac(loader, file, "kernel-mode", true))
            .len(),
        1
    );
    // Another file: new.
    assert_eq!(
        state
            .on_policy_denial(&wdac(
                loader,
                r"\Device\HarddiskVolume3\Temp\y.dll",
                "user-mode",
                true
            ))
            .len(),
        1
    );
}

#[test]
fn wdac_audit_is_low() {
    let mut state = RuleState::new();
    let alerts = state.on_policy_denial(&wdac(r"\a\p.exe", r"\a\x.dll", "user-mode", false));
    assert_eq!(alerts[0].severity, Severity::Low);
}

#[test]
fn applocker_and_wdac_do_not_share_a_shape() {
    let mut state = RuleState::new();
    assert_eq!(
        state
            .on_policy_denial(&applocker("EXE", r"c:\a\x.exe", true))
            .len(),
        1
    );
    assert_eq!(
        state
            .on_policy_denial(&wdac(r"c:\a\p.exe", r"c:\a\x.exe", "user-mode", true))
            .len(),
        1
    );
}

#[test]
fn selinux_keeps_medium_in_permissive_mode() {
    let mut state = RuleState::new();
    let alerts = state.on_policy_denial(&policy_denial_event_full(
        "selinux",
        Some("unconfined_t"),
        Some("user_home_t"),
        Some("file"),
        false,
    ));
    assert_eq!(alerts[0].severity, Severity::Medium);
}

#[test]
fn an_unknown_mechanism_never_alerts() {
    let mut state = RuleState::new();
    assert!(
        state
            .on_policy_denial(&policy_denial_event_full(
                "tcc",
                None,
                None,
                Some("x"),
                true
            ))
            .is_empty()
    );
}
