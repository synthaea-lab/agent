//! T1204.002 — a file carrying a download-provenance mark (`FileQuarantine`)
//! executed within the window (#365). Platform-neutral: the same join serves
//! macOS quarantine xattrs and Windows `Zone.Identifier` streams. Gated on the
//! image's signature (#441): resolved here as the agent's enrichment worker
//! would.

use schema::{ExecEvent, FileQuarantineEvent, Signature};

use super::meta;
use crate::{Alert, ImageSignature, RuleState, exclusions::QUARANTINE_EXEC_WINDOW_NS};

const DOWNLOAD: &str = r"C:\Users\u\Downloads\invoice.exe";

fn mark(path: &str, timestamp_ns: u64) -> FileQuarantineEvent {
    FileQuarantineEvent {
        meta: schema::EventMeta {
            timestamp_ns,
            comm: "msedge.exe".into(),
            ..meta()
        },
        path: path.into(),
        agent: Some("msedge.exe".into()),
        origin_url: Some("https://example.test/invoice.exe".into()),
        ..schema::fixtures::file_quarantine()
    }
}

fn run(image_path: &str, timestamp_ns: u64) -> ExecEvent {
    ExecEvent {
        meta: schema::EventMeta {
            pid: 4242,
            timestamp_ns,
            comm: "invoice.exe".into(),
            ..meta()
        },
        image_path: image_path.into(),
        ..schema::fixtures::exec()
    }
}

const AUTHENTICODE_UNSIGNED: ImageSignature = ImageSignature {
    verdict: Some(Signature::Unsigned),
    chain_verified: true,
};

/// The exec as the agent sees it: `on_exec`'s alerts, plus the gated ones
/// resolved with `signature`.
fn exec_with(state: &mut RuleState, event: &ExecEvent, signature: ImageSignature) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = state
        .on_exec_signature_gated(event)
        .and_then(|gated| gated.resolve(signature))
        .into_iter()
        .collect();
    alerts.extend(state.on_exec(event));
    alerts
}

/// An unsigned image on Windows: what every pre-#441 test here assumed.
fn exec(state: &mut RuleState, event: &ExecEvent) -> Vec<Alert> {
    exec_with(state, event, AUTHENTICODE_UNSIGNED)
}

#[test]
fn marked_download_executed_within_the_window_alerts_with_its_origin() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alerts = exec(&mut state, &run(DOWNLOAD, 90_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1204.002");
    assert!(
        alerts[0]
            .message
            .contains("https://example.test/invoice.exe")
    );
    assert!(alerts[0].message.contains("msedge.exe"));
    assert!(alerts[0].message.contains("90.0s"));
}

#[test]
fn path_match_ignores_case() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alerts = exec(&mut state, &run(&DOWNLOAD.to_uppercase(), 1));
    assert_eq!(alerts.len(), 1);
}

#[test]
fn exec_past_the_window_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(exec(&mut state, &run(DOWNLOAD, QUARANTINE_EXEC_WINDOW_NS + 1)).is_empty());
}

#[test]
fn unmarked_file_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(exec(&mut state, &run(r"C:\Windows\System32\notepad.exe", 1)).is_empty());
}

#[test]
fn rerunning_the_same_download_alerts_once() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert_eq!(exec(&mut state, &run(DOWNLOAD, 1)).len(), 1);
    assert!(exec(&mut state, &run(DOWNLOAD, 2)).is_empty());
}

#[test]
fn a_fresh_mark_on_the_same_path_alerts_again() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert_eq!(exec(&mut state, &run(DOWNLOAD, 1)).len(), 1);
    state.on_file_quarantine(&mark(DOWNLOAD, 10));
    assert_eq!(exec(&mut state, &run(DOWNLOAD, 11)).len(), 1);
}

#[test]
fn mark_without_recorded_urls_still_joins() {
    // A raced read of the stream reports the mark alone — still a download.
    let mut state = RuleState::new();
    state.on_file_quarantine(&FileQuarantineEvent {
        path: DOWNLOAD.into(),
        ..schema::fixtures::file_quarantine()
    });
    let alerts = exec(&mut state, &run(DOWNLOAD, 1));
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("origin: unrecorded"));
}

#[test]
fn a_signed_installer_run_does_not_alert() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let signed = ImageSignature {
        verdict: Some(Signature::Valid),
        chain_verified: true,
    };
    assert!(exec_with(&mut state, &run(DOWNLOAD, 1), signed).is_empty());
}

#[test]
fn an_unsigned_download_says_so() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alerts = exec(&mut state, &run(DOWNLOAD, 1));
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0].message.ends_with("[unsigned]"),
        "{}",
        alerts[0].message
    );
}

#[test]
fn an_invalid_signature_alerts() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let tampered = ImageSignature {
        verdict: Some(Signature::Invalid),
        chain_verified: true,
    };
    let alerts = exec_with(&mut state, &run(DOWNLOAD, 1), tampered);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.ends_with("[signature invalid]"));
}

#[test]
fn a_valid_signature_without_chain_verification_still_alerts() {
    // macOS: `Valid` includes ad-hoc signatures, which every arm64 binary has.
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark("/Users/u/Downloads/tool", 0));
    let ad_hoc = ImageSignature {
        verdict: Some(Signature::Valid),
        chain_verified: false,
    };
    let alerts = exec_with(&mut state, &run("/Users/u/Downloads/tool", 1), ad_hoc);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("chain not verified"));
}

#[test]
fn a_lost_signature_verdict_still_alerts() {
    for verdict in [None, Some(Signature::Unsupported)] {
        let mut state = RuleState::new();
        state.on_file_quarantine(&mark(DOWNLOAD, 0));
        let unknown = ImageSignature {
            verdict,
            chain_verified: true,
        };
        let alerts = exec_with(&mut state, &run(DOWNLOAD, 1), unknown);
        assert_eq!(alerts.len(), 1, "{verdict:?}");
        assert!(alerts[0].message.ends_with("[signature not verified]"));
    }
}

#[test]
fn a_caller_that_cannot_wait_gets_the_unverified_alert() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let alert = state
        .on_exec_signature_gated(&run(DOWNLOAD, 1))
        .expect("the join matches")
        .unverified();
    assert_eq!(alert.technique, "T1204.002");
    assert!(alert.message.ends_with("[signature not verified]"));
}

#[test]
fn on_exec_alone_no_longer_raises_the_download_join() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    assert!(state.on_exec(&run(DOWNLOAD, 1)).is_empty());
}

// T1566.001 (#376): the mark's writer is Apple Mail, on its expected quarantine string (not captured).

const MAC_ATTACHMENT: &str =
    "/Users/u/Library/Containers/com.apple.mail/Data/Library/Mail Downloads/invoice";

fn mark_by(agent: &str, path: &str) -> FileQuarantineEvent {
    FileQuarantineEvent {
        agent: Some(agent.into()),
        ..mark(path, 0)
    }
}

#[test]
fn a_file_marked_by_apple_mail_carries_the_attachment_technique() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark_by("Mail", MAC_ATTACHMENT));
    let alerts = exec(&mut state, &run(MAC_ATTACHMENT, 90_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1566.001/T1204.002");
    assert!(alerts[0].message.contains("marked by Mail"));
}

#[test]
fn the_mail_client_match_ignores_case_but_is_not_a_substring() {
    for (agent, tagged) in [
        ("mail", true),
        ("Safari", false),
        ("Mailspring", false),
        ("Gmail Notifier", false),
        ("", false),
    ] {
        let mut state = RuleState::new();
        state.on_file_quarantine(&mark_by(agent, MAC_ATTACHMENT));
        let alerts = exec(&mut state, &run(MAC_ATTACHMENT, 1));
        assert_eq!(alerts.len(), 1, "{agent}");
        let expected = if tagged {
            "T1566.001/T1204.002"
        } else {
            "T1204.002"
        };
        assert_eq!(alerts[0].technique, expected, "{agent}");
    }
}

#[test]
fn outlook_and_thunderbird_marks_are_not_tagged_as_mail_until_observed() {
    for agent in ["outlook.exe", "olk.exe", "thunderbird.exe"] {
        let mut state = RuleState::new();
        state.on_file_quarantine(&mark_by(agent, DOWNLOAD));
        let alerts = exec(&mut state, &run(DOWNLOAD, 1));
        assert_eq!(alerts.len(), 1, "{agent}");
        assert_eq!(alerts[0].technique, "T1204.002", "{agent}");
    }
}

#[test]
fn a_mark_without_a_recorded_agent_stays_user_execution() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&FileQuarantineEvent {
        agent: None,
        ..mark(MAC_ATTACHMENT, 0)
    });
    let alerts = exec(&mut state, &run(MAC_ATTACHMENT, 1));
    assert_eq!(alerts[0].technique, "T1204.002");
}

#[test]
fn a_valid_signature_of_a_file_that_is_not_the_image_that_ran_does_not_silence_the_alert() {
    let mut state = RuleState::new();
    state.on_file_quarantine(&mark(DOWNLOAD, 0));
    let valid = ImageSignature {
        verdict: Some(Signature::Valid),
        chain_verified: true,
    };
    let gated = state
        .on_exec_signature_gated(&run(DOWNLOAD, 90_000_000_000))
        .expect("a marked file run inside the window");
    // Same verdict that silences the alert when the image is confirmed...
    assert!(gated.clone().resolve(valid).is_none());
    // ...cannot once the verified file is not provably the one that ran (#688).
    let alert = gated
        .unconfirmed_image()
        .resolve(valid)
        .expect("an unconfirmed image alerts");
    assert_eq!(alert.technique, "T1204.002");
    assert!(alert.message.contains("not verified"), "{}", alert.message);
}
