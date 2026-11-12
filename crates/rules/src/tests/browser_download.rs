//! T1204.002 on Linux, from a browser's rename of its partial download file (#221).
//! Paths and images are the ones the 2026-11-10 lab capture recorded (Chromium 156,
//! Firefox 159, Fedora 43 packages).

use schema::{ExecEvent, FileRenameEvent, Signature};

use super::meta;
use crate::{Alert, ImageSignature, RuleState, exclusions::QUARANTINE_EXEC_WINDOW_NS};

const CHROMIUM: &str = "/usr/lib64/chromium-browser/chromium-browser";
const FIREFOX: &str = "/usr/lib64/firefox/firefox";
const OPERA: &str = "/usr/lib64/opera-stable/opera";
const FINAL: &str = "/home/u/Downloads/test.bin";

fn rename(old: &str, new: &str, image: Option<&str>, timestamp_ns: u64) -> FileRenameEvent {
    FileRenameEvent {
        meta: schema::EventMeta {
            timestamp_ns,
            // A thread-pool worker name, as in the capture: never the key.
            comm: "ThreadPoolForeg".into(),
            ..meta()
        },
        old_path: old.into(),
        new_path: new.into(),
        executable_path: image.map(Into::into),
    }
}

fn run(image_path: &str, timestamp_ns: u64) -> ExecEvent {
    ExecEvent {
        meta: schema::EventMeta {
            pid: 4242,
            timestamp_ns,
            comm: "test.bin".into(),
            ..meta()
        },
        image_path: image_path.into(),
        ..schema::fixtures::exec()
    }
}

/// The exec's T1204.002 finding, resolved as on a Linux host (no signature verdict).
fn exec(state: &mut RuleState, event: &ExecEvent) -> Vec<Alert> {
    state
        .on_exec_signature_gated(event)
        .and_then(|gated| {
            gated.resolve(ImageSignature {
                verdict: Some(Signature::Unsupported),
                chain_verified: false,
            })
        })
        .into_iter()
        .collect()
}

#[test]
fn firefox_part_rename_then_exec_alerts() {
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/home/u/Downloads/k3x9.bin.part",
        FINAL,
        Some(FIREFOX),
        0,
    ));
    let alerts = exec(&mut state, &run(FINAL, 30_000_000_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1204.002");
    assert!(alerts[0].message.contains("marked by firefox"));
    assert!(alerts[0].message.contains("origin: unrecorded"));
}

#[test]
fn an_opdownload_rename_is_a_finished_download() {
    // Opera's partial suffix (lab capture 2026-11-10, with and without a Save-as dialog:
    // `saved.bin.opdownload -> saved.bin`), by Opera's own image.
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/home/u/Downloads/test.bin.opdownload",
        FINAL,
        Some(OPERA),
        0,
    ));
    let alerts = exec(&mut state, &run(FINAL, 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1204.002");
    assert!(alerts[0].message.contains("marked by opera"));
}

#[test]
fn every_captured_browser_image_marks_a_finished_download() {
    // (image, partial suffix) as the 2026-11-10 captures showed them.
    for (image, suffix) in [
        (CHROMIUM, ".crdownload"),
        (FIREFOX, ".part"),
        ("/opt/google/chrome/chrome", ".crdownload"),
        ("/opt/microsoft/msedge/msedge", ".crdownload"),
        ("/opt/brave.com/brave/brave", ".crdownload"),
        (OPERA, ".opdownload"),
        ("/opt/vivaldi/vivaldi-bin", ".crdownload"),
    ] {
        let mut state = RuleState::new();
        state.on_file_rename(&rename(
            &format!("/home/u/Downloads/test.bin{suffix}"),
            FINAL,
            Some(image),
            0,
        ));
        let alerts = exec(&mut state, &run(FINAL, 1));
        assert_eq!(alerts.len(), 1, "{image}");
        assert_eq!(alerts[0].technique, "T1204.002", "{image}");
    }
}

#[test]
fn a_rename_into_an_opdownload_marks_nothing() {
    // The first rename (`/tmp/... -> .opdownload`) lands on the partial file, not the download.
    let partial = "/home/u/Downloads/test.bin.opdownload";
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/tmp/.org.chromium.Chromium.AbC123",
        partial,
        Some(CHROMIUM),
        0,
    ));
    assert!(exec(&mut state, &run(partial, 1)).is_empty());
}

#[test]
fn chromium_crdownload_rename_then_exec_alerts() {
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/home/u/Downloads/Non confirmé 123456.crdownload",
        FINAL,
        Some(CHROMIUM),
        0,
    ));
    let alerts = exec(&mut state, &run(FINAL, 1));
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].message.contains("marked by chromium-browser"));
}

#[test]
fn chromiums_failed_first_rename_marks_nothing() {
    // `/tmp/.org.chromium.Chromium.XXXX -> .crdownload` (EXDEV): the sensor still emits
    // it, but the destination is the partial file, not the download.
    let partial = "/home/u/Downloads/Non confirmé 123456.crdownload";
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/tmp/.org.chromium.Chromium.AbC123",
        partial,
        Some(CHROMIUM),
        0,
    ));
    assert!(exec(&mut state, &run(partial, 1)).is_empty());
}

#[test]
fn a_browser_cache_rename_marks_nothing() {
    let cache = "/home/u/.cache/mozilla/firefox/p/cache2/entries/ABCDEF";
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/home/u/.cache/mozilla/firefox/p/cache2/doomed/ABCDEF",
        cache,
        Some(FIREFOX),
        0,
    ));
    assert!(exec(&mut state, &run(cache, 1)).is_empty());
}

#[test]
fn a_non_browser_image_renaming_a_part_file_marks_nothing() {
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/home/u/Downloads/x.bin.part",
        FINAL,
        Some("/usr/bin/rsync"),
        0,
    ));
    assert!(exec(&mut state, &run(FINAL, 1)).is_empty());
}

#[test]
fn a_browser_comm_without_the_image_marks_nothing() {
    // The key is the image: a process called `firefox` run from elsewhere, or an event
    // whose `executable_path` is empty or absent, does not mark.
    for image in [None, Some(""), Some("/tmp/firefox")] {
        let mut state = RuleState::new();
        let mut event = rename("/home/u/Downloads/x.bin.part", FINAL, image, 0);
        event.meta.comm = "firefox".into();
        state.on_file_rename(&event);
        assert!(exec(&mut state, &run(FINAL, 1)).is_empty(), "{image:?}");
    }
}

#[test]
fn exec_past_the_window_stays_silent() {
    let mut state = RuleState::new();
    state.on_file_rename(&rename("/d/x.bin.part", FINAL, Some(FIREFOX), 0));
    assert!(exec(&mut state, &run(FINAL, QUARANTINE_EXEC_WINDOW_NS + 1)).is_empty());
}
