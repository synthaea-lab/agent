//! T1204.002 on Linux, from a browser's rename of its partial download file (#221).
//! Paths and images are the ones the 2026-11-10 lab capture recorded (Chromium 156,
//! Firefox 159, Fedora 43 packages).

use schema::{ExecEvent, FileRenameEvent, Signature};

use super::meta;
use crate::{Alert, ImageSignature, RuleState, exclusions::QUARANTINE_EXEC_WINDOW_NS};

const CHROMIUM: &str = "/usr/lib64/chromium-browser/chromium-browser";
const FIREFOX: &str = "/usr/lib64/firefox/firefox";
const OPERA: &str = "/usr/lib64/opera-stable/opera";
const DEBIAN_FIREFOX_ESR: &str = "/usr/lib/firefox-esr/firefox-esr";
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
        // Debian 13 firefox-esr: /proc under strace, and the sensor's own file_rename event
        (DEBIAN_FIREFOX_ESR, ".part"),
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

fn marked(image: Option<&str>) -> bool {
    let mut state = RuleState::new();
    state.on_file_rename(&rename("/home/u/Downloads/x.bin.part", FINAL, image, 0));
    exec(&mut state, &run(FINAL, 1)).len() == 1
}

#[test]
fn every_firefox_layout_is_marked_by_shape() {
    // 2026-11-12 decision on #221: the Firefox family is matched by file name and parent directory.
    for image in [
        // a Mozilla tarball unpacked anywhere (captured: the process is firefox-bin)
        "/home/u/esr/x/firefox/firefox-bin",
        // the Snap, a revision in the path (captured 2026-11-16 on Ubuntu 26.04.1: rev 9181, X11 and Wayland)
        "/snap/firefox/1234/usr/lib/firefox/firefox",
        // Debian's firefox-esr package (captured on Debian 13)
        "/usr/lib/firefox-esr/firefox-esr",
        // Fedora and Rocky packages (captured)
        "/usr/lib64/firefox/firefox",
        // Flatpak-shaped (the real path is not verified)
        "/app/lib/firefox/firefox",
    ] {
        assert!(marked(Some(image)), "{image}");
    }
}

#[test]
fn a_path_that_only_looks_like_firefox_is_not_marked() {
    for image in [
        // the launcher script, parent `bin`
        "/usr/bin/firefox",
        // right file name, wrong parent
        "/tmp/other/firefox",
        "/home/u/firefox",
        "/opt/x/firefox-esr",
        // right parent, wrong file name (a directory named firefox is the parent, not the file)
        "/usr/lib/firefox/firefox/readme",
        "/usr/lib/firefox/crashreporter",
        // a longer name is not the family
        "/usr/lib/firefox/firefox-developer",
        "/usr/lib/librewolf/librewolf",
        // case-sensitive
        "/usr/lib/Firefox/firefox",
        "",
        "firefox",
    ] {
        assert!(!marked(Some(image)), "{image:?}");
    }
    assert!(!marked(None));
}

#[test]
fn the_chromium_snap_is_marked() {
    // Captured 2026-11-16 on Ubuntu 26.04.1 (Chromium 157, rev 3593), X11 and Wayland, #267.
    assert!(marked(Some(
        "/snap/chromium/3593/usr/lib/chromium-browser/chrome"
    )));
    assert!(marked(Some(
        "/snap/chromium/1/usr/lib/chromium-browser/chrome"
    )));
}

#[test]
fn a_path_that_only_looks_like_the_chromium_snap_is_not_marked() {
    for image in [
        // not a revision number
        "/snap/chromium/current/usr/lib/chromium-browser/chrome",
        "/snap/chromium/x3593/usr/lib/chromium-browser/chrome",
        "/snap/chromium//usr/lib/chromium-browser/chrome",
        // another snap, or another layout under the same snap
        "/snap/other/3593/usr/lib/chromium-browser/chrome",
        "/snap/chromium/3593/usr/lib/chromium-browser/chromium-browser",
        "/snap/chromium/3593/usr/lib/chromium-browser/chrome-sandbox",
        "/snap/chromium/3593/usr/bin/chrome",
        "/snap/chromium/3593/usr/lib/chromium-browser/chrome/x",
        // extra leading component or relative
        "/x/snap/chromium/3593/usr/lib/chromium-browser/chrome",
        "snap/chromium/3593/usr/lib/chromium-browser/chrome",
        // case-sensitive
        "/snap/Chromium/3593/usr/lib/chromium-browser/chrome",
    ] {
        assert!(!marked(Some(image)), "{image:?}");
    }
}

const CHROMIUM_SNAP: &str = "/snap/chromium/3593/usr/lib/chromium-browser/chrome";

#[test]
fn a_chromium_snap_download_is_joined_at_its_real_downloads_path() {
    // Captured 2026-11-16 (#267): the rename is reported under the snap's home, the user runs
    // the file from ~/Downloads, which the snap's Downloads symlink points to.
    let snap_path = "/home/u/snap/chromium/3593/Downloads/test.bin";
    for exec_path in [snap_path, "/home/u/Downloads/test.bin"] {
        let mut state = RuleState::new();
        state.on_file_rename(&rename(
            "/home/u/snap/chromium/3593/Downloads/Unconfirmed 1.crdownload",
            snap_path,
            Some(CHROMIUM_SNAP),
            0,
        ));
        let alerts = exec(&mut state, &run(exec_path, 1));
        assert_eq!(alerts.len(), 1, "{exec_path}");
        assert!(alerts[0].message.contains("marked by chrome"));
    }
}

#[test]
fn the_snap_alias_covers_nothing_else() {
    // Another file in ~/Downloads, another directory under the snap, a non-numeric revision,
    // another snap, and another browser renaming into the Chromium snap's directory: no alias,
    // so a run of an unrelated path stays silent.
    const FIREFOX_SNAP: &str = "/snap/firefox/9181/usr/lib/firefox/firefox";
    for (image, renamed, executed) in [
        (
            CHROMIUM_SNAP,
            "/home/u/snap/chromium/3593/Downloads/a.bin",
            "/home/u/Downloads/b.bin",
        ),
        (
            CHROMIUM_SNAP,
            "/home/u/snap/chromium/3593/Documents/a.bin",
            "/home/u/Downloads/a.bin",
        ),
        (
            CHROMIUM_SNAP,
            "/home/u/snap/chromium/current/Downloads/a.bin",
            "/home/u/Downloads/a.bin",
        ),
        (
            CHROMIUM_SNAP,
            "/home/u/snap/chromium/3593/Downloads/",
            "/home/u/Downloads/",
        ),
        (
            FIREFOX_SNAP,
            "/home/u/snap/firefox/9181/Downloads/a.bin",
            "/home/u/Downloads/a.bin",
        ),
        // The alias is for the Chromium Snap's image, not for any browser's rename.
        (
            FIREFOX,
            "/home/u/snap/chromium/3593/Downloads/a.bin",
            "/home/u/Downloads/a.bin",
        ),
    ] {
        let mut state = RuleState::new();
        state.on_file_rename(&rename(&format!("{renamed}.part"), renamed, Some(image), 0));
        assert!(
            exec(&mut state, &run(executed, 1)).is_empty(),
            "{image}: {renamed} -> {executed}"
        );
    }
}

#[test]
fn a_chromium_snap_download_alerts_once_whichever_path_is_run_first() {
    // The mark is recorded under two paths. Running the file from one and then the other is
    // still one download: one alert per mark, not one per path.
    let snap_path = "/home/u/snap/chromium/3593/Downloads/test.bin";
    let real_path = "/home/u/Downloads/test.bin";
    for (first, second) in [(snap_path, real_path), (real_path, snap_path)] {
        let mut state = RuleState::new();
        state.on_file_rename(&rename(
            "/home/u/snap/chromium/3593/Downloads/Unconfirmed 1.crdownload",
            snap_path,
            Some(CHROMIUM_SNAP),
            0,
        ));
        assert_eq!(exec(&mut state, &run(first, 1)).len(), 1, "{first}");
        assert!(
            exec(&mut state, &run(second, 2)).is_empty(),
            "{second} after {first}"
        );
    }
}

#[test]
fn a_new_download_of_the_same_snap_file_alerts_again() {
    // The twin's `alerted` follows the mark, not the path: a re-download writes fresh marks.
    let snap_path = "/home/u/snap/chromium/3593/Downloads/test.bin";
    let mut state = RuleState::new();
    for (i, at) in [0u64, 10].into_iter().enumerate() {
        state.on_file_rename(&rename(
            "/home/u/snap/chromium/3593/Downloads/Unconfirmed 1.crdownload",
            snap_path,
            Some(CHROMIUM_SNAP),
            at,
        ));
        assert_eq!(
            exec(&mut state, &run("/home/u/Downloads/test.bin", at + 1)).len(),
            1,
            "download {i}"
        );
    }
}

#[test]
fn a_stale_twin_does_not_silence_a_newer_download_at_the_real_path() {
    // The snap's Downloads is a real directory here, and another browser then downloads a file
    // of the same name into ~/Downloads: two different files. The snap mark still points at the
    // real path, but the mark there no longer points back, so running the snap file must not
    // mark the Firefox download as alerted.
    let snap_path = "/home/u/snap/chromium/3593/Downloads/test.bin";
    let real_path = "/home/u/Downloads/test.bin";
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/home/u/snap/chromium/3593/Downloads/Unconfirmed 1.crdownload",
        snap_path,
        Some(CHROMIUM_SNAP),
        0,
    ));
    state.on_file_rename(&rename(
        "/home/u/Downloads/test.bin.part",
        real_path,
        Some(FIREFOX),
        1,
    ));
    assert_eq!(exec(&mut state, &run(snap_path, 2)).len(), 1, "snap file");
    let alerts = exec(&mut state, &run(real_path, 3));
    assert_eq!(alerts.len(), 1, "the Firefox download still alerts");
    assert!(alerts[0].message.contains("marked by firefox"));

    // Control: the Firefox download alone.
    let mut state = RuleState::new();
    state.on_file_rename(&rename(
        "/home/u/Downloads/test.bin.part",
        real_path,
        Some(FIREFOX),
        1,
    ));
    assert_eq!(exec(&mut state, &run(real_path, 3)).len(), 1, "control");
}
