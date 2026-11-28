//! The `release-tool` binary, subcommand by subcommand: what it prints, to which stream, and
//! what it writes with `--out`. Written before `main` was split into one function per
//! subcommand (#170) and unchanged by the split, so it pins the behavior the split must keep.
//! Everything is offline: only the public test key is used.

use std::{
    path::Path,
    process::{Command, Output},
};

use updater::{ContentEntry, ContentManifest, key::test_key_pair};

#[cfg(feature = "test-key")]
const TEST_PUBLIC_KEY: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
#[cfg(feature = "test-key")]
const TEST_KEY_WARNING: &str =
    "warning: signing with the PUBLIC test key; this release is for a lab, not for production\n";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_release-tool"))
        .args(args)
        .output()
        .expect("run release-tool")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf-8 output")
}

fn utf8_path(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn write_release_files(dir: &Path) {
    std::fs::write(dir.join("agent"), "agentbytes\n").unwrap();
    std::fs::write(dir.join("cli"), "clibytes\n").unwrap();
}

const RELEASE_MANIFEST: &str = r#"{
  "entries": {
    "agent": "ebee3f322f8ec6ca3d99ca7f4c62120b28acd35d2783012629c913841c480342",
    "cli": "14af8ebbd08bbea34ec3ea447e596ad08e64800e78e86122e97da289071d79aa"
  },
  "release_version": 3,
  "schema_version": 1,
  "signature": ""
}
"#;

fn signed_content_manifest(release_version: u64, paths: &[&str]) -> String {
    let mut manifest = ContentManifest {
        entries: paths
            .iter()
            .map(|p| ContentEntry {
                metadata: None,
                path: (*p).to_string(),
                sha256: "a".repeat(64),
                size: 1,
                content_type: "rule".to_string(),
            })
            .collect(),
        release_version,
        released_at: "2026-10-01T00:00:00Z".to_string(),
        ring: "canary_0".to_string(),
        schema_version: updater::content::CONTENT_MANIFEST_SCHEMA_VERSION,
        signature: String::new(),
    };
    manifest.sign(&test_key_pair());
    serde_json::to_string(&manifest).unwrap()
}

#[test]
fn manifest_writes_the_hashes_to_out_and_says_how_many_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let files = dir.path().join("dist");
    std::fs::create_dir(&files).unwrap();
    write_release_files(&files);
    let out = dir.path().join("manifest.json");

    let result = run(&[
        "manifest",
        "--release-version",
        "3",
        "--dir",
        utf8_path(&files),
        "--out",
        utf8_path(&out),
    ]);

    assert!(result.status.success(), "{}", text(&result.stderr));
    assert_eq!(text(&result.stdout), "");
    assert_eq!(
        text(&result.stderr),
        "unsigned release manifest v3: 2 entries\n"
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap(), RELEASE_MANIFEST);
}

#[test]
fn manifest_without_out_prints_the_same_text_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    write_release_files(dir.path());

    let result = run(&[
        "manifest",
        "--release-version",
        "3",
        "--dir",
        utf8_path(dir.path()),
    ]);

    assert!(result.status.success());
    assert_eq!(text(&result.stdout), RELEASE_MANIFEST);
}

#[test]
fn manifest_of_a_missing_directory_fails_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("manifest.json");

    let result = run(&[
        "manifest",
        "--release-version",
        "3",
        "--dir",
        utf8_path(&dir.path().join("no-such-dir")),
        "--out",
        utf8_path(&out),
    ]);

    assert!(!result.status.success());
    assert!(!out.exists());
}

#[test]
fn rotation_with_a_fixed_issue_time_is_reproducible() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("rotation.json");
    let new = "a".repeat(64);
    let old = "b".repeat(64);

    let result = run(&[
        "rotation",
        "--release-version",
        "9",
        "--reason",
        "scheduled",
        "--new-release-key",
        &new,
        "--retire-release-key",
        &old,
        "--issued-at",
        "1700000000",
        "--out",
        utf8_path(&out),
    ]);

    assert!(result.status.success(), "{}", text(&result.stderr));
    assert_eq!(
        text(&result.stderr),
        format!(
            "unsigned key rotation v9, valid until 1700604800; sign it with the recovery key: \
             `release-tool sign --kind rotation`\n  release: {old} (retired) -> {new} (new)\n"
        )
    );
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        format!(
            r#"{{
  "expires_at": 1700604800,
  "issued_at": 1700000000,
  "new_content_key": null,
  "new_release_key": "{new}",
  "reason": "scheduled",
  "release_version": 9,
  "retired_content_key": null,
  "retired_release_key": "{old}",
  "schema_version": 1,
  "signature": ""
}}
"#
        )
    );
}

#[test]
fn rotation_without_an_issue_time_uses_the_clock() {
    let result = run(&[
        "rotation",
        "--release-version",
        "9",
        "--reason",
        "scheduled",
        "--new-content-key",
        &"c".repeat(64),
        "--retire-content-key",
        &"d".repeat(64),
    ]);

    assert!(result.status.success(), "{}", text(&result.stderr));
    let manifest: serde_json::Value = serde_json::from_str(&text(&result.stdout)).unwrap();
    let issued = manifest["issued_at"].as_u64().unwrap();
    let expires = manifest["expires_at"].as_u64().unwrap();
    assert!(issued > 1_700_000_000, "issued_at is the present: {issued}");
    assert_eq!(
        expires - issued,
        7 * 24 * 60 * 60,
        "default validity: 7 days"
    );
    assert!(
        text(&result.stderr).contains("  content: "),
        "{}",
        text(&result.stderr)
    );
}

#[cfg(feature = "test-key")]
#[test]
fn sign_with_the_test_key_reports_the_key_and_writes_a_signed_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.json");
    let out = dir.path().join("signed.json");
    std::fs::write(&manifest, RELEASE_MANIFEST).unwrap();

    let result = run(&[
        "sign",
        "--kind",
        "release",
        "--test-key",
        utf8_path(&manifest),
        "--out",
        utf8_path(&out),
    ]);

    assert!(result.status.success(), "{}", text(&result.stderr));
    assert_eq!(text(&result.stdout), "");
    assert_eq!(
        text(&result.stderr),
        format!(
            "{TEST_KEY_WARNING}signed release manifest v3 (2 entries)\npublic key: \
             {TEST_PUBLIC_KEY}\nthe key embedded in this build of the updater accepts this \
             signature\n"
        )
    );
    let signed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(signed["release_version"], 3);
    assert_eq!(signed["signature"].as_str().unwrap().len(), 128);
}

#[cfg(feature = "test-key")]
#[test]
fn sign_of_a_missing_manifest_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such.json");

    let result = run(&[
        "sign",
        "--kind",
        "release",
        "--test-key",
        utf8_path(&missing),
    ]);

    assert!(!result.status.success());
    assert!(
        text(&result.stderr).contains(&format!("cannot read {}", missing.display())),
        "{}",
        text(&result.stderr)
    );
}

#[cfg(feature = "test-key")]
#[test]
fn public_key_prints_the_hex_on_stdout_only() {
    let result = run(&["public-key", "--test-key"]);

    assert!(result.status.success());
    assert_eq!(text(&result.stdout), format!("{TEST_PUBLIC_KEY}\n"));
    assert_eq!(text(&result.stderr), TEST_KEY_WARNING);
}

#[cfg(feature = "test-key")]
#[test]
fn a_key_file_that_is_not_a_public_test_key_is_refused() {
    // `--key-file` is reserved to the checked-in test keys: any other seed in a
    // file is not a production key and is turned away before anything is signed.
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("release.key");
    std::fs::write(&key_file, format!("{}\n", "11".repeat(32))).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let result = run(&["public-key", "--key-file", utf8_path(&key_file)]);

    assert!(!result.status.success());
    assert_eq!(text(&result.stdout), "");
    assert!(
        text(&result.stderr).contains("does not hold one of the public test keys"),
        "{}",
        text(&result.stderr)
    );
}

#[test]
fn roll_forward_rebuilds_the_earlier_content_under_a_new_number() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("v2.json");
    let out = dir.path().join("v5.json");
    std::fs::write(&from, signed_content_manifest(2, &["rules/a.yml"])).unwrap();

    let result = run(&[
        "roll-forward",
        "--from",
        utf8_path(&from),
        "--release-version",
        "5",
        "--released-at",
        "2026-10-12T09:30:00Z",
        "--out",
        utf8_path(&out),
    ]);

    assert!(result.status.success(), "{}", text(&result.stderr));
    assert_eq!(
        text(&result.stderr),
        "unsigned corrective content manifest v5 for ring canary_0 (1 entries, the content of \
         v2); sign it with `release-tool sign --kind content`\n"
    );
    let corrective: ContentManifest =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(corrective.release_version, 5);
    assert_eq!(corrective.released_at, "2026-10-12T09:30:00Z");
    assert!(corrective.signature.is_empty());
}

#[test]
fn roll_forward_with_current_lists_what_it_removes() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("v2.json");
    let current = dir.path().join("v4.json");
    std::fs::write(&from, signed_content_manifest(2, &["rules/a.yml"])).unwrap();
    std::fs::write(
        &current,
        signed_content_manifest(4, &["rules/a.yml", "rules/b.yml"]),
    )
    .unwrap();

    let result = run(&[
        "roll-forward",
        "--from",
        utf8_path(&from),
        "--release-version",
        "5",
        "--released-at",
        "2026-10-12T09:30:00Z",
        "--current",
        utf8_path(&current),
    ]);

    assert!(result.status.success(), "{}", text(&result.stderr));
    assert!(
        text(&result.stderr).ends_with(
            "against release 4: 1 unchanged, 1 removed from agents, 0 brought back\n  removed        rules/b.yml\n"
        ),
        "{}",
        text(&result.stderr)
    );
    let corrective: ContentManifest = serde_json::from_str(&text(&result.stdout)).unwrap();
    assert_eq!(corrective.release_version, 5);
}

#[test]
fn roll_forward_from_a_missing_file_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such.json");

    let result = run(&[
        "roll-forward",
        "--from",
        utf8_path(&missing),
        "--release-version",
        "5",
        "--released-at",
        "2026-10-12T09:30:00Z",
    ]);

    assert!(!result.status.success());
    assert!(
        text(&result.stderr).contains(&format!("cannot read {}", missing.display())),
        "{}",
        text(&result.stderr)
    );
}

#[test]
fn roll_forward_with_a_current_that_is_not_a_content_manifest_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("v2.json");
    let current = dir.path().join("current.json");
    std::fs::write(&from, signed_content_manifest(2, &["rules/a.yml"])).unwrap();
    std::fs::write(&current, "{}").unwrap();

    let result = run(&[
        "roll-forward",
        "--from",
        utf8_path(&from),
        "--release-version",
        "5",
        "--released-at",
        "2026-10-12T09:30:00Z",
        "--current",
        utf8_path(&current),
    ]);

    assert!(!result.status.success());
    assert!(
        text(&result.stderr).contains("--current is not a content manifest"),
        "{}",
        text(&result.stderr)
    );
}
