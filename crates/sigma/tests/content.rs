//! Content regression suite: loads the real detection content from `rules/sigma/`
//! and asserts that every shipped rule (a) parses and validates inside the engine's
//! supported subset, (b) fires on its matching sample and (c) ignores its benign
//! lookalike. Run by CI's content workflow on every rules/ change: a rule nothing can
//! trigger is dead content and fails here.
//!
//! The samples are data, not test code: `<rule>.yml` has a sibling `<rule>.samples.json`
//! holding one matching and one non-matching event (ADR-0031). A rule file alone is then
//! enough for these suites to judge it, which is what lets a tool emit a complete draft.

use std::path::{Path, PathBuf};

use schema::{EventMeta, ExecEvent};
use serde::Deserialize;
use sigma::SigmaEngine;

/// One crafted event: only the fields the shipped rules key on.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    image: String,
    cmdline: String,
    /// The parent process image, for the rules that key on lineage (`ParentImage`).
    #[serde(default)]
    parentimage: Option<String>,
    /// Why this event is in the file; for a negative sample, which boundary it probes.
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

/// The contents of `<rule>.samples.json`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Samples {
    matching: Sample,
    non_matching: Sample,
}

fn content_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma")
}

fn exec(sample: &Sample) -> ExecEvent {
    ExecEvent {
        meta: EventMeta {
            pid: 1,
            comm: "test".into(),
            ..schema::fixtures::meta()
        },
        image_path: sample.image.clone(),
        cmdline: sample.cmdline.clone(),
        parent_image_path: sample.parentimage.clone(),
        ..schema::fixtures::exec()
    }
}

/// The samples file that belongs to `rule`: `persistence.yml` -> `persistence.samples.json`.
fn samples_path(rule: &Path) -> PathBuf {
    rule.with_extension("samples.json")
}

fn load_samples(rule: &Path) -> Result<Samples, String> {
    let path = samples_path(rule);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: cannot read the samples file: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("{}: not a valid samples file: {e}", path.display()))
}

/// Every file under `dir` for which `keep` holds, sorted for stable messages.
fn walk(dir: &Path, keep: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if keep(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn is_samples_file(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".samples.json"))
}

fn rule_files(dir: &Path) -> Vec<PathBuf> {
    walk(dir, |p| {
        p.extension().is_some_and(|e| e == "yml" || e == "yaml")
    })
}

/// What is wrong with the pairing of rules and samples files under `dir`, one actionable
/// line each: a rule without samples (dead content), a samples file without a rule (stale
/// after a rename or removal). Empty when every rule has exactly its samples file.
fn pairing_errors(dir: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    for rule in rule_files(dir) {
        let samples = samples_path(&rule);
        if !samples.exists() {
            errors.push(format!(
                "{}: no samples file; add {} with a `matching` and a `non_matching` event",
                rule.display(),
                samples.display()
            ));
        }
    }
    for samples in walk(dir, is_samples_file) {
        let stem = samples
            .to_str()
            .and_then(|s| s.strip_suffix(".samples.json"))
            .unwrap_or_default();
        let has_rule = ["yml", "yaml"]
            .iter()
            .any(|ext| Path::new(&format!("{stem}.{ext}")).exists());
        if !has_rule {
            errors.push(format!(
                "{}: samples file without a rule file; remove it or restore the rule",
                samples.display()
            ));
        }
    }
    errors
}

#[test]
fn every_shipped_rule_has_exactly_its_samples_file() {
    let errors = pairing_errors(&content_dir());
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn every_shipped_rule_ignores_its_negative_sample() {
    let engine = SigmaEngine::load_dir(&content_dir()).unwrap();
    for rule in rule_files(&content_dir()) {
        let title = SigmaEngine::load_rule(&rule).unwrap().title;
        let samples = load_samples(&rule).unwrap_or_else(|e| panic!("{e}"));
        let hits = engine.eval_exec(&exec(&samples.non_matching));
        assert!(
            hits.is_empty(),
            "benign lookalike for `{title}` ({}) fired: {:?}",
            samples_path(&rule).display(),
            hits.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn every_shipped_rule_loads() {
    let dir = content_dir();
    let files = rule_files(&dir);
    assert!(
        !files.is_empty(),
        "no rule files found under {}",
        dir.display()
    );
    // load_dir skips invalid rules with a warning — for content CI we want hard
    // failure instead, so load each file individually.
    for f in &files {
        SigmaEngine::load_rule(f).unwrap_or_else(|e| panic!("shipped rule failed to load: {e}"));
    }
    let engine = SigmaEngine::load_dir(&dir).unwrap();
    assert_eq!(
        engine.rule_count(),
        files.len(),
        "engine must load every shipped rule"
    );
}

#[test]
fn every_shipped_rule_fires_on_its_sample() {
    let engine = SigmaEngine::load_dir(&content_dir()).unwrap();
    for rule in rule_files(&content_dir()) {
        let title = SigmaEngine::load_rule(&rule).unwrap().title;
        let samples = load_samples(&rule).unwrap_or_else(|e| panic!("{e}"));
        let hits = engine.eval_exec(&exec(&samples.matching));
        assert!(
            hits.iter().any(|a| a.title == title),
            "rule `{title}` did not fire on its crafted sample in {} (hits: {:?})",
            samples_path(&rule).display(),
            hits.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_rule_without_a_samples_file_fails_naming_both_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lonely.yml"), "title: x\n").unwrap();
    let errors = pairing_errors(dir.path());
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("lonely.yml") && errors[0].contains("lonely.samples.json"));
}

#[test]
fn a_samples_file_without_a_rule_fails_as_stale() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("gone.samples.json"), "{}").unwrap();
    let errors = pairing_errors(dir.path());
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("gone.samples.json") && errors[0].contains("without a rule"));
}

#[test]
fn a_samples_file_with_an_unknown_field_or_a_missing_half_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let rule = dir.path().join("r.yml");
    std::fs::write(&rule, "title: x\n").unwrap();
    let write = |json: &str| std::fs::write(samples_path(&rule), json).unwrap();

    write(r#"{"matching": {"image": "a", "cmdline": "b"}}"#);
    assert!(
        load_samples(&rule).is_err(),
        "the negative sample is mandatory"
    );
    write(
        r#"{"matching": {"image": "a", "cmdline": "b", "extra": 1},
            "non_matching": {"image": "a", "cmdline": "b"}}"#,
    );
    assert!(load_samples(&rule).is_err(), "unknown fields are typos");
    write(
        r#"{"matching": {"image": "a", "cmdline": "b"},
            "non_matching": {"image": "c", "cmdline": "d", "note": "near miss"}}"#,
    );
    assert!(load_samples(&rule).is_ok());
}

/// The storage and paste rules' domain lists and upload shapes (#380, T1567): the samples file holds
/// one pair per rule, which cannot show every listed name or shape. Each row is a command line
/// and the rule file it must (or must not) raise.
#[test]
fn the_storage_and_paste_rules_cover_each_listed_domain_and_upload_shape() {
    let engine = SigmaEngine::load_dir(&content_dir()).unwrap();
    let storage = "Linux curl uploads a file to a cloud storage endpoint";
    let paste = "Linux curl uploads a file to a paste service";
    let fires = |title: &str, cmdline: &str| {
        let event = ExecEvent {
            image_path: "/usr/bin/curl".to_string(),
            cmdline: cmdline.to_string(),
            ..schema::fixtures::exec()
        };
        engine.eval_exec(&event).iter().any(|a| a.title == title)
    };
    for host in [
        "drive.google.com",
        "storage.googleapis.com",
        "content.dropboxapi.com",
        "www.dropbox.com",
        "dl.dropboxusercontent.com",
        "acct.blob.core.windows.net",
        "acme.sharepoint.com",
        "onedrive.live.com",
        "1drv.ms",
        "upload.box.com",
        "box.com",
        "mega.nz",
        "wetransfer.com",
        "transfer.sh",
        "file.io",
        "gofile.io",
        "anonfiles.com",
        "catbox.moe",
        "0x0.st",
        "bucket.s3.amazonaws.com",
    ] {
        assert!(
            fires(storage, &format!("curl -T /tmp/a.tgz https://{host}/up")),
            "{host}"
        );
        assert!(
            !fires(paste, &format!("curl -T /tmp/a.tgz https://{host}/up")),
            "{host}"
        );
    }
    for host in [
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "rentry.co",
        "controlc.com",
        "dpaste.com",
        "dpaste.org",
        "ix.io",
        "termbin.com",
        "justpaste.it",
        "privatebin.net",
    ] {
        assert!(
            fires(paste, &format!("curl -T /tmp/a.txt https://{host}/up")),
            "{host}"
        );
        assert!(
            !fires(storage, &format!("curl -T /tmp/a.txt https://{host}/up")),
            "{host}"
        );
    }
    for shape in [
        "--upload-file /tmp/a",
        "-T /tmp/a",
        "-F file=@/tmp/a",
        "--form file=@/tmp/a",
        "-d @/tmp/a",
        "--data @/tmp/a",
        "--data-binary @/tmp/a",
    ] {
        assert!(
            fires(storage, &format!("curl {shape} https://mega.nz/up")),
            "{shape}"
        );
        assert!(
            fires(paste, &format!("curl {shape} https://pastebin.com/up")),
            "{shape}"
        );
    }
    // A host that merely contains a listed name as a substring, and a request without an upload.
    for cmdline in [
        "curl -T /tmp/a https://sandbox.com/up",
        "curl -T /tmp/a https://profile.io/up",
        "curl -s https://mega.nz/file/abc",
        "curl -d name=x https://mega.nz/api",
    ] {
        assert!(!fires(storage, cmdline), "{cmdline}");
    }
    assert!(!fires(paste, "curl -d name=x https://pastebin.com/api"));
}

#[test]
fn the_local_and_remote_shell_service_rules_split_on_the_unc_argument() {
    const LOCAL: &str = "Service created with a command-shell binary path";
    const REMOTE: &str = "Remote service created with a command-shell binary path";
    let engine = SigmaEngine::load_dir(&content_dir()).unwrap();
    let titles = |cmdline: &str| -> Vec<String> {
        let sample = Sample {
            image: "C:\\Windows\\System32\\sc.exe".into(),
            cmdline: cmdline.into(),
            parentimage: None,
            note: None,
        };
        engine
            .eval_exec(&exec(&sample))
            .into_iter()
            .map(|alert| alert.title)
            .collect()
    };
    // Every covered launcher form: a local create with a drive path raises the local rule
    // only (`C:\` has one backslash, the remote test needs two); the same create against
    // `\\lab` raises both.
    for launcher in [
        "cmd.exe /c",
        "cmd /c",
        "cmd.exe /k",
        "cmd /k",
        "powershell.exe -c",
        "pwsh.exe -c",
        "%COMSPEC% /c",
    ] {
        let local = titles(&format!(
            r#"sc.exe create L binPath= "{launcher} C:\ProgramData\x.cmd""#
        ));
        assert!(local.iter().any(|t| t == LOCAL), "{launcher}: {local:?}");
        assert!(!local.iter().any(|t| t == REMOTE), "{launcher}: {local:?}");
        let remote = titles(&format!(
            r#"sc.exe \\lab create L binPath= "{launcher} C:\ProgramData\x.cmd""#
        ));
        assert!(remote.iter().any(|t| t == LOCAL), "{launcher}: {remote:?}");
        assert!(remote.iter().any(|t| t == REMOTE), "{launcher}: {remote:?}");
    }
}
