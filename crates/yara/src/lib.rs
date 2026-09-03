//! # yara
//!
//! On-device content scanning built on YARA-X (pure Rust). Rule content lives in
//! `rules/yara/` and ships on its own cadence like Sigma content; matches become
//! [`schema::detection::DetectionSource::Yara`] detections and feed the pipeline like
//! any other engine.
//!
//! ## Budget
//!
//! Scanning is never inline on the event path: [`ScanQueue`] owns a worker thread
//! behind a bounded queue — when the queue is full, requests are dropped and counted
//! (same observable-loss stance as `store`). Files over [`MAX_SCAN_BYTES`] are
//! refused. A short settle delay runs before each scan so a just-opened-for-write
//! file has content by the time it is read.

mod queue;

use std::path::Path;

pub use queue::{ScanOutcome, ScanQueue, ScanStats};

pub const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum YaraError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("rule compilation failed in {path}: {message}")]
    Compile { path: String, message: String },
}

/// Compiled rule set, ready to scan. Compile once, scan many.
pub struct RuleSet {
    rules: yara_x::Rules,
    /// Number of compiled RULES, not source files — a file can hold many rules,
    /// and the content suite pairs one sample per rule (review finding: the
    /// file count let a multi-rule file ship with untested rules).
    count: usize,
}

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSet")
            .field("rules", &self.count)
            .finish_non_exhaustive()
    }
}

impl RuleSet {
    /// Compiles every `.yar`/`.yara` file under `dir` (recursive — content
    /// convention is `rules/yara/<category>/...`). A file that fails to compile is a
    /// hard error naming the file: shipped content must compile (the content CI
    /// suite enforces it), and silently dropping rules is the failure mode the sigma
    /// migration already taught us about.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Io`] when the directory tree or a rule file cannot be
    /// read, and [`YaraError::Compile`] (naming the file) when a rule does not
    /// compile.
    pub fn load_dir(dir: &Path) -> Result<Self, YaraError> {
        let mut compiler = yara_x::Compiler::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let entries = std::fs::read_dir(&d).map_err(|source| YaraError::Io {
                path: d.display().to_string(),
                source,
            })?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "yar" || e == "yara") {
                    let src = std::fs::read_to_string(&path).map_err(|source| YaraError::Io {
                        path: path.display().to_string(),
                        source,
                    })?;
                    compiler
                        .add_source(src.as_bytes())
                        .map_err(|e| YaraError::Compile {
                            path: path.display().to_string(),
                            message: e.to_string(),
                        })?;
                }
            }
        }
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        Ok(Self {
            rules,
            count: rule_count,
        })
    }

    /// Number of compiled rules (not source files).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.count
    }

    /// Scans one file, returning the identifiers of matching rules. Refuses files
    /// over [`MAX_SCAN_BYTES`] and non-regular files (a FIFO would block the
    /// worker forever, /dev/zero would read without end — review finding). The
    /// read itself is bounded with `Read::take`, because a special file or a file
    /// growing under our feet can exceed what its metadata claimed.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::Io`] when the file cannot be read (a vanished dropper
    /// payload is the normal case) and [`YaraError::Compile`] when the scan itself
    /// fails inside the engine.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<String>, YaraError> {
        let io = |source: std::io::Error| YaraError::Io {
            path: path.display().to_string(),
            source,
        };
        let meta = std::fs::metadata(path).map_err(io)?;
        if !meta.is_file() {
            log::debug!("yara: {} is not a regular file, skipping", path.display());
            return Ok(Vec::new());
        }
        if meta.len() > MAX_SCAN_BYTES {
            log::debug!(
                "yara: {} over scan budget ({} bytes), skipping",
                path.display(),
                meta.len()
            );
            return Ok(Vec::new());
        }
        let mut data = Vec::new();
        {
            use std::io::Read as _;
            let file = std::fs::File::open(path).map_err(io)?;
            file.take(MAX_SCAN_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(io)?;
        }
        if data.len() as u64 > MAX_SCAN_BYTES {
            log::debug!(
                "yara: {} grew past the scan budget, skipping",
                path.display()
            );
            return Ok(Vec::new());
        }
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(&data).map_err(|e| YaraError::Compile {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Ok(results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RULE: &str = r#"
rule test_marker {
    strings:
        $m = "SYNTHAEA-TEST-MARKER"
    condition:
        $m
}
"#;

    fn ruleset_from(src: &str) -> RuleSet {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(src.as_bytes()).unwrap();
        RuleSet {
            rules: compiler.build(),
            count: 1,
        }
    }

    fn tmp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("yara-test-{}-{name}", std::process::id()));
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn matches_marker_and_ignores_benign() {
        let rules = ruleset_from(TEST_RULE);
        let hit = tmp_file("hit", b"payload SYNTHAEA-TEST-MARKER payload");
        let miss = tmp_file("miss", b"nothing to see");
        assert_eq!(rules.scan_file(&hit).unwrap(), vec!["test_marker"]);
        assert!(rules.scan_file(&miss).unwrap().is_empty());
    }

    #[test]
    fn load_dir_compiles_and_counts() {
        let dir = std::env::temp_dir().join(format!("yara-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("cat")).unwrap();
        std::fs::write(dir.join("cat/a.yar"), TEST_RULE).unwrap();
        let rules = RuleSet::load_dir(&dir).unwrap();
        assert_eq!(rules.rule_count(), 1);
    }

    #[test]
    fn broken_rule_is_a_hard_error_naming_the_file() {
        let dir = std::env::temp_dir().join(format!("yara-broken-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("broken.yar"), "rule x { cond").unwrap();
        let err = RuleSet::load_dir(&dir).unwrap_err();
        assert!(err.to_string().contains("broken.yar"), "{err}");
    }
}
