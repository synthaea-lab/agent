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

mod access;
mod queue;

use std::{collections::HashMap, path::Path};

pub use access::{Refused, Requester};
pub use queue::{ScanContext, ScanOutcome, ScanQueue, ScanStats};
use schema::detection::Severity;

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
    /// Issue #73: every rule must carry severity/technique/falsepositives in its
    /// `meta:` block. Names the rule identifier — the file path isn't available
    /// once rules are compiled into one `yara_x::Rules` set.
    #[error("missing or invalid rule metadata in `{identifier}`: {what}")]
    MissingMetadata { identifier: String, what: String },
}

/// Required `meta:` fields, extracted and validated at compile time so a rule
/// missing them is a hard load-time error, not a silently-unused YAML/text block.
struct RuleMetadata {
    severity: Severity,
    /// ATT&CK technique id (`T1234` or `T1234.001`), issue #74. Already validated at
    /// extraction time by [`extract_metadata`] — #73 checked its format and then
    /// discarded it; this keeps it instead of re-deriving it later.
    technique: String,
}

/// One YARA match, with the metadata required by issues #73/#74 attached — the
/// scanner no longer hands back a bare rule identifier only.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub identifier: String,
    pub severity: Severity,
    pub technique: String,
}

/// Compiled rule set, ready to scan. Compile once, scan many.
pub struct RuleSet {
    rules: yara_x::Rules,
    /// Number of compiled RULES, not source files — a file can hold many rules,
    /// and the content suite pairs one sample per rule (review finding: the
    /// file count let a multi-rule file ship with untested rules).
    count: usize,
    /// Keyed by rule identifier; populated at compile time by [`Self::from_compiled`].
    metadata: HashMap<String, RuleMetadata>,
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
    /// read, [`YaraError::Compile`] (naming the file) when a rule does not compile,
    /// and [`YaraError::MissingMetadata`] (naming the rule identifier) when a rule's
    /// `meta:` block lacks a valid `severity`, `technique`, or `falsepositives`.
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
        Self::from_compiled(compiler.build())
    }

    /// Extracts and validates required metadata for every compiled rule. Shared by
    /// [`Self::load_dir`] and the crate's own unit tests, so metadata validation is
    /// never bypassed by a hand-built `RuleSet`.
    fn from_compiled(rules: yara_x::Rules) -> Result<Self, YaraError> {
        let mut metadata = HashMap::new();
        let mut count = 0;
        for rule in rules.iter() {
            count += 1;
            metadata.insert(rule.identifier().to_string(), extract_metadata(&rule)?);
        }
        Ok(Self {
            rules,
            count,
            metadata,
        })
    }

    /// Number of compiled rules (not source files).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.count
    }

    /// Identifiers of every compiled rule. Lets a caller (the content test
    /// suite's sample-pairing checks) assert against the actual rule set rather
    /// than only its size — a count match alone (review, Jihair54/Sollykhan)
    /// can't catch a renamed or swapped rule keeping a stale sample label.
    #[must_use]
    pub fn rule_identifiers(&self) -> Vec<&str> {
        self.metadata.keys().map(String::as_str).collect()
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
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraError> {
        let io = |source: std::io::Error| YaraError::Io {
            path: path.display().to_string(),
            source,
        };
        let meta = std::fs::metadata(path).map_err(io)?;
        if !meta.is_file() {
            tracing::debug!(path = %path.display(), "yara: not a regular file, skipping");
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(path).map_err(io)?;
        self.scan_open_file(path, file)
    }

    /// [`Self::scan_file`] on behalf of the user whose process queued the scan (#594):
    /// the file is read only if that user could read it themselves
    /// ([`Requester::open`]), otherwise the request is dropped as if it had matched
    /// nothing. The agent holds `CAP_DAC_READ_SEARCH`, so without this any local user
    /// could have it scan a file they cannot read.
    ///
    /// # Errors
    ///
    /// As [`Self::scan_file`].
    pub fn scan_file_as(
        &self,
        path: &Path,
        requester: Requester,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let io = |source: std::io::Error| YaraError::Io {
            path: path.display().to_string(),
            source,
        };
        match requester.open(path).map_err(io)? {
            Ok(file) => self.scan_open_file(path, file),
            Err(refused) => {
                tracing::debug!(path = %path.display(), ?refused, "yara: not the requester's to read, skipping");
                Ok(Vec::new())
            }
        }
    }

    /// The size budget, the bounded read and the scan, on a file already opened.
    fn scan_open_file(
        &self,
        path: &Path,
        file: std::fs::File,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let io = |source: std::io::Error| YaraError::Io {
            path: path.display().to_string(),
            source,
        };
        let len = file.metadata().map_err(io)?.len();
        if len > MAX_SCAN_BYTES {
            tracing::debug!(path = %path.display(), size = len, "yara: over scan budget, skipping");
            return Ok(Vec::new());
        }
        let mut data = Vec::new();
        {
            use std::io::Read as _;
            file.take(MAX_SCAN_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(io)?;
        }
        if data.len() as u64 > MAX_SCAN_BYTES {
            tracing::debug!(path = %path.display(), "yara: grew past the scan budget, skipping");
            return Ok(Vec::new());
        }
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(&data).map_err(|e| YaraError::Compile {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Ok(results
            .matching_rules()
            .map(|r| {
                let identifier = r.identifier().to_string();
                // Every rule in `self.rules` got a metadata entry from the same
                // `rules.iter()` pass in `from_compiled` — this is defensive, not
                // expected to ever fall back, kept panic-free because scanning runs
                // on attacker-influenced file content.
                let found = self.metadata.get(&identifier);
                let severity = found.map_or(Severity::Low, |m| m.severity);
                let technique = found.map_or_else(String::new, |m| m.technique.clone());
                YaraMatch {
                    identifier,
                    severity,
                    technique,
                }
            })
            .collect())
    }
}

/// Reads and validates a compiled rule's required `meta:` fields: `severity`
/// (matching a [`Severity`] variant), `technique` (`T\d{4}` or `T\d{4}.\d{3}`), and
/// `falsepositives` (non-empty). Issue #73's metadata-schema requirement.
fn extract_metadata(rule: &yara_x::Rule) -> Result<RuleMetadata, YaraError> {
    let mut severity = None;
    let mut technique = None;
    let mut falsepositives = None;
    for (key, value) in rule.metadata() {
        let yara_x::MetaValue::String(s) = value else {
            continue;
        };
        match key {
            "severity" => severity = parse_severity(s),
            "technique" => technique = Some(s),
            "falsepositives" => falsepositives = Some(s),
            _ => {}
        }
    }

    let severity = severity.ok_or_else(|| {
        missing_metadata(
            rule.identifier(),
            "missing or invalid `severity` meta (expected low/medium/high/critical)".to_string(),
        )
    })?;

    let technique = match technique {
        Some(t) if is_technique(t) => t.to_string(),
        Some(t) => {
            return Err(missing_metadata(
                rule.identifier(),
                format!("invalid `technique` meta `{t}` (expected e.g. T1105 or T1059.004)"),
            ));
        }
        None => {
            return Err(missing_metadata(
                rule.identifier(),
                "missing `technique` meta".to_string(),
            ));
        }
    };

    match falsepositives {
        Some(fp) if !fp.trim().is_empty() => {}
        _ => {
            return Err(missing_metadata(
                rule.identifier(),
                "missing or empty `falsepositives` meta".to_string(),
            ));
        }
    }

    Ok(RuleMetadata {
        severity,
        technique,
    })
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Matches `T1234` or `T1234.001` (MITRE ATT&CK technique ID convention already used
/// in shipped YARA content).
fn is_technique(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('T') else {
        return false;
    };
    let mut parts = rest.splitn(2, '.');
    let Some(id) = parts.next() else {
        return false;
    };
    if id.len() != 4 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(sub) => sub.len() == 3 && sub.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn missing_metadata(identifier: &str, what: String) -> YaraError {
    YaraError::MissingMetadata {
        identifier: identifier.to_string(),
        what,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RULE: &str = r#"
rule test_marker {
    meta:
        severity = "high"
        technique = "T1105"
        falsepositives = "none known"
    strings:
        $m = "SYNTHAEA-TEST-MARKER"
    condition:
        $m
}
"#;

    fn ruleset_from(src: &str) -> RuleSet {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(src.as_bytes()).unwrap();
        RuleSet::from_compiled(compiler.build()).unwrap()
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
        let hits = rules.scan_file(&hit).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].identifier, "test_marker");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].technique, "T1105");
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

    #[cfg(unix)]
    #[test]
    fn a_file_the_requester_cannot_read_is_not_scanned_on_their_behalf() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let rules = ruleset_from(
            r#"
rule as_user {
    meta:
        severity = "high"
        technique = "T1105"
        falsepositives = "none known"
    strings:
        $m = "AS-USER-MARKER"
    condition:
        $m
}
"#,
        );
        let path = std::env::temp_dir().join(format!("yara-as-user-{}", std::process::id()));
        std::fs::write(&path, b"AS-USER-MARKER").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let owner = Requester {
            uid: meta.uid(),
            gid: meta.gid(),
        };
        let stranger = Requester {
            uid: 4_000_000,
            gid: 4_000_000,
        };

        // The agent itself can read it, and so can its owner; a stranger's request finds
        // nothing, as if the file had not matched.
        assert_eq!(rules.scan_file(&path).unwrap().len(), 1);
        assert_eq!(rules.scan_file_as(&path, owner).unwrap().len(), 1);
        assert!(rules.scan_file_as(&path, stranger).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
