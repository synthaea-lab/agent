//! Loading of Sigma rules: directory walk, parse, and hand-off to load-time
//! validation (`crate::validate`). Evaluation lives in `crate::eval`.

use std::path::Path;

use schema::ExecEvent;

pub use crate::validate::SigmaError;
use crate::{
    eval::eval_rule_exec,
    rule::{SigmaAlert, SigmaRule},
    validate::validate,
};

/// Sigma engine: set of loaded, validated rules, ready to evaluate.
pub struct SigmaEngine {
    rules: Vec<SigmaRule>,
}

impl SigmaEngine {
    /// Loads all `.yml` / `.yaml` rules from a directory tree (recursive — content
    /// convention is `rules/sigma/<platform>/...`). Rules that fail to parse or use
    /// unsupported constructs are skipped with a warning naming the reason; the
    /// engine loads the rest.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError::Io`] when the directory tree itself cannot be read —
    /// individual bad rules are skipped, not errors.
    pub fn load_dir(dir: &Path) -> Result<Self, SigmaError> {
        let mut rules = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let entries = std::fs::read_dir(&d).map_err(|source| SigmaError::Io {
                path: d.display().to_string(),
                source,
            })?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                    match Self::load_rule(&path) {
                        Ok(rule) => rules.push(rule),
                        Err(e) => tracing::warn!(error = %e, "sigma rule skipped"),
                    }
                }
            }
        }
        Ok(Self { rules })
    }

    /// Loads and validates one rule from a YAML file.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError::Io`] when the file cannot be read, [`SigmaError::Yaml`]
    /// on invalid YAML, and [`SigmaError::Unsupported`] when the rule uses
    /// constructs this engine rejects at validation.
    pub fn load_rule(path: &Path) -> Result<SigmaRule, SigmaError> {
        let display = path.display().to_string();
        let content = std::fs::read_to_string(path).map_err(|source| SigmaError::Io {
            path: display.clone(),
            source,
        })?;
        let rule = parse_rule_yaml(&content).map_err(|source| SigmaError::Yaml {
            path: display.clone(),
            source: Box::new(source),
        })?;
        validate(&rule, &display)?;
        Ok(rule)
    }

    /// Evaluates all loaded rules against an `ExecEvent`.
    #[must_use]
    pub fn eval_exec(&self, event: &ExecEvent) -> Vec<SigmaAlert> {
        self.rules
            .iter()
            .filter_map(|rule| eval_rule_exec(rule, event))
            .collect()
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Titles of every loaded rule, in load order. Lets a caller (the content
    /// test suite's sample-pairing checks) assert against the actual rule set
    /// rather than only its size — a count match alone (review, Jihair54/
    /// Sollykhan) can't catch a renamed or swapped rule keeping a stale sample
    /// label.
    #[must_use]
    pub fn rule_titles(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.title.as_str()).collect()
    }
}

/// The one place a rule's YAML text becomes a [`SigmaRule`] (the loader and the tests both
/// go through it, so a test exercises the parser settings the engine really runs with).
///
/// The parser is `serde-saphyr`, safe Rust, which replaced `serde_yaml` (and its
/// `unsafe-libyaml`, archived: RUSTSEC-2024-0449, #790). What it does with the same input,
/// from a differential run over the shipped rules and a corpus of edge cases (every shipped
/// rule parsed identically):
/// - **duplicate keys are an error** (a second `selection:` used to win silently, which let a
///   rule be weakened without a trace), as is a duplicate top-level `title`;
/// - an alias bomb is refused by the parser's budget instead of being expanded;
/// - a UTF-8 byte-order mark is accepted;
/// - merge keys (`<<`) and tags the parser does not know are errors, and a `!!binary` value
///   stays the literal text it shows (`merge_keys`, `reject_unsupported_tags`,
///   `ignore_binary_tag_for_string`): none of them may change what a rule matches unseen;
/// - only the exact literals `true` and `false` are booleans (`strict_booleans`), as before:
///   an unquoted `yes`, `no`, `on`, `off` or `y` stays the string it looks like. Without the
///   option the new parser reads them as YAML 1.1 booleans and the rule would fail to load.
pub(crate) fn parse_rule_yaml(content: &str) -> Result<SigmaRule, serde_saphyr::Error> {
    // Set explicitly: a default that moves in a later release must not change what a rule
    // means, and rule files ship as signed content to every agent. (`Options` is
    // non-exhaustive, hence the macro.)
    let options = serde_saphyr::options! {
        strict_booleans: true,
        duplicate_keys: serde_saphyr::options::DuplicateKeyPolicy::Error,
        // `<<` would resolve a duplicate silently (a merged field or selection is
        // overridden without an error), the same hole the duplicate-key policy closes.
        merge_keys: serde_saphyr::options::MergeKeyPolicy::Error,
        // A tag on a key (`!x selection:`) otherwise escapes the duplicate check and the
        // last one wins; custom tags have no meaning in a rule.
        reject_unsupported_tags: true,
        // `!!binary` would base64-decode a matched value, hiding it from a reviewer.
        ignore_binary_tag_for_string: true,
    };
    serde_saphyr::from_str_with_options(content, options)
}
