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
        let too_large = std::fs::metadata(path)
            .map(|meta| meta.len() > MAX_RULE_FILE_BYTES)
            .unwrap_or(false);
        if too_large {
            return Err(SigmaError::Io {
                path: display,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("rule file larger than {MAX_RULE_FILE_BYTES} bytes"),
                ),
            });
        }
        let content = std::fs::read_to_string(path).map_err(|source| SigmaError::Io {
            path: display.clone(),
            source,
        })?;
        let rule = parse_rule_yaml(&content).map_err(|error| SigmaError::Yaml {
            path: display.clone(),
            message: describe_yaml_error(&error),
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

/// A rule is a few dozen lines; anything near this is not one. Checked before the file is read.
const MAX_RULE_FILE_BYTES: u64 = 1024 * 1024;

/// The one place a rule's YAML text becomes a [`SigmaRule`] (the loader and the tests both
/// go through it, so a test exercises the parser settings the engine really runs with).
///
/// The parser is `serde-saphyr`, safe Rust, which replaced `serde_yaml` (and its
/// `unsafe-libyaml`, archived: RUSTSEC-2024-0449, #790). Rule files ship as signed content to
/// every agent and what the parser accepts is part of what a rule means, so **every option that
/// could change it is set explicitly**: a default that moves in a later release must not change
/// what a rule means. What they do, from a differential run over the shipped rules and a corpus
/// of edge cases (every shipped rule parsed identically):
/// - duplicate keys are an error (a second `selection:` used to win silently, which let a rule
///   be weakened without a trace), and so are merge keys (`<<`) and any tag the parser does not
///   recognise (a tag on a key is part of its identity for the duplicate check, so it could hide a
///   duplicate `selection`);
/// - a `!!binary` value stays the literal text it shows (`ignore_binary_tag_for_string`), as under
///   the old parser, instead of being base64-decoded into a value a reviewer cannot read;
/// - only the exact literals `true` and `false` are booleans (`strict_booleans`): an unquoted
///   `yes`, `no`, `on`, `off` or `y` stays the string it looks like. (Numbers such as `017`, `08`
///   or `1_000` were strings before and are integers now: such a rule is refused at load, loudly.)
/// - the budget is sized for a rule, not for a configuration file: a few thousand nodes, a
///   shallow depth and almost no aliases, with the parser's own defaults far looser;
/// - errors carry no source snippet, so a log line stays one line and does not hint at weakening
///   the duplicate-key policy.
pub(crate) fn parse_rule_yaml(content: &str) -> Result<SigmaRule, serde_saphyr::Error> {
    use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};
    // `Options` and `Budget` are non-exhaustive, hence the macros.
    let options = serde_saphyr::options! {
        strict_booleans: true,
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        reject_unsupported_tags: true,
        ignore_binary_tag_for_string: true,
        with_snippet: false,
        budget: serde_saphyr::budget! {
            max_events: 100_000,
            max_nodes: 20_000,
            max_depth: 16,
            max_aliases: 100,
            max_anchors: 100,
            max_total_scalar_bytes: 1024 * 1024,
        },
    };
    serde_saphyr::from_str_with_options(content, options)
}

/// The parser's message with the hints it adds for its own library users removed: a duplicate
/// key error ends with "set `DuplicateKeyPolicy` in `Options` if acceptable", which in a log line
/// next to a rule file reads as advice to weaken the policy. Kept on one line.
fn describe_yaml_error(error: &serde_saphyr::Error) -> String {
    let text = error.to_string().replace('\n', " ");
    match (text.find(", set "), text.find(" at line")) {
        (Some(hint), Some(end)) if hint < end && text[hint..end].contains("Options") => {
            format!("{}{}", &text[..hint], &text[end..])
        }
        _ => text,
    }
}
