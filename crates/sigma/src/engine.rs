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
                        Err(e) => log::warn!("sigma rule skipped: {e}"),
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
        let rule: SigmaRule =
            serde_yaml::from_str(&content).map_err(|source| SigmaError::Yaml {
                path: display.clone(),
                source,
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
}
