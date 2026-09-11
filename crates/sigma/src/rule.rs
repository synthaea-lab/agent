//! Data structures for a parsed Sigma rule.

use std::collections::HashMap;

use serde::Deserialize;

/// Sigma rule as loaded from the YAML.
#[derive(Debug, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub detection: Detection,
}

/// `detection` block of a Sigma rule.
#[derive(Debug, Deserialize)]
pub struct Detection {
    /// Named selections: selection, selection1, filter, etc.
    #[serde(flatten)]
    pub selections: HashMap<String, Selection>,
    /// Condition expression: "selection", "selection1 and selection2", etc.
    pub condition: String,
}

/// A selection = map of field → list of values (OR between values).
/// Example:
/// ```yaml
/// selection:
///   Image|endswith: '\cmd.exe'
///   CommandLine|contains: 'payload'
/// ```
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Selection {
    /// Map of field → values
    FieldMap(HashMap<String, ValueList>),
    /// List of keywords
    Keywords(Vec<String>),
}

/// A Sigma value can be a scalar or a list (implicit OR).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ValueList {
    Single(String),
    Many(Vec<String>),
}

impl ValueList {
    #[must_use]
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            ValueList::Single(s) => vec![s.as_str()],
            ValueList::Many(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// Alert emitted when a Sigma rule matches.
#[derive(Debug, Clone)]
pub struct SigmaAlert {
    pub title: String,
    pub tags: Vec<String>,
    pub description: String,
}
