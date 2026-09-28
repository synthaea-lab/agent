//! Data structures for a parsed Sigma rule.

use std::collections::HashMap;

use schema::detection::Severity;
use serde::{Deserialize, Deserializer};

/// Sigma rule as loaded from the YAML.
#[derive(Debug, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Required by `validate()` for any rule shipped through
    /// [`crate::SigmaEngine::load_rule`] — `Option` here (rather than a plain
    /// required field) so a missing value is one validation error among several,
    /// not a deserialize failure that would also break every hand-parsed YAML
    /// fixture in unit tests that don't care about metadata.
    ///
    /// Upstream Sigma's field is `level` (review, Jihair54/Sollykhan), not
    /// `severity` — `informational`/`low`/`medium`/`high`/`critical`. This crate
    /// targets sigmahq.io and already keeps `falsepositives` for that
    /// compatibility reason; a rule shipped as `severity:` instead was
    /// non-standard and would reject any real `SigmaHQ` rule as-is. `severity`
    /// stays this crate's own name for the mapped value (matching
    /// `schema::detection::Severity` used everywhere else); `informational`
    /// maps to `Low`, the closest existing rung.
    #[serde(default, rename = "level", deserialize_with = "deserialize_level")]
    pub severity: Option<Severity>,
    /// Upstream Sigma field name. Required non-empty by `validate()`.
    #[serde(default)]
    pub falsepositives: Vec<String>,
    pub detection: Detection,
}

/// Maps upstream Sigma's `level` string onto `schema::detection::Severity`.
/// `informational` (the one upstream rung with no direct match) becomes `Low`.
/// An unrecognized non-empty value is a deserialize error, not a silent `None`
/// — a typo in `level:` must surface as "bad value", not be indistinguishable
/// from a rule that never set it at all.
fn deserialize_level<'de, D>(deserializer: D) -> Result<Option<Severity>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match raw.to_lowercase().as_str() {
        "informational" | "low" => Ok(Some(Severity::Low)),
        "medium" => Ok(Some(Severity::Medium)),
        "high" => Ok(Some(Severity::High)),
        "critical" => Ok(Some(Severity::Critical)),
        other => Err(serde::de::Error::custom(format!(
            "unrecognized Sigma `level` value `{other}` (expected \
             informational/low/medium/high/critical)"
        ))),
    }
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
    pub severity: Severity,
    /// ATT&CK technique ids (`T1234`, `T1234.001`) extracted from `tags`, normalized
    /// to bare uppercase form — issue #74. `tags` keeps the full raw list (tactic
    /// tags included); this is the filtered, structured subset of it.
    pub techniques: Vec<String>,
}
