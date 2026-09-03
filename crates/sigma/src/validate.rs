//! Load-time validation: every construct outside the supported subset is rejected
//! with an error naming exactly what is unsupported. Nothing is ever silently
//! never-matching at evaluation time — that failure mode is what this module kills.

use crate::eval::parse_field_spec;
use crate::rule::{Selection, SigmaRule, ValueList};

const SUPPORTED_FIELDS: &[&str] = &["image", "commandline", "parentimage"];
const SUPPORTED_MODIFIERS: &[&str] = &["contains", "startswith", "endswith"];

#[derive(Debug, thiserror::Error)]
pub enum SigmaError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid YAML in {path}: {source}")]
    Yaml {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("unsupported Sigma construct in {path}: {what}")]
    Unsupported { path: String, what: String },
}

/// Rejects any construct outside the supported subset, naming it precisely.
pub(crate) fn validate(rule: &SigmaRule, path: &str) -> Result<(), SigmaError> {
    validate_condition(rule, path)?;
    let Some(selection) = rule.detection.selections.get("selection") else {
        return Err(unsupported(path, "missing `selection` block".to_string()));
    };
    match selection {
        Selection::FieldMap(fields) => validate_field_map(fields, path),
        Selection::Keywords(keywords) => validate_keywords(keywords, path),
    }
}

fn validate_condition(rule: &SigmaRule, path: &str) -> Result<(), SigmaError> {
    let condition = rule.detection.condition.trim();
    if condition == "selection" {
        Ok(())
    } else {
        Err(unsupported(
            path,
            format!("condition `{condition}` (only `condition: selection` is supported)"),
        ))
    }
}

fn validate_field_map(
    fields: &std::collections::HashMap<String, ValueList>,
    path: &str,
) -> Result<(), SigmaError> {
    // An empty map would vacuously match EVERY event (Iterator::all on
    // nothing) — a malformed rule must never become an alert flood.
    if fields.is_empty() {
        return Err(unsupported(
            path,
            "empty selection (would match everything)".into(),
        ));
    }
    for (spec, values) in fields {
        let (field, modifier) = parse_field_spec(spec);
        if !SUPPORTED_FIELDS.contains(&field.to_lowercase().as_str()) {
            return Err(unsupported(
                path,
                format!("field `{field}` (supported: Image, CommandLine, ParentImage)"),
            ));
        }
        if let Some(m) = modifier
            && !SUPPORTED_MODIFIERS.contains(&m.to_lowercase().as_str())
        {
            return Err(unsupported(
                path,
                format!("modifier `{m}` (supported: contains, startswith, endswith)"),
            ));
        }
        // Interior wildcards are standard Sigma but outside the edge-only
        // subset — an accepted-but-never-matching rule is the silent-death
        // failure mode this validator exists to kill.
        if modifier.is_none() {
            for value in values.as_slice() {
                validate_edge_only_wildcard(value, path, "")?;
            }
        }
    }
    Ok(())
}

fn validate_keywords(keywords: &[String], path: &str) -> Result<(), SigmaError> {
    if keywords.is_empty() {
        return Err(unsupported(
            path,
            "empty keyword list (would match nothing)".into(),
        ));
    }
    for keyword in keywords {
        validate_edge_only_wildcard(keyword, path, "keyword ")?;
    }
    Ok(())
}

fn validate_edge_only_wildcard(value: &str, path: &str, kind: &str) -> Result<(), SigmaError> {
    let inner = value.trim_matches('*');
    if inner.contains('*') {
        return Err(unsupported(
            path,
            format!("interior wildcard in {kind}`{value}` (only leading/trailing `*`)"),
        ));
    }
    Ok(())
}

fn unsupported(path: &str, what: String) -> SigmaError {
    SigmaError::Unsupported {
        path: path.to_string(),
        what,
    }
}
