//! Load-time validation: every construct outside the supported subset is rejected
//! with an error naming exactly what is unsupported. Nothing is ever silently
//! never-matching at evaluation time — that failure mode is what this module kills.

use crate::{
    eval::parse_field_spec,
    rule::{Selection, SigmaRule, ValueList},
};

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
    #[error("missing or invalid rule metadata in {path}: {what}")]
    MissingMetadata { path: String, what: String },
}

/// Platforms `rules/sigma/` is organized by (issue #73: platform is derived from the
/// directory, not a redundant YAML field).
const KNOWN_PLATFORMS: &[&str] = &["linux", "windows", "macos"];

/// Rejects any construct outside the supported subset, naming it precisely, and any
/// rule missing the required metadata (issue #73: severity, ATT&CK technique,
/// false-positive notes, platform).
pub(crate) fn validate(rule: &SigmaRule, path: &str) -> Result<(), SigmaError> {
    validate_condition(rule, path)?;
    let Some(selection) = rule.detection.selections.get("selection") else {
        return Err(unsupported(path, "missing `selection` block".to_string()));
    };
    match selection {
        Selection::FieldMap(fields) => validate_field_map(fields, path)?,
        Selection::Keywords(keywords) => validate_keywords(keywords, path)?,
    }
    validate_metadata(rule, path)
}

/// Checks the required rule metadata: severity (`level`, upstream Sigma's field
/// name), at least one ATT&CK technique tag, non-empty false-positive notes, and
/// a recognized platform directory.
fn validate_metadata(rule: &SigmaRule, path: &str) -> Result<(), SigmaError> {
    if rule.severity.is_none() {
        return Err(missing_metadata(path, "missing `level`".to_string()));
    }
    if rule.falsepositives.is_empty() {
        return Err(missing_metadata(
            path,
            "missing `falsepositives` (must list at least one known FP scenario, or explain why none are known)".to_string(),
        ));
    }
    if !rule.tags.iter().any(|t| technique_id(t).is_some()) {
        return Err(missing_metadata(
            path,
            "no ATT&CK technique tag in `tags` (expected e.g. `attack.t1059.004`)".to_string(),
        ));
    }
    let normalized = path.replace('\\', "/");
    if !KNOWN_PLATFORMS
        .iter()
        .any(|p| normalized.contains(&format!("/{p}/")))
    {
        return Err(missing_metadata(
            path,
            format!(
                "not under a known platform directory ({})",
                KNOWN_PLATFORMS.join("/")
            ),
        ));
    }
    Ok(())
}

/// Matches Sigma's `attack.t<technique>[.<sub-technique>]` tag convention, e.g.
/// `attack.t1059.004` or `attack.t1105`, and returns the normalized bare form
/// (`T1059.004`). `pub(crate)`: also used by `crate::eval` to extract
/// `SigmaAlert.techniques` from the raw tag list (issue #74) — one parser, so
/// validation and extraction can never disagree on what counts as a technique tag.
pub(crate) fn technique_id(tag: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let rest = lower.strip_prefix("attack.t")?;
    let mut parts = rest.splitn(2, '.');
    let id = parts.next()?;
    if id.len() != 4 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match parts.next() {
        None => Some(format!("T{id}")),
        Some(sub) if sub.len() == 3 && sub.bytes().all(|b| b.is_ascii_digit()) => {
            Some(format!("T{id}.{sub}"))
        }
        Some(_) => None,
    }
}

fn missing_metadata(path: &str, what: String) -> SigmaError {
    SigmaError::MissingMetadata {
        path: path.to_string(),
        what,
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
