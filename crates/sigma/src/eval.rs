//! Evaluation of validated rules against events. Everything here assumes the rule
//! passed [`crate::validate`] — the defensive `false` arms exist only for direct
//! evaluation of hand-constructed rules in tests.

use schema::{ExecEvent, detection::Severity};

use crate::{
    rule::{Selection, SigmaAlert, SigmaRule, ValueList},
    validate::technique_id,
};

/// Evaluates a validated rule against an `ExecEvent`.
pub(crate) fn eval_rule_exec(rule: &SigmaRule, event: &ExecEvent) -> Option<SigmaAlert> {
    let selection = rule.detection.selections.get("selection")?;
    if eval_selection_exec(selection, event) {
        Some(SigmaAlert {
            title: rule.title.clone(),
            tags: rule.tags.clone(),
            description: rule.description.clone(),
            // `validate()` rejects a missing severity for anything shipped through
            // `SigmaEngine::load_rule` — the fallback only fires for a
            // hand-constructed rule evaluated directly in a test.
            severity: rule.severity.unwrap_or(Severity::Low),
            techniques: rule.tags.iter().filter_map(|t| technique_id(t)).collect(),
        })
    } else {
        None
    }
}

/// Evaluates a selection against an `ExecEvent`.
fn eval_selection_exec(selection: &Selection, event: &ExecEvent) -> bool {
    match selection {
        Selection::FieldMap(fields) => {
            // Implicit AND between fields
            fields
                .iter()
                .all(|(field_spec, values)| eval_field(field_spec, values, event))
        }
        Selection::Keywords(keywords) => eval_keywords(keywords, &event.cmdline),
    }
}

/// OR over the full command line; keywords share the field values' wildcard
/// semantics (`*mimikatz*` must strip its stars, not be matched literally). A bare
/// keyword means substring containment.
fn eval_keywords(keywords: &[String], cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    keywords.iter().any(|kw| {
        let k = kw.to_lowercase();
        if k.contains('*') {
            glob_match(&lower, &k)
        } else {
            lower.contains(&k)
        }
    })
}

/// Evaluates one Sigma field. `ParentImage` matches only when the sensor provided
/// lineage (see `schema::ExecEvent::parent_image_path`).
fn eval_field(field_spec: &str, values: &ValueList, event: &ExecEvent) -> bool {
    let parsed = parse_field_spec(field_spec);
    let mut modifiers = parsed.modifiers;
    let mut modifier = None;
    let mut all = false;
    if let Some(first) = modifiers.next() {
        if first.eq_ignore_ascii_case("all") {
            return false;
        }
        modifier = Some(first);
        if let Some(second) = modifiers.next() {
            if !second.eq_ignore_ascii_case("all") || modifiers.next().is_some() {
                return false;
            }
            all = true;
        }
    }
    let field = parsed.field;
    let haystack: &str = match field.to_lowercase().as_str() {
        "image" => &event.image_path,
        "commandline" => &event.cmdline,
        "parentimage" => match &event.parent_image_path {
            Some(p) => p,
            None => return false,
        },
        // Unreachable for validated rules; defensive for direct eval of a
        // hand-constructed rule.
        _ => return false,
    };

    match values {
        ValueList::Single(value) => match_value(haystack, value, modifier),
        ValueList::Many(values) if all => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| match_value(haystack, value, modifier))
        }
        ValueList::Many(values) => values
            .iter()
            .any(|value| match_value(haystack, value, modifier)),
    }
}

/// Parses a field specification into its field name and modifiers without allocating.
pub(crate) fn parse_field_spec(spec: &str) -> ParsedFieldSpec<'_> {
    let mut parts = spec.split('|');
    let field = parts.next().unwrap_or(spec);
    ParsedFieldSpec {
        field,
        modifiers: parts,
    }
}

pub(crate) struct ParsedFieldSpec<'a> {
    pub field: &'a str,
    pub modifiers: std::str::Split<'a, char>,
}

/// Tests whether `haystack` matches `pattern` according to the Sigma modifier.
fn match_value(haystack: &str, pattern: &str, modifier: Option<&str>) -> bool {
    let h = haystack.to_lowercase();
    let p = pattern.to_lowercase();
    // Validation accepts modifiers case-insensitively; evaluation must agree
    // (`Image|EndsWith` loaded fine but silently glob-matched before this).
    match modifier.map(str::to_lowercase).as_deref() {
        None => glob_match(&h, &p),
        Some("contains") => h.contains(&p),
        Some("startswith") => h.starts_with(&p),
        Some("endswith") => h.ends_with(&p),
        _ => glob_match(&h, &p),
    }
}

/// Minimal wildcard glob: `*` at the start/end only.
pub(crate) fn glob_match(haystack: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let starts_star = pattern.starts_with('*');
    let ends_star = pattern.ends_with('*');
    let inner = pattern.trim_matches('*');
    match (starts_star, ends_star) {
        (true, true) => haystack.contains(inner),
        (true, false) => haystack.ends_with(inner),
        (false, true) => haystack.starts_with(inner),
        (false, false) => haystack == pattern,
    }
}
