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
    let Some((modifier, all)) = parse_modifiers(parsed.modifiers) else {
        return false;
    };
    let field = parsed.field;
    let haystack: &str = if field.eq_ignore_ascii_case("image") {
        &event.image_path
    } else if field.eq_ignore_ascii_case("commandline") {
        &event.cmdline
    } else if field.eq_ignore_ascii_case("parentimage") {
        match &event.parent_image_path {
            Some(p) => p,
            None => return false,
        }
    } else {
        // Unreachable for validated rules; defensive for direct eval of a
        // hand-constructed rule.
        return false;
    };
    // Lowercased once per field, not once per listed value.
    let haystack = haystack.to_lowercase();
    let modifier = modifier.map(str::to_lowercase);
    let modifier = modifier.as_deref();

    match values {
        ValueList::Single(value) => match_value(&haystack, value, modifier),
        ValueList::Many(values) if all => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| match_value(&haystack, value, modifier))
        }
        ValueList::Many(values) => values
            .iter()
            .any(|value| match_value(&haystack, value, modifier)),
    }
}

/// The matching modifier and the `|all` flag of a field specification's modifiers: at most
/// one matching modifier, optionally followed by `all`. `None` for any other shape, which
/// evaluation treats as never matching. [`crate::validate`] refuses the same shapes with a
/// specific message; a test keeps the two in agreement.
pub(crate) fn parse_modifiers<'a>(
    mut modifiers: impl Iterator<Item = &'a str>,
) -> Option<(Option<&'a str>, bool)> {
    let mut matching = None;
    let mut all = false;
    if let Some(first) = modifiers.next() {
        if first.eq_ignore_ascii_case("all") {
            return None;
        }
        matching = Some(first);
        if let Some(second) = modifiers.next() {
            if !second.eq_ignore_ascii_case("all") || modifiers.next().is_some() {
                return None;
            }
            all = true;
        }
    }
    Some((matching, all))
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

/// Tests whether `haystack` matches `pattern` according to the Sigma modifier. The haystack
/// and the modifier arrive already lowercased (see `eval_field`): validation accepts
/// modifiers case-insensitively and evaluation must agree (`Image|EndsWith` loaded fine but
/// silently glob-matched before that was fixed).
fn match_value(haystack: &str, pattern: &str, modifier: Option<&str>) -> bool {
    let p = pattern.to_lowercase();
    match modifier {
        None => glob_match(haystack, &p),
        Some("contains") => haystack.contains(&p),
        Some("startswith") => haystack.starts_with(&p),
        Some("endswith") => haystack.ends_with(&p),
        _ => glob_match(haystack, &p),
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
