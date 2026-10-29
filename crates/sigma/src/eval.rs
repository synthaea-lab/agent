//! Evaluation of validated rules against events. Everything here assumes the rule
//! passed [`crate::validate`] — the defensive `false` arms exist only for direct
//! evaluation of hand-constructed rules in tests.

use std::cell::OnceCell;

use schema::{ExecEvent, detection::Severity};

use crate::{
    rule::{Selection, SigmaAlert, SigmaRule, ValueList},
    validate::technique_id,
};

/// Evaluates a validated rule against an `ExecEvent`: its condition over its blocks. A rule
/// whose condition is outside the grammar (never validated) matches nothing.
pub(crate) fn eval_rule_exec(rule: &SigmaRule, event: &ExecEvent) -> Option<SigmaAlert> {
    let Ok(compiled) = rule.compiled() else {
        return None;
    };
    let haystacks = Haystacks::new(event);
    let matched = compiled.eval(|index| {
        rule.detection
            .selections
            .get(&compiled.blocks[index])
            .is_some_and(|selection| eval_selection_exec(selection, event, &haystacks))
    });
    if matched {
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

/// The lowercased fields of one event, each made at most once however many blocks and field
/// specifications read it: a condition over many blocks costs three allocations, not one per
/// field specification.
struct Haystacks<'a> {
    event: &'a ExecEvent,
    image: OnceCell<String>,
    cmdline: OnceCell<String>,
    parent_image: OnceCell<Option<String>>,
    original_file_name: OnceCell<Option<String>>,
    company: OnceCell<Option<String>>,
    description: OnceCell<Option<String>>,
    product: OnceCell<Option<String>>,
}

impl<'a> Haystacks<'a> {
    fn new(event: &'a ExecEvent) -> Self {
        Self {
            event,
            image: OnceCell::new(),
            cmdline: OnceCell::new(),
            parent_image: OnceCell::new(),
            original_file_name: OnceCell::new(),
            company: OnceCell::new(),
            description: OnceCell::new(),
            product: OnceCell::new(),
        }
    }

    /// The lowercased value of a supported field; `None` for `ParentImage` when the sensor
    /// provided no lineage, for the PE version-resource fields (`OriginalFileName`, `Company`,
    /// `Description`, `Product`) when enrichment found none (no PE version resource, parse
    /// failure, or the image was over `enrich`'s size budget — #983), and for a field no
    /// validated rule uses.
    fn get(&self, field: &str) -> Option<&str> {
        let event = self.event;
        if field.eq_ignore_ascii_case("image") {
            Some(self.image.get_or_init(|| event.image_path.to_lowercase()))
        } else if field.eq_ignore_ascii_case("commandline") {
            Some(self.cmdline.get_or_init(|| event.cmdline.to_lowercase()))
        } else if field.eq_ignore_ascii_case("parentimage") {
            lowered(&self.parent_image, event.parent_image_path.as_deref())
        } else if field.eq_ignore_ascii_case("originalfilename") {
            lowered(
                &self.original_file_name,
                event.original_file_name.as_deref(),
            )
        } else if field.eq_ignore_ascii_case("company") {
            lowered(&self.company, event.company_name.as_deref())
        } else if field.eq_ignore_ascii_case("description") {
            lowered(&self.description, event.file_description.as_deref())
        } else if field.eq_ignore_ascii_case("product") {
            lowered(&self.product, event.product_name.as_deref())
        } else {
            None
        }
    }
}

/// `value` lowercased, made once into `cell`.
fn lowered<'c>(cell: &'c OnceCell<Option<String>>, value: Option<&str>) -> Option<&'c str> {
    cell.get_or_init(|| value.map(str::to_lowercase)).as_deref()
}

/// Evaluates a selection against an `ExecEvent`.
fn eval_selection_exec(
    selection: &Selection,
    event: &ExecEvent,
    haystacks: &Haystacks<'_>,
) -> bool {
    match selection {
        Selection::FieldMap(fields) => eval_field_map(fields, haystacks),
        // OR between the maps; each one keeps `FieldMap`'s implicit AND between fields.
        Selection::OrOfMaps(maps) => maps.iter().any(|fields| eval_field_map(fields, haystacks)),
        Selection::Keywords(keywords) => eval_keywords(keywords, &event.cmdline),
    }
}

/// Implicit AND between a map's fields — the body shared by `FieldMap` and every element of
/// `OrOfMaps`.
fn eval_field_map(
    fields: &std::collections::HashMap<String, ValueList>,
    haystacks: &Haystacks<'_>,
) -> bool {
    fields
        .iter()
        .all(|(field_spec, values)| eval_field(field_spec, values, haystacks))
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
fn eval_field(field_spec: &str, values: &ValueList, haystacks: &Haystacks<'_>) -> bool {
    let parsed = parse_field_spec(field_spec);
    let Some((modifier, all)) = parse_modifiers(parsed.modifiers) else {
        return false;
    };
    // `None`: no lineage, or (unreachable for validated rules; defensive for direct eval of a
    // hand-constructed rule) a field this engine does not know.
    let Some(haystack) = haystacks.get(parsed.field) else {
        return false;
    };
    let modifier = modifier.map(str::to_lowercase);
    let modifier = modifier.as_deref();

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
