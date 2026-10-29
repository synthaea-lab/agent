//! Load-time validation: every construct outside the supported subset is rejected
//! with an error naming exactly what is unsupported. Nothing is ever silently
//! never-matching at evaluation time — that failure mode is what this module kills.

use crate::{
    eval::parse_field_spec,
    rule::{Selection, SigmaRule, ValueList},
};

const SUPPORTED_FIELDS: &[&str] = &[
    "image",
    "commandline",
    "parentimage",
    "originalfilename",
    "company",
    "description",
    "product",
];
/// [`SUPPORTED_FIELDS`] as the error message spells them.
const SUPPORTED_FIELD_NAMES: &str =
    "Image, CommandLine, ParentImage, OriginalFileName, Company, Description, Product";
const SUPPORTED_MODIFIERS: &[&str] = &["contains", "startswith", "endswith"];

/// `OriginalFileName`, `Company`, `Description` and `Product` are PE version-resource
/// metadata (issues #983, #719): a Windows/PE concept with no Mach-O or ELF equivalent.
/// A `linux/` or `macos/` rule using one would never match on the platforms that load
/// it — the exact silent-death failure mode this module exists to kill (its own module
/// doc) — so it is refused at load time there, the same way `validate_metadata` already
/// refuses a rule outside any known platform directory. A Windows-platform rule using
/// one is accepted even though a *particular* event may still lack the value (PE parse
/// failure, no version resource): that per-event gap is the same posture as
/// `ParentImage`, not a load-time refusal (see `eval::Haystacks::get`'s doc).
const WINDOWS_ONLY_FIELDS: &[&str] = &["originalfilename", "company", "description", "product"];

/// The one `logsource` category the fields above are mapped for: every supported field is read
/// from an `ExecEvent`.
const SUPPORTED_CATEGORY: &str = "process_creation";

#[derive(Debug, thiserror::Error)]
pub enum SigmaError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid YAML in {path}: {message}")]
    Yaml {
        path: String,
        /// The parser's message on one line: see `engine::describe_yaml_error`.
        message: String,
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
///
/// The platform directory is looked for in the whole of `path`: use [`validate_under`] when the
/// rules root is known, so a word in the content root's own path cannot pass for a platform.
pub(crate) fn validate(rule: &SigmaRule, path: &str) -> Result<(), SigmaError> {
    let normalized = path.replace('\\', "/");
    // The innermost platform directory: `.../windows/x/linux/rule.yml` is a Linux rule.
    let platform = KNOWN_PLATFORMS
        .iter()
        .filter_map(|p| normalized.rfind(&format!("/{p}/")).map(|at| (at, *p)))
        .max_by_key(|(at, _)| *at)
        .map(|(_, p)| p);
    validate_with(rule, path, platform)
}

/// [`validate`] for a rule found at `relative` (`/` or `\` separated) under the rules root: the
/// platform is the first directory of that relative path, nothing in the root's own path (#980).
pub(crate) fn validate_under(
    rule: &SigmaRule,
    path: &str,
    relative: &str,
) -> Result<(), SigmaError> {
    let normalized = relative.replace('\\', "/");
    let mut parts = normalized.split('/');
    // The file name is not a directory: a rule directly under the root has no platform.
    let platform = parts.next().and_then(|first| {
        parts.next()?;
        KNOWN_PLATFORMS.iter().copied().find(|p| *p == first)
    });
    validate_with(rule, path, platform)
}

/// `platform` is the rule's platform directory (one of [`KNOWN_PLATFORMS`]), `None` when it is
/// under none.
fn validate_with(
    rule: &SigmaRule,
    path: &str,
    platform: Option<&'static str>,
) -> Result<(), SigmaError> {
    // First: a rule written for other telemetry is refused for that, not for the fields that
    // telemetry has and an `ExecEvent` does not.
    validate_logsource(rule, path, platform)?;
    let compiled = validate_condition(rule, path)?;
    // Every block the condition refers to is checked as strictly as `selection` always was. A
    // block it does not refer to is never evaluated and stays unchecked, as before.
    for name in &compiled.blocks {
        // `compile` resolved every name against the rule's blocks.
        let Some(block) = rule.detection.selections.get(name) else {
            return Err(unsupported(path, format!("missing `{name}` block")));
        };
        let checked = match block {
            Selection::FieldMap(fields) => validate_field_map(fields, path, platform),
            Selection::OrOfMaps(maps) => validate_or_of_maps(maps, path, platform),
            Selection::Keywords(keywords) => validate_keywords(keywords, path),
        };
        // The message of the one block every rule used to have is unchanged; the others say
        // which block they are about.
        checked.map_err(|error| match error {
            SigmaError::Unsupported { path, what } if name != "selection" => {
                SigmaError::Unsupported {
                    path,
                    what: format!("{what} (in block `{name}`)"),
                }
            }
            other => other,
        })?;
    }
    validate_metadata(rule, path, platform.is_some())
}

/// Checks `logsource` (#719). Every supported field is read from an `ExecEvent`, so the engine
/// evaluates every rule against process creations: a rule written for another category or a
/// log channel would be evaluated against the wrong events, and is refused. An absent
/// `logsource` is `process_creation`. A `product` must name the rule's own platform directory;
/// with no platform directory, `validate_metadata` refuses the rule.
fn validate_logsource(
    rule: &SigmaRule,
    path: &str,
    platform: Option<&'static str>,
) -> Result<(), SigmaError> {
    let Some(logsource) = &rule.logsource else {
        return Ok(());
    };
    if let Some(service) = &logsource.service {
        return Err(unsupported(
            path,
            format!(
                "logsource `service: {service}` (log channels are not mapped; only `category: \
                 {SUPPORTED_CATEGORY}` is)"
            ),
        ));
    }
    match &logsource.category {
        Some(category) if category.eq_ignore_ascii_case(SUPPORTED_CATEGORY) => {}
        Some(category) => {
            return Err(unsupported(
                path,
                format!("logsource `category: {category}` (only `{SUPPORTED_CATEGORY}` is mapped)"),
            ));
        }
        None => {
            return Err(unsupported(
                path,
                format!("logsource without a `category` (only `{SUPPORTED_CATEGORY}` is mapped)"),
            ));
        }
    }
    match (&logsource.product, platform) {
        (Some(product), Some(platform)) if !product.eq_ignore_ascii_case(platform) => {
            Err(unsupported(
                path,
                format!(
                    "logsource `product: {product}` in a rule under `{platform}/` (the product \
                     must be the rule's platform directory)"
                ),
            ))
        }
        _ => Ok(()),
    }
}

/// Checks the required rule metadata: severity (`level`, upstream Sigma's field
/// name), at least one ATT&CK technique tag, non-empty false-positive notes, and
/// a recognized platform directory.
fn validate_metadata(rule: &SigmaRule, path: &str, under_platform: bool) -> Result<(), SigmaError> {
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
    if !under_platform {
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

/// Parses the condition (see [`crate::condition`]) and refuses a `timeframe`, which only an
/// aggregation gives a meaning to.
fn validate_condition<'a>(
    rule: &'a SigmaRule,
    path: &str,
) -> Result<&'a crate::condition::Compiled, SigmaError> {
    let condition = rule.detection.condition.trim();
    let compiled = rule.compiled().as_ref().map_err(|reason| {
        unsupported(
            path,
            format!(
                "condition `{condition}`: {reason} (supported: and, or, not, parentheses, \
                 `1 of` / `all of` a block, a `prefix*` pattern or `them`)"
            ),
        )
    })?;
    if let Some(timeframe) = &rule.detection.timeframe {
        return Err(unsupported(
            path,
            format!(
                "`timeframe: {timeframe}` (only meaningful with an aggregation, which is not supported)"
            ),
        ));
    }
    Ok(compiled)
}

fn validate_field_map(
    fields: &std::collections::HashMap<String, ValueList>,
    path: &str,
    platform: Option<&'static str>,
) -> Result<(), SigmaError> {
    // An empty map would vacuously match EVERY event (Iterator::all on
    // nothing) — a malformed rule must never become an alert flood.
    if fields.is_empty() {
        return Err(unsupported(
            path,
            "empty selection (would match everything)".into(),
        ));
    }
    // Two keys that differ only by case are different keys to the parser, and evaluation ANDs
    // them. Keep the original spelling so the error can name both keys.
    let mut seen = std::collections::HashMap::new();
    for spec in fields.keys() {
        if let Some(previous) = seen.insert(spec.to_lowercase(), spec) {
            return Err(unsupported(
                path,
                format!("field specs `{previous}` and `{spec}` differ only by case"),
            ));
        }
    }
    for (spec, values) in fields {
        let parsed = parse_field_spec(spec);
        let field = parsed.field;
        let field_lower = field.to_lowercase();
        if !SUPPORTED_FIELDS.contains(&field_lower.as_str()) {
            return Err(unsupported(
                path,
                format!("field `{field}` (supported: {SUPPORTED_FIELD_NAMES})"),
            ));
        }
        if WINDOWS_ONLY_FIELDS.contains(&field_lower.as_str()) && platform != Some("windows") {
            return Err(unsupported(
                path,
                format!(
                    "field `{field}` is Windows-only (PE version-resource metadata, issue #983); \
                     this rule is not under a `windows/` directory and would never match there"
                ),
            ));
        }
        let mut match_modifier = None;
        let mut seen_all = false;
        for modifier in parsed.modifiers.clone() {
            if modifier.eq_ignore_ascii_case("all") {
                if seen_all {
                    return Err(unsupported(
                        path,
                        format!("duplicate `all` modifier in `{spec}`"),
                    ));
                }
                seen_all = true;
            } else {
                if !SUPPORTED_MODIFIERS.contains(&modifier.to_lowercase().as_str()) {
                    return Err(unsupported(
                        path,
                        format!(
                            "modifier `{modifier}` (supported: contains, startswith, endswith, all)"
                        ),
                    ));
                }
                if match_modifier.replace(modifier).is_some() {
                    return Err(unsupported(
                        path,
                        format!(
                            "multiple matching modifiers in `{spec}`; only one of contains, startswith, endswith is supported"
                        ),
                    ));
                }
            }
        }
        if seen_all
            && parsed
                .modifiers
                .clone()
                .next_back()
                .is_some_and(|modifier| !modifier.eq_ignore_ascii_case("all"))
        {
            return Err(unsupported(
                path,
                format!("modifier `all` must be last in `{spec}`"),
            ));
        }
        if seen_all && match_modifier.is_none() {
            return Err(unsupported(
                path,
                format!("modifier `all` in `{spec}` must follow one matching modifier"),
            ));
        }
        if values.as_slice().is_empty() {
            return Err(unsupported(path, format!("empty value list for `{spec}`")));
        }
        // Interior wildcards are standard Sigma but outside the edge-only
        // subset — an accepted-but-never-matching rule is the silent-death
        // failure mode this validator exists to kill.
        if match_modifier.is_none() {
            for value in values.as_slice() {
                validate_edge_only_wildcard(value, path, "")?;
            }
        }
    }
    Ok(())
}

/// Validates a selection written as a list of maps (issue #982): OR between the maps, so an
/// empty list matches nothing (the dual of the empty-map check in `validate_field_map`, which
/// matches everything) — both are load errors, never a silent always/never-match. Each map gets
/// exactly `validate_field_map`'s checks, so a list-of-maps selection is refused as loudly as a
/// lone map for an unsupported field, modifier, or interior wildcard.
fn validate_or_of_maps(
    maps: &[std::collections::HashMap<String, ValueList>],
    path: &str,
    platform: Option<&'static str>,
) -> Result<(), SigmaError> {
    if maps.is_empty() {
        return Err(unsupported(
            path,
            "empty selection list (would match nothing)".into(),
        ));
    }
    for fields in maps {
        validate_field_map(fields, path, platform)?;
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
