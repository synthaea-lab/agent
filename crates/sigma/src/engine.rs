//! Loading, validation, and evaluation of Sigma rules.
//!
//! Validation happens at load time: every selection field, modifier, and the
//! condition are checked against the supported subset, and a rule outside it is an
//! error naming exactly what is unsupported. `load_dir` logs and skips such rules
//! (the agent keeps running with the rest), but nothing is ever silently
//! never-matching at evaluation time.

use std::path::Path;

use schema::ExecEvent;

use crate::rule::{Selection, SigmaAlert, SigmaRule, ValueList};

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

const SUPPORTED_FIELDS: &[&str] = &["image", "commandline", "parentimage"];
const SUPPORTED_MODIFIERS: &[&str] = &["contains", "startswith", "endswith"];

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

/// Rejects any construct outside the supported subset, naming it precisely.
fn validate(rule: &SigmaRule, path: &str) -> Result<(), SigmaError> {
    let unsupported = |what: String| SigmaError::Unsupported {
        path: path.to_string(),
        what,
    };
    let condition = rule.detection.condition.trim();
    if condition != "selection" {
        return Err(unsupported(format!(
            "condition `{condition}` (only `condition: selection` is supported)"
        )));
    }
    let Some(selection) = rule.detection.selections.get("selection") else {
        return Err(unsupported("missing `selection` block".to_string()));
    };
    match selection {
        Selection::FieldMap(fields) => {
            // An empty map would vacuously match EVERY event (Iterator::all on
            // nothing) — a malformed rule must never become an alert flood.
            if fields.is_empty() {
                return Err(unsupported(
                    "empty selection (would match everything)".into(),
                ));
            }
            for (spec, values) in fields {
                let (field, modifier) = parse_field_spec(spec);
                if !SUPPORTED_FIELDS.contains(&field.to_lowercase().as_str()) {
                    return Err(unsupported(format!(
                        "field `{field}` (supported: Image, CommandLine, ParentImage)"
                    )));
                }
                if let Some(m) = modifier
                    && !SUPPORTED_MODIFIERS.contains(&m.to_lowercase().as_str())
                {
                    return Err(unsupported(format!(
                        "modifier `{m}` (supported: contains, startswith, endswith)"
                    )));
                }
                // Interior wildcards are standard Sigma but outside the edge-only
                // subset — an accepted-but-never-matching rule is the silent-death
                // failure mode this validator exists to kill.
                if modifier.is_none() {
                    for value in values.as_slice() {
                        let inner = value.trim_matches('*');
                        if inner.contains('*') {
                            return Err(unsupported(format!(
                                "interior wildcard in `{value}` (only leading/trailing `*`)"
                            )));
                        }
                    }
                }
            }
        }
        Selection::Keywords(keywords) => {
            if keywords.is_empty() {
                return Err(unsupported(
                    "empty keyword list (would match nothing)".into(),
                ));
            }
            for keyword in keywords {
                let inner = keyword.trim_matches('*');
                if inner.contains('*') {
                    return Err(unsupported(format!(
                        "interior wildcard in keyword `{keyword}`"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Evaluates a validated rule against an `ExecEvent`.
fn eval_rule_exec(rule: &SigmaRule, event: &ExecEvent) -> Option<SigmaAlert> {
    let selection = rule.detection.selections.get("selection")?;
    if eval_selection_exec(selection, event) {
        Some(SigmaAlert {
            title: rule.title.clone(),
            tags: rule.tags.clone(),
            description: rule.description.clone(),
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
        Selection::Keywords(keywords) => {
            // OR over the full command line; keywords share the field values'
            // wildcard semantics (`*mimikatz*` must strip its stars, not be
            // matched literally). A bare keyword means substring containment.
            let lower = event.cmdline.to_lowercase();
            keywords.iter().any(|kw| {
                let k = kw.to_lowercase();
                if k.contains('*') {
                    glob_match(&lower, &k)
                } else {
                    lower.contains(&k)
                }
            })
        }
    }
}

/// Evaluates one Sigma field. `ParentImage` matches only when the sensor provided
/// lineage (see `schema::ExecEvent::parent_image_path`).
fn eval_field(field_spec: &str, values: &ValueList, event: &ExecEvent) -> bool {
    let (field, modifier) = parse_field_spec(field_spec);
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

    values
        .as_slice()
        .iter()
        .any(|val| match_value(haystack, val, modifier))
}

/// Parses `FieldName|modifier` → (`FieldName`, `Some("modifier")`) or (`FieldName`, `None`).
fn parse_field_spec(spec: &str) -> (&str, Option<&str>) {
    if let Some(idx) = spec.find('|') {
        (&spec[..idx], Some(&spec[idx + 1..]))
    } else {
        (spec, None)
    }
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
fn glob_match(haystack: &str, pattern: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use schema::{EventMeta, ExecEvent, User};

    use super::*;

    fn exec(image: &str, cmdline: &str) -> ExecEvent {
        ExecEvent {
            meta: EventMeta {
                pid: 1,
                ppid: 0,
                user: User::Unknown,
                timestamp_ns: 0,
                comm: "test".into(),
            },
            image_path: image.to_string(),
            cmdline: cmdline.to_string(),
            argv: vec![],
            parent_comm: None,
            parent_image_path: None,
            sha256: None,
            signature: None,
        }
    }

    fn parse(yaml: &str) -> SigmaRule {
        let rule: SigmaRule = serde_yaml::from_str(yaml).unwrap();
        validate(&rule, "<test>").unwrap();
        rule
    }

    #[test]
    fn glob_match_star_any() {
        assert!(glob_match("c:\\windows\\system32\\cmd.exe", "*\\cmd.exe"));
        assert!(glob_match(
            "c:\\windows\\system32\\cmd.exe",
            "c:\\windows\\*"
        ));
        assert!(glob_match("payload", "*payload*"));
        assert!(!glob_match("notepad.exe", "*\\cmd.exe"));
    }

    #[test]
    fn eval_rule_endswith_image() {
        let rule = parse(
            r#"
title: Test cmd
description: test
detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection
"#,
        );
        let ev = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe");
        assert!(eval_rule_exec(&rule, &ev).is_some());
        let ev2 = exec("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
        assert!(eval_rule_exec(&rule, &ev2).is_none());
    }

    #[test]
    fn eval_rule_commandline_contains() {
        let rule = parse(
            r#"
title: Base64 PowerShell
description: PS encoded
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'encodedcommand'
  condition: selection
"#,
        );
        let ev = exec(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -EncodedCommand ZWNobyBoZWxsbw==",
        );
        assert!(eval_rule_exec(&rule, &ev).is_some());
        let ev2 = exec(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -NoProfile",
        );
        assert!(eval_rule_exec(&rule, &ev2).is_none());
    }

    #[test]
    fn eval_rule_keywords() {
        let rule = parse(
            r#"
title: Suspicious keyword
description: test
detection:
  selection:
    - mimikatz
    - sekurlsa
  condition: selection
"#,
        );
        let ev = exec("C:\\temp\\mimikatz.exe", "C:\\temp\\mimikatz.exe");
        assert!(eval_rule_exec(&rule, &ev).is_some());
        let ev2 = exec("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
        assert!(eval_rule_exec(&rule, &ev2).is_none());
    }

    #[test]
    fn parent_image_matches_only_with_lineage() {
        let rule = parse(
            r#"
title: Office spawning shell
description: test
detection:
  selection:
    ParentImage|endswith: '\winword.exe'
    Image|endswith: '\cmd.exe'
  condition: selection
"#,
        );
        let mut ev = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami");
        assert!(
            eval_rule_exec(&rule, &ev).is_none(),
            "no lineage — must not match"
        );
        ev.parent_image_path = Some("C:\\Program Files\\Office\\winword.exe".into());
        assert!(eval_rule_exec(&rule, &ev).is_some());
    }

    #[test]
    fn empty_selection_is_rejected_not_match_everything() {
        // Review finding: `selection: {}` matched EVERY event (vacuous all()).
        let rule: SigmaRule = serde_yaml::from_str(
            "title: Empty\ndetection:\n  selection: {}\n  condition: selection\n",
        )
        .unwrap();
        let err = validate(&rule, "<t>").unwrap_err();
        assert!(err.to_string().contains("empty selection"), "{err}");
    }

    #[test]
    fn interior_wildcards_are_rejected_at_load() {
        // Review finding: `C:\*\cmd.exe` loaded fine and then never matched.
        let rule: SigmaRule = serde_yaml::from_str(
            "title: Interior\ndetection:\n  selection:\n    Image: 'C:\\*\\cmd.exe'\n  condition: selection\n",
        )
        .unwrap();
        let err = validate(&rule, "<t>").unwrap_err();
        assert!(err.to_string().contains("interior wildcard"), "{err}");
    }

    #[test]
    fn keyword_wildcards_match_like_field_globs() {
        let rule = parse(
            "title: KW\ndetection:\n  selection:\n    - '*mimikatz*'\n  condition: selection\n",
        );
        let ev = exec("C:\\t\\x.exe", "run mimikatz please");
        assert!(eval_rule_exec(&rule, &ev).is_some());
    }

    #[test]
    fn modifier_case_is_insensitive_at_eval() {
        let rule = parse(
            "title: Case\ndetection:\n  selection:\n    Image|EndsWith: '\\cmd.exe'\n  condition: selection\n",
        );
        let ev = exec("C:\\Windows\\System32\\cmd.exe", "cmd.exe");
        assert!(
            eval_rule_exec(&rule, &ev).is_some(),
            "EndsWith must behave as endswith"
        );
    }

    #[test]
    fn unsupported_constructs_are_rejected_at_load() {
        let complex_condition: SigmaRule = serde_yaml::from_str(
            r#"
title: Complex
detection:
  selection:
    Image: 'x'
  filter:
    Image: 'y'
  condition: selection and not filter
"#,
        )
        .unwrap();
        let err = validate(&complex_condition, "<t>").unwrap_err();
        assert!(err.to_string().contains("condition"), "{err}");

        let bad_field: SigmaRule = serde_yaml::from_str(
            r#"
title: Bad field
detection:
  selection:
    TargetFilename|endswith: '.dll'
  condition: selection
"#,
        )
        .unwrap();
        let err = validate(&bad_field, "<t>").unwrap_err();
        assert!(err.to_string().contains("TargetFilename"), "{err}");

        let bad_modifier: SigmaRule = serde_yaml::from_str(
            r#"
title: Bad modifier
detection:
  selection:
    CommandLine|re: '.*'
  condition: selection
"#,
        )
        .unwrap();
        let err = validate(&bad_modifier, "<t>").unwrap_err();
        assert!(err.to_string().contains("modifier `re`"), "{err}");
    }
}
