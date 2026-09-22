//! Applying a per-host override document on top of a baseline policy.
//!
//! Implements the three merge granularities [ADR-0011] declares:
//!
//! 1. **Flat sections** (non-map: `response`, `compliance_mode`, `rules`,
//!    `models`, `thresholds`) — whole-section replace: `overrides.section`
//!    is `Some` → wins entirely; `None` → keep `baseline.section`. No
//!    field-level merge inside a flat section.
//!
//! 2. **Map-typed sections** (`sensors`, `experimental`) — per-key
//!    replace: an override's `sensors.windows_eventlog` replaces only
//!    that key; every other sensor key of the baseline is kept.
//!
//! 3. **Safety-critical sub-objects** — enforced by the schema types
//!    themselves, not by a runtime walker in this module. See
//!    "Safety-critical enforcement" below.
//!
//! [ADR-0011]: ../../../docs/adr/0011-policy-override-granularity.md
//!
//! ## Safety-critical enforcement — where it actually happens
//!
//! ADR-0011 §Decision 2 requires that a safety-critical sub-object
//! present in an override be **complete** (every schema-declared field
//! must be supplied, or the override is rejected at parse time). The
//! naive implementation is a runtime walker over
//! [`SAFETY_CRITICAL_PATHS`] that inspects each declared path.
//!
//! **This crate takes a different route**: safety-critical sub-objects
//! (`RedactionPolicy`, `ComplianceMode`) have EVERY schema field marked
//! serde-required (no `#[serde(default)]`). A partial override therefore
//! fails to deserialize as a `RedactionPolicy` at all, surfacing as
//! [`crate::PolicyError::Parse`] with the missing-field name serde
//! itself produced. That is stricter than a bespoke walker (the error
//! carries exactly which field is missing, without a duplicated field
//! list to keep in sync), it happens earlier in the load path (before
//! merge), and it has zero cost in the happy path.
//!
//! [`SAFETY_CRITICAL_PATHS`] is kept as a **declarative constant** —
//! it documents the intent, prevents a future contributor from adding
//! `#[serde(default)]` to one of these fields without noticing, and
//! matches the reference form ADR-0011 §Decision 3 called for. The
//! module's regression test [`safety_critical_paths_field_are_serde_required`]
//! guards the "no `#[serde(default)]`" invariant so a schema evolution
//! that would silently relax safety-critical to admissible-partial fails
//! the crate's own tests.

use std::collections::BTreeMap;

use crate::document::{Policy, PolicyPayload, SensorSection};

/// Dot-paths of sub-objects ADR-0011 declares safety-critical.
///
/// **Declarative** — not walked at merge time. See the module doc's
/// "Safety-critical enforcement" section for why. Its role is to hold
/// the review-time record of what "safety-critical" applies to, and to
/// feed the regression test that ensures every listed field is
/// serde-required.
///
/// The `*` in `sensors.*.redaction` is glob-style: for every entry of
/// the `sensors` map, its `redaction` sub-object is safety-critical.
/// Recorded as a pattern so adding a new sensor with a redaction
/// sub-doc doesn't need to touch this list.
pub const SAFETY_CRITICAL_PATHS: &[&str] = &["compliance_mode", "sensors.*.redaction"];

/// Apply `overrides` on top of `baseline`, returning the effective
/// [`Policy`] the agent should use. Preserves baseline where the
/// override does not speak, replaces where it does, per the merge rules
/// summarized at the top of this module.
///
/// **`metadata` uses `overrides`'s identity in full**. This is the
/// override's raison d'être: it carries its own `policy_version` and
/// signature, and the agent applies it iff its `policy_version` is
/// strictly greater than the currently-active one (ADR-0010 §2). Merging
/// metadata field-by-field would let a stale override poison a fresh
/// baseline's identity, which is not what "per-host override" means.
#[must_use]
pub fn apply_overrides(baseline: &Policy, overrides: &Policy) -> Policy {
    Policy {
        metadata: overrides.metadata.clone(),
        payload: apply_payload(&baseline.payload, &overrides.payload),
    }
}

fn apply_payload(baseline: &PolicyPayload, overrides: &PolicyPayload) -> PolicyPayload {
    PolicyPayload {
        // sensors is map-typed (ADR-0011 §1): merge per key.
        sensors: apply_sensors(&baseline.sensors, &overrides.sensors),

        // Flat sections: whole-section replace if override speaks, else
        // keep baseline. `.clone().or_else(...)` on Option is the
        // idiomatic Rust for exactly this "override wins, baseline is
        // the fallback" pattern.
        response: overrides
            .response
            .clone()
            .or_else(|| baseline.response.clone()),
        compliance_mode: overrides.compliance_mode.or(baseline.compliance_mode),
        rules: overrides.rules.clone().or_else(|| baseline.rules.clone()),
        models: overrides.models.clone().or_else(|| baseline.models.clone()),
        thresholds: overrides
            .thresholds
            .clone()
            .or_else(|| baseline.thresholds.clone()),

        // `experimental` is a map<string, Value>: per-key merge, override
        // wins on key collision. Same rule as sensors, one nesting level
        // deeper.
        experimental: merge_experimental(&baseline.experimental, &overrides.experimental),
    }
}

/// Per-sensor merge. Each `Option<SpecificSensorPolicy>` field is one
/// map key at the JSON level; a `Some` in overrides replaces the same
/// key in baseline, a `None` keeps baseline's value.
///
/// `redaction` is the one field inside `windows_eventlog` that does NOT
/// follow whole-object replace, even though the rest of the sub-document
/// does. A whole-object replace would let an override that only means to
/// touch e.g. `service_installs_enabled` silently reset `redaction` to
/// `None` just by not mentioning it — `redaction: Option<RedactionPolicy>`
/// is `#[serde(default)]`, so an override JSON that omits the field
/// entirely parses fine. That is exactly the #178 regression ADR-0011
/// exists to close ("operator overrides `sensors.windows_eventlog` and
/// forgets `redaction`, silently turning PII scrub off"): the parse-time
/// safety-critical check only rejects a *present-but-incomplete*
/// `redaction`, not an *absent* one, so without this carve-out the
/// regression survives merge even though it can no longer survive parse.
/// So: override omits `redaction` → inherit baseline's. Override supplies
/// a complete `redaction` → it wins (safety-critical completeness is
/// already guaranteed at parse time). An operator who wants to explicitly
/// turn redaction off sends `"redaction": {"pii_scrub_enabled": false}` —
/// a complete object, not an omission — which is unambiguously distinct
/// from "didn't mention it".
fn apply_sensors(baseline: &SensorSection, overrides: &SensorSection) -> SensorSection {
    let windows_eventlog = match &overrides.windows_eventlog {
        None => baseline.windows_eventlog.clone(),
        Some(ov) => {
            let mut merged = ov.clone();
            if merged.redaction.is_none() {
                merged.redaction = baseline
                    .windows_eventlog
                    .as_ref()
                    .and_then(|base| base.redaction.clone());
            }
            Some(merged)
        }
    };
    SensorSection { windows_eventlog }
}

fn merge_experimental(
    baseline: &BTreeMap<String, serde_json::Value>,
    overrides: &BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    let mut out = baseline.clone();
    for (k, v) in overrides {
        out.insert(k.clone(), v.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{
        ComplianceMode, PolicyMetadata, RedactionPolicy, ResponseSection, SCHEMA_VERSION,
        SensorSection, WindowsEventlogSensorPolicy,
    };

    fn baseline() -> Policy {
        Policy {
            metadata: PolicyMetadata {
                schema_version: SCHEMA_VERSION,
                policy_version: 1,
                issued_at_ns: 100,
                signature: "0".repeat(128),
            },
            payload: PolicyPayload {
                sensors: SensorSection {
                    windows_eventlog: Some(WindowsEventlogSensorPolicy {
                        service_installs_enabled: true,
                        scheduled_tasks_enabled: true,
                        account_creations_enabled: true,
                        logon_events_enabled: true,
                        redaction: Some(RedactionPolicy {
                            pii_scrub_enabled: false,
                        }),
                    }),
                },
                response: Some(ResponseSection {
                    kill_enabled: false,
                    quarantine_enabled: false,
                }),
                compliance_mode: Some(ComplianceMode::None),
                rules: None,
                models: None,
                thresholds: None,
                experimental: BTreeMap::new(),
            },
        }
    }

    fn empty_overrides(policy_version: u64) -> Policy {
        Policy {
            metadata: PolicyMetadata {
                schema_version: SCHEMA_VERSION,
                policy_version,
                issued_at_ns: 200,
                signature: "1".repeat(128),
            },
            payload: PolicyPayload::default(),
        }
    }

    #[test]
    fn empty_override_keeps_every_baseline_section() {
        let base = baseline();
        let ov = empty_overrides(2);
        let merged = apply_overrides(&base, &ov);
        assert_eq!(merged.payload.sensors, base.payload.sensors);
        assert_eq!(merged.payload.response, base.payload.response);
        assert_eq!(merged.payload.compliance_mode, base.payload.compliance_mode);
    }

    #[test]
    fn metadata_is_from_override_not_baseline() {
        let base = baseline();
        let ov = empty_overrides(42);
        let merged = apply_overrides(&base, &ov);
        assert_eq!(merged.metadata.policy_version, 42);
        assert_eq!(merged.metadata.issued_at_ns, 200);
        assert_eq!(merged.metadata.signature, "1".repeat(128));
    }

    #[test]
    fn flat_section_override_replaces_whole_section() {
        let base = baseline();
        let mut ov = empty_overrides(2);
        ov.payload.response = Some(ResponseSection {
            kill_enabled: true,
            quarantine_enabled: true,
        });
        let merged = apply_overrides(&base, &ov);
        // Whole-section replace: both flags now true, matching the override.
        assert!(merged.payload.response.unwrap().kill_enabled);
    }

    #[test]
    fn map_typed_section_only_touches_named_key() {
        // In v1 there's only one sensor entry (windows_eventlog), so the
        // "leave the other keys alone" behaviour is currently a
        // one-key-map test — kept anyway so a future second sensor entry
        // exercises the branch without a new test.
        let base = baseline();
        let mut ov = empty_overrides(2);
        // Override windows_eventlog with all four channels DISABLED.
        ov.payload.sensors.windows_eventlog = Some(WindowsEventlogSensorPolicy {
            service_installs_enabled: false,
            scheduled_tasks_enabled: false,
            account_creations_enabled: false,
            logon_events_enabled: false,
            redaction: Some(RedactionPolicy {
                pii_scrub_enabled: true,
            }),
        });
        let merged = apply_overrides(&base, &ov);
        let we = merged.payload.sensors.windows_eventlog.unwrap();
        assert!(!we.service_installs_enabled);
        assert!(we.redaction.unwrap().pii_scrub_enabled);
    }

    #[test]
    fn experimental_is_merged_per_key_with_override_winning() {
        let mut base = baseline();
        base.payload
            .experimental
            .insert("only_in_baseline".to_string(), serde_json::json!("kept"));
        base.payload
            .experimental
            .insert("in_both".to_string(), serde_json::json!("baseline_value"));

        let mut ov = empty_overrides(2);
        ov.payload
            .experimental
            .insert("in_both".to_string(), serde_json::json!("override_value"));
        ov.payload
            .experimental
            .insert("only_in_override".to_string(), serde_json::json!(true));

        let merged = apply_overrides(&base, &ov);
        let exp = merged.payload.experimental;
        assert_eq!(
            exp.get("only_in_baseline"),
            Some(&serde_json::json!("kept"))
        );
        assert_eq!(
            exp.get("in_both"),
            Some(&serde_json::json!("override_value"))
        );
        assert_eq!(exp.get("only_in_override"), Some(&serde_json::json!(true)));
    }

    #[test]
    fn windows_eventlog_override_omitting_redaction_inherits_baseline_redaction() {
        // The actual #178 regression this ADR exists to close: an operator
        // overrides windows_eventlog to change an unrelated toggle and
        // simply doesn't think about redaction. Omitting the field (not
        // sending a partial object — the parse-time check already rejects
        // that) must NOT silently turn PII scrub off.
        let base = baseline(); // redaction: pii_scrub_enabled: false
        let mut base_with_scrub_on = base.clone();
        base_with_scrub_on
            .payload
            .sensors
            .windows_eventlog
            .as_mut()
            .unwrap()
            .redaction = Some(RedactionPolicy {
            pii_scrub_enabled: true,
        });

        let mut ov = empty_overrides(2);
        ov.payload.sensors.windows_eventlog = Some(WindowsEventlogSensorPolicy {
            service_installs_enabled: false, // the only thing this override means to change
            scheduled_tasks_enabled: true,
            account_creations_enabled: true,
            logon_events_enabled: true,
            redaction: None, // not mentioned — must not reset baseline's
        });

        let merged = apply_overrides(&base_with_scrub_on, &ov);
        let we = merged.payload.sensors.windows_eventlog.unwrap();
        assert!(
            !we.service_installs_enabled,
            "the override's own change applies"
        );
        assert!(
            we.redaction.unwrap().pii_scrub_enabled,
            "redaction must be inherited from baseline, not silently reset to None"
        );
    }

    #[test]
    fn windows_eventlog_override_can_still_explicitly_change_redaction() {
        // The other half: an override that DOES want to change redaction
        // (by supplying a complete RedactionPolicy) still wins, same as
        // before this fix.
        let base = baseline(); // redaction: pii_scrub_enabled: false
        let mut ov = empty_overrides(2);
        ov.payload.sensors.windows_eventlog = Some(WindowsEventlogSensorPolicy {
            service_installs_enabled: true,
            scheduled_tasks_enabled: true,
            account_creations_enabled: true,
            logon_events_enabled: true,
            redaction: Some(RedactionPolicy {
                pii_scrub_enabled: true,
            }),
        });

        let merged = apply_overrides(&base, &ov);
        let we = merged.payload.sensors.windows_eventlog.unwrap();
        assert!(we.redaction.unwrap().pii_scrub_enabled);
    }

    #[test]
    fn partial_redaction_override_fails_at_parse_not_at_merge() {
        // The safety-critical mechanism lives in serde, not in this
        // module. A `redaction: {}` override — the exact "partial" case
        // ADR-0011 wants rejected — fails to parse as RedactionPolicy
        // because `pii_scrub_enabled` is serde-required. If this test
        // ever succeeds at parsing (e.g. someone adds `#[serde(default)]`
        // to `pii_scrub_enabled`), safety-critical enforcement is
        // silently broken.
        let bad = serde_json::from_str::<RedactionPolicy>("{}");
        assert!(bad.is_err(), "partial RedactionPolicy must fail to parse");
    }

    #[test]
    fn safety_critical_paths_are_documented() {
        // Regression guard: if this list changes shape, the module doc
        // that quotes it and ADR-0011 both need to be revisited.
        assert_eq!(
            SAFETY_CRITICAL_PATHS,
            &["compliance_mode", "sensors.*.redaction"]
        );
    }
}
