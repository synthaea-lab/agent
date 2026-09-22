//! On-the-wire shape of a signed policy document.
//!
//! Types in this module ARE the JSON serialization format the agent and the
//! (future) control plane exchange. A change here is a schema-visible change;
//! a rename is a breaking change that requires a [`SCHEMA_VERSION`] bump.
//!
//! ## Structure (per ADR-0010)
//!
//! ```text
//! Policy
//! ├── metadata: PolicyMetadata     # identity: schema/policy version + signature
//! └── payload:  PolicyPayload      # actionable content (open-ended sections)
//!     ├── sensors                  # map-typed: per-sensor sub-document
//!     ├── response                 # flat: deny-by-default action allowlist
//!     ├── compliance_mode          # flat, safety-critical
//!     └── experimental             # reserved namespace for unknown keys
//! ```
//!
//! The split between metadata and payload is deliberate: the release gate can
//! check `schema_version`/`policy_version`/`signature` without deserializing
//! the payload, and the payload can grow without touching the metadata's
//! fixed shape.
//!
//! ## What v1 ships vs. what ADR-0010 lists
//!
//! ADR-0010 §Payload sections declares six top-level sections
//! (`sensors`, `rules`, `models`, `response`, `thresholds`, `compliance_mode`)
//! plus a reserved `experimental` namespace. v1 ships **four** of them, in
//! the minimum-viable subset that lets an implementation of `Policy = baseline
//! ⊕ overrides` exercise every merge granularity ADR-0011 declares:
//! `sensors` (map-typed), `response` (flat), `compliance_mode` (flat +
//! safety-critical), and `experimental` (open-ended). `rules`, `models`, and
//! `thresholds` are placeholders (empty types in this file, one line each) —
//! they land when a real consumer of them exists. Adding them later is a
//! non-breaking additive change; the schema does not bump.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The schema version this build understands. Bump only on a breaking
/// change; additive fields in existing sections, or new sections, do not
/// require a bump.
pub const SCHEMA_VERSION: u32 = 1;

/// The whole signed policy document.
///
/// A file whose [`PolicyMetadata::schema_version`] doesn't equal
/// [`SCHEMA_VERSION`] fails to load with
/// [`crate::PolicyError::SchemaVersionMismatch`] before the payload is
/// touched — old documents never smuggle their way through as
/// "close enough".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Identity + signature. See [`PolicyMetadata`].
    pub metadata: PolicyMetadata,
    /// Actionable content. See [`PolicyPayload`].
    pub payload: PolicyPayload,
}

/// Everything that identifies WHICH policy this is, distinct from what it
/// says.
///
/// Serialized first in canonical JSON output so a reader that only needs the
/// version-and-signature (release gate, control plane admission) can stop
/// after this section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMetadata {
    /// Structural schema of this document. Reader rejects a value it does
    /// not know (currently only [`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Monotone identifier assigned by the issuer on each publish. The
    /// agent applies a policy iff its `policy_version` is strictly greater
    /// than the currently active one — prevents rollback attacks and
    /// duplicate-apply (ADR-0010 §2).
    pub policy_version: u64,
    /// When the issuer produced this document. Nanoseconds since the Unix
    /// epoch (UTC), matching [`schema::EventMeta`]'s timestamp unit across
    /// the workspace. Not used for freshness enforcement in v1 (that
    /// belongs to the distribution mechanism ADR-0010 defers) but recorded
    /// so audit trails and post-mortems have a definitive "issued at"
    /// value.
    pub issued_at_ns: u64,
    /// Ed25519 signature over this document's canonical JSON form (see
    /// [`crate::to_canonical_json`]), encoded as 128 lowercase-hex
    /// characters. During canonicalization for signing, this field is set
    /// to `""` (the empty string, not omitted or null) so the schema shape
    /// stays fixed regardless of whether the document is signed or being
    /// signed — same convention ADR-0015 fixes for updater manifests.
    pub signature: String,
}

/// The actionable content of a policy: sections growing additively as new
/// sensors, rules, and response tiers land.
///
/// Every section is optional so an override document (per ADR-0010 §5) can
/// carry only the sections it changes. A baseline document typically
/// carries every section; a per-host override typically carries one or
/// two.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPayload {
    /// Per-sensor toggles and knobs. Map-typed section per ADR-0011 §1:
    /// each key of this struct is treated as a map key at merge time (an
    /// override that touches `windows_eventlog` leaves `linux_uprobes`
    /// alone). Serialized as `{"windows_eventlog": {...}, ...}` at the JSON
    /// level, matching the "map<string, sub-document>" shape ADR-0011
    /// describes.
    #[serde(default, skip_serializing_if = "SensorSection::is_empty")]
    pub sensors: SensorSection,

    /// Which response actions are permitted at each verdict tier (kill,
    /// quarantine, isolate, `live_session`). Flat section per ADR-0011 §1:
    /// present in override → replaces baseline as a whole. `deny`-by-default
    /// for every action until explicitly enabled (ADR-0010 §Payload
    /// sections).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseSection>,

    /// Gates built-in redaction and retention rules. Flat section AND
    /// safety-critical per ADR-0011: partial override is refused at parse
    /// time. Marker enum today; expands to `PciDss`, `Hipaa`, etc. as those
    /// modes gain real behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_mode: Option<ComplianceMode>,

    /// Placeholder for [ADR-0010]'s `rules` section — allowlist/denylist of
    /// rule identifiers, per-rule overrides. No consumer yet; landing this
    /// today would ship a shape whose real consumer would change. Serialized
    /// only when non-empty.
    ///
    /// [ADR-0010]: ../../../docs/adr/0010-shared-policy-model.md
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<RulesSection>,

    /// Placeholder for ADR-0010's `models` section — ONNX model
    /// registry+version authorisation. Empty in v1; real fields land with a
    /// consumer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<ModelsSection>,

    /// Placeholder for ADR-0010's `thresholds` section — global scoring
    /// cut-offs. Empty in v1; bounded ranges added as consumers land.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thresholds: Option<ThresholdsSection>,

    /// Reserved namespace for fields not covered by [`SCHEMA_VERSION`].
    /// Readers ignore unknown keys **only inside this map**; anywhere else
    /// in the payload is strict (`deny_unknown_fields`). Present so
    /// forward-compatibility escape hatches exist without opening the whole
    /// document to schema drift.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub experimental: BTreeMap<String, serde_json::Value>,
}

// ── sensors section ──────────────────────────────────────────────────────

/// Per-sensor policy sub-documents. Struct-with-Option-fields rather than
/// `BTreeMap<String, dyn SensorPolicy>` because each sensor's schema is a
/// distinct type; the JSON shape is still a map (thanks to
/// `skip_serializing_if = "Option::is_none"`) so the ADR-0011 §1 map-typed
/// merge rule applies naturally.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SensorSection {
    /// The four channel-group toggles of the Windows Event Log poll target
    /// (`sensor-windows-eventlog`), plus an optional safety-critical
    /// [`RedactionPolicy`]. Absorbs the pre-ADR-0010 in-code
    /// [`crate::EventLogPolicy`] flat struct — the two coexist during v1 as
    /// ADR-0010's Consequences explicitly instruct.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_eventlog: Option<WindowsEventlogSensorPolicy>,
    // Future entries — `linux_ebpf`, `linux_uprobes`, `macos_endpointsecurity`,
    // etc. — land here as their own sub-document types when they gain
    // policy-visible knobs.
}

impl SensorSection {
    /// Every optional entry is `None` — used by
    /// `#[serde(skip_serializing_if)]` to omit the whole `sensors` section
    /// from canonical JSON when nothing is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.windows_eventlog.is_none()
    }
}

/// `sensors.windows_eventlog` sub-document — supersedes today's
/// [`crate::EventLogPolicy`] as the canonical shape of this sensor's policy
/// slice, without deleting the older type (ADR-0010 §Consequences: "give
/// callers a stepping stone").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEventlogSensorPolicy {
    /// Event 7045 poll target (T1543.003 — service install persistence).
    pub service_installs_enabled: bool,
    /// Event 4698 poll target (T1053.005 — scheduled task persistence).
    pub scheduled_tasks_enabled: bool,
    /// Event 4720 poll target (T1136.001 — local account creation).
    pub account_creations_enabled: bool,
    /// Events 4624/4625/4648/4672 poll target (logon/session, #94).
    pub logon_events_enabled: bool,
    /// Sensor-side redaction policy. Safety-critical per ADR-0011: an
    /// override that carries this field must supply every documented
    /// [`RedactionPolicy`] field, or the whole override is rejected at
    /// parse time. Absent in v1 for a fresh install (baseline has redaction
    /// off), present only when an operator explicitly overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionPolicy>,
}

/// Sensor-agnostic redaction knobs applied at emission time. Structurally
/// minimal in v1 — a single flag exercised end-to-end by the safety-critical
/// merge test — so the mechanism is in place and reviewable BEFORE any
/// sensor actually wires a real scrubber into it. Additive fields land per
/// sensor as the redaction work does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionPolicy {
    /// Whether the sensor scrubs matched PII-like patterns before emitting.
    /// Off by default — turning it ON is what an override is for. Turning
    /// it back OFF via an override is exactly the "silent disable of a
    /// security control" that safety-critical completeness prevents at
    /// parse time.
    pub pii_scrub_enabled: bool,
}

// ── response section ─────────────────────────────────────────────────────

/// `response` section — which automated actions the agent may take at each
/// verdict tier. Flat section (not map-typed), per ADR-0011 §1. Every action
/// defaults to `deny` (`false`) until explicitly enabled — the "policy off =
/// observe-only" contract from issue #25.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSection {
    /// Automated process termination on a high-confidence correlated
    /// verdict. Mirrors the pre-ADR-0010 [`crate::ResponsePolicy`] flat
    /// struct.
    pub kill_enabled: bool,
    /// Automated quarantine of a payload a scan confirms malicious. Mirrors
    /// the pre-ADR-0010 [`crate::ResponsePolicy`] flat struct.
    pub quarantine_enabled: bool,
}

// ── compliance_mode section ──────────────────────────────────────────────

/// `compliance_mode` — gates built-in redaction and retention rules
/// according to a named regulatory profile.
///
/// Safety-critical per ADR-0011 §2: an override that carries this section
/// must carry the entire enum value; a partial override never made sense
/// here (a section is either present or absent, and a variant is what it is).
/// Enumeration extends additively as profiles land — adding `Gdpr` is a
/// non-breaking additive change; renaming or removing a variant is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceMode {
    /// No regulatory profile applied. Redaction/retention defaults to
    /// whatever the individual sensor configuration specifies.
    None,
    /// PCI-DSS mode. Reserved for future work — no behaviour attached in
    /// v1 beyond appearing in the enum so the wire format admits it.
    PciDss,
    /// HIPAA mode. Same as above.
    Hipaa,
}

// ── placeholder sections ─────────────────────────────────────────────────
//
// These three exist so `PolicyPayload` matches ADR-0010's declared shape at
// the type level. They are deliberately empty in v1 — landing real fields
// today would ship a schema without a consumer, and the first real consumer
// would inevitably ask for a different shape. Empty structs serialize as
// `{}` and deserialize round-trip clean.

/// Placeholder for ADR-0010's `rules` section — allowlist/denylist +
/// per-rule overrides. Real fields land with a consumer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesSection {}

/// Placeholder for ADR-0010's `models` section — ONNX model authorisation.
/// Real fields land with a consumer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelsSection {}

/// Placeholder for ADR-0010's `thresholds` section — global scoring
/// cut-offs. Real fields land with a consumer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdsSection {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_round_trips() {
        let p = PolicyPayload::default();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "{}", "an empty payload should serialize to `{{}}`");
        let back: PolicyPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn full_document_round_trips() {
        let doc = Policy {
            metadata: PolicyMetadata {
                schema_version: SCHEMA_VERSION,
                policy_version: 42,
                issued_at_ns: 1_700_000_000_000_000_000,
                signature: "0".repeat(128),
            },
            payload: PolicyPayload {
                sensors: SensorSection {
                    windows_eventlog: Some(WindowsEventlogSensorPolicy {
                        service_installs_enabled: true,
                        scheduled_tasks_enabled: true,
                        account_creations_enabled: true,
                        logon_events_enabled: false,
                        redaction: Some(RedactionPolicy {
                            pii_scrub_enabled: true,
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
        };
        let json = serde_json::to_string(&doc).unwrap();
        let back: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, back);
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        // `deny_unknown_fields` on Policy catches a mistyped section name.
        let bad = r#"{"metadata":{"schema_version":1,"policy_version":1,"issued_at_ns":0,"signature":""},"payload":{},"typo":true}"#;
        assert!(serde_json::from_str::<Policy>(bad).is_err());
    }

    #[test]
    fn unknown_experimental_key_is_kept() {
        // Inside `experimental`, unknown keys are the entire point — they
        // survive round-trip via `serde_json::Value`.
        let doc = r#"{"metadata":{"schema_version":1,"policy_version":1,"issued_at_ns":0,"signature":""},"payload":{"experimental":{"my_flag":42}}}"#;
        let p: Policy = serde_json::from_str(doc).unwrap();
        assert_eq!(
            p.payload.experimental.get("my_flag"),
            Some(&serde_json::json!(42))
        );
    }
}
