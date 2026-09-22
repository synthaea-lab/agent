//! Canonical JSON serialization of a policy document.
//!
//! Two operations that both need the SAME byte sequence — signing and
//! verifying — live here so exactly one canonicalizer exists in the
//! workspace, per ADR-0010 §4 and ADR-0015 §Decision 2. Updater manifests
//! (ADR-0015) will call this same function once their implementation lands
//! (issue #30).
//!
//! ## Contract (ADR-0010 §3)
//!
//! The canonical form is a **deterministic pretty-printed JSON** with:
//!
//! - `indent=2` (two-space indentation)
//! - **Keys sorted lexicographically** at every object level
//! - No trailing whitespace on any line
//! - `metadata.signature` set to the empty string `""` (not omitted, not
//!   null) — ADR-0015 §Decision 2 pins the placeholder value; ADR-0010
//!   originally left it unspecified.
//!
//! The output is UTF-8 bytes; callers hash/sign the raw bytes without any
//! encoding step. `signature` is left in-place with its empty-string value
//! so the schema shape stays fixed regardless of whether the document is
//! being signed, signed already, or verified.

use serde_json::Value;

use crate::document::Policy;

/// Canonical bytes to sign or verify.
///
/// Serializes `policy` to a `serde_json::Value`, replaces
/// `metadata.signature` with `""` in that value (leaving the caller's
/// document unchanged), then formats the tree with sorted keys and 2-space
/// indent. Returns the raw UTF-8 bytes of the resulting text.
///
/// # Errors
///
/// Returns a JSON error only if `policy` itself fails to serialize — which
/// for the concrete types in [`crate::document`] cannot happen at runtime
/// (all fields are serde-supported primitives, structs, and enums).
pub fn to_canonical_bytes(policy: &Policy) -> Result<Vec<u8>, serde_json::Error> {
    // Serialize to Value FIRST so we can operate on the tree structurally
    // (replacing signature, sorting keys) rather than doing it at the byte
    // level with string manipulation — which would be brittle against any
    // future field addition. The Value → sorted-JSON step below is the one
    // deterministic pass.
    let mut v = serde_json::to_value(policy)?;

    // Set metadata.signature to `""` for canonicalization. If either
    // `metadata` is missing or `signature` is missing, that is a bug in the
    // caller's document — we produce the canonical form assuming the
    // documented shape and let the round-trip test catch any drift.
    if let Some(metadata) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.insert("signature".to_string(), Value::String(String::new()));
    }

    // Write sorted, indent=2, LF line endings. serde_json's default
    // serializer does NOT sort object keys — we write a small manual walker
    // instead. Keeps the crate free of an extra dep (e.g. `serde-jcs`) for
    // one small, testable function.
    let mut out = Vec::with_capacity(256);
    write_sorted(&v, &mut out, 0);
    Ok(out)
}

/// Recursive writer. Uses `Vec<u8>` directly (not `Write`) to keep the
/// error path collapsed — this function's inputs are always in-memory
/// values, no I/O.
fn write_sorted(v: &Value, out: &mut Vec<u8>, depth: usize) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            // `serde_json::to_string(s)` re-uses serde's own escaping,
            // producing the exact same output as `serde_json::to_writer`
            // — critical: our canonical form's byte-for-byte agreement
            // with any other serde_json-produced document depends on
            // sharing the escape rules.
            out.extend_from_slice(serde_json::to_string(s).unwrap().as_bytes());
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                out.extend_from_slice(b"[]");
                return;
            }
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                out.push(b'\n');
                indent(out, depth + 1);
                write_sorted(item, out, depth + 1);
                if i + 1 < arr.len() {
                    out.push(b',');
                }
            }
            out.push(b'\n');
            indent(out, depth);
            out.push(b']');
        }
        Value::Object(obj) => {
            if obj.is_empty() {
                out.extend_from_slice(b"{}");
                return;
            }
            // Sort keys lexicographically. `serde_json::Map` iterates in
            // insertion order (or key-sorted order if the `preserve_order`
            // feature is off, which it is by default for us). Either way
            // we do NOT trust that iteration order here — the whole point
            // of canonicalization is that the output does not depend on
            // how the input was built.
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                out.push(b'\n');
                indent(out, depth + 1);
                out.extend_from_slice(serde_json::to_string(k).unwrap().as_bytes());
                out.extend_from_slice(b": ");
                write_sorted(&obj[k.as_str()], out, depth + 1);
                if i + 1 < keys.len() {
                    out.push(b',');
                }
            }
            out.push(b'\n');
            indent(out, depth);
            out.push(b'}');
        }
    }
}

fn indent(out: &mut Vec<u8>, depth: usize) {
    for _ in 0..depth {
        out.extend_from_slice(b"  ");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::document::{
        ComplianceMode, PolicyMetadata, PolicyPayload, ResponseSection, SCHEMA_VERSION,
        SensorSection, WindowsEventlogSensorPolicy,
    };

    fn minimal_policy(signature: &str) -> Policy {
        Policy {
            metadata: PolicyMetadata {
                schema_version: SCHEMA_VERSION,
                policy_version: 1,
                issued_at_ns: 0,
                signature: signature.to_string(),
            },
            payload: PolicyPayload::default(),
        }
    }

    #[test]
    fn signature_is_blanked_in_canonical_form() {
        // Two documents identical except for the signature field must
        // canonicalize to the same bytes — that's the whole point of the
        // blanking step. Without it, the signature would sign itself.
        let a = minimal_policy(&"0".repeat(128));
        let b = minimal_policy(&"a".repeat(128));
        assert_eq!(
            to_canonical_bytes(&a).unwrap(),
            to_canonical_bytes(&b).unwrap()
        );
    }

    #[test]
    fn signature_field_present_as_empty_string() {
        // Blanking is `""`, not omission — ADR-0015 §2 pins this.
        let p = minimal_policy(&"f".repeat(128));
        let bytes = to_canonical_bytes(&p).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("\"signature\": \"\""));
        assert!(!s.contains("null"));
    }

    #[test]
    fn keys_are_sorted() {
        // metadata's fields have four keys — the canonical form emits them
        // alphabetically regardless of struct field order.
        let p = minimal_policy(&"0".repeat(128));
        let bytes = to_canonical_bytes(&p).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let issued_at = s.find("issued_at_ns").unwrap();
        let policy_version = s.find("policy_version").unwrap();
        let schema_version = s.find("schema_version").unwrap();
        let signature = s.find("\"signature\"").unwrap();
        // Alphabetical: issued_at_ns < policy_version < schema_version < signature
        assert!(issued_at < policy_version);
        assert!(policy_version < schema_version);
        assert!(schema_version < signature);
    }

    #[test]
    fn output_uses_two_space_indent() {
        let p = minimal_policy(&"0".repeat(128));
        let bytes = to_canonical_bytes(&p).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Nested fields under metadata are indented with exactly 4 spaces
        // (2 for depth=1 inside root object + 2 for depth=2 inside metadata
        // object).
        assert!(s.contains("\n    \"schema_version\":"));
    }

    #[test]
    fn stable_across_repeated_serialization() {
        // Same input → same bytes. Guarded against a future refactor that
        // introduces nondeterminism (e.g. HashMap in an intermediate step).
        let p = Policy {
            metadata: PolicyMetadata {
                schema_version: SCHEMA_VERSION,
                policy_version: 7,
                issued_at_ns: 1_700_000_000_000_000_000,
                signature: "abc".repeat(43) + "d", // 130 chars, doesn't matter for canonical form
            },
            payload: PolicyPayload {
                sensors: SensorSection {
                    windows_eventlog: Some(WindowsEventlogSensorPolicy {
                        service_installs_enabled: true,
                        scheduled_tasks_enabled: true,
                        account_creations_enabled: true,
                        logon_events_enabled: true,
                        redaction: None,
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
        let a = to_canonical_bytes(&p).unwrap();
        let b = to_canonical_bytes(&p).unwrap();
        assert_eq!(a, b);
    }
}
