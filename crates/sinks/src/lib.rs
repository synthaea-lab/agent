//! # sinks
//!
//! Local output sinks for events, detections, and alerts: JSONL files, syslog/CEF for
//! "not a SIEM — we export to yours". Sinks are composable and configured per install;
//! the agent hosts them. To be migrated from `old/agent` (sinks.rs, jsonl.rs).
//!
//! Scope rule: the agent speaks only neutral formats (JSONL, syslog/CEF, and later
//! OCSF/ECS mappings as additional sinks here). Vendor-specific SIEM connectors
//! (Splunk HEC, Sentinel, Elastic) live in the control plane's export module — one
//! fleet-level integration point forwarding enriched cases, never per-agent clients.
