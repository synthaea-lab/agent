//! # sinks
//!
//! Local output sinks for events, detections, and alerts: JSONL files, syslog/CEF for
//! "not a SIEM — we export to yours". Sinks are composable and configured per install;
//! the agent hosts them. To be migrated from `old/agent` (sinks.rs, jsonl.rs).
