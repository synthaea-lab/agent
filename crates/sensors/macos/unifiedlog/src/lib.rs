//! # sensor-macos-unifiedlog
//!
//! macOS unified log as a supplementary sensor: `OSLog` store streaming with strict
//! predicates for records `EndpointSecurity` does not express —
//! - authentication and session events beyond ES login (loginwindow, sudo, sshd)
//! - TCC grants/denials (who got camera/screen/full-disk access, and when)
//! - Gatekeeper/XProtect verdicts as context on exec events
//!
//! Predicate-allowlisted (the unified log is a firehose), normalized with
//! provenance, volume-bounded.
