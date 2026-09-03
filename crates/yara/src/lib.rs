//! # yara
//!
//! On-device content scanning built on YARA-X. Evaluates the rule content from
//! `rules/yara/` against files (on write/exec triggers from sensors) and process
//! memory, within a strict performance budget. Matches are detections and feed the
//! correlator like any other source.
