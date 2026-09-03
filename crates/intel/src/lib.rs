//! # intel
//!
//! On-device IOC (Indicator of Compromise) matching. Indicator sets — file hashes,
//! IP addresses, domains — ship as signed content via canary rings (like rules and
//! models) and are matched against the event stream: hashes against `enrich` output
//! on exec/write, IPs against connect events, domains against DNS telemetry as
//! sensors gain it. Matches are detections (`DetectionSource` gains an `Ioc` variant)
//! and feed the correlator like any other source.
//!
//! IOA (Indicators of Attack — behavioral patterns) are deliberately NOT a separate
//! engine: they are what `rules`, `sigma`, and the correlator already express; the
//! server-side feed pipeline converts IOA feeds into rule/sigma content. This crate
//! stays about fast set-membership on atomic indicators: memory-bounded (bloom or
//! binary-fuse filters over large hash sets with an exact confirmation tier),
//! updatable without agent restart.
