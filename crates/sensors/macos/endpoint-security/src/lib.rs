//! # sensor-macos
//!
//! macOS platform sensor (new in this iteration — not present in the old codebase).
//! Uses the EndpointSecurity framework (`es_new_client`) for process, file, and network
//! telemetry, with inline AUTH events enabling prevention. Requires the
//! `com.apple.developer.endpoint-security.client` entitlement.
//!
//! Compiles to a stub on non-macOS targets so `cargo check --workspace` works anywhere.
