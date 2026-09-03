//! # sensor-macos-network-extension
//!
//! macOS network sensor. NetworkExtension (NEFilterDataProvider / NEDNSProxyProvider)
//! for per-flow network telemetry and DNS visibility that EndpointSecurity does not
//! provide: inbound connections, DNS queries with process attribution, flow byte counts.
//! Requires network-extension entitlements and runs as a system extension.
//!
//! Compiles to a stub on non-macOS targets.
