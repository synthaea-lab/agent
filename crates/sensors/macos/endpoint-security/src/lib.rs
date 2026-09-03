//! # sensor-macos
//!
//! macOS `EndpointSecurity` sensor (new development). `es_new_client` subscriptions for
//! process (exec/fork/exit with argv and code-signing info), file, persistence
//! (launchd/BTM), credential-access paths, and injection/tamper signals
//! (`task_for_pid`, ptrace, code-signature invalidation). AUTH events enable inline
//! prevention. Network/DNS telemetry lives in `sensor-macos-network-extension`.
//!
//! Requires the `com.apple.developer.endpoint-security.client` entitlement.
//! Compiles to a stub on non-macOS targets.
