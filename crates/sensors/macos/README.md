# sensors/macos

macOS telemetry. Primary mechanism is EndpointSecurity (`endpoint-security/`);
`network-extension/` adds the network/DNS visibility ES does not carry. Both run as
system extensions with their respective entitlements.

Coverage targets:

| Telemetry source | Mechanism | Where |
| --- | --- | --- |
| Process exec/fork/exit (argv, code signing info, TCC) | ES NOTIFY/AUTH exec | `endpoint-security/` |
| File open/write/rename/delete/mmap | ES file events | `endpoint-security/` |
| Persistence (launchd plists, login items, cron) | ES file events on known paths + ES_EVENT_BTM | `endpoint-security/` |
| Credential access (keychain files), TCC bypass attempts | ES file/auth events | `endpoint-security/` |
| Injection/tamper (task_for_pid, ptrace, cs invalidation) | ES proc events | `endpoint-security/` |
| Network flows with process attribution, inbound + outbound | NEFilterDataProvider | `network-extension/` |
| DNS queries/responses | NEDNSProxyProvider | `network-extension/` |
| sudo auth, TCC decisions, Gatekeeper verdicts | Unified log (`log stream`, strict predicates) | `unifiedlog/` |
| Listening ports + LISTENER-DRIFT baseline (no entitlement) | libproc socket-table snapshots | `sockets/` |
