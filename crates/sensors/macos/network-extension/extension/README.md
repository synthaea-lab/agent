# extension/ — the Swift system-extension half of this sensor

`NEFilterDataProvider` (flows, inbound + outbound, audit-token process
attribution, byte counts at flow close) and `NEDNSProxyProvider` (DNS
query/response pairs, minimal wire-format parse), writing the NDJSON records
`src/wire.rs` defines over the agent's Unix socket. `EventPipe.swift`'s
`wireVersion` must match `wire::WIRE_VERSION` — bump both together.

Not built by cargo. Type-check locally (drift against the SDK becomes a
diagnostic, not a runtime surprise):

```sh
swiftc -typecheck -sdk "$(xcrun --show-sdk-path)" Sources/*.swift
```

Known deprecations: the `NWHostEndpoint`-based flow APIs are deprecated as
of macOS 15 in favor of the Network-framework endpoint accessors — a
contained migration once the packaged extension exists. Packaging, signing,
entitlements, and the approval flow: `packaging/macos/README.md`.
