# Network extension (Swift)

The Swift half of `sensor-macos-network-extension`. `NEFilterDataProvider` reports flows,
inbound and outbound, with audit-token process attribution and byte counts at flow close.
`NEDNSProxyProvider` reports DNS query and response pairs from a minimal wire-format parse.
Both write the NDJSON records defined in [`../src/wire.rs`](../src/wire.rs) to the agent's
Unix socket. `wireVersion` in `EventPipe.swift` must match `wire::WIRE_VERSION`; change both
together.

Cargo does not build these sources. Type-check them on a Mac to catch SDK drift:

```sh
swiftc -typecheck -sdk "$(xcrun --show-sdk-path)" Sources/*.swift
```

The flow APIs based on `NWHostEndpoint` are deprecated as of macOS 15 in favor of the
Network framework endpoint accessors. Packaging, signing, entitlements and the approval flow
are described in [packaging/macos](../../../../../packaging/macos/README.md).
