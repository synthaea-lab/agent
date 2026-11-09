# packaging/macos

The design for installing the macOS agent: the app bundle that hosts the network system
extension, the entitlements each part needs, and the approval flow. There is no `.pkg` build
yet; releases carry the bare agent binary, which is not notarized.

## Why an app bundle

macOS activates a system extension only from a signed app bundle in `/Applications`
(`OSSystemExtensionRequest`); a bare daemon cannot host one. The agent therefore ships as an
app bundle for the network extension and a launchd daemon for the agent. The planned layout:

```text
/Applications/Synthaea.app/
  Contents/MacOS/Synthaea                       activation and status UI
  Contents/Library/SystemExtensions/
    dev.synthaea.agent.network.systemextension  NEFilterDataProvider and NEDNSProxyProvider
/usr/local/synthaea/agent                       the agent daemon
/Library/LaunchDaemons/dev.synthaea.agent.plist
```

The EndpointSecurity sensor needs no system extension: an entitled daemon is enough, so the
agent stays a plain launchd daemon. The extension's sources are in
[`crates/sensors/macos/network-extension/extension`](../../crates/sensors/macos/network-extension/extension/README.md).

## Entitlements

| Part | Entitlements |
| --- | --- |
| Agent daemon | `com.apple.developer.endpoint-security.client` (restricted, granted by Apple), app group |
| Host app | `com.apple.developer.system-extension.install`, app group |
| Network extension | `com.apple.developer.networking.networkextension` with `content-filter-provider` and `dns-proxy` (restricted), app group |

All three share the app group `group.dev.synthaea.agent`. The extension's sandbox reaches
only its group container, which is where the agent's Unix socket for the extension's events
lives. The agent listens and the extension reconnects, because macOS starts and stops the
extension on its own schedule.

The restricted entitlements must be granted by Apple before a build can use them. Until
then, no provisioning profile authorizes them, and a SIP-enabled host kills a binary that
claims them at exec.

## Activation and approval

1. The installer places `Synthaea.app` and the daemon, and loads the launchd plist.
2. The app requests activation of the network extension
   (`OSSystemExtensionRequest.activationRequest`).
3. macOS asks the user to approve it in System Settings, under General, Login Items &
   Extensions, unless an MDM profile pre-approves it with:
   - `com.apple.system-extension-policy` for the allowed team and bundle IDs, and
   - `com.apple.webcontent-filter` and `com.apple.dnsProxy` payloads, so the content filter
     and DNS proxy attach without per-user consent.
4. The daemon needs Full Disk Access for EndpointSecurity, granted by the user or by a
   `com.apple.TCC.configuration-profile-policy` payload.
5. `systemextensionsctl list` shows the activated extension.

Without MDM a user sees three prompts (extension, filter, Full Disk Access); with MDM, none.
The installer treats approval as state that arrives later, not as an install-time result.

## Development

On a test Mac with SIP relaxed, `systemextensionsctl developer on` lets a build outside
`/Applications` activate extensions without notarization, and `systemextensionsctl reset`
removes them. The extension builds from its sources with Xcode or `swiftc`.
