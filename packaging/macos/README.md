# packaging/macos

How the macOS agent becomes installable and approved: the app bundle that
hosts the system extensions, the entitlements each piece needs, and the
activation/approval flow. Written with issue #33 (the NetworkExtension
sensor's extension) and #32 (the EndpointSecurity entitlement) — the .pkg
build scripts land when the walking-skeleton lab run needs them, same
sequencing as `packaging/windows`.

## Why an app bundle at all

Apple only activates a **system extension** from inside a signed app bundle
in `/Applications` (`OSSystemExtensionRequest`); a bare daemon cannot host
one. The macOS agent therefore ships as:

```
Synthaea.app/
  Contents/MacOS/Synthaea                    ← thin activation/status UI
  Contents/Library/SystemExtensions/
    dev.synthaea.agent.network.systemextension   ← NEFilterDataProvider +
                                                   NEDNSProxyProvider
                                                   (crates/sensors/macos/
                                                    network-extension/extension)
  Contents/Resources/ ...
/usr/local/synthaea/agent                    ← the Rust agent daemon (launchd)
/Library/LaunchDaemons/dev.synthaea.agent.plist
```

The ES sensor (`sensor-macos`) does **not** need a system extension — an
entitled daemon binary is enough (`docs/sensors/macos.md`), so the agent
stays a plain launchd daemon.

## Entitlements

| Piece | Entitlements |
| --- | --- |
| agent daemon | `com.apple.developer.endpoint-security.client` (Apple-granted, restricted), app group |
| host app | `com.apple.developer.system-extension.install`, app group |
| network extension | `com.apple.developer.networking.networkextension` with `content-filter-provider` + `dns-proxy` (restricted — same Apple request form as ES), app group |

All three share one **app group** (`group.dev.synthaea.agent`): the network
extension's sandbox only reaches its own group container, and that is where
the agent's Unix socket for the extension↔agent event pipe lives
(`crates/sensors/macos/network-extension`, `receiver.rs` — the agent
listens, the extension reconnects, since the OS starts/stops the extension
on its own schedule).

## Activation & approval flow

1. The installer places `Synthaea.app` and the daemon, loads the launchd
   plist.
2. The app calls `OSSystemExtensionRequest.activationRequest` for the
   network extension.
3. macOS prompts the user (System Settings → General → Login Items &
   Extensions) unless an MDM profile pre-approves:
   - `com.apple.system-extension-policy` (allowed team/bundle ids), and
   - `com.apple.webcontent-filter` + `com.apple.dnsProxy` payloads so the
     content filter and DNS proxy attach without per-user consent.
4. Separately, TCC Full Disk Access for the daemon (ES requirement) — user
   grant or `com.apple.TCC.configuration-profile-policy` via MDM.
5. `systemextensionsctl list` shows the activated extension;
   `systemextensionsctl reset` is the lab-machine escape hatch.

Fleet reality: without MDM, three user prompts (extension, filter, FDA);
with MDM, zero. The installer must treat "approved" as asynchronous state,
not an install-time postcondition.

## Dev loop (lab machine)

- `systemextensionsctl developer on` lets a non-`/Applications` build
  activate extensions without notarization (SIP-relaxed lab machines only,
  same caveat as the ES dev-signing path in `docs/sensors/macos.md`).
- The extension builds from
  `crates/sensors/macos/network-extension/extension/` (Xcode target or
  `swiftc`; CI type-checks the sources with `swiftc -typecheck` so SDK
  drift is caught without an Xcode project).
- The DNS proxy's upstream resolver comes from the provider configuration
  (`NEDNSProxyManager`) — the scaffold's hardcoded default is replaced by
  the managed value when the manager wiring lands.

## Status

Scaffold + this document (issues #32/#33). Real `.pkg` build scripts,
signing/notarization pipeline, and the beacon-scenario lab validation are
the follow-up — they need the Developer ID + restricted entitlements
(requested via <https://developer.apple.com/system-extensions/>), which is
an organizational step, not a code one.
