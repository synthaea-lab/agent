# packaging — Installers and Service Integration

Everything that turns build output into an installable, running agent per platform.
Subfolders are created when work on a platform starts.

| Platform | Artifacts | Service integration |
| --- | --- | --- |
| `windows/` | MSI (fleet deploy via GPO/Intune), signed binaries (signing not yet done) | SCM service (watchdog self-registers `SynthaEDR` via `install`/`uninstall`, invoked as MSI custom actions — see `windows/README.md`) |
| `macos/` | notarized .pkg, app bundle for the UI | launchd daemons, system-extension approval flow (ES + network entitlements) |
| `linux/` | .deb and .rpm, static musl build option | systemd units (agent + watchdog), sysusers/tmpfiles |

`windows/` (#37) is the first subfolder with real content: `Product.wxs` (WiX v3),
`build.ps1`, and its own `README.md` with install/build/test steps. Build-tested
end to end (install, uninstall, clean removal) on a real Windows 11 machine — see
that README's "Status" note for details. The "ETW manifest registration" this
table used to list for Windows has been dropped: `sensor-windows-etw` only
*consumes* existing OS/ETW providers, it doesn't publish its own manifest-based
provider, so there is nothing to register for that sensor. If a future sensor
does need to register its own ETW manifest, that belongs back in this table then.

Shared rules:
- Installers install the `updater`-managed layout from day one, so self-update never
  fights the package manager (packages own the bootstrap, `updater` owns the payload).
- Uninstall must be clean and complete — an EDR that leaves residue destroys trust.
- Signing/notarization pipelines are part of packaging, not an afterthought; unsigned
  dev builds are clearly marked and refuse to enroll against production servers.

The lab's `provisioning/agent-install` scripts consume these artifacts, so packaging
becomes real at the walking-skeleton milestone (first end-to-end scenario run).
