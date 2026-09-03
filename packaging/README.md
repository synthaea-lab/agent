# packaging — Installers and Service Integration

Everything that turns build output into an installable, running agent per platform.
Subfolders are created when work on a platform starts.

| Platform | Artifacts | Service integration |
| --- | --- | --- |
| `windows/` | MSI (fleet deploy via GPO/Intune), signed binaries | SCM services (agent + watchdog), ETW manifest registration |
| `macos/` | notarized .pkg, app bundle for the UI | launchd daemons, system-extension approval flow (ES + network entitlements) |
| `linux/` | .deb and .rpm, static musl build option | systemd units (agent + watchdog), sysusers/tmpfiles |

Shared rules:
- Installers install the `updater`-managed layout from day one, so self-update never
  fights the package manager (packages own the bootstrap, `updater` owns the payload).
- Uninstall must be clean and complete — an EDR that leaves residue destroys trust.
- Signing/notarization pipelines are part of packaging, not an afterthought; unsigned
  dev builds are clearly marked and refuse to enroll against production servers.

The lab's `provisioning/agent-install` scripts consume these artifacts, so packaging
becomes real at the walking-skeleton milestone (first end-to-end scenario run).
