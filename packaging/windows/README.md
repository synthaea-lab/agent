# packaging/windows - MSI (#37)

Builds `SynthaeaAgent.msi`: installs `agent.exe` + `watchdog.exe` into
`Program Files\Synthaea` and, on install, runs `watchdog.exe install` to
register the `SynthaEDR` Windows service (the watchdog self-registers - see
`watchdog/src/service/windows.rs` - this MSI does not duplicate that with
WiX's own ServiceInstall/ServiceControl elements). On uninstall it runs
`watchdog.exe uninstall`, then force-deletes everything left under
`INSTALLFOLDER` via a `cmd.exe /c rd /s /q` custom action - including files
the running agent/watchdog wrote at runtime (`alerts.ndjson`,
`alerts.heartbeat`, `events.jsonl`) that MSI itself never installed and would
otherwise leave behind (see `Product.wxs`'s `CleanupInstallFolder` comment
for why, and why it isn't done via WiX's `util:RemoveFolderEx`).

**Status: build-tested (2026-09-18) end to end on a real Windows 11 machine**
(install, service running, uninstall, service and all files gone). Issues
found and fixed during that pass, already reflected in `Product.wxs`/
`build.ps1`: ICE80 (needed `Win64="yes"` on both components plus
`Platform="x64"` on `<Package>`), and incomplete uninstall cleanup (MSI only
removes files it installed itself, not the runtime-generated ones - now
handled by the `CleanupInstallFolder` custom action). First-pass authoring
notes below are kept for context but the "not yet build-tested" caveat no
longer applies.

## Install WiX v3

A standalone toolset (no dotnet/NuGet needed to install or to build with it,
unlike WiX v4/v5):

```powershell
Invoke-WebRequest -Uri "https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314.exe" -OutFile "$env:TEMP\wix314.exe"
Start-Process -FilePath "$env:TEMP\wix314.exe" -ArgumentList "/quiet" -Wait
```

Installs to `C:\Program Files (x86)\WiX Toolset v3.14\` - `build.ps1` below
looks for it there.

## Build

From the repo root, with a release build already on disk:

```powershell
cargo build --release -p agent -p watchdog
.\packaging\windows\build.ps1
```

Produces `packaging\windows\out\SynthaeaAgent.msi`.

## Test install/uninstall (elevated PowerShell)

```powershell
msiexec /i packaging\windows\out\SynthaeaAgent.msi /quiet /l*v install.log
sc query SynthaEDR
Get-Process agent, watchdog

msiexec /x packaging\windows\out\SynthaeaAgent.msi /quiet /l*v uninstall.log
sc query SynthaEDR   # should report "service does not exist"
Get-ChildItem "C:\Program Files\Synthaea" -ErrorAction SilentlyContinue  # should be empty/gone
```

`install.log` / `uninstall.log` (the `/l*v` verbose MSI log) are the first
place to look if either step fails - in particular around the
`InstallService` / `UninstallService` / `CleanupInstallFolder` custom actions
in `Product.wxs`. Note: right after `msiexec` returns, the Windows Installer
service can still be finishing asynchronously - if a verification command
run immediately after shows nothing, wait a moment and re-check before
concluding it failed. Also run each `msiexec` call as its own step, not
back-to-back with the next one pasted immediately after - a second `msiexec`
invocation started before the first has actually finished can produce
confusing, hard-to-read results.

## Uninstall data retention - deliberate choice, not a default

The `CleanupInstallFolder` custom action deletes `events.jsonl`/
`alerts.ndjson`/`alerts.heartbeat` along with the binaries on uninstall. This
trades away forensic value (an EDR's own local logs surviving after someone
removes the agent, useful for incident response) in favor of
`packaging/README.md`'s stated rule that uninstall must be clean and
complete. If the team later decides log retention-after-uninstall matters
more for a given deployment, that needs an explicit, separate decision (e.g.
an MSI property to opt out of the cleanup) - not a silent revert of this
behavior.

## Signing - not yet decided

`Done when` in #37 doesn't require this, but GPO/Intune deployment in
practice wants a signed MSI and signed `agent.exe`/`watchdog.exe` (unsigned
binaries trip SmartScreen and can be blocked outright by AppLocker/WDAC
policies on managed endpoints). That needs a real code-signing certificate
(EV/OV from a CA, or an internal one issued by the org) plus a `signtool.exe`
step added to `build.ps1` - a procurement/infra decision, not a code change,
so it is deliberately left out of this first pass. A self-signed cert is fine
for lab-only testing (`New-SelfSignedCertificate` + `Set-AuthenticodeSignature`)
but is not a substitute for the real thing before this goes anywhere near a
managed fleet.

## Known gaps (first pass, #37)

- `rules/sigma` and `rules/yara` content directories are not included -
  `agent.exe` runs fine without them (see `agent/src/sink.rs`'s
  `content_dir` doc), so this is deferred until there is real content to
  ship, not because it is hard to add (one more `Directory`/`Component`
  pair mirroring `INSTALLFOLDER`).
- No Start Menu shortcut / Add-Remove-Programs icon polish - irrelevant for
  a background service with no UI.
- `light.exe` may emit ICE validation warnings (common, usually benign) -
  read them once on the first real build rather than assuming they are all
  noise.
