# packaging/windows

Builds `SynthaeaAgent.msi`, which installs `agent.exe` and `watchdog.exe` into
`Program Files\Synthaea` and registers the `SynthaEDR` Windows service. The watchdog
registers the service itself (`watchdog.exe install` and `uninstall`, run as MSI custom
actions), so the MSI does not duplicate it with WiX service elements.

The MSI is not published with releases yet, and neither it nor the binaries are code-signed.
Unsigned binaries trigger SmartScreen and can be blocked by AppLocker or WDAC policies; use
these builds on test machines only.

## Build

Install WiX Toolset v3.14. It is a standalone toolset with no .NET or NuGet dependency, and
`build.ps1` looks for it in `C:\Program Files (x86)\WiX Toolset v3.14\`:

```powershell
Invoke-WebRequest -Uri "https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314.exe" -OutFile "$env:TEMP\wix314.exe"
Start-Process -FilePath "$env:TEMP\wix314.exe" -ArgumentList "/quiet" -Wait
```

Then, from the repository root:

```powershell
cargo build --release --no-default-features --features agent/dynamic-onnx -p agent -p watchdog
.\packaging\windows\build.ps1
```

The MSI is written to `packaging\windows\out\SynthaeaAgent.msi`.

`--no-default-features` keeps the public test signing keys out of the package: the agent's
default `test-key` feature embeds updater keys whose seeds are public. `--features
agent/dynamic-onnx` restores the other default feature, the ONNX Runtime library. `build.ps1`
scans both executables for the test-key marker and refuses to package a build that carries
it.

## Install and uninstall

From an elevated PowerShell prompt:

```powershell
msiexec /i packaging\windows\out\SynthaeaAgent.msi /quiet /l*v install.log
sc.exe query SynthaEDR
Get-Process agent, watchdog

msiexec /x packaging\windows\out\SynthaeaAgent.msi /quiet /l*v uninstall.log
sc.exe query SynthaEDR
```

After uninstall the service no longer exists and `C:\Program Files\Synthaea` is gone. The
verbose logs are the first place to look when a step fails, around the `InstallService`,
`UninstallService` and `CleanupInstallFolder` custom actions in
[`Product.wxs`](Product.wxs). Windows Installer can still be finishing in the background when
`msiexec` returns; run each `msiexec` on its own and wait for it before checking the result.

Uninstall deletes the whole install folder, including the files the agent wrote at run time
(`alerts.ndjson`, `alerts.heartbeat`, `events.jsonl`). This favors a clean uninstall over
keeping the agent's local logs for later investigation.

## Containers

A host install covers process-isolated containers: their processes run on the host kernel
and carry the container ID. It does not cover:

- Hyper-V isolated containers, which run their own kernel in a utility VM. Treat one as a
  separate machine with its own agent, or run the workload process-isolated.
- WSL 2 distributions and Docker Desktop's Linux engine, which are Linux in a VM. Install the
  [Linux package](../linux/README.md) inside the distribution.

## Not included yet

- The detection content directories (`rules/sigma`, `rules/yara`): the agent runs without
  them.
- Code signing of the MSI and the executables.
