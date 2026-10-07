# sensors/windows/driver

Windows kernel-mode components of Synthaea. Not a Cargo workspace member:
kernel drivers have their own build and signing pipeline (WDK). Language and
framework choice: [ADR-0012](../../../../docs/adr/0012-windows-driver-framework-language-choice.md)
(C against the classic WDK).

## Layout

- `minifilter/`: the `SynthaeaFilter` file-system minifilter (C, WDK).

## Milestone 1 (current state)

A minimal minifilter that registers with the Filter Manager, starts filtering,
and unloads cleanly. It registers **no operation callbacks** yet: file telemetry
(#136) and the kernel/agent communication port come in the next milestones.

Deliberate choices for this milestone:

- **Unload is allowed.** Development needs load/unload cycles without rebooting.
  Refusing non-mandatory unloads (tamper resistance) will be a separate,
  documented and tested change.
- **Automatic attachment** to volumes (`Instance1.Flags = 0x0` in the INF), so
  `fltmc instances` shows the filter attached.
- **Altitude `370020`** comes from the Microsoft sample and sits in the
  "FSFilter Activity Monitor" range (360000-389999). Fine for the lab; a
  production altitude must be requested from Microsoft.
- **Demand start** (`StartType = 3`): loaded explicitly with `fltmc`.

## Build

Requirements (Windows host):

- Visual Studio 2022 Build Tools (or Community) with the C++ desktop workload
- **MSVC v143 x64/x86 Spectre-mitigated libraries** (otherwise MSB8040)
- WDK **10.0.26100.6584** and its Visual Studio component. The newer WDK
  (28000) requires Visual Studio 2026.

From a *Developer Command Prompt for VS 2022*:

```cmd
cd crates\sensors\windows\driver\minifilter
msbuild SynthaeaFilter.sln /p:Configuration=Debug /p:Platform=x64
```

Output: `x64\Debug\SynthaeaFilter\` (`.sys`, `.inf`, signed `.cat`). The build
test-signs with a local WDK test certificate. Build outputs and certificates
are git-ignored.

## Run (lab VM only)

**Never load the driver on a host machine.** Use a dedicated Windows 11 VM with
test-signing enabled and Secure Boot off, and take a snapshot before each load
(ADR-0012). Lab setup and signing scripts: follow-up by the Windows team.

Load messages use `DbgPrintEx` (component `IHVDRIVER`). Errors are always
printed; to see the info-level load/unload messages in DebugView, enable them
in the VM:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d 0xF
```

Then, after installing the package:

```cmd
fltmc load SynthaeaFilter
fltmc filters
fltmc instances
fltmc unload SynthaeaFilter
```

## Guardrails for C code (ADR-0012)

1. Thin kernel side: collect and forward, no detection logic in kernel mode.
2. Every message from user mode is hostile: validate sizes and pointers.
3. SAL annotations and `/analyze`, CodeQL driver queries, Driver Verifier on the test VM.
4. Two-person review for any change to C code.

## Roadmap

- Minifilter: file deletes/renames (ransomware signal), named pipes, quarantine (#136)
- Kernel callbacks: process/thread/image notify, handle access (#137)
- ELAM + PPL: Threat-Intelligence ETW provider and agent self-protection (#39,
  gated on Microsoft Virus Initiative membership)

## License

The files in `minifilter/` are derived from the `nullFilter` sample of
[microsoft/Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples)
and are distributed under the **Microsoft Public License (MS-PL)**, see
`minifilter/LICENSE.windows-driver-samples`. This applies to this directory
only; the rest of the repository keeps its own license.
