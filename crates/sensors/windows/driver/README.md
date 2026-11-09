# crates/sensors/windows/driver

Windows kernel-mode components of the agent. `minifilter/` holds `SynthaeaFilter`, a
file-system minifilter that reports file deletes, renames, timestamp changes and raw volume
opens to the agent over a Filter Manager communication port. The user-mode side is the
[`sensor-windows-minifilter`](../minifilter) crate.

The driver is written in C against the classic WDK and is not a Cargo workspace member: it
has its own build and signing. Only the kernel binary is C; everything past the
communication port is Rust. Its design, wire format and current limits are documented in
[docs/sensors/windows/minifilter.md](../../../../docs/sensors/windows/minifilter.md).

## Build

Requirements, on a Windows host:

- Visual Studio 2022 (Build Tools or Community) with the C++ desktop workload
- the MSVC v143 x64/x86 Spectre-mitigated libraries
- WDK 10.0.26100.x and its Visual Studio component

From a *Developer Command Prompt for VS 2022*:

```bat
cd crates\sensors\windows\driver\minifilter
msbuild SynthaeaFilter.sln /p:Configuration=Debug /p:Platform=x64
```

The output is in `x64\Debug\SynthaeaFilter\` (`.sys`, `.inf` and a test-signed `.cat`). The
build signs with a local WDK test certificate.

## Run in a test VM

Load the driver only on a dedicated Windows VM with test signing enabled and Secure Boot
off, and take a snapshot first. A fault in a kernel driver stops the whole machine.

From an elevated prompt, after installing the package
([`test/install-test-build.ps1`](test/install-test-build.ps1) installs it and checks which
binary the service will load):

```bat
fltmc load SynthaeaFilter
fltmc filters
fltmc instances
fltmc unload SynthaeaFilter
```

The INF uses demand start and altitude 370020, from the Microsoft sample, in the FSFilter
Activity Monitor range; a production altitude must be assigned by Microsoft. Unload is
allowed, so the driver offers no tamper resistance yet.

## Rules for kernel code

1. The kernel side collects and forwards. No detection logic runs in kernel mode.
2. Everything that comes from user mode is hostile and is validated.
3. Changes pass SAL annotations and `/analyze`, run under Driver Verifier in the test VM, and
   get a second reviewer.

## License

The files in `minifilter/` are derived from the `nullFilter` sample of
[microsoft/Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples) and
are distributed under the Microsoft Public License (MS-PL); see
[`minifilter/LICENSE.windows-driver-samples`](minifilter/LICENSE.windows-driver-samples). This
applies to that directory only.
