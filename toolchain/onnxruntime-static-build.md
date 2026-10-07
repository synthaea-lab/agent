# ONNX Runtime Static Linking Guide

**Status:** Implementation of ADR-0002 decision #2 (static linking for single-binary deployment)
**Issue:** #110
**Platform:** Linux (Ubuntu 24.04+ tested; Alpine/musl tested but not a target platform) and Windows MSVC (see the Windows section below)

## Background

ADR-0002 requires onnxruntime statically linked into the agent binary to support:
- Single-binary deployment (no runtime .so dependencies)
- Updater integrity guarantees
- Root/SYSTEM execution security posture

The workspace `ort` dependency (v2.0.0-rc.13) now has `default-features = false` to disable `download-binaries` and `copy-dylibs`, which were previously downloading and using dynamic libraries in violation of ADR-0002.

## Build onnxruntime from Source

### Prerequisites

Ubuntu 24.04:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git python3
```

### Build Steps

1. **Clone onnxruntime:**
```bash
git clone --depth 1 --branch v1.30.0 https://github.com/microsoft/onnxruntime.git
cd onnxruntime
```

2. **Build static libraries:**
```bash
./build.sh \
  --config Release \
  --update \
  --build \
  --no_telemetry \
  --cmake_extra_defines onnxruntime_BUILD_UNIT_TESTS=OFF \
  --parallel $(nproc)
```

**Flags explained:**
- `--no_telemetry`: Disables Microsoft's telemetry SDK which requires glibc-only `execinfo.h`
- `onnxruntime_BUILD_UNIT_TESTS=OFF`: Avoids GCC 15 compilation issues in onnxruntime's test suite
- No `--build_shared_lib`: Produces static libraries only

3. **Build re2 explicitly (Ubuntu-specific):**

The `re2` library is an orphaned CMake target in static-only builds - it's never scheduled automatically:

```bash
cmake --build build/Linux/Release --target re2 -j$(nproc)
```

4. **Set environment variable:**
```bash
export ORT_LIB_LOCATION="$PWD/build/Linux/Release"
```

## Generate Static Link Flags

The `ort-sys` crate's hardcoded static library list is incomplete for onnxruntime 1.30.0, missing:
- ~78 abseil sub-libraries (Cord/Cordz/Status/crc_internal families)
- `utf8_range`
- `model_package`
- `re2`

Use the auto-discovery script to generate the necessary flags:

```bash
eval "$(./lab/provisioning/ort-static-link-flags.sh)"
```

This walks `$ORT_LIB_LOCATION` for every `.a` file produced and emits `-L native=<dir> -l static=<name>` flags.

## Build and Test

From the repository root:

```bash
cargo test -p ml --release
```

**Expected result:** 31/31 tests pass, including real inference tests:
- `scores_match_onnxruntime_reference`
- `vectors_match_python_aggregator`

## Verify Static Linking

Check the resulting binary has no runtime onnxruntime dependency:

```bash
ldd target/release/deps/ml-* | grep -i onnx
```

Should return nothing. Only system libraries (`libc`, `libm`, `libgcc_s`, etc.) should appear.

For static-PIE builds:
```bash
file target/release/deps/ml-*
```

Should report `static-pie linked` or similar (no `dynamically linked` mention for onnxruntime).

## Known Issues

### ort-sys Incomplete Library List

**Root cause:** `ort-sys` v2.0.0-rc.13's `static_link/mod.rs` has a hardcoded list of libraries to link that doesn't cover onnxruntime 1.30.0's full dependency tree.

**Impact:** Affects both glibc (Ubuntu) and musl (Alpine) builds identically (~78 missing libraries).

**Workaround:** The `ort-static-link-flags.sh` script generates the complete list dynamically.

**Upstream:** Consider filing issue with pykeio/ort about incomplete library list for onnxruntime 1.30.0.

### re2 Orphaned Target (Ubuntu/glibc)

**Root cause:** `onnxruntime_providers_cpu.cmake` uses `onnxruntime_add_include_to_target(... re2::re2 ...)` (headers only), never `target_link_libraries`. With no shared lib or test targets depending on it, CMake never schedules `re2` to build.

**Impact:** `cargo build` fails with "could not find native static library re2" unless explicitly built first.

**Workaround:** `cmake --build build/Linux/Release --target re2 -j$(nproc)` before running cargo.

**Upstream:** This is arguably an onnxruntime CMake issue - the CPU provider genuinely links against `re2` symbols, but the build graph doesn't express the dependency.

## Binary Size Impact

**TODO (ADR-0002 §3):** Measure and document the binary size delta:
- Before: dynamic onnxruntime (baseline)
- After: static onnxruntime

Measure final agent binary size, not just the `ml` crate test binaries.

## CI Integration

**Not yet implemented.** Options:

1. **Pre-built static libraries:** Cache onnxruntime static build artifacts in CI, keyed by version + platform
2. **Build on demand:** Run the full onnxruntime build in CI (adds ~5-10 minutes to build time)
3. **Hybrid:** Provide pre-built artifacts for common platforms, fall back to build-from-source for others

Decision deferred pending binary size measurement and platform support requirements.

## Windows (MSVC)

Issue #337. Same idea as Linux, different tools: PowerShell scripts, `.lib` files, the
Visual Studio generator.

### Prerequisites

- Visual Studio 2022 Build Tools with the "Desktop development with C++" workload
  (MSVC 14.3x and a Windows SDK). CMake is taken from `PATH`, else from the Build Tools.
- Git and Python 3 on `PATH`, Rust with the `x86_64-pc-windows-msvc` target.
- A path without spaces: `RUSTFLAGS` is split on whitespace.

### Build

```powershell
# 1. Build onnxruntime v1.30.0 from source (CPU only), then re2 explicitly
.\lab\provisioning\build-onnxruntime-static.ps1

# 2. Point ort-sys at the result and generate the link flags
$env:ORT_LIB_LOCATION = "$PWD\onnxruntime\build\Windows\Release\Release"
.\lab\provisioning\ort-static-link-flags.ps1 | Invoke-Expression

# 3. Build and test with static linking (disables dynamic-onnx)
cargo test -j 1 -p ml --release --no-default-features

# 4. Check what the result depends on
python tools\check-pe-imports.py target\release\deps\ml-*.exe
```

Measured on a 12-thread laptop, cold: the onnxruntime build took 48 minutes and left a
3.4 GB build directory with 101 `.lib` files (1.1 GB). `cargo test -p ml` then passes
(58 tests across the lib and the integration tests).

### What is different from Linux

- **CPU only, on purpose.** The prebuilt archive that `dynamic-onnx` downloads links
  DirectML, so the agent imports `directml.dll` and `d3d12.dll` for an execution provider
  it never uses. The source build has neither. `dxgi.dll` stays: onnxruntime's own device
  discovery imports it, and it is an OS component, not something to ship or sign.
- **Dynamic C runtime (`/MD`).** Same as rustc's MSVC target; mixing `/MT` libraries into
  a Rust binary fails with duplicate CRT symbols. The consequence is that the binary
  imports `msvcp140.dll` and `vcruntime140.dll` (the Visual C++ Redistributable), as the
  agent built on the prebuilt download already does. A static CRT would need the whole
  workspace on `-C target-feature=+crt-static`; not attempted here.
- **`re2` is not built either.** Same cause as on Linux (the CPU provider only takes its
  include path), so `ort-sys` stops with ``could not find native static library `re2` ``.
  `cmake --build --target re2` does not find it with the Visual Studio generator, because
  it lives in a sub-project; the build script builds `_deps\re2-build\re2.vcxproj` with
  MSBuild.
- **`shell32` must be linked.** onnxruntime's `telemetry.cc` calls `CommandLineToArgvW`;
  without `-l dylib=shell32` the link fails with `LNK2019 unresolved external symbol
  __imp_CommandLineToArgvW`. The flags script adds it. `shell32.dll` is on every Windows.
- **Libraries go to the linker as paths, not as `-l static=`.** `RUSTFLAGS` reaches every
  crate, and `-l static=<name>` bundles the library into each crate's `.rlib`: 101
  libraries (1.1 GB) times every dependency grew a `target` directory to 276 GB and filled
  a 950 GB disk. `-l static:-bundle=` avoids it but is refused for any library `ort-sys`
  also names itself ("overriding linking modifiers from command line is not supported"),
  and it names most of them. The flags script therefore emits `-C link-arg=<path to .lib>`:
  nothing is copied (the `ml` test run leaves a 4.3 GB `target`) and a library given twice
  is ignored. The Linux script uses `-l static=` and has the same bundling mechanism; its
  `target` size is worth a look.
- **Run cargo with `-j 1` (or 2) while linking the tests.** Each test binary links all
  101 libraries; several at once exhausted the commit limit on a 16 GB machine (`os error
  1455`, reported by `rustc` as "found invalid metadata files for crate `serde`", which
  points nowhere near the cause). Stop WSL first if it is running: its VM reserves memory.

### The full agent, measured

`cargo build -j 2 --release --no-default-features -p agent -p watchdog -p cli` with the
flags above: 20 minutes, exit 0 (onnxruntime already built).

| | static source build | prebuilt download (`dynamic-onnx`) |
|---|---|---|
| `agent.exe` | 39.1 MB | 42.6 MB |
| DLL imports (`check-pe-imports.py`) | 31 | 32 |
| `directml.dll`, `d3d12.dll` | no | yes |

The static agent is smaller and imports no DirectML. `agent.exe --help` runs. One host, one
build; not run under load or as the service.

### Still open for #337

- A `dumpbin`-based or CI check: `tools/check-pe-imports.py` reads the import tables
  without Visual Studio, but nothing runs it in CI because CI does not build a static
  Windows binary yet (the build takes about an hour).

## Platform Support

**Currently tested:**
- ✅ Ubuntu 24.04 (glibc) - ADR-0002 target platform
- ✅ Alpine 3.x (musl) - Not a target platform, but confirms approach works cross-libc
- ✅ Windows 11 (MSVC, CPU only) - `cargo test -p ml` passes, no `onnxruntime.dll`, no
  `directml.dll`, no `d3d12.dll` (see above)

**TODO:**
- ⏳ macOS (similar `.a` workflow, but untested)

macOS is an ADR-0002 target platform that has not been attempted yet.

## References

- Issue #110: ML crate static linking tracking issue
- Script #197: `lab/provisioning/ort-static-link-flags.sh`
- onnxruntime: https://github.com/microsoft/onnxruntime
- ort crate: https://github.com/pykeio/ort
