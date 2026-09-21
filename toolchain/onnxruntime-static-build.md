# ONNX Runtime Static Linking Guide

**Status:** Implementation of ADR-0002 decision #2 (static linking for single-binary deployment)
**Issue:** #110
**Platform:** Linux (Ubuntu 24.04+ tested; Alpine/musl tested but not a target platform)

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

## Platform Support

**Currently tested:**
- ✅ Ubuntu 24.04 (glibc) - ADR-0002 target platform
- ✅ Alpine 3.x (musl) - Not a target platform, but confirms approach works cross-libc

**TODO:**
- ⏳ Windows (MSVC `.lib` files, different flag syntax)
- ⏳ macOS (similar `.a` workflow, but untested)

Both Windows and macOS are ADR-0002 target platforms but haven't been attempted yet.

## References

- Issue #110: ML crate static linking tracking issue
- Script #197: `lab/provisioning/ort-static-link-flags.sh`
- onnxruntime: https://github.com/microsoft/onnxruntime
- ort crate: https://github.com/pykeio/ort
