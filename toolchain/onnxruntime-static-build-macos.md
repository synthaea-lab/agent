# Static onnxruntime on macOS (ADR-0002, issue #338)

ADR-0002 asks for one statically linked agent binary on every platform: no
`libonnxruntime.dylib` to ship, sign and version beside it, and no library path an attacker
could hijack in a privileged process. Linux (`onnxruntime-static-build.md`) and Windows
(`build-onnxruntime-static.ps1`, #337) have it. This is the macOS recipe.

> **Status: validated on hosted Apple Silicon and Intel runners (2026-10-12), not on a Mac of
> ours.** The scripts were written without a Mac; the first run of
> `.github/workflows/macos-static-agent.yml` (PR #788, `macos-15`, macOS 15.7.9, Xcode 16.4, CMake
> 4.4.3, Rust 1.94.1) passed every step: onnxruntime from source, the link flags, the ML tests under
> static linking, the agent, and the import check against `otool -L`; the Intel runner
> (`macos-15-intel`, same macOS and Xcode) passed the same steps on its first complete run. See
> "Measured" and "What the assumptions turned out to be".

## Prerequisites

- Apple Silicon (arm64) or Intel (x86_64) Mac with macOS 13 or later. **Build natively on each
  architecture**; universal binaries are out of scope, and an x86_64 build under Rosetta on an
  Apple Silicon machine is refused by the script (see below).
- Xcode command line tools (`xcode-select --install`), `brew install cmake python@3.12 git`.
- Rust from `rust-toolchain.toml` (rustup picks it up).

## Steps (from the repository root)

```bash
# 1. onnxruntime v1.30.0 from source, static libraries only (cold: not measured on macOS)
./lab/provisioning/build-onnxruntime-static.sh

# 2. the link flags (the .a files the build produced, discovered rather than listed)
export ORT_LIB_LOCATION="$PWD/onnxruntime/build/MacOS/Release"
eval "$(./lab/provisioning/ort-static-link-flags.sh)"

# 3. build and test without the dynamic download
cargo test -p ml --release --no-default-features
cargo build --release --no-default-features -p agent

# 4. nothing but OS libraries may be loaded
python3 tools/check-macho-imports.py target/release/agent
otool -L target/release/agent        # the same list, from Apple's tool
```

What the scripts do on macOS that they do not do on Linux:

- `build-onnxruntime-static.sh` picks `build/MacOS/Release` (onnxruntime's name for the
  platform directory), counts CPUs with `sysctl -n hw.ncpu` and exports
  `MACOSX_DEPLOYMENT_TARGET` (default `13.0`, the oldest macOS the sensors document) so that
  onnxruntime and the agent target the same system.
- After the build it runs `lipo -archs` on every archive and stops if one is not built for this
  machine (`uname -m`): a build under Rosetta, or a universal archive, would link or fail
  depending on the Rust target. An archive `lipo` cannot describe (no object files) is skipped,
  but if it cannot describe *any* the script stops (the check would have looked at nothing).
- Both platforms now check that the onnxruntime checkout is at the commit the `v1.30.0` tag
  pointed at when this was pinned (`ONNX_COMMIT`), so a moved tag or a stale checkout fails
  instead of building something nobody reviewed.
- `ort-static-link-flags.sh` no longer needs bash 4 (`mapfile`, associative arrays), which
  macOS does not ship: `/bin/bash` there is 3.2. Its Linux output is byte-identical to before
  (checked on a synthetic tree).

## `tools/check-macho-imports.py`

`otool -L` exists only with the command line tools. The checker reads the Mach-O load commands
itself (thin and universal, 32 and 64 bit) and accepts a library only if its install name starts
with `/usr/lib/` or `/System/Library/`; anything else fails (`@rpath/...`, `/opt/homebrew/...`),
and a name containing `onnxruntime` fails even under an allowed prefix. A slice that loads no library at all is refused too (exit 2): every macOS program loads libSystem, so zero means the parser read the wrong thing. `--allow PREFIX` adds a
prefix. Exit 1: a library is not accepted; exit 2: not a Mach-O file, truncated, or a pattern that
matched nothing. `tools/tests/test_check_macho_imports.py` covers it with hand-built files; it was
also run against real Mach-O files (a thin arm64 `.dylib` and universal x86_64+arm64 ones taken
from unrelated software): the install names it printed are plausible, but it has not been
compared with `otool -L` on a binary this project built; the workflow prints both.

## Measured (2026-10-12; macOS 15.7.9, Xcode 16.4, Rust 1.94.1)

| What | Apple Silicon (`macos-15`, 3 cores) | Intel (`macos-15-intel`) |
| --- | --- | --- |
| onnxruntime v1.30.0 from source, cold | 20 min 11 s (23 min 06 s on a second cold run); 97 `.a` files, 23 directories | 40 min 41 s; 96 `.a` files, 22 directories |
| `ort-static-link-flags.sh` | no adjustment needed | no adjustment needed |
| `cargo test -p ml --release --no-default-features` | all pass (42 in the lib, the golden and scorer suites), 1 min 20 s | all pass, 4 min 37 s |
| agent link (`cargo build -j 2 --release --no-default-features -p agent`) | 13 to 14 min | 20 min 06 s |
| the agent's imports | nine libraries, **identical in `check-macho-imports.py` and `otool -L`**: CoreFoundation, CoreML, Foundation, libEndpointSecurity, libSystem, libbsm, libc++, libiconv, libobjc | the same nine |
| the `ml` test binary's imports | the first six of those (no sensor libraries); no onnxruntime | not printed |
| deployment target | `minos 13.0`, SDK 15.5 | `minos 13.0`, SDK 15.5 |
| the agent's size | 50,663,424 bytes (48.3 MiB), arm64 | 56,975,180 bytes (54.3 MiB), x86_64 |
| `agent --help` | runs | runs |
| a run with the libraries cached | the tests and the agent link only, about 16 to 17 minutes | not run |

## What the assumptions turned out to be

1. **onnxruntime builds unchanged with the Xcode tools and writes to `build/MacOS/Release`:** confirmed
   (its own argument dump shows `build_dir=.../build/MacOS`).
2. **A native build needs no architecture flag:** confirmed (`osx_arch='arm64'` by default, and the
   `lipo -archs` check passed on all 97 archives).
3. **`re2` needs the explicit target as on Linux:** the step ran and the build continued; whether it
   was *needed* was not tested.
4. **The abseil, utf8_range and model_package libraries are found by the same `.a` discovery:** confirmed.
5. **`ort-sys` adds the C++ runtime and the frameworks a static link needs:** confirmed, no extra
   flag was needed. **Surprise:** the link loads `CoreML.framework`, although this build has
   `use_coreml=False`. It is an OS framework (present since macOS 10.13, so it satisfies the
   "system libraries only" rule), and `ort-sys` is what asks for it; the agent therefore needs it
   at load time even though the CoreML execution provider is not compiled in.
6. **`MACOSX_DEPLOYMENT_TARGET=13.0` is accepted:** confirmed (`minos 13.0`).
7. **Runners:** `macos-15` is Apple Silicon; **`macos-15-intel` is a real Intel runner** (its CMake
   configured `CMAKE_OSX_ARCHITECTURES=x86_64`). `cmake`, `python3`, `cpio` and rustup were all
   there, and the cold build fits the job's limit with a wide margin.

**One thing the assumptions did not cover:** onnxruntime's CMake downloads its dependencies from
GitHub while it configures (protobuf's `protoc`, `cpuinfo`, abseil, ...). On the first manual
run both legs stopped a minute and a half in with `HTTP 504` on one of those downloads. The
workflow now retries the build up to three times (the checkout and what was already fetched are
reused). A build in a place with no route to GitHub needs those dependencies mirrored first
(`--cmake_deps_mirror_dir` in onnxruntime's `build.py`; not tried).

## Not covered

- Universal (fat) binaries: build each architecture natively and merge with `lipo` later if wanted.
- Code signing and notarization of the agent: unaffected by static linking, tracked with the
  macOS packaging (`packaging/macos`).
- A universal agent: each architecture is built natively and the sizes above are per architecture.
- Anything that needs the Endpoint Security entitlement: this only checks the link and the ML
  tests, not a running sensor.

## What was checked, and where

| Piece | Checked | How |
| --- | --- | --- |
| `ort-static-link-flags.sh` | yes (Linux) | same flags, byte for byte, as before on a synthetic tree |
| `build-onnxruntime-static.sh`, Linux path | yes | a stub `build.sh` and `cmake`: same steps and output as before |
| `build-onnxruntime-static.sh`, macOS branch | the shell logic only | stubbed `uname`, `sysctl`, `lipo` on Linux: `MacOS` directory, `hw.ncpu` jobs, the architecture check passes and refuses |
| `tools/check-macho-imports.py` | yes | 14 unit tests, plus real Mach-O files from other software |
| onnxruntime build, link, tests, `otool -L`, size (Apple Silicon) | **yes** | `macos-static-agent.yml` on `macos-15`, 2026-10-12 |
| the same on Intel (`macos-15-intel`) | **yes** | `workflow_dispatch` with `intel: true`, 2026-10-12 |
