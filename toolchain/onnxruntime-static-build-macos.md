# Static onnxruntime on macOS (ADR-0002, issue #338)

ADR-0002 asks for one statically linked agent binary on every platform: no
`libonnxruntime.dylib` to ship, sign and version beside it, and no library path an attacker
could hijack in a privileged process. Linux (`onnxruntime-static-build.md`) and Windows
(`build-onnxruntime-static.ps1`, #337) have it. This is the macOS recipe.

> **Status: written, never run.** Everything below was prepared without a Mac. The scripts and the
> parser were tested for what can be tested on Linux (see "What was checked"); the build of
> onnxruntime on macOS, the link, and the `otool` comparison have **not** been done by anyone.
> `.github/workflows/macos-static-agent.yml` is the first run. Treat the "What this assumes"
> section as a list of hypotheses that run must confirm or correct, and update this file from its log.

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
  depending on the Rust target. An archive `lipo` cannot describe (no object files) is skipped.
- `ort-static-link-flags.sh` no longer needs bash 4 (`mapfile`, associative arrays), which
  macOS does not ship: `/bin/bash` there is 3.2. Its Linux output is byte-identical to before
  (checked on a synthetic tree).

## `tools/check-macho-imports.py`

`otool -L` exists only with the command line tools. The checker reads the Mach-O load commands
itself (thin and universal, 32 and 64 bit) and accepts a library only if its install name starts
with `/usr/lib/` or `/System/Library/`; anything else fails (`@rpath/...`, `/opt/homebrew/...`),
and a name containing `onnxruntime` fails even under an allowed prefix. `--allow PREFIX` adds a
prefix. Exit 1: a library is not accepted; exit 2: not a Mach-O file, truncated, or a pattern that
matched nothing. `tools/tests/test_check_macho_imports.py` covers it with hand-built files; it was
also run against real Mach-O files (a thin arm64 `.dylib` and universal x86_64+arm64 ones taken
from unrelated software): the install names it printed are plausible, but it has not been
compared with `otool -L` on a binary this project built; the workflow prints both.

## What this assumes (to confirm on the first real run)

1. `./build.sh --config Release --update --build --no_telemetry ...` works unchanged on macOS
   with the Xcode command line tools and a recent CMake, and writes to `build/MacOS/Release`.
2. A native build needs no architecture flag (onnxruntime follows the host). If the
   `lipo` check fails on a native Apple Silicon runner, this is the assumption that was wrong.
3. `re2` is an orphaned CMake target here as on Linux, so the explicit
   `cmake --build ... --target re2` is needed (if the target does not exist the script stops there).
4. The ~78 abseil libraries, `utf8_range` and `model_package` that `ort-sys` 2.0.0-rc.13 does not
   list are found by the same `.a` discovery the Linux script uses.
5. `ort-sys` adds what a static link needs from the C++ runtime and the system frameworks on
   macOS. If the link fails with undefined `std::` or Objective-C/CoreFoundation symbols, that
   assumption is wrong: add `-C link-arg=-lc++` or `-C link-arg=-framework -C link-arg=Foundation`
   to `RUSTFLAGS` in the script and record why here.
6. `MACOSX_DEPLOYMENT_TARGET=13.0` is accepted by onnxruntime's CMake and by cargo for this
   dependency graph; some macOS APIs the sensors use are 14+ and are gated at run time.
7. The hosted runners: `macos-15` is Apple Silicon, `macos-15-intel` is Intel (a label this file
   cannot verify; hence the Intel leg only runs on `workflow_dispatch`), both have `cmake`,
   `python3`, `cpio` and rustup, and a cold onnxruntime build fits the job's 240 minutes. The cold
   duration and the cache size are unknown and should be written here after the first run.

## Not covered

- Universal (fat) binaries: build each architecture natively and merge with `lipo` later if wanted.
- Code signing and notarization of the agent: unaffected by static linking, tracked with the
  macOS packaging (`packaging/macos`).
- The size of the binary: the workflow prints it in its job summary; record it here after a run.
- Anything that needs the Endpoint Security entitlement: this only checks the link and the ML
  tests, not a running sensor.

## What was checked, and where

| Piece | Checked | How |
| --- | --- | --- |
| `ort-static-link-flags.sh` | yes (Linux) | same flags, byte for byte, as before on a synthetic tree |
| `build-onnxruntime-static.sh`, Linux path | yes | a stub `build.sh` and `cmake`: same steps and output as before |
| `build-onnxruntime-static.sh`, macOS branch | the shell logic only | stubbed `uname`, `sysctl`, `lipo` on Linux: `MacOS` directory, `hw.ncpu` jobs, the architecture check passes and refuses |
| `tools/check-macho-imports.py` | yes | 14 unit tests, plus real Mach-O files from other software |
| onnxruntime build, link, tests, `otool -L`, size | **no** | `macos-static-agent.yml`, never run |
