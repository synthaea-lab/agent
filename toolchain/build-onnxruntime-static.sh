#!/usr/bin/env bash
# Builds onnxruntime v1.30.0 from source as static libraries for Linux and macOS,
# implementing ADR-0002 decision #2 (static linking for single-binary deployment).
#
# Issue #110 tracks the full static-linking integration; this script automates
# the onnxruntime build portion only — you still need to run the companion
# ort-static-link-flags.sh script and set RUSTFLAGS before building the ml crate.
#
# Tested on:
# - Ubuntu 24.04 (glibc) — ADR-0002 target platform
# - Alpine 3.x (musl) — not a target, but confirms cross-libc viability
# - macOS (Apple Silicon and Intel, #338): NOT TESTED by whoever wrote the macOS branch of
#   this script (no Mac was available). It is exercised by .github/workflows/macos-static-agent.yml;
#   read onnxruntime-static-build-macos.md for what is assumed and what that run must confirm.
#
# Prerequisites (Ubuntu):
#   sudo apt-get install -y build-essential cmake git python3
# Prerequisites (macOS): Xcode command line tools and `brew install cmake python@3.12 git`.
#
# Usage:
#   ./lab/provisioning/build-onnxruntime-static.sh [--clean] [--jobs N]
#
# Options:
#   --clean    Remove existing onnxruntime checkout before cloning
#   --jobs N   Parallel build jobs (default: nproc)
#
# Output:
#   ./onnxruntime/build/Linux/Release/*.a (macOS: build/MacOS/Release) — all static libraries
#   Prints the ORT_LIB_LOCATION to set for the next step (ort-static-link-flags.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ONNX_DIR="$REPO_ROOT/onnxruntime"
ONNX_VERSION="v1.30.0"
CLEAN=false

# The platform decides the build directory onnxruntime's build.py uses and how to count CPUs
# (`nproc` is GNU coreutils; macOS has `sysctl -n hw.ncpu`).
case "$(uname -s)" in
  Linux)
    PLATFORM_DIR="Linux"
    JOBS=$(nproc)
    ;;
  Darwin)
    PLATFORM_DIR="MacOS"
    JOBS=$(sysctl -n hw.ncpu)
    # One deployment target for onnxruntime and, through the same variable, for the cargo
    # build that links it: a library built for a newer macOS than the agent links against
    # produces "was built for newer macOS version" warnings and, worse, symbols the oldest
    # supported system lacks.
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
    ;;
  *)
    echo "Unsupported platform: $(uname -s) (Linux and macOS only; Windows has build-onnxruntime-static.ps1)" >&2
    exit 1
    ;;
esac

while [[ $# -gt 0 ]]; do
  case $1 in
    --clean)
      CLEAN=true
      shift
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [--clean] [--jobs N]" >&2
      exit 1
      ;;
  esac
done

echo "[onnxruntime] Building static libraries for ADR-0002 (issue #110)"
echo "  Version: $ONNX_VERSION"
echo "  Jobs: $JOBS"

# Clean previous checkout if requested
if [ "$CLEAN" = true ] && [ -d "$ONNX_DIR" ]; then
  echo "[onnxruntime] Removing existing checkout: $ONNX_DIR"
  rm -rf "$ONNX_DIR"
fi

# Clone if not present
if [ ! -d "$ONNX_DIR" ]; then
  echo "[onnxruntime] Cloning $ONNX_VERSION (shallow clone, ~200 MB)"
  git clone --depth 1 --branch "$ONNX_VERSION" \
    https://github.com/microsoft/onnxruntime.git "$ONNX_DIR"
else
  echo "[onnxruntime] Using existing checkout: $ONNX_DIR"
fi

cd "$ONNX_DIR"

# Build static libraries
echo "[onnxruntime] Building static libraries (this takes 5-15 minutes)"
ORT_BUILD_ARGS=()
# ONNX Runtime blocks root by default. The package-portability workflow runs in
# an isolated root-owned Alpine container and opts in explicitly for this build.
if [ "${SYNTHAEA_ALLOW_ORT_ROOT_BUILD:-0}" = "1" ] && [ "$(id -u)" -eq 0 ]; then
  ORT_BUILD_ARGS+=(--allow_running_as_root)
fi
# ONNX Runtime builds with -Werror by default. Newer toolchains warn inside their
# own headers (GCC 15's libstdc++ raises -Wmaybe-uninitialized in bits/unicode.h
# while compiling onnxruntime_common/logging.cc on Alpine), which is not ours to
# fix and would stop the whole build. Keep warnings visible, but not fatal.
ORT_BUILD_ARGS+=(--compile_no_warning_as_error)
./build.sh \
  --config Release \
  --update \
  --build \
  --no_telemetry \
  --cmake_extra_defines onnxruntime_BUILD_UNIT_TESTS=OFF \
  --parallel "$JOBS" \
  "${ORT_BUILD_ARGS[@]}"

# Ubuntu-specific (assumed to apply on macOS too: same CMake graph, nothing there schedules
# it either; if the target does not exist the build stops here and says so):
# re2 is an orphaned CMake target in static-only builds
# (onnxruntime_providers_cpu.cmake only does onnxruntime_add_include_to_target,
# never target_link_libraries, so nothing in the build graph schedules it).
# Build it explicitly before the ml crate tries to link against it.
echo "[onnxruntime] Building re2 explicitly (Ubuntu/glibc requirement)"
cmake --build "build/$PLATFORM_DIR/Release" --target re2 -j"$JOBS"

BUILD_DIR="$ONNX_DIR/build/$PLATFORM_DIR/Release"

# Verify output
LIB_COUNT=$(find "$BUILD_DIR" -name 'lib*.a' | wc -l)
if [ "$LIB_COUNT" -eq 0 ]; then
  echo "[onnxruntime] ERROR: No .a files found in $BUILD_DIR" >&2
  echo "  The build may have failed silently. Check build logs above." >&2
  exit 1
fi

# On macOS the libraries must be for the machine the agent is built on: a stray x86_64 build
# under Rosetta, or a universal archive, would link or not depending on the Rust target.
if [ "$(uname -s)" = "Darwin" ]; then
  HOST_ARCH="$(uname -m)"
  WRONG=0
  while IFS= read -r archive; do
    archs="$(lipo -archs "$archive" 2>/dev/null || true)"
    # An archive lipo cannot describe (no object files) says nothing about the architecture.
    [ -n "$archs" ] || continue
    case " $archs " in
      *" $HOST_ARCH "*) ;;
      *)
        echo "[onnxruntime] ERROR: $archive is built for '${archs:-unknown}', not for this machine ($HOST_ARCH)" >&2
        WRONG=$((WRONG + 1))
        ;;
    esac
  done < <(find "$BUILD_DIR" -name 'lib*.a')
  if [ "$WRONG" -gt 0 ]; then
    echo "[onnxruntime] $WRONG archive(s) for another architecture; is this shell running under Rosetta?" >&2
    exit 1
  fi
fi

echo "[onnxruntime] Build complete!"
echo "  Static libraries: $LIB_COUNT .a files"
echo "  Location: $BUILD_DIR"
echo ""
echo "Next steps:"
echo "  1. Set environment variable:"
echo "       export ORT_LIB_LOCATION=\"$BUILD_DIR\""
echo ""
echo "  2. Generate RUSTFLAGS for static linking:"
echo "       eval \"\$(./lab/provisioning/ort-static-link-flags.sh)\""
echo ""
echo "  3. Build and test the ml crate:"
echo "       cargo test -p ml --release"
echo ""
echo "  4. Verify no runtime onnxruntime dependency:"
if [ "$(uname -s)" = "Darwin" ]; then
  echo "       python3 tools/check-macho-imports.py target/release/deps/ml-*"
  echo "     (exit 0; otool -L is the same list)"
else
  echo "       ldd target/release/deps/ml-* | grep -i onnx"
  echo "     (should return nothing)"
fi
