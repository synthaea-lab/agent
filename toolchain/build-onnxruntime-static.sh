#!/usr/bin/env bash
# Builds onnxruntime v1.30.0 from source as static libraries for Linux,
# implementing ADR-0002 decision #2 (static linking for single-binary deployment).
#
# Issue #110 tracks the full static-linking integration; this script automates
# the onnxruntime build portion only — you still need to run the companion
# ort-static-link-flags.sh script and set RUSTFLAGS before building the ml crate.
#
# Tested on:
# - Ubuntu 24.04 (glibc) — ADR-0002 target platform
# - Alpine 3.x (musl) — not a target, but confirms cross-libc viability
#
# Prerequisites (Ubuntu):
#   sudo apt-get install -y build-essential cmake git python3
#
# Usage:
#   ./lab/provisioning/build-onnxruntime-static.sh [--clean] [--jobs N]
#
# Options:
#   --clean    Remove existing onnxruntime checkout before cloning
#   --jobs N   Parallel build jobs (default: nproc)
#
# Output:
#   ./onnxruntime/build/Linux/Release/*.a — all static libraries
#   Sets ORT_LIB_LOCATION for the next step (ort-static-link-flags.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ONNX_DIR="$REPO_ROOT/onnxruntime"
ONNX_VERSION="v1.30.0"
CLEAN=false
JOBS=$(nproc)

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
./build.sh \
  --config Release \
  --update \
  --build \
  --no_telemetry \
  --cmake_extra_defines onnxruntime_BUILD_UNIT_TESTS=OFF \
  --parallel "$JOBS"

# Ubuntu-specific: re2 is an orphaned CMake target in static-only builds
# (onnxruntime_providers_cpu.cmake only does onnxruntime_add_include_to_target,
# never target_link_libraries, so nothing in the build graph schedules it).
# Build it explicitly before the ml crate tries to link against it.
echo "[onnxruntime] Building re2 explicitly (Ubuntu/glibc requirement)"
cmake --build build/Linux/Release --target re2 -j"$JOBS"

BUILD_DIR="$ONNX_DIR/build/Linux/Release"

# Verify output
LIB_COUNT=$(find "$BUILD_DIR" -name 'lib*.a' | wc -l)
if [ "$LIB_COUNT" -eq 0 ]; then
  echo "[onnxruntime] ERROR: No .a files found in $BUILD_DIR" >&2
  echo "  The build may have failed silently. Check build logs above." >&2
  exit 1
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
echo "       ldd target/release/deps/ml-* | grep -i onnx"
echo "     (should return nothing)"
