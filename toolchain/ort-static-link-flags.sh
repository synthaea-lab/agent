#!/usr/bin/env bash
# Generates the RUSTFLAGS needed to statically link onnxruntime into `ml`
# (ADR-0002) on Linux — a workaround for `ort-sys` v2.0.0-rc.13's hardcoded
# static-link library list, which is incomplete for onnxruntime 1.30.0 built
# from source (issue #110).
#
# Confirmed on two independent builds — Alpine/musl (Jihair's PoC) and Ubuntu
# 24.04/glibc (reproduced separately) — that a normal
# `./build.sh --config Release --update --build` produces ~78 abseil
# sub-libraries (the Cord/Cordz/Status family) plus utf8_range and
# model_package that genuinely get linked into onnxruntime's own static libs,
# but sit in `_deps/*`/`model_package/` directories `ort-sys` never searches.
# Rather than hand-maintain a list of `-L`/`-l` flags (fragile: it drifts every
# time onnxruntime restructures a dependency), this walks $ORT_LIB_LOCATION for
# every `.a` file the build actually produced and emits flags from that.
#
# On Ubuntu specifically, `re2` needs one extra step first: onnxruntime's CPU
# provider only pulls in re2's headers (`onnxruntime_add_include_to_target`),
# never a `target_link_libraries` — so without a shared-lib or test target to
# create a real CMake dependency on it, `re2` is never scheduled to build at
# all (not just "hard to find"; `libre2.a` won't exist yet). Build it
# explicitly before running this script:
#   cmake --build "$ORT_LIB_LOCATION" --target re2 -j"$(nproc)"
#
# NOT wired into the workspace Cargo.toml or CI, and not a decision that
# static linking should ship this way — a hand-run prototype for issue #110,
# to be pointed at from there. See that issue for the two root causes this
# papers over (ort-sys's incomplete list vs. onnxruntime's own CMake graph
# never scheduling `re2`) and why neither is fixed upstream yet.
#
# Usage on Linux (from an onnxruntime checkout, after building; on macOS use
# `build/MacOS/Release` and `sysctl -n hw.ncpu`, or just run build-onnxruntime-static.sh):
#   ./build.sh --config Release --update --build --no_telemetry \
#     --cmake_extra_defines onnxruntime_BUILD_UNIT_TESTS=OFF
#   cmake --build build/Linux/Release --target re2 -j"$(nproc)"
#   export ORT_LIB_LOCATION="$PWD/build/Linux/Release"
#   eval "$(./lab/provisioning/ort-static-link-flags.sh)"
#   cargo test -p ml --release
#
# Linux and macOS (`.a` extension, `-l`/`-L` syntax; on macOS ORT_LIB_LOCATION is
# `build/MacOS/Release`, see build-onnxruntime-static.sh and onnxruntime-static-build-macos.md,
# #338). Windows (`.lib`, MSVC) has its own variant, ort-static-link-flags.ps1 (#337).
set -euo pipefail

: "${ORT_LIB_LOCATION:?set ORT_LIB_LOCATION to the onnxruntime build/Linux/Release directory}"

if [ ! -d "$ORT_LIB_LOCATION" ]; then
  echo "ORT_LIB_LOCATION does not exist: $ORT_LIB_LOCATION" >&2
  exit 1
fi

# Written for bash 3.2 (the one macOS ships as /bin/bash): no `mapfile`, no associative
# arrays. The output is the same as the bash-4 version it replaces, flag for flag.
libs="$(find "$ORT_LIB_LOCATION" -name 'lib*.a' | sort)"

if [ -z "$libs" ]; then
  echo "no .a files found under $ORT_LIB_LOCATION — did the build actually run?" >&2
  exit 1
fi

seen_dirs=$'\n'
seen_names=$'\n'
n_dirs=0
n_names=0
flags=()

while IFS= read -r path; do
  dir=$(dirname "$path")
  base=$(basename "$path")
  name=${base#lib}
  name=${name%.a}

  case "$seen_dirs" in
    *$'\n'"$dir"$'\n'*) ;;
    *)
      flags+=("-L" "native=$dir")
      seen_dirs="$seen_dirs$dir"$'\n'
      n_dirs=$((n_dirs + 1))
      ;;
  esac
  case "$seen_names" in
    *$'\n'"$name"$'\n'*) ;;
    *)
      flags+=("-l" "static=$name")
      seen_names="$seen_names$name"$'\n'
      n_names=$((n_names + 1))
      ;;
  esac
done <<< "$libs"

# RUSTFLAGS is whitespace-split, so this breaks if $ORT_LIB_LOCATION itself
# contains a space — a real limitation of the mechanism, not just this
# script; build onnxruntime under a space-free path.
printf 'export RUSTFLAGS="%s"\n' "${flags[*]}"
echo "# $n_dirs directories, $n_names libraries" >&2
