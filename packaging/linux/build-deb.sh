#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

TARGET="x86_64-unknown-linux-musl"

fail() {
    echo "error: $*" >&2
    exit 1
}

if [ "$(uname -m)" != "x86_64" ]; then
    fail "the static .deb builder currently supports x86_64 only (found $(uname -m))"
fi
if ! ldd --version 2>&1 | head -n 1 | grep -qi musl; then
    fail "run this script on an x86_64 musl host (Alpine); the ONNX Runtime archives must be built for musl"
fi
command -v dpkg-deb >/dev/null || fail "install dpkg-deb (on Alpine: apk add dpkg)"
command -v readelf >/dev/null || fail "install readelf (on Alpine: apk add binutils)"
command -v bpf-linker >/dev/null || fail "install bpf-linker with lab/provisioning/alpine-toolchain.sh"

# cargo-deb only packages; build the exact musl artifacts ourselves so Cargo
# cannot re-enable ml's default download-binaries feature.
if ! command -v cargo-deb >/dev/null 2>&1; then
    echo "cargo-deb not found. Installing..."
    cargo install cargo-deb --locked
fi

if [ -z "${ORT_LIB_LOCATION:-}" ]; then
    echo "Building static ONNX Runtime libraries from source on this musl host..."
    "$REPO_ROOT/lab/provisioning/build-onnxruntime-static.sh"
    export ORT_LIB_LOCATION="$REPO_ROOT/onnxruntime/build/Linux/Release"
fi
[ -d "$ORT_LIB_LOCATION" ] || fail "ORT_LIB_LOCATION does not exist: $ORT_LIB_LOCATION"

# ort-sys's pinned static-link list omits libraries produced by ONNX Runtime
# 1.30.0; discover them from the source build rather than linking pyke's glibc archive.
eval "$("$REPO_ROOT/lab/provisioning/ort-static-link-flags.sh")"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-feature=+crt-static"
rustup target add "$TARGET"

# Real inference stays enabled; only the prebuilt, glibc-built download is disabled.
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER=env \
    cargo test --locked --release --target "$TARGET" --no-default-features -p ml
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" cargo build --locked --release \
    --target "$TARGET" --no-default-features -p agent -p watchdog -p cli

for binary in agent watchdog cli; do
    path="$REPO_ROOT/target/$TARGET/release/$binary"
    [ -x "$path" ] || fail "expected release binary missing: $path"
    if readelf -l "$path" | grep -q 'Requesting program interpreter'; then
        fail "$binary is dynamically linked; the package must contain static musl binaries"
    fi
done

for crate in sensor-linux sensor-linux-uprobes; do
    probe="$(find "$REPO_ROOT/target/$TARGET/release/build" -type f -path "*/build/${crate}-*/out/sensor-linux-ebpf" -print -quit)"
    [ -n "$probe" ] || fail "$crate was built without embedded eBPF probes"
done
"$REPO_ROOT/target/$TARGET/release/agent" --help >/dev/null

cargo deb -p watchdog --target "$TARGET" --no-build
DEB_FILE="$(find "$REPO_ROOT/target/debian" -maxdepth 1 -type f -name '*.deb' -print | sort | head -n 1)"
[ -n "$DEB_FILE" ] || fail "cargo-deb did not produce a .deb"

echo
echo "==> Static musl package created: $DEB_FILE"
echo "Package contents:"
dpkg-deb -c "$DEB_FILE"
echo
echo "Install with: sudo dpkg -i $DEB_FILE"
echo "             sudo apt-get install -f"
