#!/usr/bin/env bash
# Clippy for the eBPF probes (sensor-linux-ebpf). The workspace clippy passes exclude this crate
# because it only builds for bpfel-unknown-none with the pinned nightly, so it is linted here,
# once per `bpf_target_arch` it is built for (AS-029). The workspace lints apply (lints.workspace).
# `x86` (i686) is not linted: aya-ebpf-cty does not build for it in a host-side check.
set -euo pipefail
cd "$(dirname "$0")/.."
toolchain="$(tr -d '[:space:]' < packaging/toolchain/ebpf-toolchain.txt)"
for arch in x86_64 aarch64; do
    echo "== clippy sensor-linux-ebpf, bpf_target_arch=$arch"
    RUSTFLAGS="--cfg bpf_target_arch=\"$arch\"" cargo "+$toolchain" clippy -p sensor-linux-ebpf         --target bpfel-unknown-none -Z build-std=core --target-dir "target/clippy-ebpf-$arch"         -- -D warnings
done
