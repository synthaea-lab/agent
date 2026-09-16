#!/usr/bin/env bash
# Provisioning for the lab's Alpine VM (musl/BusyBox, x86_64): Rust + eBPF
# toolchain for building the agent and probes, plus the packages the
# lab/scenarios/ scripts need. Companion to linux-toolchain.sh (Debian/RPM) —
# see issue #123. Idempotent: rerunnable via `vagrant provision <machine>` or
# a plain re-run.
#
# Unlike linux-toolchain.sh, this script does NOT need to align bpf-linker's
# LLVM major with the pinned nightly's: `cargo install bpf-linker` on Alpine
# hits a genuine musl linking bug (the resulting binary has no PT_INTERP
# segment — it's built as a static/dynamic hybrid that crashes on the very
# first LLVM call, SIGSEGV, no usable error). The upstream prebuilt release
# (musl-static, bundles its own LLVM) sidesteps that entirely and was
# verified to work against BOTH the pinned nightly (LLVM 22) and a plain
# `rustup toolchain install nightly` (LLVM 23) on Alpine 3.24 — no alignment
# dance needed. Full source-build post-mortem (three stacked bugs, how each
# was diagnosed) is in the #123 PR discussion if a future bpf-linker release
# regresses this and the prebuilt-release workaround stops being enough.
set -euo pipefail

APK="sudo apk"

if ! command -v apk >/dev/null 2>&1; then
  echo "[err] apk not found — this script targets Alpine only" >&2
  exit 1
fi
. /etc/os-release
echo "== System packages (distro: ${ID:-?} ${VERSION_ID:-?}) =="

$APK update -q
# build-base: gcc/make/musl-dev, the musl-native equivalent of build-essential.
# tar + zstd: BusyBox's built-in tar does NOT support --zstd (verified: fails
# with "unrecognized option: zstd") — needed to unpack bpf-linker's release
# archive below.
$APK add -q \
  build-base curl git pkgconf rsync tar zstd bind-tools \
  openssl-dev zstd-dev elfutils-dev \
  clang llvm-dev

echo "== BTF check =="
if [ -r /sys/kernel/btf/vmlinux ]; then
  echo "[ok] BTF present (/sys/kernel/btf/vmlinux) — kernel $(uname -r)"
else
  echo "[warn] no BTF on this kernel ($(uname -r)) — the eBPF sensor won't be able to attach to it" >&2
fi

echo "== Rust (rustup, stable + nightly + rust-src) =="
if ! command -v "$HOME/.cargo/bin/cargo" >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup toolchain install nightly --component rust-src

# Pre-install the exact channel rust-toolchain.toml pins, with its components,
# so the first `cargo` inside the tree doesn't download a toolchain mid-build.
_pinned=$(grep -oE 'channel *= *"[^"]+"' "${SYNTHAEA_SRC:-/synthaea}/rust-toolchain.toml" 2>/dev/null | cut -d'"' -f2)
if [ -n "${_pinned:-}" ]; then
  echo "[info] rust-toolchain.toml pins $_pinned — installing it now"
  rustup toolchain install "$_pinned" --component rustfmt --component clippy
fi

echo "== bpf-linker (prebuilt musl-static release) =="
BPF_LINKER_VERSION="v0.11.1"
install_bpf_linker() {
  local url="https://github.com/aya-rs/bpf-linker/releases/download/${BPF_LINKER_VERSION}/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst"
  local tmp bin rc
  tmp=$(mktemp -d)
  echo "[info] bpf-linker ${BPF_LINKER_VERSION} (prebuilt): $url"
  curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors "$url" -o "$tmp/bl.tar.zst" \
    && zstd -d -q "$tmp/bl.tar.zst" -o "$tmp/bl.tar" \
    && tar -xf "$tmp/bl.tar" -C "$tmp" \
    && bin=$(find "$tmp" -type f -name bpf-linker -print -quit) && [ -n "$bin" ] \
    && install -m755 "$bin" "$HOME/.cargo/bin/bpf-linker"
  rc=$?
  rm -rf "$tmp"
  return $rc
}

# Same stale-build-cache bust as linux-toolchain.sh (userspace/build.rs's
# rerun-if-env-changed=PATH doesn't fire when ~/.cargo/bin was already on
# PATH and only the linker binary appeared).
bust_stale_sensor_linux_build() {
  local src="${SYNTHAEA_SRC:-/synthaea}" d
  for d in "$src"/target/*/build "$src"/target/*/.fingerprint; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 1 -name 'sensor-linux-*' -exec rm -rf {} + 2>/dev/null || true
  done
}

if ! command -v bpf-linker >/dev/null 2>&1; then
  if install_bpf_linker; then
    bust_stale_sensor_linux_build
  else
    echo "[warn] bpf-linker install failed — eBPF builds impossible in this VM" >&2
    echo "[warn] (replay-only: build the agent elsewhere, run scenarios here)" >&2
  fi
fi
command -v bpf-linker >/dev/null 2>&1 && bpf-linker --version

echo "== bindgen-cli + aya-tool =="
# Verified on Alpine: `cargo install bindgen-cli` produces a static-pie binary
# (Rust's musl default) that can generate --version output fine but panics
# the moment it actually needs libclang ("Unable to find libclang: ... Dynamic
# loading not supported") — a static musl binary cannot dlopen anything at
# runtime, no path config fixes that. Same class of bug as bpf-linker/ort
# earlier in this script: rebuild dynamic. aya-tool, by contrast, generates
# bindings straight from kernel BTF without touching libclang/dlopen — it
# works fine static-pie, no rebuild needed.
command -v bindgen >/dev/null 2>&1 \
  || RUSTFLAGS="-C target-feature=-crt-static" cargo install bindgen-cli --locked
command -v aya-tool >/dev/null 2>&1 || cargo install --git https://github.com/aya-rs/aya aya-tool

for tool in bindgen aya-tool bpf-linker; do
  [ -x "$HOME/.cargo/bin/$tool" ] && sudo ln -sf "$HOME/.cargo/bin/$tool" "/usr/local/bin/$tool"
done

echo "== Done =="
echo "Source synced into /synthaea — see lab/vagrant/README.md for the build."
echo
echo "Known caveats not resolved by this script (see issue #123):"
echo "  - lab/scenarios/beacon.sh: verified against BusyBox's own nc applet"
echo "    (not netcat-openbsd — that package isn't installed by this script)."
echo "    Its listener fallback (nc -l -p PORT || nc -l PORT, from issue #113)"
echo "    handles the BusyBox/OpenBSD flag difference correctly; the full"
echo "    T1071/T1041 walking-skeleton scenario fires as expected. Other"
echo "    lab/scenarios/*.sh scripts (wget/sh usage) remain unverified."
echo "  - ml/ (ONNX Runtime) is out of scope here: it needs a newer onnxruntime"
echo "    than Alpine's stable branch ships (API version mismatch), plus"
echo "    ORT_LIB_LOCATION/ORT_PREFER_DYNAMIC_LINK and a non-static-pie build"
echo "    (RUSTFLAGS=\"-C target-feature=-crt-static\"). ml is not currently a"
echo "    dependency of the agent binary, so this doesn't block the"
echo "    walking-skeleton scenario. See issue #110 (ADR-0002 wants ort"
echo "    statically linked, which Alpine's onnxruntime package cannot do —"
echo "    no static archive is shipped, only the .so)."
