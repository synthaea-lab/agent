#!/usr/bin/env bash
# Provisioning for the lab's Arch Linux VM (rolling, glibc, x86_64): Rust +
# eBPF toolchain for building the agent and probes, plus the packages the
# lab/scenarios/ scripts need. Companion to linux-toolchain.sh (Debian/RPM)
# and alpine-toolchain.sh (musl) — see issue #124. Idempotent: rerunnable via
# `vagrant provision <machine>` or a plain re-run.
#
# The point of this box is that it moves: rolling repos mean whatever kernel
# and LLVM/clang are current the day someone runs `vagrant up` here, which is
# exactly where #53's no-CO-RE fragility and the bpf-linker/rustc-nightly
# LLVM-major alignment (see linux-toolchain.sh's comment on that) are most
# likely to drift first. Record the versions actually seen in lab/MATRIX.md
# after a run, don't hardcode them here.
set -euo pipefail

PACMAN="sudo pacman -S --needed --noconfirm"

if ! command -v pacman >/dev/null 2>&1; then
  echo "[err] pacman not found — this script targets Arch only" >&2
  exit 1
fi
. /etc/os-release
echo "== System packages (distro: ${ID:-?}) =="

echo "== Keyring refresh (rolling box image, likely older than today's repos) =="
# generic/arch's published box image lags the rolling repos by however long
# since it was last rebuilt (v4.3.12 here dates to 2024-01) — every day past
# that, new packager signing keys land upstream that the box's local keyring
# has never seen. `pacman -Sy` then aborts mid-transaction with "signature
# ... unknown trust" / "invalid or corrupted package (PGP signature)" on
# whichever packages happen to be signed by a newer key, not because
# anything is actually corrupted. Fix the keyring FIRST, before installing
# anything else, or every subsequent pacman -S is a coin flip.
sudo pacman-key --init
sudo pacman-key --populate archlinux
sudo pacman -Sy --noconfirm archlinux-keyring
sudo pacman -Su --noconfirm

# base-devel: gcc/make/binutils, the Arch equivalent of build-essential.
# Arch doesn't split runtime/-dev packages the way apt/dnf do — one package
# (openssl, zstd, elfutils, clang, llvm) carries both the library and its
# headers, so there's no libssl-dev/libzstd-dev/libclang-dev/llvm-dev list
# to separately install here.
$PACMAN base-devel curl git pkgconf rsync zstd openbsd-netcat bind \
  openssl elfutils clang llvm

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
# Same upstream prebuilt as linux-toolchain.sh/alpine-toolchain.sh, for the
# same reason: it bundles its own LLVM cut in lockstep with recent rustc
# nightly, so it doesn't depend on whatever LLVM major `pacman -S llvm`
# happens to pull today. Building from source against Arch's rolling LLVM
# would reintroduce exactly the alignment fragility the prebuilt exists to
# avoid — and rolling makes that drift more likely here than anywhere else
# in the matrix, not less.
BPF_LINKER_VERSION="v0.11.1"
install_bpf_linker() {
  local url="https://github.com/aya-rs/bpf-linker/releases/download/${BPF_LINKER_VERSION}/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst"
  local tmp bin rc
  tmp=$(mktemp -d)
  echo "[info] bpf-linker ${BPF_LINKER_VERSION} (prebuilt): $url"
  curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors "$url" -o "$tmp/bl.tar.zst" \
    && tar --zstd -xf "$tmp/bl.tar.zst" -C "$tmp" \
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

# The one check that matters most on THIS box: this is the rolling-repo
# machine, so its nightly's LLVM major is the most likely in the whole
# matrix to run ahead of the prebuilt bpf-linker release (see the header
# comment above). Same sanity check as linux-toolchain.sh.
_nightly_llvm=$(rustup run nightly rustc -Vv 2>/dev/null | awk '/^LLVM version/{print $3}' | cut -d. -f1)
if [ -n "${_nightly_llvm:-}" ] && [ "$_nightly_llvm" -gt 24 ]; then
  echo "[warn] nightly rustc uses LLVM $_nightly_llvm — bump BPF_LINKER_VERSION if probe builds hit bitcode-version errors" >&2
fi

echo "== bindgen-cli + aya-tool =="
# NOT verified against Arch in the session this script was written from —
# revisit if libclang discovery needs LIBCLANG_PATH set explicitly here.
command -v bindgen >/dev/null 2>&1 || cargo install bindgen-cli
command -v aya-tool >/dev/null 2>&1 || cargo install --git https://github.com/aya-rs/aya aya-tool

# sudo's restricted PATH doesn't see ~/.cargo/bin — symlinks into
# /usr/local/bin so `sudo cargo`-driven builds and the agent's helpers work.
for tool in bindgen aya-tool bpf-linker; do
  [ -x "$HOME/.cargo/bin/$tool" ] && sudo ln -sf "$HOME/.cargo/bin/$tool" "/usr/local/bin/$tool"
done

echo "== Done =="
echo "Source synced into /synthaea — see lab/vagrant-hyperv/README.md for the build."
echo
echo "Known caveats not resolved by this script (see issue #124):"
echo "  - ml/ (ONNX Runtime) is out of scope here, same as Alpine (#123): not"
echo "    currently a dependency of the agent binary, so this doesn't block"
echo "    the walking-skeleton scenario. See issue #110 (ADR-0002 static"
echo "    linking) separately."
echo "  - This installs whatever kernel/LLVM/clang the rolling repos serve"
echo "    today. Record the actual versions seen in lab/MATRIX.md after a"
echo "    run — pinning them here would defeat the point of this box."
