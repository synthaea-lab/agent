#!/usr/bin/env bash
# Provisioning for the lab's Linux VMs (Debian/RPM matrix, x86_64 or arm64):
# Rust + eBPF toolchain for building the agent and probes, plus the packages the
# lab/scenarios/ scripts need. Provider-neutral — run by any harness (Vagrant
# shell provisioner, ssh, cloud-init). Idempotent: rerunnable via
# `vagrant provision <machine>` or a plain re-run.
#
# bpf-linker comes from the upstream musl-static release (bundled LLVM matching
# recent rustc nightly). If that download fails the script CONTINUES with a
# warning — the VM is then replay-only (run scenarios against a binary built
# elsewhere), matching the replay-only rows in lab/MATRIX.md.
set -euo pipefail

# sudo does not propagate the environment: pass DEBIAN_FRONTEND explicitly,
# otherwise debconf tries to open whiptail without a terminal (notably the
# "pending kernel upgrade" dialog — non-fatal, but noisy).
APT="sudo env DEBIAN_FRONTEND=noninteractive apt-get"
DNF="sudo dnf -q -y"

if command -v apt-get >/dev/null 2>&1; then FAMILY=debian
elif command -v dnf >/dev/null 2>&1; then FAMILY=rpm
else echo "[err] neither apt-get nor dnf — unsupported distro" >&2; exit 1
fi
. /etc/os-release
echo "== System packages (family: $FAMILY, distro: ${ID:-?}) =="

if [ "$FAMILY" = debian ]; then
  $APT update -qq
  $APT install -y -qq \
    build-essential curl git pkg-config rsync zstd netcat-openbsd dnsutils \
    clang llvm llvm-dev libclang-dev libelf-dev libssl-dev libzstd-dev
  # perf: `linux-tools-*` is Ubuntu-only; Debian ships it as `linux-perf`. Not
  # required by the eBPF sensor — best-effort, never fatal.
  if [ "${ID:-}" = ubuntu ]; then
    $APT install -y -qq linux-tools-common "linux-tools-$(uname -r)" linux-tools-generic \
      || echo "[warn] linux-tools unavailable — perf not installed (not needed for the sensor)"
  else
    $APT install -y -qq linux-perf \
      || echo "[warn] linux-perf unavailable — perf not installed (not needed for the sensor)"
  fi
else
  # Rocky/Alma: the -devel packages (libclang…) live in the CRB repository.
  if grep -qiE 'rocky|alma|centos|rhel' /etc/os-release; then
    sudo dnf config-manager --set-enabled crb 2>/dev/null || true
  fi
  $DNF install gcc gcc-c++ make curl git pkgconf-pkg-config rsync zstd nmap-ncat bind-utils \
    clang llvm llvm-devel clang-devel clang-libs \
    elfutils-libelf-devel openssl-devel libzstd-devel zlib-devel bpftool
fi

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

echo "== bpf-linker =="
# bpf-linker links against an LLVM whose major must match the one the pinned
# nightly rustc emits bitcode with (otherwise: "Unknown attribute kind …
# Producer: LLVM23 … Reader: LLVM 21"). Building it from source against
# apt.llvm.org is fragile: no `llvm-23` repo exists for jammy (20/21/22, then a
# rolling 24), and bpf-linker 0.11 dropped the `--features llvm-NN` flag the
# old code passed. The upstream release binaries are musl-static with a bundled
# LLVM cut in lockstep with recent rustc nightly, so they Just Work and the
# "revalidate on nightly bump" problem goes away (#113). Pin explicitly.
BPF_LINKER_VERSION="v0.11.1"
install_bpf_linker() {
  local url="https://github.com/aya-rs/bpf-linker/releases/download/${BPF_LINKER_VERSION}/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst"
  local tmp bin rc
  tmp=$(mktemp -d)
  echo "[info] bpf-linker ${BPF_LINKER_VERSION} (prebuilt): $url"
  # A single lost packet here silently makes the VM replay-only (the caller only
  # warns). Retry the fetch — 3 attempts, transient HTTP errors included.
  curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors "$url" -o "$tmp/bl.tar.zst" \
    && tar --zstd -xf "$tmp/bl.tar.zst" -C "$tmp" \
    && bin=$(find "$tmp" -type f -name bpf-linker -print -quit) && [ -n "$bin" ] \
    && install -m755 "$bin" "$HOME/.cargo/bin/bpf-linker"
  rc=$?
  rm -rf "$tmp"
  return $rc
}

# Bust a probe-less build cached before bpf-linker existed. userspace/build.rs
# has `rerun-if-env-changed=PATH`, but that does not fire when ~/.cargo/bin was
# already on PATH (cargo itself lives there) and only the linker binary appeared
# — so cargo replays the stale "no embedded eBPF" build script output forever.
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

# Sanity: the prebuilt tracks a recent nightly; warn (don't fail) if the pinned
# nightly's LLVM major looks far ahead of what v0.11.x was cut against.
_nightly_llvm=$(rustup run nightly rustc -Vv 2>/dev/null | awk '/^LLVM version/{print $3}' | cut -d. -f1)
if [ -n "${_nightly_llvm:-}" ] && [ "$_nightly_llvm" -gt 24 ]; then
  echo "[warn] nightly rustc uses LLVM $_nightly_llvm — bump BPF_LINKER_VERSION if probe builds hit bitcode-version errors" >&2
fi

echo "== bindgen-cli + aya-tool =="
command -v bindgen >/dev/null 2>&1 || cargo install bindgen-cli
command -v aya-tool >/dev/null 2>&1 || cargo install --git https://github.com/aya-rs/aya aya-tool

# sudo's restricted PATH doesn't see ~/.cargo/bin — symlinks into
# /usr/local/bin so `sudo cargo`-driven builds and the agent's helpers work.
for tool in bindgen aya-tool bpf-linker; do
  [ -x "$HOME/.cargo/bin/$tool" ] && sudo ln -sf "$HOME/.cargo/bin/$tool" "/usr/local/bin/$tool"
done

echo "== Done =="
echo "Source synced into /synthaea — see lab/vagrant/README.md for the build."
