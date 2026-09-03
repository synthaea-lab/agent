#!/usr/bin/env bash
# Provisioning for the lab's Linux VMs (Debian/RPM matrix, arm64): Rust + eBPF
# toolchain for building the agent and probes. Provider-neutral — run by any
# harness (Vagrant shell provisioner, ssh, cloud-init). Idempotent: rerunnable
# via `vagrant provision <machine>` or a plain re-run.
#
# The full eBPF toolchain (bpf-linker) requires LLVM >= 21: guaranteed on the
# Debian family via apt.llvm.org; on Fedora/Rocky, if the distro LLVM is too
# old the script CONTINUES with a warning — the VM is then used for replaying
# scenarios with a binary built elsewhere, not for eBPF builds (replay-only
# rows in lab/MATRIX.md).
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
echo "== System packages (family: $FAMILY) =="

if [ "$FAMILY" = debian ]; then
  $APT update -qq
  $APT install -y -qq \
    build-essential curl git pkg-config rsync \
    clang llvm llvm-dev libclang-dev libelf-dev libssl-dev libzstd-dev \
    linux-tools-common "linux-tools-$(uname -r)" linux-tools-generic
else
  # Rocky/Alma: the -devel packages (libclang…) live in the CRB repository.
  if grep -qiE 'rocky|alma|centos|rhel' /etc/os-release; then
    sudo dnf config-manager --set-enabled crb 2>/dev/null || true
  fi
  $DNF install gcc gcc-c++ make curl git pkgconf-pkg-config rsync \
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
# The current bpf-linker (0.11.x) requires LLVM 21/22/23 via an explicit
# feature flag — Ubuntu 24.04's LLVM 18 is not enough. And that version must
# be able to READ the bitcode emitted by the nightly rustc (error observed
# otherwise: "Unknown attribute kind … Producer: LLVM23… Reader: LLVM 21") —
# so we align bpf-linker's LLVM major with the nightly's, not with "the
# newest available".
install_bpf_linker() {
  # Build dynamically linked against the system LLVM. Two subtleties validated
  # on ubuntu2404: (1) the llvm-config of the right version must come first in
  # the PATH, (2) llvm-sys doesn't emit the right -L for the final link
  # (`ld: cannot find -lLLVM`), hence the explicit RUSTFLAGS.
  bpf_linker_build() {
    local prefix=$1 v=$2
    PATH="$prefix/bin:$PATH" RUSTFLAGS="-L$prefix/lib" \
      env "LLVM_SYS_${v}1_PREFIX=$prefix" \
      cargo install bpf-linker --no-default-features --features "llvm-$v"
  }
  local need v
  need=$(rustup run nightly rustc -Vv | awk '/^LLVM version/{print $3}' | cut -d. -f1)
  if [ "$need" -lt 21 ] || [ "$need" -gt 23 ]; then
    echo "[warn] the nightly uses LLVM $need, outside bpf-linker 0.11's features (21–23)" >&2
    return 1
  fi
  v=$(llvm-config --version 2>/dev/null | cut -d. -f1 || echo 0)
  if [ "$v" = "$need" ]; then
    bpf_linker_build "$(llvm-config --prefix)" "$v" && return 0
  fi
  if [ "$FAMILY" = debian ]; then
    echo "[info] distro LLVM ($v) != nightly's LLVM ($need) — LLVM $need via apt.llvm.org"
    . /etc/os-release
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
      | sudo tee /etc/apt/trusted.gpg.d/apt-llvm-org.asc >/dev/null
    echo "deb http://apt.llvm.org/$VERSION_CODENAME/ llvm-toolchain-$VERSION_CODENAME-$need main" \
      | sudo tee "/etc/apt/sources.list.d/llvm$need.list" >/dev/null
    $APT update -qq
    $APT install -y -qq "llvm-$need-dev" "libpolly-$need-dev"
    bpf_linker_build "/usr/lib/llvm-$need" "$need"
  else
    return 1
  fi
}
if ! command -v bpf-linker >/dev/null 2>&1; then
  if ! install_bpf_linker; then
    echo "[warn] bpf-linker not installed (LLVM >= 21 unavailable on this distro) —" >&2
    echo "[warn] eBPF builds impossible in this VM; build on ubuntu2404 (see lab/vagrant/README.md)" >&2
  fi
fi
command -v bpf-linker >/dev/null 2>&1 && bpf-linker --version

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
