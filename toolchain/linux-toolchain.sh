#!/usr/bin/env bash
# Placeholder — per-VM toolchain provisioning, migrated from old/lab/vagrant/provision.sh
# after review. Installs family packages (apt or dnf+CRB), rustup (stable + nightly +
# rust-src), bpf-linker, bindgen-cli, aya-tool; aligns the LLVM major with the nightly
# rustc's so bpf-linker can read its bitcode. RPM-family VMs without a recent LLVM are
# provisioned for replay only.
set -euo pipefail
echo "placeholder — see README.md" >&2
exit 1
