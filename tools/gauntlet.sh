#!/usr/bin/env bash
# The full local check matrix — everything CI would enforce, runnable on one
# machine. Exists because CI is currently billing-blocked (workflow_dispatch
# only, see .github/workflows/ci.yml): until it is back, this script is the
# enforcement. It mirrors ci.yml's jobs plus the cross-target sweep from
# docs/development/code-style.md ("host-only clippy misses every cfg'd item").
#
# Usage: tools/gauntlet.sh            # everything
#        tools/gauntlet.sh --fast     # skip the cross-target and docs passes
#
# Opt-in pre-push enforcement:  git config core.hooksPath tools/hooks

set -euo pipefail
cd "$(dirname "$0")/.."

FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "rustfmt (nightly — rustfmt.toml uses unstable options stable ignores)"
cargo +nightly fmt --all --check

step "dependency direction"
python3 tools/check-deps.py

step "clippy, host, all targets, -D warnings"
cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets -- -D warnings

step "tests"
cargo test --workspace --exclude sensor-linux-ebpf

step "cargo deny (licenses, advisories, bans, sources)"
cargo deny check

if [[ $FAST -eq 0 ]]; then
    step "clippy, x86_64-unknown-linux-gnu (the platform-gated Linux sensor code)"
    cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets \
        --target x86_64-unknown-linux-gnu -- -D warnings

    step "clippy, Windows sensor crates, x86_64-pc-windows-msvc"
    # Only the Windows-gated crates: a full workspace pass needs a cross C
    # toolchain for ring (transport) that most dev machines lack; CI's native
    # windows-latest job covers the rest.
    cargo clippy -p sensor-windows -p sensor-windows-eventlog -p sensor-windows-sockets --all-targets \
        --target x86_64-pc-windows-msvc -- -D warnings

    step "docs, -D warnings, Linux view (what CI's lint job builds)"
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude sensor-linux-ebpf \
        --no-deps --target x86_64-unknown-linux-gnu >/dev/null
fi

printf '\n\033[1;32mgauntlet clean\033[0m\n'
