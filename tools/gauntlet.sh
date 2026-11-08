#!/usr/bin/env bash
# The full local check matrix — everything CI enforces, runnable on one
# machine before pushing. CI (.github/workflows/ci.yml) is the enforcement;
# this script catches the same failures earlier. It mirrors ci.yml's
# jobs plus the cross-target sweep (host-only clippy misses every cfg'd item).
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

# Needs the `rules` sibling; CI's `content` job makes its absence fatal.
if [[ -d "${SYNTHAEA_ROOT:-..}/rules/sigma" ]]; then
    step "ATT&CK coverage matrix up to date"
    python3 tools/attack-coverage.py --check
fi

step "PowerShell scripts ASCII-only (Windows PowerShell 5.1 misreads anything else)"
python3 tools/check-ps1-ascii.py

step "clippy, host, all targets, -D warnings"
cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets -- -D warnings

step "tests"
# Cross-repo contract tests read the sibling checkouts (crates/siblings)
# and skip with a `skipped:` line when one is absent; export
# SYNTHAEA_REQUIRE_SIBLINGS=1 to make a missing sibling fail, as CI does.
cargo test --workspace --exclude sensor-linux-ebpf

step "updater trust set without the test key (production code path, ADR-0027)"
cargo test -p updater --no-default-features

step "cargo deny (licenses, advisories, bans, sources)"
cargo deny check

# ML robustness check — only runs if the `ml` sibling (synthaea-lab/edr-ml,
# checked out as ../ml or $SYNTHAEA_ROOT/ml) is present and has a latest model.
# Verifies escape rate and degradation metrics stay within thresholds.
ML_DIR="${SYNTHAEA_ROOT:-..}/ml"
if [[ -d "$ML_DIR/registry/cmdline-iforest-linux/latest" ]]; then
    step "mutation robustness (T0 cmdline mutations)"
    (cd "$ML_DIR" && python3 -m synthaea_ml.evaluation.robustness_cli verify \
        --model-dir registry/cmdline-iforest-linux/latest/ \
        --max-escape-rate 0.15 \
        --max-median-degradation 0.20)
fi

if [[ $FAST -eq 0 ]]; then
    step "clippy, x86_64-unknown-linux-gnu (the platform-gated Linux sensor code)"
    cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets \
        --target x86_64-unknown-linux-gnu -- -D warnings

    step "clippy, Windows sensor crates, x86_64-pc-windows-msvc"
    # Only the Windows-gated crates: a full workspace pass needs a cross C
    # toolchain for ring (transport) that most dev machines lack; CI's native
    # windows-latest job covers the rest.
    cargo clippy -p sensor-windows -p sensor-windows-eventlog -p sensor-windows-sockets -p sensor-windows-minifilter --all-targets \
        --target x86_64-pc-windows-msvc -- -D warnings

    step "docs, -D warnings, Linux view (what CI's lint job builds)"
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude sensor-linux-ebpf \
        --no-deps --target x86_64-unknown-linux-gnu >/dev/null
fi

printf '\n\033[1;32mgauntlet clean\033[0m\n'
