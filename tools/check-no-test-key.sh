#!/usr/bin/env bash
# A packaged build must not carry the public test signing key (ADR-0027, #753).
#
# Two checks, cheap enough for every CI run:
#   1. Feature resolution: for the packaged binaries built without default features, the
#      updater's `test-key` feature must not be enabled (feature unification is how it would
#      sneak in: a sibling crate asking for it is enough).
#   2. The artifact: the updater built without the feature must not contain the test-set marker,
#      and built with it must (so the check cannot pass by looking for something absent).
# Run from anywhere; needs cargo only.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "check-no-test-key: $*" >&2; exit 1; }

# The packaged set and flags: keep in step with packaging/linux (build-deb.sh, build-rpm.sh).
tree() { cargo tree --locked "$@" -e features,no-dev -i updater 2>/dev/null; }

if tree -p agent -p watchdog -p cli --no-default-features | grep -q 'feature "test-key"'; then
    fail "a packaged build (agent, watchdog, cli, --no-default-features) enables updater/test-key"
fi
tree -p agent -p watchdog -p cli | grep -q 'feature "test-key"' \
    || fail "the default build no longer enables updater/test-key: this check lost its positive control"

marker="SYNTHAEA-PUBLIC-TEST-KEY-SET-V1"
target="$(mktemp -d)"
trap 'rm -rf "$target"' EXIT
holds_marker() {
    CARGO_TARGET_DIR="$target" cargo build --locked -q -p updater "$@"
    # The rlib holds the crate's constants; there is exactly one for the profile just built.
    local rlib
    rlib="$(find "$target/debug" -maxdepth 2 -name 'libupdater*.rlib' -newer "$0" | head -n1)"
    [ -n "$rlib" ] || fail "no updater rlib was produced"
    grep -aq "$marker" "$rlib"
}

if holds_marker --no-default-features; then
    fail "the updater built without the test-key feature contains the test-set marker"
fi
rm -rf "${target:?}/debug"
holds_marker || fail "the updater built with the test-key feature lacks the marker: the check is blind"

echo "check-no-test-key: ok"
