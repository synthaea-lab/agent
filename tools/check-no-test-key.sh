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
# The tree is captured and its exit status tested before anything greps it: a failing
# `cargo tree` (a renamed package, a lockfile problem) must stop the script, not look like
# "the feature is absent".
tree() {
    local out
    out="$(cargo tree --locked "$@" -e features,no-dev -i updater)" \
        || fail "cargo tree failed for: $* (the check would otherwise pass without having looked)"
    printf '%s\n' "$out"
}

packaged="$(tree -p agent -p watchdog -p cli --no-default-features)"
[ -n "$packaged" ] || fail "cargo tree printed nothing for the packaged build"
if grep -q 'feature "test-key"' <<<"$packaged"; then
    fail "a packaged build (agent, watchdog, cli, --no-default-features) enables updater/test-key"
fi
# The no-default-features tree must still show the updater itself, or it proves nothing.
grep -q '^updater ' <<<"$packaged" \
    || fail "the packaged build's cargo tree does not list the updater: the check is blind"
default_build="$(tree -p agent -p watchdog -p cli)"
grep -q 'feature "test-key"' <<<"$default_build" \
    || fail "the default build no longer enables updater/test-key: this check lost its positive control"

# The packaging scripts hold the real flags; this script's own copy above must not drift from
# them, so assert that each still builds the same package set without default features.
for script in packaging/linux/build-deb.sh packaging/linux/build-rpm.sh; do
    # Join backslash continuations first: build-deb.sh spreads the command over two lines.
    build_line="$(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$script" \
        | grep -E '^[^#]*cargo build .*-p agent -p watchdog -p cli' || true)"
    [ -n "$build_line" ] || fail "$script no longer has a \`cargo build ... -p agent -p watchdog -p cli\` line: update this check"
    grep -q -- '--no-default-features' <<<"$build_line" \
        || fail "$script builds the packaged binaries with default features (test key)"
    grep -q 'assert-no-test-key.sh' "$script" \
        || fail "$script does not scan its built binaries with tools/assert-no-test-key.sh"
done

# The binary scan must be able to see the marker, or its silence means nothing.
probe="$(mktemp)"
printf 'xx SYNTHAEA-PUBLIC-TEST-KEY-SET-V1 xx' > "$probe"
if tools/assert-no-test-key.sh "$probe" 2>/dev/null; then
    rm -f "$probe"
    fail "tools/assert-no-test-key.sh did not flag a file that carries the marker"
fi
rm -f "$probe"
tools/assert-no-test-key.sh /nonexistent 2>/dev/null && fail "assert-no-test-key.sh accepted a missing binary"

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
