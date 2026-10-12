#!/usr/bin/env bash
# Fails if any of the given built binaries carries the public test signing key set
# (ADR-0027, #753): the marker the updater's `test-key` feature links in is looked up in the
# artifact itself, not in a nearby build product. Used by the packaging scripts on the exact
# binaries they ship, and self-tested by tools/check-no-test-key.sh.
# usage: tools/assert-no-test-key.sh <binary>...
set -euo pipefail

marker="SYNTHAEA-PUBLIC-TEST-KEY-SET-V1"
[ "$#" -gt 0 ] || { echo "assert-no-test-key: no binary given" >&2; exit 2; }
for binary in "$@"; do
    [ -s "$binary" ] || { echo "assert-no-test-key: $binary is missing or empty: nothing was checked" >&2; exit 1; }
    if grep -aq "$marker" "$binary"; then
        echo "assert-no-test-key: $binary carries the public test signing key set" >&2
        exit 1
    fi
done
