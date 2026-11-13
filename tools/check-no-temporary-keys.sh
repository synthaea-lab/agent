#!/usr/bin/env bash
# A release must not embed the temporary signing keys (ADR-0027, ADR-0019 in the vault,
# https://github.com/synthaea-lab/agent/issues/43).
#
# The three keys committed on 2026-11-12 were generated on a developer machine outside the
# ceremony: no custody, no holders, a private half in a plain file. They let the lab run the
# production path, and they must never reach a customer. Each of them says TEMPORARY in its
# header; the ceremony replaces the file, and the header goes with it.
#
# This fails when any key file under the keys directory still carries that marker. It reads the
# files the build includes (crates/updater/keys by default; an argument names another directory,
# which the tests use) and refuses to pass on an empty directory, so a moved folder is not read
# as "no temporary key".
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "check-no-temporary-keys: $*" >&2; exit 1; }

dir="${1:-crates/updater/keys}"
[ -d "$dir" ] || fail "$dir is not a directory: the check would pass without looking"

shopt -s nullglob
files=("$dir"/*.pub)
[ "${#files[@]}" -gt 0 ] || fail "no *.pub file in $dir: the check would pass without looking"

bad=()
for f in "${files[@]}"; do
    if grep -q 'TEMPORARY' "$f"; then
        bad+=("$f")
    fi
done

if [ "${#bad[@]}" -gt 0 ]; then
    printf 'check-no-temporary-keys: these keys are temporary (no custody, no holders):\n' >&2
    printf '  %s\n' "${bad[@]}" >&2
    fail "replace them through the ADR-0027 ceremony before a release reaches anyone"
fi
echo "check-no-temporary-keys: ${#files[@]} key file(s), none marked TEMPORARY"
