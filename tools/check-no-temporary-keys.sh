#!/usr/bin/env bash
# A release must not embed the temporary signing keys (ADR-0027, ADR-0019 in the vault,
# https://github.com/synthaea-lab/agent/issues/43).
#
# The three keys committed on 2026-11-12 were generated on a developer machine outside the
# ceremony: no custody, no holders, a private half in a plain file. They let the lab run the
# production path, and they must never reach a customer. Each of them says TEMPORARY in its
# header; the ceremony replaces the file, and the header goes with it.
#
# This fails when a key file under the keys directory either (1) still carries the TEMPORARY
# marker, or (2) holds one of the three public keys of 2026-11-12 on its key line, whatever its
# comments say: the build embeds the first line that is not blank or a `#` comment
# (`parse_key_file` in crates/updater/src/key.rs), so deleting the comment would otherwise keep
# the same key embedded and pass the marker check. It reads the files the build includes
# (crates/updater/keys by default; an argument names another directory, relative to the caller's
# working directory, which the tests use) and refuses to pass on an empty directory, so a moved
# folder is not read as "no temporary key".
set -euo pipefail

# Resolve the argument against the caller's directory before moving to the repo root.
arg="${1:-}"
if [ -n "$arg" ] && [ -d "$arg" ]; then
    arg="$(cd "$arg" && pwd)"
fi
cd "$(dirname "$0")/.."

# The temporary public keys committed on 2026-11-12 (agent#242). Public halves only.
TEMPORARY_KEYS=(
    05a0a338b23f35b05c690095f54d7a857d195912f92543de8f5330bbf17f945a # release
    5331efd87507ab8b0e7c3910b04e3bf87eee73699fcfadeda7e34b6930e20b02 # content
    16f3001ea2181b1cb7c98b9659c8edc125156fd4abacb0239bdfd34275df4e7d # recovery
)

fail() { echo "check-no-temporary-keys: $*" >&2; exit 1; }

dir="${arg:-crates/updater/keys}"
[ -d "$dir" ] || fail "$dir is not a directory: the check would pass without looking"

shopt -s nullglob
files=("$dir"/*.pub)
[ "${#files[@]}" -gt 0 ] || fail "no *.pub file in $dir: the check would pass without looking"

# The key line the build embeds: the first line that is not blank or a `#` comment.
key_line() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" | grep -v -e '^$' -e '^#' | head -n 1 || true; }

bad=()
for f in "${files[@]}"; do
    reason=""
    if grep -q 'TEMPORARY' "$f"; then
        reason="marked TEMPORARY"
    else
        line="$(key_line "$f" | tr 'A-F' 'a-f')"
        for known in "${TEMPORARY_KEYS[@]}"; do
            if [ -n "$line" ] && [ "$line" = "$known" ]; then
                reason="holds a temporary key of 2026-11-12 (its comment no longer says so)"
            fi
        done
    fi
    if [ -n "$reason" ]; then
        bad+=("$f: $reason")
    fi
done

if [ "${#bad[@]}" -gt 0 ]; then
    printf 'check-no-temporary-keys: these keys are temporary (no custody, no holders):\n' >&2
    printf '  %s\n' "${bad[@]}" >&2
    fail "replace them through the ADR-0027 ceremony before a release reaches anyone"
fi
echo "check-no-temporary-keys: ${#files[@]} key file(s), none marked TEMPORARY and none a known temporary key"
