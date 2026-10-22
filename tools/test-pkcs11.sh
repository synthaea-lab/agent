#!/usr/bin/env bash
# Runs release-tool's PKCS#11 test against SoftHSM with a throwaway token directory (ADR-0027).
#   RELEASE_TOOL_SOFTHSM_MODULE=/path/to/libsofthsm2.so tools/test-pkcs11.sh
# Without the variable the usual SoftHSM locations are tried. No real key is involved: the
# token is created by the test in a temporary directory removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

module="${RELEASE_TOOL_SOFTHSM_MODULE:-}"
if [ -z "$module" ]; then
  for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so \
    /usr/lib64/pkcs11/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /opt/homebrew/lib/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then module="$candidate"; break; fi
  done
fi
if [ -z "$module" ] || [ ! -f "$module" ]; then
  echo "test-pkcs11: SoftHSM not found; install softhsm2 or set RELEASE_TOOL_SOFTHSM_MODULE" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/tokens"
cat >"$work/softhsm2.conf" <<CONF
directories.tokendir = $work/tokens
objectstore.backend = file
log.level = ERROR
CONF

# The default cargo runner is `sudo -E` (the eBPF tests); this test needs no root.
export SOFTHSM2_CONF="$work/softhsm2.conf"
export RELEASE_TOOL_SOFTHSM_MODULE="$module"
export SYNTHAEA_REQUIRE_PKCS11_TESTS=1
exe="$(cargo test -p release-tool --test pkcs11_softhsm --no-run --message-format=json \
  | jq -r 'select(.profile.test == true and .target.name == "pkcs11_softhsm") | .executable' \
  | tail -n 1)"
test -x "$exe"
"$exe" --nocapture
