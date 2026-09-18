#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building Synthaea Agent .deb package"

# Install cargo-deb if needed
if ! command -v cargo-deb &> /dev/null; then
    echo "cargo-deb not found. Installing..."
    cargo install cargo-deb
fi

# Build release binaries
echo "Building release binaries..."
cargo build --release --workspace --exclude sensor-linux-ebpf

# Generate .deb
echo "Generating .deb package..."
cargo deb -p watchdog --no-build

# Output
DEB_FILE=$(ls -t target/debian/*.deb | head -1)
echo ""
echo "==> Package created: $DEB_FILE"
echo ""
echo "Package contents:"
dpkg-deb -c "$DEB_FILE"

# Lintian check (optional)
if command -v lintian &> /dev/null; then
    echo ""
    echo "Running lintian checks..."
    lintian "$DEB_FILE" || true
fi

echo ""
echo "==> Installation command:"
echo "    sudo dpkg -i $DEB_FILE"
echo "    sudo apt-get install -f"
