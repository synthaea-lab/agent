#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building Synthaea Agent .rpm package"

# Setup RPM build environment
RPMBUILD_DIR="$REPO_ROOT/target/rpmbuild"
mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Extract version
VERSION=$(grep -m1 '^version' agent/Cargo.toml | cut -d'"' -f2)
echo "Version: $VERSION"

# Build binaries
echo "Building release binaries..."
cargo build --release --bins --exclude sensor-linux-ebpf

# Create source tarball
echo "Creating source tarball..."
tar czf "$RPMBUILD_DIR/SOURCES/synthaea-agent-$VERSION.tar.gz" \
  --transform "s,^,synthaea-agent-$VERSION/," \
  --exclude-vcs --exclude target \
  agent/ watchdog/ cli/ crates/ Cargo.* packaging/linux/systemd/

# Copy spec file
cp packaging/linux/rpm/synthaea-agent.spec.template \
   "$RPMBUILD_DIR/SPECS/synthaea-agent.spec"

# Build RPM
echo "Building RPM..."
rpmbuild -bb \
  --define "_topdir $RPMBUILD_DIR" \
  --define "_version $VERSION" \
  "$RPMBUILD_DIR/SPECS/synthaea-agent.spec"

RPM_PATH=$(find "$RPMBUILD_DIR/RPMS" -name "synthaea-agent-*.rpm" -print -quit)
echo ""
echo "==> RPM built: $RPM_PATH"

# Copy to output
mkdir -p "$REPO_ROOT/packaging/output"
cp "$RPM_PATH" "$REPO_ROOT/packaging/output/"

echo ""
echo "Package contents:"
rpm -qpl "$RPM_PATH"

echo ""
echo "==> Installation command:"
echo "    sudo dnf install $(basename "$RPM_PATH")"
