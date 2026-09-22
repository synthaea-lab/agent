# Linux Packaging - Debian (.deb) and RPM

This directory contains packaging infrastructure for distributing the Synthaea EDR agent on Linux distributions.

**Issue:** #36
**Status:** Complete (Debian + RPM with systemd integration)

---

## Overview

The packaging follows the **bootstrap model** where:
- **Package installs:** Infrastructure (directories, systemd units, system user) and bootstrap binaries
- **Updater manages:** Actual agent versions in `/var/lib/synthaea/versions/` and the `current` symlink

This separation ensures that package managers (apt/dnf) and the updater never conflict.

### Directory Layout (FHS-Compliant)

```
/var/lib/synthaea/
├── bootstrap/          # Package-installed binaries (never modified by updater)
│   ├── agent
│   ├── watchdog
│   └── cli
├── current -> bootstrap    # Symlink (updater-managed, initially points to bootstrap)
├── versions/           # Updater-managed version directories, named by the signed
│   ├── v1/             # manifest's monotone release_version (ADR-0015), not semver
│   └── v2/
└── banned_versions.json  # Release versions that failed a health check on this
                           # install and are refused even if offered again (ADR-0015
                           # Decision 6). Bare JSON array, unsigned — created on the
                           # first rollback, absent otherwise.

/var/log/synthaea/      # Log directory (owned by synthaea user)
├── agent.log           # Agent stdout/stderr
└── alerts.ndjson       # Detection alerts

/etc/synthaea/          # Configuration directory (reserved for issue #19)
└── agent.conf          # Config template (empty for now)

/usr/bin/
└── synthaea-ctl -> /var/lib/synthaea/current/cli   # CLI symlink
```

---

## Building Packages

### Prerequisites

**Debian/Ubuntu (.deb):**
```bash
cargo install cargo-deb
```

**RHEL/Fedora (.rpm):**
```bash
# RPM tools
sudo dnf install rpm-build rpmlint

# Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Debian Package

```bash
cd packaging/linux
./build-deb.sh
```

Output: `target/debian/synthaea-agent_0.1.0-1_amd64.deb`

### Build RPM Package

```bash
cd packaging/linux
./build-rpm.sh
```

Output: `packaging/output/synthaea-agent-0.1.0-1.fc40.x86_64.rpm`

---

## Installation

### Debian/Ubuntu

```bash
# Install package
sudo dpkg -i synthaea-agent_*.deb
sudo apt-get install -f  # Resolve dependencies

# Verify installation
systemctl status synthaea-agent
id synthaea
ls -la /var/lib/synthaea
```

### RHEL/Fedora/Rocky

```bash
# Install package
sudo dnf install ./synthaea-agent-*.rpm

# Verify installation
systemctl status synthaea-agent
id synthaea
ls -la /var/lib/synthaea
```

---

## Testing

### Test Checklist (Issue #36 Acceptance Criteria)

**1. Fresh Installation**
- [ ] User `synthaea` exists: `id synthaea`
- [ ] Directories created: `ls -la /var/lib/synthaea`
- [ ] Bootstrap binaries present: `ls /var/lib/synthaea/bootstrap/`
- [ ] Current symlink: `readlink /var/lib/synthaea/current` → `bootstrap`
- [ ] Service running: `systemctl status synthaea-agent`
- [ ] Service enabled: `systemctl is-enabled synthaea-agent`
- [ ] Logs in journal: `journalctl -u synthaea-agent -n 20`

**2. Reboot Persistence**
```bash
sudo reboot
# After reboot:
systemctl status synthaea-agent  # Must be active
```

**3. Upgrade**
```bash
# Debian:
sudo dpkg -i synthaea-agent_0.2.0-1_amd64.deb

# RHEL:
sudo dnf upgrade ./synthaea-agent-0.2.0-1.rpm
```

Verify:
- [ ] Service restarted cleanly
- [ ] Data preserved: `/var/lib/synthaea/versions/` intact
- [ ] Config preserved: `/etc/synthaea/agent.conf` unchanged

**4. Clean Uninstall**

Debian:
```bash
sudo apt-get remove synthaea-agent   # Remove but preserve data
sudo apt-get purge synthaea-agent    # Full cleanup
```

RHEL:
```bash
sudo dnf remove synthaea-agent       # Full cleanup
```

Verify:
- [ ] Service stopped and disabled
- [ ] Binaries removed
- [ ] Directories removed (on purge/remove)
- [ ] No residue: `systemctl list-unit-files | grep -v synthaea`

**5. Lab Scenario Integration**
```bash
# After package install, run walking-skeleton scenario
cd lab/scenarios
./beacon.sh
cat /var/log/synthaea/alerts.ndjson | grep T1071
```

### Test Matrix

| Distribution | Version | systemd | Status |
|--------------|---------|---------|--------|
| Debian | Trixie (13) | 257+ | Primary .deb target |
| Ubuntu | 26.04 LTS | 257+ | Primary .deb target |
| Ubuntu | 24.04 LTS | 255 | Backward compat |
| RHEL | 9.x | 252 | Primary .rpm target (Rocky/Alma) |
| RHEL | 8.x | 239 | Backward compat (CentOS Stream) |
| Fedora | 40 | 255 | Latest .rpm target |

---

## Troubleshooting

### Package Installation Fails

**Symptom:** `dpkg: dependency problems`

**Solution:**
```bash
sudo apt-get install -f  # Resolve dependencies
```

### Service Won't Start

**Check logs:**
```bash
journalctl -u synthaea-agent -n 50
```

**Common causes:**
- Missing binaries: `ls /var/lib/synthaea/bootstrap/`
- Broken symlink: `readlink /var/lib/synthaea/current`
- Permissions: `ls -la /var/lib/synthaea`

### User Creation Failed

**Symptom:** Service fails with "User synthaea not found"

**Manual fix:**
```bash
sudo systemd-sysusers /usr/lib/sysusers.d/synthaea.conf
```

### SELinux Denials (RHEL/Fedora)

**Check for denials:**
```bash
sudo ausearch -m avc -ts recent | grep synthaea
```

**Temporary workaround (testing only):**
```bash
sudo setenforce 0  # Permissive mode
```

**Permanent fix:**
```bash
sudo restorecon -R /var/lib/synthaea /var/log/synthaea
```

---

## Development Mode

The packaging coexists with development mode. When a package is installed:
- `watchdog install` detects `/usr/lib/systemd/system/synthaea-agent.service` and uses it
- Manual `watchdog install` (no package) still generates `/etc/systemd/system/synthaea-agent.service`

Package-owned units take precedence (in `/usr/lib`), preserving backward compatibility.

---

## File Structure

```
packaging/linux/
├── README.md                          # This file
├── build-deb.sh                       # Debian build script
├── build-rpm.sh                       # RPM build script
├── systemd/
│   ├── synthaea-agent.service         # systemd unit (shared by .deb and .rpm)
│   ├── synthaea.sysusers              # User creation manifest
│   └── synthaea.tmpfiles              # Runtime directory creation
├── debian/
│   ├── agent.conf.template            # Empty config template
│   └── maintainer-scripts/
│       ├── postinst.sh                # Post-install (create symlinks, enable service)
│       ├── prerm.sh                   # Pre-removal (stop service)
│       └── postrm.sh                  # Post-removal (cleanup on purge)
└── rpm/
    └── synthaea-agent.spec.template   # RPM spec file with scriptlets
```

---

## Future Work (Out of Scope for #36)

1. **Package Signing** - GPG signatures for production deployment
2. **APT/YUM Repository** - Host packages in proper repos for `apt install synthaea-agent`
3. **musl Static Builds** - `.tar.gz` distribution for containers
4. **SELinux Custom Policy** - RHEL hardening (deferred to issue #112)
5. **Capability Management** - Fine-grained privileges for sensors
6. **Configuration Format** - Currently placeholder (blocked on issue #19)

---

## References

- **Issue #36:** Packaging: Linux (deb/rpm + systemd)
- **CLAUDE.md:** Project conventions and dependency rules
- **packaging/README.md:** Cross-platform packaging overview
- **Plan file:** `/home/emile/.claude/plans/fuzzy-humming-bengio.md`

---

For questions or issues, file a GitHub issue at https://github.com/synthaea-lab/edr/issues
