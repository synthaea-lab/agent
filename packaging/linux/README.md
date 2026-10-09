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
│   ├── v2/             # a `.healthy` file appears here once the release's agent has
│   │                   # shown progress after promotion (watchdog probation, #30)
│   └── .stage-3/       # a release being downloaded (`agent apply-release`); renamed to
│                       # v3 only once complete, so a crash never leaves a partial vN
└── banned_versions.json  # Release versions that failed a health check on this
                           # install and are refused even if offered again (ADR-0015
                           # Decision 6). Bare JSON array, unsigned — created on the
                           # first rollback, absent otherwise.

/var/log/synthaea/      # Log directory (owned by synthaea user)
├── agent.log           # Agent stdout/stderr
└── alerts.ndjson       # Detection alerts

/etc/synthaea/          # Configuration directory
└── agent.toml          # Default template (ADR-0013); every control-plane field
                         # is a # CHANGE ME placeholder, offline_fallback = true
                         # lets the agent run as shipped

/usr/bin/
└── synthaea-ctl -> /var/lib/synthaea/current/cli   # CLI symlink
```

---

## Building Packages

### Prerequisites

**Static .deb:** build on an x86_64 Alpine/musl host with the toolchain provisioned by
`lab/provisioning/alpine-toolchain.sh`. The build creates ONNX Runtime from source and
needs several gigabytes of disk and build time on first run. The resulting binaries are
static musl executables, so one `.deb` runs on glibc-based Debian and Ubuntu versions
without inheriting the build host's glibc or libstdc++ baseline.

**RHEL/Fedora (.rpm):**
```bash
# RPM tools
sudo dnf install rpm-build rpmlint

# Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Debian Package

On an x86_64 Alpine host with `lab/provisioning/alpine-toolchain.sh` already run:

```bash
./packaging/linux/build-deb.sh
```

The script builds and tests ML with source-built static ONNX Runtime, builds the agent,
watchdog and CLI for `x86_64-unknown-linux-musl`, checks that none has a program
interpreter, then packages those exact artifacts. `ORT_LIB_LOCATION` may point to an
existing ONNX Runtime 1.30.0 musl static build; otherwise the first run builds it under
`onnxruntime/build/Linux/Release`.

Output: `target/debian/synthaea-agent_<version>-1_amd64.deb`

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
- [ ] Config preserved: `/etc/synthaea/agent.toml` unchanged

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

The binaries live under `/var/lib/synthaea`, whose default type is `var_lib_t`,
and `init_t` may not execute that type: an unlabelled install dies with
`status=203/EXEC`, `Permission denied`. The RPM's `%post` therefore adds file-context
rules that label the binaries `bin_t` (`semanage fcontext`, then `restorecon`); the
service then runs as `unconfined_service_t`. A custom policy is still deferred (#112).

**Check for denials.** `ausearch` reads `/var/log/audit/audit.log`, which does not
exist unless `auditd` runs (it does not on a default Fedora cloud image), so it
answers "no matches" whatever happened. Read the journal instead:
```bash
sudo journalctl _TRANSPORT=audit | grep AVC | grep synthaea
```

**Check the labels:**
```bash
ls -Z /var/lib/synthaea/bootstrap        # expect bin_t
sudo semanage fcontext -l | grep synthaea
```

**Repair after a manual copy:**
```bash
sudo restorecon -R /var/lib/synthaea /var/log/synthaea
```
Files written by the updater into `versions/vN/` inherit `var_lib_t` from the
directory and need a `restorecon` before they can be executed on an Enforcing host.
`agent apply-release` runs `restorecon -R` on the staged release itself, before it
promotes it (#559): on an Enforcing host it refuses the release, leaving `current`
untouched, if `restorecon` is missing or fails; on a Permissive host it warns and
promotes. A manual copy still needs the command above.

**Temporary workaround (testing only):**
```bash
sudo setenforce 0  # Permissive mode
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
│   └── maintainer-scripts/
│       ├── postinst                   # Post-install (create symlinks, enable service)
│       ├── prerm                      # Pre-removal (stop service)
│       └── postrm                     # Post-removal (cleanup on purge)
└── rpm/
    └── synthaea-agent.spec.template   # RPM spec file with scriptlets
```

---

## Future Work (Out of Scope for #36)

1. **Package Signing** - GPG signatures for production deployment
2. **APT/YUM Repository** - Host packages in proper repos for `apt install synthaea-agent`
3. **musl Static Builds** - `.tar.gz` distribution for containers
4. **SELinux Custom Policy** - RHEL hardening (deferred to issue #112)
5. **Capability Management** - The unit grants a minimal ambient capability set (ADR-0014); `CAP_SYS_PTRACE`, `CAP_CHOWN`/`CAP_FOWNER` and the audit capabilities are added with the features that need them

---

## References

- **Issue #36:** Packaging: Linux (deb/rpm + systemd)
- **CLAUDE.md:** Project conventions and dependency rules
- **packaging/README.md:** Cross-platform packaging overview
- **Plan file:** `/home/emile/.claude/plans/fuzzy-humming-bengio.md`

---

For questions or issues, file a GitHub issue at https://github.com/synthaea-lab/edr/issues
