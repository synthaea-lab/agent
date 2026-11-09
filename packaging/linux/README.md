# packaging/linux

Linux packages for the agent: a static musl `.deb` for Debian and Ubuntu, an `.apk` for
Alpine, and an `.rpm` for RHEL, Rocky and Fedora. All three install the same layout and run
the agent under its watchdog as a service. The design, the systemd unit's sandboxing and
capabilities, and the CI checks are described in
[docs/packaging.md](../../docs/packaging.md#linux).

| Path | Contents |
| --- | --- |
| [`build-deb.sh`](build-deb.sh) | Builds the static `.deb` (run on Alpine) |
| [`alpine/`](alpine) | `APKBUILD` and the OpenRC service script |
| [`build-rpm.sh`](build-rpm.sh), [`rpm/`](rpm) | Builds the `.rpm` from the spec template |
| [`systemd/`](systemd) | The `synthaea-agent` unit, sysusers and tmpfiles, shared by `.deb` and `.rpm` |
| [`debian/`](debian) | Debian maintainer scripts |

## Installed layout

The package owns the bootstrap binaries; the self-updater owns `versions/` and the
`current` link. A package upgrade replaces `bootstrap/` and never touches what the updater
installed.

```text
/var/lib/synthaea/
├── bootstrap/            agent, watchdog, cli as installed by the package
├── current -> bootstrap  the release that runs; the updater repoints it
├── versions/             releases installed by the updater, by release number
└── banned_versions.json  releases that failed their health check (after a rollback)
/var/log/synthaea/        alerts.ndjson, the detections
/etc/synthaea/agent.toml  configuration; runs as shipped, uploads once a control plane is set
/usr/bin/synthaea-ctl     root-owned copy of cli
```

`synthaea-ctl` is a copy, not a link into `current/`: the unprivileged `synthaea` user owns
`current` and could otherwise repoint it to gain root through `sudo synthaea-ctl`.

## Build

The `.deb` is built on an x86_64 Alpine host provisioned with
[`alpine-toolchain.sh`](../toolchain/alpine-toolchain.sh). The binaries are static, so one
package runs on any x86_64 Debian or Ubuntu release. The first run builds ONNX Runtime from
source, which takes several gigabytes of disk and a long time; point `ORT_LIB_LOCATION` at
an existing musl static build to skip it.

```sh
./packaging/linux/build-deb.sh
```

The package is written to `target/debian/synthaea-agent_<version>-1_amd64.deb`.

The `.apk` is built on the same kind of host, as a user in the `abuild` group with a signing
key (`abuild-keygen -a -i`), and with `ORT_LIB_LOCATION` pointing at a static ONNX Runtime
build:

```sh
./packaging/toolchain/build-onnxruntime-static.sh
export ORT_LIB_LOCATION="$PWD/onnxruntime/build/Linux/Release"
cd packaging/linux/alpine && abuild -r
```

The `.rpm` is built on a Fedora or RHEL host with `rpm-build` and a Rust toolchain. It links
ONNX Runtime dynamically.

```sh
./packaging/linux/build-rpm.sh
```

The package is copied to `packaging/output/`.

## Install, upgrade and remove

| | Debian and Ubuntu | Alpine | RHEL, Rocky, Fedora |
| --- | --- | --- | --- |
| Install or upgrade | `sudo apt install ./synthaea-agent_*.deb` | `sudo apk add --allow-untrusted ./synthaea-agent-*.apk` | `sudo dnf install ./synthaea-agent-*.rpm` |
| Remove | `sudo apt remove synthaea-agent` keeps data and logs | `sudo apk del synthaea-agent` removes state and the user, keeps logs | `sudo dnf remove synthaea-agent` keeps data and logs |
| Remove everything | `sudo apt purge synthaea-agent` | `apk del`, then `sudo rm -rf /var/log/synthaea` | see below |

On Alpine, enable and start the service with `sudo rc-update add synthaea-agent default`
and `sudo rc-service synthaea-agent start`. On systemd hosts the package starts it; check it
with `systemctl status synthaea-agent` and `journalctl -u synthaea-agent`. Upgrades keep
`/etc/synthaea/agent.toml` and `/var/lib/synthaea/versions/`.

RPM has no purge step. A full cleanup after `dnf remove` is manual, including the SELinux
file-context rules the package added:

```sh
sudo rm -rf /var/lib/synthaea /var/log/synthaea
sudo userdel synthaea
sudo semanage fcontext -d '/var/lib/synthaea/bootstrap(/.*)?'
sudo semanage fcontext -d '/var/lib/synthaea/versions/[^/]+/.+'
```

## SELinux

Files under `/var/lib/synthaea` default to `var_lib_t`, which `init_t` may not execute: an
unlabeled install fails with `status=203/EXEC`. The RPM's `%post` adds file-context rules
that label the binaries `bin_t` and runs `restorecon`; the service then runs as
`unconfined_service_t`. `agent apply-release` relabels each release it stages, and on an
enforcing host refuses a release it cannot relabel.

To investigate a denial, read the journal (`ausearch` finds nothing when `auditd` is not
running), check the labels, and relabel after copying binaries by hand:

```sh
sudo journalctl _TRANSPORT=audit | grep AVC | grep synthaea
ls -Z /var/lib/synthaea/bootstrap
sudo restorecon -R /var/lib/synthaea /var/log/synthaea
```

## Troubleshooting

If the service does not start, read `journalctl -u synthaea-agent -n 50`, then check that
`/var/lib/synthaea/bootstrap/` holds the three binaries, that
`readlink /var/lib/synthaea/current` resolves, and that the `synthaea` user exists. A
missing user is created with `sudo systemd-sysusers /usr/lib/sysusers.d/synthaea.conf`.

The packages ship their unit in `/usr/lib/systemd/system/`. A manual `watchdog install` on
a host without a package writes its own to `/etc/systemd/system/synthaea-agent.service`.
