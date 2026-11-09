# crates/sensors/linux

Linux telemetry. The primary sensor is eBPF; the other crates add sources the probes do not
cover, and `audit` takes over on hosts where eBPF is unavailable.

| Crate | Package | Mechanism |
| --- | --- | --- |
| `ebpf/` | `sensor-linux-ebpf` | Kernel programs (raw tracepoints, BPF-LSM, uprobes), target `bpfel-unknown-none` |
| `wire/` | `sensor-linux-wire` | Ring-buffer record layout shared by the probes and the loader |
| `container/` | `sensor-linux-container` | Container attribution (cgroup id to container id, Docker image and name) shared by `userspace` and `uprobes` |
| `userspace/` | `sensor-linux` | Loads and attaches the probes, drains the ring buffers, normalizes events |
| `lsm/` | `sensor-linux-lsm` | BPF-LSM `file_open` and `inode_setattr` |
| `uprobes/` | `sensor-linux-uprobes` | TLS plaintext, shell readline and `getaddrinfo` |
| `netlink/` | `sensor-linux-netlink` | `sock_diag`, conntrack and the proc connector |
| `journal/` | `sensor-linux-journal` | sshd, PAM, sudo/su and systemd unit events from journald |
| `logs/` | `sensor-linux-logs` | Web access logs and the MySQL/MariaDB error log |
| `procmem/` | `sensor-linux-procmem` | Bounded process-memory reads for YARA memory scanning |
| `audit/` | `sensor-linux-audit` | Audit netlink fallback and the SELinux AVC reader |

`sensor-linux-ebpf` is a workspace member but not a default member. `sensor-linux`'s build
script compiles and embeds it when the eBPF toolchain and `bpf-linker` are installed
([packaging/toolchain/linux-toolchain.sh](../../../packaging/toolchain/linux-toolchain.sh));
workspace-wide commands pass `--exclude sensor-linux-ebpf`. The probes are dual-licensed
GPL-2.0-only OR MIT; everything else is Apache-2.0.

The [Linux sensor guide](../../../docs/sensors/linux/README.md) covers each source, the events
it produces, kernel requirements, and how to test it
([testing.md](../../../docs/sensors/linux/testing.md)).
