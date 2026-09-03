# sensor-linux-ebpf

Linux kernel probes (eBPF, GPLv2 — a kernel constraint, not a preference).

Tracepoint/kprobe programs for process execution, file access, and network connections,
sharing ring buffers with the userspace side in `sensor-linux`.

Excluded from the workspace default build: targets `bpfel-unknown-none` via `aya-build`
and is built explicitly on a Linux machine with the eBPF toolchain.

To be migrated from `old/crates/synthaea-sensor-linux-ebpf (now crates/sensors/linux-ebpf)` (lib, main, vmlinux bindings).
