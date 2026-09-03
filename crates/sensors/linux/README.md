# sensors/linux

Linux telemetry. Primary mechanism is eBPF (`ebpf/` kernel probes + `userspace/`
loader); `audit/` is the reduced-fidelity fallback (auditd netlink + fanotify) for
hosts where eBPF is unavailable.

Coverage targets:

| Telemetry source | Mechanism | Where |
| --- | --- | --- |
| Process exec/exit (argv, uid/gid, cgroup/container id) | tracepoints | `ebpf/` + `userspace/` |
| File open/write/delete/rename/chmod | LSM hooks / tracepoints | `ebpf/` |
| Network connect/accept/listen (TCP+UDP, v4+v6) | kprobes/tracepoints | `ebpf/` |
| DNS | uprobe on resolver / socket capture | `ebpf/` |
| Module load, bpf() usage, ptrace (injection/tamper signal) | tracepoints | `ebpf/` |
| Privilege change (setuid, capset) | tracepoints | `ebpf/` |
| Fallback: exec/connect/file | auditd + fanotify | `audit/` |
| Container context (Docker/containerd): container id + image on every event | cgroup resolution in `userspace/` + runtime metadata lookup | `userspace/` — issue #80 |
