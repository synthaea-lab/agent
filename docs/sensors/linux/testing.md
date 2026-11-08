# Testing the Linux sensors

The Linux sensors are tested at four levels. Only the first two run on every pull request; loading
probes needs a privileged kernel, which CI runners do not offer.

## 1. Unit tests (every CI leg)

`cargo test --workspace --exclude sensor-linux-ebpf` runs them. Code is split so that what can be
tested without a kernel is pure and compiles on every OS:

| Pure module | What its tests pin |
| --- | --- |
| [`normalize.rs`](../../../crates/sensors/linux/userspace/src/normalize.rs) | Every wire → schema mapping; open-flag masking; argv truth table; rename path resolution; FILETIME conversion |
| [`proc.rs`](../../../crates/sensors/linux/userspace/src/proc.rs) | cmdline/environ/stat parsing, argv windows to tokens, comm with spaces and `)` |
| [`btf.rs`](../../../crates/sensors/linux/userspace/src/btf.rs) | Synthetic BTF blobs, refusal of truncated or incomplete BTF, the running kernel's BTF when present |
| [`syscall.rs`](../../../crates/sensors/linux/userspace/src/syscall.rs) | Dispatch handler ids unique and in range |
| [`parent_image.rs`](../../../crates/sensors/linux/userspace/src/parent_image.rs), [`container.rs`](../../../crates/sensors/linux/userspace/src/container.rs), [`unit_procs.rs`](../../../crates/sensors/linux/userspace/src/unit_procs.rs) | Caches and scans over fake `/proc` and cgroup trees, injected liveness tests |
| [`dns_udp.rs`](../../../crates/sensors/linux/userspace/src/dns_udp.rs), [`tls_client_hello.rs`](../../../crates/sensors/linux/userspace/src/tls_client_hello.rs) | Wire parsers on valid, truncated and hostile input |
| [`path_filter.rs`](../../../crates/sensors/linux/wire/src/path_filter.rs) | The filter's decision table, run as ordinary Rust |
| audit, netlink, journal, logs, procmem, uprobes | Parsers and mappings on captured and synthetic input |

The eBPF crate itself has no tests: it is `no_std` for a BPF target. Logic it shares with userspace
lives in the wire crate so it can be tested there (`is_filtered_path`, the pending-exit packing,
`parse_exec_record`).

Kernel-dependent tests skip themselves rather than fail when the host cannot run them (no
`journalctl`, no root, no BPF-LSM).

## 2. Build with embedded probes (every CI run)

The `test` job has no `bpf-linker`, so the probes are not compiled there. A separate `linux-ebpf`
job installs the pinned nightly and `bpf-linker`, runs clippy on `sensor-linux`,
`sensor-linux-uprobes` and `agent` with the probes embedded, and fails if either crate was built
without its embedded object. This catches code that is only dead, or only broken, in one of the two
build variants.

## 3. Parser robustness and fuzzing

Every parser of bytes that come from outside the agent has a never-panic contract: a panic on a
drain path kills the sensor.

| Parser | Deterministic suite | Fuzz target |
| --- | --- | --- |
| `parse_exec_record` | [`wire/tests/exec_record.rs`](../../../crates/sensors/linux/wire/tests/exec_record.rs) | [`exec_record_parse`](../../../fuzz/fuzz_targets/exec_record_parse.rs) |
| `parse_audit_message` | [`audit/tests/robustness.rs`](../../../crates/sensors/linux/audit/tests/robustness.rs) | [`audit_parse`](../../../fuzz/fuzz_targets/audit_parse.rs) |
| `DiagMsg`, `ProcEvent`, `ConntrackFlow` | [`netlink/tests/robustness.rs`](../../../crates/sensors/linux/netlink/tests/robustness.rs) | [`netlink_parse`](../../../fuzz/fuzz_targets/netlink_parse.rs) |
| access-log and MySQL parsers | unit tests | [`logs_parse`](../../../fuzz/fuzz_targets/logs_parse.rs) |

The deterministic suites use a seeded LCG, so they are reproducible without a fuzzer. The
scheduled fuzz workflow currently runs `audit_parse` and `netlink_parse`; the other two targets run
locally with `cargo +nightly fuzz run <target>` (see [`fuzz/README.md`](../../../fuzz/README.md)).

## 4. Live tests on a lab host

These need root and a real kernel:

- `agent status`: loads the embedded object and every raw tracepoint program through the verifier
  without attaching; exits non-zero on any rejection. The first check on a new kernel.
- [`agent/tests/lsm_io_uring_evasion.rs`](../../../agent/tests/lsm_io_uring_evasion.rs): the
  `file_open` hook fires for an `io_uring` write (needs BPF-LSM and `fio`).
- [`agent/tests/probe_open_synthetic_bits.rs`](../../../agent/tests/probe_open_synthetic_bits.rs):
  no synthetic `FLAG_*` bit survives normalization of a probe-shaped open (runs without root; lives
  in the agent because it needs the normalizer and the rules).
- [`examples/accept_map_pressure.rs`](../../../crates/sensors/linux/userspace/examples/accept_map_pressure.rs)
  and [`examples/pending_syscall_exit_pressure.rs`](../../../crates/sensors/linux/userspace/examples/pending_syscall_exit_pressure.rs):
  thousands of threads blocked in `accept()` must not blind later `accept`, `memfd_create` or
  `recvfrom` events. The load runs in child processes, because the sensor drops events from its
  own pid. Each file's header gives the build and run commands, including the `ulimit -n` needed.

## Checklist for a probe change

1. `cargo test` for the pure parts and `cargo clippy` with embedded probes.
2. On a lab VM: `agent status` on the oldest kernel in the matrix (5.14/5.15 verifiers reject what
   newer ones accept), then a real run producing the event.
3. If a new byte parser was added: a never-panic suite in the crate's `tests/` and a fuzz target.
