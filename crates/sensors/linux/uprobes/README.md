# sensor-linux-uprobes

User-space probe telemetry for Linux: TLS plaintext from `SSL_read`/`SSL_write`, interactive
shell input from `readline`, and DNS resolutions from `getaddrinfo`. This crate resolves the
symbols, attaches the uprobes compiled into `sensor-linux-ebpf`, enforces per-process budgets
and allowlists, redacts the captured text, and normalizes it into `schema` events.

Every capture is off by default. TLS plaintext and shell input can contain credentials,
tokens and personal data; enable them only where that collection is authorized. The agent
exposes them as `agent run --enable-tls-capture`, `--enable-readline-capture` and
`--enable-dns-capture`.

```rust
use sensor_linux_uprobes::{UprobesConfig, UprobesSensor};

let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_budget(8192)?                 // bytes per process per second (default 4096)
    .tls_allow_processes(&["curl"])    // empty allowlist: every process
    .with_readline_enabled()
    .readline_allow_processes(&["bash", "zsh"]);
let sensor = UprobesSensor::with_config(config);
```

Requirements: kernel BTF at `/sys/kernel/btf/vmlinux`, and root or `CAP_BPF` with
`CAP_PERFMON`. Budgets, redaction rules, the UDP/53 capture and the known limits are
documented in [docs/sensors/linux/uprobes.md](../../../../docs/sensors/linux/uprobes.md).

## Testing

```sh
cargo test -p sensor-linux-uprobes
```

The unit tests cover the configuration builder, the normalizers and every redaction
pattern. Attaching the probes needs root and a kernel with BTF.
