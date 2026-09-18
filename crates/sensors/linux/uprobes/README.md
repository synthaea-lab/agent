# sensor-linux-uprobes

Linux uprobe telemetry sensor for capturing:
- **TLS plaintext taps** - SSL_read/SSL_write before encryption/after decryption
- **Shell readline** - Interactive shell commands at typing time

## Security Notice

⚠️ **TLS capture is disabled by default** - it captures plaintext data that may contain
credentials, tokens, or PII. Only enable in controlled environments with proper access
controls and data handling policies.

## Configuration

### Default (All Captures Disabled)

```rust
use sensor_linux_uprobes::UprobesSensor;

// Default: all captures disabled
let sensor = UprobesSensor::new();
```

### Enable TLS Capture with Default Budget

```rust
use sensor_linux_uprobes::{UprobesSensor, UprobesConfig};

let config = UprobesConfig::new()
    .with_tls_enabled(); // 4096 bytes/sec per process

let sensor = UprobesSensor::with_config(config);
```

### Enable with Custom Budget

```rust
let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_budget(8192)?; // 8KB/sec per process

let sensor = UprobesSensor::with_config(config);
```

### Process Allowlist (Security Recommended)

```rust
let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_allow_processes(&["curl", "wget"]); // Only capture from these processes

let sensor = UprobesSensor::with_config(config);
```

### Library Denylist

```rust
use std::path::PathBuf;

let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_deny_libraries(&[PathBuf::from("/lib/libcurl.so.4")]);

let sensor = UprobesSensor::with_config(config);
```

### Enable Readline Capture

```rust
let config = UprobesConfig::new()
    .with_readline_enabled() // 10 commands/sec per process
    .readline_allow_processes(&["bash", "zsh"]);

let sensor = UprobesSensor::with_config(config);
```

### Combined Configuration

```rust
let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_budget(8192)?
    .tls_allow_processes(&["curl"])
    .with_readline_enabled()
    .readline_budget(20)?
    .readline_allow_processes(&["bash"]);

let sensor = UprobesSensor::with_config(config);
```

## Budget Enforcement

Budget enforcement prevents a single noisy process from flooding the event stream:

- **TLS**: Bytes per process per second (default: 4096)
  - Sliding 1-second window
  - ~16 HTTP requests with headers
  - Exceeded budget → event dropped, logged at debug level

- **Readline**: Commands per process per second (default: 10)
  - Sliding 1-second window
  - Interactive shells rarely exceed this
  - Exceeded budget → event dropped, logged at debug level

Dropped events are counted and logged at shutdown:
```
sensor-linux-uprobes: TLS captures dropped (budget/allowlist): 142
```

## Allowlist Behavior

- **Empty allowlist** (default): All processes allowed
- **Non-empty allowlist**: Only listed process names allowed
- Allowlist is checked against the process `comm` (15-byte kernel name)

Example:
```rust
// Only capture TLS from curl
.tls_allow_processes(&["curl"])
```

## Architecture

```
Userspace (sensor-linux-uprobes)
  - Symbol resolution (goblin ELF parsing)
  - Uprobe attachment (all processes)
  - Ring buffer draining
  - Budget enforcement (per-PID sliding window)
  - Allowlist filtering
  - Normalization to schema::Event

Kernel space (sensor-linux-ebpf)
  - ssl_write uprobe (pre-encryption)
  - ssl_read_entry + ssl_read_exit (post-decryption)
  - readline_exit uretprobe
  - Per-CPU scratch buffers
  - Ring buffer emission
```

## Performance

Uprobes are more expensive than tracepoints (~2-10x overhead). Mitigation:

1. **Disable by default** - opt-in only in controlled environments
2. **Budget enforcement** - rate limiting per process
3. **Allowlist filtering** - reduce attachment scope
4. **Library denylist** - skip high-traffic libraries

## Requirements

- Linux kernel with BTF support (`/sys/kernel/btf/vmlinux`)
- CAP_BPF + CAP_PERFMON or root
- bpf-linker for eBPF compilation

## Testing

```bash
# Status check (preflight, no attachment)
sudo ./target/release/agent status

# Run with TLS capture enabled (code example needed)
# See agent/src/commands/linux.rs for integration
```

## Related Issues

- #90 - Initial implementation
- #80 - Container attribution (TODO: pass container_id from /proc/pid/cgroup)

## Security Considerations

1. **Sensitive data**: TLS plaintext may contain credentials, tokens, session cookies
2. **Access control**: Restrict who can enable TLS capture
3. **Data retention**: Captured plaintext should have same retention as logs
4. **Compliance**: May require legal review in regulated environments (GDPR, HIPAA)
5. **Audit trail**: Log when TLS capture is enabled/disabled and by whom

## Future Work

- eBPF-side budget enforcement (reduce ring buffer pressure)
- Per-library budgets (not just per-process)
- Sampling (1 in N events) for high-throughput processes
- Container-aware allowlists (capture only from specific containers)
