# Operator Guide - sensor-linux-uprobes

Complete guide for deploying and operating the TLS plaintext and shell readline capture sensor in production environments.

**Audience:** DevOps engineers, security operators, compliance officers

**Prerequisites:**
- Linux kernel 5.3+ with BTF support (`/sys/kernel/btf/vmlinux`)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities
- bpf-linker installed (for eBPF compilation)
- Phase 7.3 lab validation completed

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration Examples](#configuration-examples)
3. [Compliance Modes](#compliance-modes)
4. [Security Best Practices](#security-best-practices)
5. [Performance Tuning](#performance-tuning)
6. [Monitoring and Alerting](#monitoring-and-alerting)
7. [Troubleshooting](#troubleshooting)
8. [Integration Examples](#integration-examples)
9. [CLI Flags (Future)](#cli-flags-future)
10. [YAML Configuration (Future)](#yaml-configuration-future)

---

## Quick Start

### Development Environment

**Scenario:** Test TLS capture on your local machine with curl.

```rust
use sensor_linux_uprobes::{UprobesSensor, UprobesConfig};
use schema::sensor::{Sensor, EventSink};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable TLS capture, limit to curl only
    let config = UprobesConfig::new()
        .with_tls_enabled()
        .tls_allow_processes(&["curl"]); // Only capture from curl

    let mut sensor = UprobesSensor::with_config(config);

    // Create your event sink (e.g., JsonlEventSink)
    let sink = create_sink()?;

    // Run sensor (blocks until Ctrl-C)
    sensor.run(Box::new(sink))?;

    Ok(())
}
```

**Test:**
```bash
# Terminal 1: Run sensor
sudo ./your-agent

# Terminal 2: Generate TLS traffic
curl -v https://httpbin.org/get
```

**Expected:** You should see `Event::TlsCapture` with the HTTP request line (Authorization/Cookie headers redacted).

---

### Production Environment (Minimal Risk)

**Scenario:** Production monitoring with strict allowlist and budget limits.

```rust
use sensor_linux_uprobes::{UprobesConfig, ComplianceMode};

let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_budget(2048)? // Limit to 2KB/sec per process
    .tls_allow_processes(&["curl", "wget"]) // Only known-safe processes
    .with_readline_enabled()
    .readline_allow_processes(&["bash"]); // Only bash, not zsh

let mut sensor = UprobesSensor::with_config(config);
```

**Rationale:**
- Allowlist reduces attack surface (only captures from listed processes)
- Budget prevents runaway capture from single process
- TLS and readline both opt-in (disabled by default)

---

## Configuration Examples

### 1. Default (All Disabled)

```rust
let config = UprobesConfig::new();
// tls.enabled = false
// readline.enabled = false
// compliance_mode = None
```

**Use case:** Default safe state. Sensors inactive until explicitly enabled.

---

### 2. TLS Capture Only (No Readline)

```rust
let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_budget(4096)? // Default: 4KB/sec per process
    .tls_allow_processes(&["curl", "wget", "python3"]);
```

**Use case:** Monitor outbound HTTPS traffic for data exfiltration detection. Don't need shell commands.

---

### 3. Readline Only (No TLS)

```rust
let config = UprobesConfig::new()
    .with_readline_enabled()
    .readline_budget(10)? // Default: 10 commands/sec per process
    .readline_allow_processes(&["bash", "zsh"]);
```

**Use case:** Detect shell-based persistence (cron, rc files) and privilege escalation. Don't need TLS.

---

### 4. Both TLS and Readline (Full Monitoring)

```rust
let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_budget(2048)? // Lower budget for production
    .tls_allow_processes(&["curl"])
    .with_readline_enabled()
    .readline_budget(5)?
    .readline_allow_processes(&["bash"]);
```

**Use case:** Comprehensive monitoring for high-value assets (critical servers, admin workstations).

---

### 5. Library Denylist (Exclude Noisy Libraries)

```rust
use std::path::PathBuf;

let config = UprobesConfig::new()
    .with_tls_enabled()
    .tls_deny_libraries(&[
        PathBuf::from("/usr/lib/libcurl.so.4"), // High-traffic HTTP client
        PathBuf::from("/usr/lib/firefox/libssl3.so"), // Browser (too noisy)
    ]);
```

**Use case:** Reduce event volume by excluding libraries that generate high traffic.

---

## Compliance Modes

### GDPR Mode

**Scenario:** EU deployment with GDPR requirements (data minimization, right to erasure).

```rust
use sensor_linux_uprobes::ComplianceMode;

let config = UprobesConfig::new()
    .with_compliance_mode(ComplianceMode::Gdpr)
    .with_tls_enabled()
    .tls_allow_processes(&["curl"]);

// Presets applied:
// - tls.bytes_per_process_per_sec = 2048 (reduced)
// - readline.commands_per_process_per_sec = 5 (reduced)
// - Retention hint: 30 days
```

**Operator responsibilities:**
- ✅ Document legal basis (legitimate interest: security monitoring)
- ✅ Implement right to erasure (delete events by subject ID)
- ✅ DPO review before deployment
- ✅ Data breach notification plan (72 hours)

**Verification:**
```rust
assert_eq!(config.tls.bytes_per_process_per_sec, 2048); // GDPR preset
assert_eq!(config.compliance_mode, ComplianceMode::Gdpr);
```

---

### HIPAA Mode

**Scenario:** Healthcare deployment with HIPAA requirements (encryption at rest, audit logging).

```rust
let config = UprobesConfig::new()
    .with_compliance_mode(ComplianceMode::Hipaa)
    .with_tls_enabled()
    .tls_allow_processes(&["curl"]); // Minimal capture scope

// Presets applied:
// - tls.bytes_per_process_per_sec = 1024 (strictest)
// - readline.commands_per_process_per_sec = 5
// - Retention hint: 30 days (minimum necessary)
```

**Operator responsibilities:**
- ✅ Enable encryption at rest (LUKS/dm-crypt for spool, PostgreSQL TDE)
- ✅ Implement comprehensive audit trail (all event queries logged)
- ✅ Sign Business Associate Agreement (BAA) with vendor
- ✅ Minimum necessary principle (use allowlist)

**Pre-deployment checklist:**
```bash
# 1. Verify spool encryption
sudo cryptsetup status /var/lib/synthea
# Should show: type: LUKS2

# 2. Verify PostgreSQL TDE
psql -c "SHOW data_encryption;"
# Should show: on

# 3. Verify audit logging enabled
grep audit_logging /etc/synthea/config.yaml
# Should show: audit_logging: true
```

---

### PCI-DSS Mode (⚠️ NOT PRODUCTION-READY)

**Status:** ⚠️ **DO NOT USE IN PRODUCTION** - PAN (credit card) redaction not implemented.

```rust
let config = UprobesConfig::new()
    .with_compliance_mode(ComplianceMode::PciDss)
    .with_tls_enabled();
// ⚠️ Will set budget to 1024 bytes/sec, but PAN NOT REDACTED
```

**Recommendation:**
- **Disable TLS capture entirely** for payment processing systems
- Use allowlist to exclude payment-related processes
- Wait for PAN redaction implementation (future work)

**When PAN redaction is implemented:**
- Credit card numbers masked (all but last 4 digits)
- Luhn algorithm validation
- 90-day maximum retention enforced

---

### Override Compliance Presets

**Scenario:** GDPR mode, but need higher budget for specific use case.

```rust
let config = UprobesConfig::new()
    .with_compliance_mode(ComplianceMode::Gdpr) // Sets TLS to 2048
    .with_tls_enabled()
    .tls_budget(4096)?; // Override to 4096

assert_eq!(config.tls.bytes_per_process_per_sec, 4096); // Overridden
assert_eq!(config.compliance_mode, ComplianceMode::Gdpr); // Still GDPR
```

**Use case:** Compliance mode sets safe defaults, but operator needs flexibility for edge cases.

---

## Security Best Practices

### 1. Principle of Least Privilege

✅ **DO:**
```rust
// Minimal allowlist
.tls_allow_processes(&["curl"]) // Only curl

// Capability-scoped deployment (systemd)
[Service]
AmbientCapabilities=CAP_BPF CAP_PERFMON
User=synthea
```

❌ **DON'T:**
```rust
// Empty allowlist = all processes captured
.with_tls_enabled() // No allowlist!

// Running as root when unnecessary
sudo ./agent # Use capabilities instead
```

---

### 2. Defense in Depth

**Layer 1: Capture**
- Allowlist limits which processes can be captured
- Budget limits prevent runaway capture

**Layer 2: Redaction**
- Authorization headers masked
- Passwords in commands redacted
- (Best-effort, not all patterns caught)

**Layer 3: Storage**
- Spool: 0600 permissions (root only)
- Database: Access control + audit logging

**Layer 4: Transport**
- mTLS for agent → server
- TLS 1.2+ encryption

**Layer 5: Access Control**
- RBAC in query API
- Audit trail for all access

---

### 3. Monitoring Dropped Events

**Log at sensor shutdown:**
```
sensor-linux-uprobes: TLS captures dropped (budget/allowlist): 142
```

**Interpretation:**
- **Low (< 10):** Normal operation
- **Medium (10-100):** Noisy process or tight budget
- **High (> 100):** Investigate - possible attack or misconfiguration

**Action:**
```rust
// Increase budget if legitimate high-traffic process
.tls_budget(8192)? // Double the budget

// Or exclude noisy library
.tls_deny_libraries(&[PathBuf::from("/lib/libcurl.so.4")])
```

---

### 4. Regular Security Audits

**Quarterly review:**
- Review redaction patterns (new credential formats?)
- Review allowlist (remove retired processes, add new ones)
- Review budget (adjust based on dropped event metrics)
- Review access logs (who queried TLS/readline events?)

**After security incident:**
- Check if attacker credentials were captured
- Check if captured data was accessed
- Update redaction patterns if new credential format seen

---

## Performance Tuning

### Budget Sizing

**Rule of thumb:**
- **TLS:** 4096 bytes/sec = ~16 HTTP requests/sec per process
- **Readline:** 10 commands/sec = interactive shell (human speed)

**Tune based on workload:**

| Workload | TLS Budget | Readline Budget |
|----------|------------|-----------------|
| Dev/test | 8192 | 20 |
| Low-traffic prod | 4096 | 10 |
| High-traffic prod | 2048 | 5 |
| GDPR compliance | 2048 | 5 |
| HIPAA compliance | 1024 | 5 |

**Signs budget too low:**
- High dropped event count (> 100)
- Missing expected captures in events

**Signs budget too high:**
- No drops, but high CPU/memory usage
- Large spool files (> 1GB)

---

### CPU and Memory Impact

**Baseline overhead (no capture):**
- CPU: < 1% (ring buffer polling)
- Memory: ~50 MB (eBPF maps + userspace)

**With TLS capture enabled:**
- CPU: +2-5% (depends on traffic volume)
- Memory: +10-50 MB (ring buffers)

**Mitigation:**
- Use allowlist (only capture from specific processes)
- Use library denylist (exclude high-traffic libraries)
- Lower budget (reduce capture volume)

**Monitoring:**
```bash
# CPU usage
top -p $(pgrep synthea-agent)

# Memory usage
ps -o rss,vsz -p $(pgrep synthea-agent)

# eBPF map memory
bpftool map show | grep -A5 "TLS_CAPTURE"
```

---

### Disk Space (Spool)

**Estimate:**
- TLS: 4096 bytes/sec × 10 processes × 3600 sec/hour = ~140 MB/hour
- Readline: 10 cmd/sec × 100 bytes/cmd × 10 processes × 3600 = ~35 MB/hour
- **Total: ~175 MB/hour = ~4.2 GB/day**

**Spool rotation:**
```yaml
# /etc/synthea/config.yaml (future)
spool:
  max_size: 10GB # Rotate when total size exceeds
  max_age: 7d # Delete files older than 7 days
```

**Monitoring:**
```bash
# Spool size
du -sh /var/lib/synthea/spool

# Oldest file
ls -lt /var/lib/synthea/spool | tail -1
```

---

## Monitoring and Alerting

### Metrics to Track

**1. Dropped Events**
```
sensor_uprobes_dropped_events{sensor="tls"} 142
sensor_uprobes_dropped_events{sensor="readline"} 5
```

**Alert:** `sensor_uprobes_dropped_events > 100` for 5 minutes

---

**2. Capture Rate**
```
sensor_uprobes_events_total{sensor="tls"} 15234
sensor_uprobes_events_total{sensor="readline"} 892
```

**Alert:** `rate(sensor_uprobes_events_total[5m]) > 1000` (anomaly detection)

---

**3. Budget Utilization**
```
sensor_uprobes_budget_used_bytes{pid=1234} 3500
sensor_uprobes_budget_limit_bytes{pid=1234} 4096
```

**Alert:** `sensor_uprobes_budget_used_bytes / sensor_uprobes_budget_limit_bytes > 0.9` (near limit)

---

**4. Sensor Health**
```
sensor_uprobes_status{sensor="tls"} 1 # 1=running, 0=stopped
```

**Alert:** `sensor_uprobes_status == 0` (sensor stopped unexpectedly)

---

### Dashboards

**Grafana dashboard panels:**

1. **Event Rate** (line chart)
   - TLS capture events/sec
   - Readline events/sec

2. **Dropped Events** (counter)
   - Total dropped (budget + allowlist)
   - Split by reason

3. **Budget Utilization** (heatmap)
   - Per-PID budget usage
   - Color: green (< 50%), yellow (50-90%), red (> 90%)

4. **Top Processes** (table)
   - Process name | Events captured | Bytes captured | Dropped count

---

## Troubleshooting

### Problem: No Events Captured

**Symptoms:**
- Sensor running, no errors
- Expected TLS/readline events not appearing

**Diagnosis:**
```rust
// Check if enabled
assert!(config.tls.enabled); // Should be true

// Check allowlist
assert!(!config.tls.process_allowlist.is_empty()); // Should contain process name

// Check process comm
cat /proc/$(pgrep curl)/comm
# Should match allowlist entry
```

**Solutions:**
1. Verify `with_tls_enabled()` called
2. Verify process name in allowlist matches `/proc/<pid>/comm` (15-byte kernel truncation)
3. Verify no library denylist blocking capture

---

### Problem: High Dropped Event Count

**Symptoms:**
- `sensor-linux-uprobes: TLS captures dropped: 500+`

**Diagnosis:**
- Budget too low for process traffic volume
- Or: allowlist includes noisy process

**Solutions:**
```rust
// Option 1: Increase budget
.tls_budget(8192)? // Double it

// Option 2: Exclude noisy library
.tls_deny_libraries(&[PathBuf::from("/lib/libcurl.so.4")])

// Option 3: Remove noisy process from allowlist
.tls_allow_processes(&["wget"]) // Remove "curl" if too noisy
```

---

### Problem: Sensor Fails to Start

**Error:** `failed to load eBPF object: kernel verifier rejected`

**Diagnosis:**
- Kernel too old (< 5.3)
- No BTF support
- Missing capabilities

**Solutions:**
```bash
# 1. Check kernel version
uname -r # Should be >= 5.3

# 2. Check BTF
ls /sys/kernel/btf/vmlinux # Should exist

# 3. Check capabilities
sudo -E ./agent # Try with root first

# 4. Check verifier logs
sudo dmesg | grep -i bpf # Look for rejection details
```

---

### Problem: lib_type Always Reports OpenSSL

**Symptoms:**
- GnuTLS traffic captured, but `lib_type` field shows `OpenSsl`

**Diagnosis:**
- Phase 7 separate probe functions not deployed
- Or: GnuTLS symbols not resolved

**Solutions:**
```bash
# 1. Verify Phase 7 fixes deployed
git log --oneline | grep "lib_type"
# Should show commit e40f796

# 2. Check symbol resolution
sudo ./agent --debug 2>&1 | grep gnutls_record
# Should show: "Resolved symbol: gnutls_record_send @ 0x..."

# 3. Rebuild with latest code
git pull && cargo build --release
```

---

## Integration Examples

### Standalone Sensor

**Use case:** Run uprobes sensor independently from main agent.

```rust
// examples/standalone_uprobes.rs
use sensor_linux_uprobes::{UprobesSensor, UprobesConfig};
use sinks::JsonlEventSink;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = UprobesConfig::new()
        .with_tls_enabled()
        .tls_allow_processes(&["curl", "wget"]);

    let mut sensor = UprobesSensor::with_config(config);
    let sink = JsonlEventSink::open("uprobes_events.jsonl")?;

    eprintln!("Uprobes sensor running (Ctrl-C to stop)");
    sensor.run(Box::new(sink))?;

    Ok(())
}
```

---

### Multi-Sensor Integration

**Use case:** Run both tracepoint sensor (LinuxSensor) and uprobes sensor simultaneously.

```rust
use sensor_linux::LinuxSensor;
use sensor_linux_uprobes::{UprobesSensor, UprobesConfig};
use std::sync::Arc;
use tokio::sync::Notify;

fn main() -> anyhow::Result<()> {
    let sink = Arc::new(create_shared_sink()?);
    let stop = Arc::new(Notify::new());

    // Spawn tracepoint sensor (exec, file_open, connect)
    let sink1 = Arc::clone(&sink);
    let stop1 = Arc::clone(&stop);
    let handle1 = std::thread::spawn(move || {
        let mut sensor = LinuxSensor::new();
        sensor.run(Box::new(sink1))?;
        stop1.notify_one();
        Ok::<_, anyhow::Error>(())
    });

    // Spawn uprobes sensor (TLS, readline)
    let sink2 = Arc::clone(&sink);
    let stop2 = Arc::clone(&stop);
    let handle2 = std::thread::spawn(move || {
        let config = UprobesConfig::new()
            .with_tls_enabled()
            .tls_allow_processes(&["curl"]);
        let mut sensor = UprobesSensor::with_config(config);
        sensor.run(Box::new(sink2))?;
        stop2.notify_one();
        Ok::<_, anyhow::Error>(())
    });

    // Wait for Ctrl-C
    ctrlc::set_handler(move || {
        stop.notify_waiters();
    })?;

    handle1.join().unwrap()?;
    handle2.join().unwrap()?;

    Ok(())
}
```

---

## CLI Flags (Future)

**Recommended design for agent CLI integration:**

```bash
# Enable TLS capture
./agent run --uprobes-tls --uprobes-tls-allow curl,wget

# Enable readline capture
./agent run --uprobes-readline --uprobes-readline-allow bash

# Set budgets
./agent run \
  --uprobes-tls \
  --uprobes-tls-budget 2048 \
  --uprobes-readline \
  --uprobes-readline-budget 5

# Compliance mode
./agent run --uprobes-compliance gdpr --uprobes-tls

# Library denylist
./agent run \
  --uprobes-tls \
  --uprobes-tls-deny-lib /lib/libcurl.so.4

# All together
./agent run \
  --uprobes-compliance hipaa \
  --uprobes-tls \
  --uprobes-tls-allow curl \
  --uprobes-readline \
  --uprobes-readline-allow bash \
  --alerts alerts.ndjson \
  --events events.jsonl
```

**Implementation sketch:**

```rust
// agent/src/main.rs
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        // Existing flags
        #[arg(long, default_value = "alerts.ndjson")]
        alerts: PathBuf,
        #[arg(long, default_value = "events.jsonl")]
        events: PathBuf,

        // Uprobes TLS flags
        #[arg(long)]
        uprobes_tls: bool,
        #[arg(long)]
        uprobes_tls_allow: Option<String>, // Comma-separated
        #[arg(long, default_value = "4096")]
        uprobes_tls_budget: u32,
        #[arg(long)]
        uprobes_tls_deny_lib: Vec<PathBuf>,

        // Uprobes readline flags
        #[arg(long)]
        uprobes_readline: bool,
        #[arg(long)]
        uprobes_readline_allow: Option<String>, // Comma-separated
        #[arg(long, default_value = "10")]
        uprobes_readline_budget: u32,

        // Compliance mode
        #[arg(long, value_enum)]
        uprobes_compliance: Option<ComplianceModeArg>,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum ComplianceModeArg {
    None,
    Gdpr,
    Hipaa,
    PciDss,
}

// Build config from CLI args
fn build_uprobes_config(args: &RunArgs) -> anyhow::Result<UprobesConfig> {
    let mut config = UprobesConfig::new();

    if let Some(mode) = &args.uprobes_compliance {
        config = config.with_compliance_mode(mode.into());
    }

    if args.uprobes_tls {
        config = config.with_tls_enabled();
        config = config.tls_budget(args.uprobes_tls_budget)?;

        if let Some(allow) = &args.uprobes_tls_allow {
            let procs: Vec<&str> = allow.split(',').collect();
            config = config.tls_allow_processes(&procs);
        }

        if !args.uprobes_tls_deny_lib.is_empty() {
            config = config.tls_deny_libraries(&args.uprobes_tls_deny_lib);
        }
    }

    if args.uprobes_readline {
        config = config.with_readline_enabled();
        config = config.readline_budget(args.uprobes_readline_budget)?;

        if let Some(allow) = &args.uprobes_readline_allow {
            let procs: Vec<&str> = allow.split(',').collect();
            config = config.readline_allow_processes(&procs);
        }
    }

    Ok(config)
}
```

---

## YAML Configuration (Future)

**Recommended design for YAML config file:**

```yaml
# /etc/synthea/agent.yaml
sensors:
  # Existing tracepoint sensor
  linux:
    enabled: true

  # Uprobes sensor (new)
  linux_uprobes:
    enabled: true
    compliance_mode: gdpr # none, gdpr, hipaa, pcidss

    tls:
      enabled: true
      budget_bytes_per_sec: 2048
      allow_processes:
        - curl
        - wget
      deny_libraries:
        - /lib/libcurl.so.4

    readline:
      enabled: true
      budget_commands_per_sec: 5
      allow_processes:
        - bash

# Spool configuration
spool:
  path: /var/lib/synthea/spool
  max_size: 10GB
  max_age: 7d
  encryption: true # Encrypt JSON files at rest

# Retention policies
retention:
  tls_capture: 30d # GDPR/HIPAA minimum
  readline_input: 30d
  exec_event: 90d # Other events longer retention

# Audit logging
audit:
  enabled: true
  log_all_queries: true
  log_file: /var/log/synthea/audit.log
```

**Implementation sketch:**

```rust
// crates/config/src/lib.rs (new crate)
use serde::{Deserialize, Serialize};
use sensor_linux_uprobes::{UprobesConfig, ComplianceMode};

#[derive(Deserialize, Serialize)]
struct AgentConfig {
    sensors: SensorsConfig,
    spool: SpoolConfig,
    retention: RetentionConfig,
    audit: AuditConfig,
}

#[derive(Deserialize, Serialize)]
struct SensorsConfig {
    linux: LinuxSensorConfig,
    linux_uprobes: LinuxUprobesConfig,
}

#[derive(Deserialize, Serialize)]
struct LinuxUprobesConfig {
    enabled: bool,
    compliance_mode: ComplianceMode,
    tls: TlsYamlConfig,
    readline: ReadlineYamlConfig,
}

#[derive(Deserialize, Serialize)]
struct TlsYamlConfig {
    enabled: bool,
    budget_bytes_per_sec: u32,
    allow_processes: Vec<String>,
    deny_libraries: Vec<PathBuf>,
}

// Load from YAML
fn load_config(path: &Path) -> anyhow::Result<AgentConfig> {
    let yaml = std::fs::read_to_string(path)?;
    let config: AgentConfig = serde_yaml::from_str(&yaml)?;
    Ok(config)
}

// Convert to UprobesConfig
impl From<LinuxUprobesConfig> for UprobesConfig {
    fn from(yaml: LinuxUprobesConfig) -> Self {
        let mut config = UprobesConfig::new()
            .with_compliance_mode(yaml.compliance_mode);

        if yaml.tls.enabled {
            config = config
                .with_tls_enabled()
                .tls_budget(yaml.tls.budget_bytes_per_sec)
                .expect("valid budget")
                .tls_allow_processes(
                    &yaml.tls.allow_processes.iter().map(|s| s.as_str()).collect::<Vec<_>>()
                )
                .tls_deny_libraries(&yaml.tls.deny_libraries);
        }

        if yaml.readline.enabled {
            config = config
                .with_readline_enabled()
                .readline_budget(yaml.readline.budget_commands_per_sec)
                .expect("valid budget")
                .readline_allow_processes(
                    &yaml.readline.allow_processes.iter().map(|s| s.as_str()).collect::<Vec<_>>()
                );
        }

        config
    }
}
```

---

## Summary

**Phase 10 deliverables:**
- ✅ Comprehensive operator guide (this document)
- ✅ Configuration examples for common scenarios
- ✅ Compliance mode usage documentation
- ✅ Security best practices
- ✅ CLI flags design (for future implementation)
- ✅ YAML configuration design (for future implementation)

**Next steps for full integration:**
1. Implement CLI flags in `agent/src/main.rs`
2. Create `crates/config` for YAML configuration
3. Wire `UprobesSensor` into agent run loop
4. Add metrics/monitoring instrumentation
5. Create Grafana dashboard templates

**Prerequisites before production:**
- Phase 7.3: Lab validation (eBPF verifier + lib_type correctness)
- Phase 8: Integration tests (curl capture, readline, budgets)
- Security review with compliance team

---

**Last Updated:** 2026-09-15 (Phase 10 - Operator guide)
**Maintainers:** DevOps team, security team
**Review Cycle:** Quarterly, or after major changes
