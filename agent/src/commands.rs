//! Per-platform implementations of the subcommands. All of the agent's
//! `cfg(target_os)` lives here — the sink stays platform-agnostic. On a platform
//! without a wired sensor (macOS today, Windows until the M3 migration), the commands
//! compile and fail cleanly at runtime instead of breaking the workspace build.

#[cfg(any(target_os = "linux", windows))]
use schema::sensor::Sensor as _;

#[cfg(any(target_os = "linux", windows))]
use crate::sink::DetectionSink;

/// `RuleState` pre-filled with the processes already running at startup — without
/// it, the parent-side exclusions and lineage rules don't apply to processes
/// launched before the agent, the most common case in practice (see `RuleState`).
#[cfg(target_os = "linux")]
fn seeded_rule_state() -> rules::RuleState {
    let mut rule_state = rules::RuleState::new();
    rule_state.seed_from_proc();
    rule_state
}

/// Windows equivalent: pid → comm via `tasklist` (carried over from the old agent —
/// no extra API surface; the sensor keeps its own richer store independently).
#[cfg(windows)]
fn seeded_rule_state() -> rules::RuleState {
    let mut map = std::collections::HashMap::new();
    if let Ok(output) = std::process::Command::new("tasklist")
        .args(["/fo", "csv", "/nh"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            // CSV: "Image Name","PID",...
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            if parts.len() < 2 {
                continue;
            }
            let comm = parts[0].trim_matches('"').to_string();
            if let Ok(pid) = parts[1].trim_matches('"').parse::<u32>() {
                map.insert(pid, comm);
            }
        }
    }
    let mut rule_state = rules::RuleState::new();
    rule_state.seed_pid_comm(map);
    rule_state
}

/// Runs a Windows sensor to completion with Ctrl-C wired to its stop flag.
#[cfg(windows)]
fn run_windows_sensor(sink: Box<dyn schema::sensor::EventSink>) -> anyhow::Result<()> {
    let mut sensor = sensor_windows::WindowsSensor::new();
    let stop = sensor.stop_handle();
    ctrlc::set_handler(move || {
        eprintln!("\n[!] Shutdown requested...");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    })?;
    sensor
        .run(sink)
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

// ── status ────────────────────────────────────────────────────────────────────

/// Linux: non-invasive eBPF preflight (loads the programs without attaching them).
#[cfg(target_os = "linux")]
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        println!("[OK]   privileges: uid=0");
    } else if has_bpf_capabilities() {
        // Not root, but the effective capability set carries what eBPF loading
        // needs — a capability-scoped deployment (systemd AmbientCapabilities)
        // is the recommended setup, not a failure (review finding: the uid-only
        // check flagged FAIL on properly capability-scoped services).
        println!("[OK]   privileges: uid={uid} with CAP_BPF/CAP_SYS_ADMIN + CAP_PERFMON");
    } else {
        println!(
            "[FAIL] privileges: not root (uid={uid}) and no CAP_BPF/CAP_PERFMON — loading an eBPF program will fail"
        );
    }

    let btf_path = "/sys/kernel/btf/vmlinux";
    if std::path::Path::new(btf_path).exists() {
        println!("[OK]   kernel BTF present ({btf_path})");
    } else {
        println!("[FAIL] kernel BTF missing ({btf_path}) — task_struct reads (ppid) will fail");
    }

    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        println!("[OK]   kernel: {}", release.trim());
    }

    let mut ebpf = sensor_linux::load_ebpf()
        .map_err(|e| anyhow::anyhow!("failed to load the embedded eBPF bytecode: {e}"))?;
    let mut failures = 0u32;
    for (program_name, category, name) in sensor_linux::TRACEPOINTS {
        match sensor_linux::load_program(&mut ebpf, program_name) {
            Ok(()) => println!(
                "[OK]   program `{program_name}` ({category}:{name}) accepted by the verifier"
            ),
            Err(e) => {
                failures += 1;
                println!("[FAIL] program `{program_name}` ({category}:{name}) rejected: {e}");
            }
        }
    }

    // Scripts and provisioning gate on the exit code, not on parsing stdout —
    // a rejected probe must fail the preflight (review finding: `status` always
    // exited 0, so `agent status && agent run` proceeded onto a broken sensor).
    if failures > 0 {
        anyhow::bail!("{failures} eBPF program(s) rejected by the verifier");
    }
    Ok(())
}

/// True when the effective capability set allows eBPF loading: CAP_SYS_ADMIN,
/// or CAP_BPF plus CAP_PERFMON (tracepoint attachment). Read from
/// /proc/self/status CapEff — best-effort, false on any parse failure.
#[cfg(target_os = "linux")]
fn has_bpf_capabilities() -> bool {
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(cap_eff) = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
    else {
        return false;
    };
    let has = |bit: u32| cap_eff & (1 << bit) != 0;
    has(CAP_SYS_ADMIN) || (has(CAP_BPF) && has(CAP_PERFMON))
}

// ── run ───────────────────────────────────────────────────────────────────────

/// Linux: eBPF capture + detection via LinuxSensor (Ctrl-C handled by the sensor).
#[cfg(target_os = "linux")]
pub(crate) fn cmd_run(alerts: &std::path::Path, events: &std::path::Path) -> anyhow::Result<()> {
    let sink = DetectionSink::new(seeded_rule_state(), alerts, events)?;
    eprintln!("Synthaea agent — detection active (Ctrl-C to stop)");
    eprintln!(
        "alerts: {} · events: {}",
        alerts.display(),
        events.display()
    );
    let mut sensor = sensor_linux::LinuxSensor::new();
    sensor
        .run(Box::new(sink))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

// ── capture-baseline ──────────────────────────────────────────────────────────

/// Linux: rules-filtered benign capture via BaselineSink (Ctrl-C handled by the
/// sensor). Platform-neutral by construction — other platforms join as their
/// sensors land.
#[cfg(target_os = "linux")]
pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    eprintln!("Perform normal activity on a CLEAN host for ~10 minutes.");
    let mut sensor = sensor_linux::LinuxSensor::new();
    sensor
        .run(Box::new(sink))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

// ── capture-events ────────────────────────────────────────────────────────────

/// Linux: raw capture, no detection — `sinks::JsonlEventSink` verbatim.
#[cfg(target_os = "linux")]
pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    eprintln!("Perform normal activity for ~10-15 minutes.");
    let mut sensor = sensor_linux::LinuxSensor::new();
    sensor
        .run(Box::new(sink))
        .map_err(|e| anyhow::anyhow!("sensor failed: {e}"))
}

// ── Windows commands ──────────────────────────────────────────────────────────

/// Windows: administrator privileges are required by the ETW kernel providers.
#[cfg(windows)]
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    println!("Synthaea agent — platform: Windows");
    println!("Sensor: ETW (Kernel-Process + Kernel-Network + Kernel-File)");
    println!("Run as administrator for the kernel providers.");
    Ok(())
}

#[cfg(windows)]
pub(crate) fn cmd_run(alerts: &std::path::Path, events: &std::path::Path) -> anyhow::Result<()> {
    let sink = DetectionSink::new(seeded_rule_state(), alerts, events)?;
    eprintln!("Synthaea agent — detection active (Ctrl-C to stop)");
    eprintln!(
        "alerts: {} · events: {}",
        alerts.display(),
        events.display()
    );
    run_windows_sensor(Box::new(sink))
}

#[cfg(windows)]
pub(crate) fn cmd_capture_events(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = sinks::JsonlEventSink::open(output)?;
    eprintln!("Synthaea — raw event capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensor(Box::new(sink))
}

#[cfg(windows)]
pub(crate) fn cmd_capture_baseline(output: &std::path::Path) -> anyhow::Result<()> {
    let sink = crate::sink::BaselineSink::new(seeded_rule_state(), output)?;
    eprintln!("Synthaea — baseline capture (Ctrl-C to stop)");
    eprintln!("Output: {}", output.display());
    run_windows_sensor(Box::new(sink))
}

// ── unsupported platforms ─────────────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", windows)))]
const UNSUPPORTED_PLATFORM: &str = "no sensor is wired for this platform yet — Linux (eBPF) and Windows (ETW) are \
     live; macOS (EndpointSecurity) arrives with M5. This build is for development \
     only (cargo check/test).";

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_run(_alerts: &std::path::Path, _events: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_capture_events(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn cmd_capture_baseline(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}
