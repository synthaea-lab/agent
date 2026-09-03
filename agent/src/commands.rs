//! Per-platform implementations of the subcommands. All of the agent's
//! `cfg(target_os)` lives here — the sink stays platform-agnostic. On a platform
//! without a wired sensor (macOS today, Windows until the M3 migration), the commands
//! compile and fail cleanly at runtime instead of breaking the workspace build.

#[cfg(target_os = "linux")]
use schema::sensor::Sensor as _;

#[cfg(target_os = "linux")]
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

// ── status ────────────────────────────────────────────────────────────────────

/// Linux: non-invasive eBPF preflight (loads the programs without attaching them).
#[cfg(target_os = "linux")]
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        println!(
            "[FAIL] privileges: not root (uid={uid}) — loading an eBPF program requires root or CAP_BPF/CAP_PERFMON"
        );
    } else {
        println!("[OK]   privileges: uid=0");
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
    for (program_name, category, name) in sensor_linux::TRACEPOINTS {
        match sensor_linux::load_program(&mut ebpf, program_name) {
            Ok(()) => println!(
                "[OK]   program `{program_name}` ({category}:{name}) accepted by the verifier"
            ),
            Err(e) => {
                println!("[FAIL] program `{program_name}` ({category}:{name}) rejected: {e}")
            }
        }
    }

    Ok(())
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

// ── unsupported platforms ─────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
const UNSUPPORTED_PLATFORM: &str = "no sensor is wired for this platform yet — Linux (eBPF) is the walking skeleton; \
     Windows (ETW) returns with the M3 migration, macOS (EndpointSecurity) with M5. \
     This build is for development only (cargo check/test).";

#[cfg(not(target_os = "linux"))]
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn cmd_run(_alerts: &std::path::Path, _events: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn cmd_capture_events(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn cmd_capture_baseline(_output: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(UNSUPPORTED_PLATFORM)
}
