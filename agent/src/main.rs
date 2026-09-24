//! `agent` — entry point of the Synthaea agent.
//!
//! Walking-skeleton scope (issue #8): sensor -> schema -> rules -> sinks in one
//! process. The correlator, ML scoring, and Sigma engines join the pipeline as their
//! crates are migrated (M2) — `DetectionSink` is where they plug in.
//!
//! Layout: `commands` carries all the `cfg(target_os)` (sensor selection, rule
//! seeding); `sink` the agent's `EventSink` wiring events into the detection engines
//! and the output sinks; `heartbeat` the progress-backed liveness signal the
//! watchdog polls (#102); `silence` per-sensor silence detection via
//! `tamper::heartbeat`, wired into the health beacon and a real local alert (#71);
//! `integrity` periodic re-verification of the installed binaries against the
//! signed release manifest `updater` persisted at promote time — the real root of
//! trust `silence` alone cannot provide (#71/#30, Linux only);
//! `protected` watches the agent's own on-disk footprint for a foreign writer (#71);
//! `kill_loudness` attributes who sent a catchable termination signal before the
//! agent actually dies (#71).

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod alerts;
mod commands;
mod enrich_queue;
mod health;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod heartbeat;
// Linux-only: the module itself calls raw POSIX signal APIs
// (sigemptyset/pthread_sigmask/sigwaitinfo) that don't exist in the `libc` crate on
// Windows, and `agent/Cargo.toml` only pulls `libc` in under
// `cfg(target_os = "linux")` — unlike `heartbeat`/`sink` above, there's no
// cross-platform body here to keep alive with an `allow(dead_code)`.
#[cfg(target_os = "linux")]
mod integrity;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod ipc_handler;
#[cfg(target_os = "linux")]
mod journal_cursor;
#[cfg(target_os = "linux")]
mod kill_loudness;
mod protected;
mod silence;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod sink;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod upload;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agent")]
struct Cli {
    /// Path to the agent configuration file (TOML). See ADR-0013 for the
    /// discovery order (this flag, `SYNTHAEA_CONFIG` env, OS default).
    /// The agent refuses to start without a valid config — this is
    /// intentional; there is no in-memory default (ADR-0013 §5).
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Checks that the environment can load the collectors, without attaching them
    /// (no event capture and no persistent effect).
    Status,
    /// Loads the collectors and runs detection until Ctrl-C.
    Run {
        /// JSON-Lines file alerts are appended to.
        #[arg(long, default_value = "alerts.ndjson")]
        alerts: std::path::PathBuf,
        /// JSON-Lines file every normalized event is appended to (raw capture,
        /// consumed by ML calibration and lab assertions).
        #[arg(long, default_value = "events.jsonl")]
        events: std::path::PathBuf,
        /// Enables automated process termination on a high-confidence correlated
        /// verdict (issue #25). Off by default: observe-only — logs what would have
        /// been killed without acting. See `policy::ResponsePolicy`.
        #[arg(long)]
        enable_kill: bool,
        /// Enables automated quarantine of a payload a scan confirms malicious
        /// (issue #25). Off by default: observe-only. See `policy::ResponsePolicy`.
        #[arg(long)]
        enable_quarantine: bool,
        /// Enables TLS plaintext capture via `SSL_read`/`SSL_write` uprobes (issue #90):
        /// pre-encryption content visibility, budgeted and redacted. Off by default —
        /// captures process traffic before it's encrypted, opt-in only. Linux only.
        #[arg(long)]
        enable_tls_capture: bool,
        /// Enables shell readline capture (bash/zsh interactive commands, issue #90):
        /// catches shell builtins and history-evading input `execve` never sees. Off
        /// by default, redacted. Linux only.
        #[arg(long)]
        enable_readline_capture: bool,
        /// Control-plane base URL (e.g. `https://api.synthaea.example.com`).
        /// When set, every normalized event is spooled next to the alerts file
        /// and uploaded store-and-forward (at-least-once; the spool sheds
        /// oldest past its byte cap). Without it the agent runs standalone,
        /// exactly as before.
        #[arg(long)]
        server: Option<String>,
    },
    /// Captures a baseline of healthy activity to train the ML models: records the
    /// command lines of exec events that trigger no deterministic rule, as
    /// JSON-Lines consumable by `synthaea_ml` training. Run ~10 min on a clean host.
    CaptureBaseline {
        /// JSON-Lines output file.
        #[arg(long, default_value = "baseline_capture.jsonl")]
        output: std::path::PathBuf,
    },
    /// Raw capture of all events as JSON-Lines, without evaluating any rules —
    /// feeds ML baseline/calibration work.
    CaptureEvents {
        /// JSON-Lines output file.
        #[arg(long, default_value = "events.jsonl")]
        output: std::path::PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load the local install configuration BEFORE anything else — logging
    // level, spool paths, and (soon) transport URLs all come from here, and
    // per ADR-0013 §5 the agent fails fast if the file is missing or
    // invalid rather than fall back on invented defaults. `config::load`
    // returns a `ConfigError` whose Display already lists the paths it
    // tried, so `anyhow` propagates a copy-pasteable error message.
    let cfg = config::load(cli.config.as_deref())?;

    // Init the logger with the level from the config file. `cfg.log.level` is
    // validated at load-time to be one of trace/debug/info/warn/error.
    // The `RUST_LOG` env variable still overrides this — matches the operator-
    // familiar pattern for ad-hoc debug (`RUST_LOG=debug agent run` doesn't
    // need a file edit). `init()` also installs the `log` bridge, so records
    // from aya-log and other `log`-facade dependencies land in the same subscriber.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(cfg.log.level.as_str())),
        )
        .init();
    tracing::debug!(
        "loaded configuration (schema_version={}, log.level={}, server={})",
        cfg.schema_version,
        cfg.log.level,
        cfg.server.control_plane_url
    );

    match cli.command {
        Command::Status => commands::cmd_status(),
        Command::Run {
            alerts,
            events,
            enable_kill,
            enable_quarantine,
            enable_tls_capture,
            enable_readline_capture,
            server,
        } => commands::cmd_run(commands::RunOptions {
            alerts: &alerts,
            events: &events,
            state_dir: &cfg.storage.state_dir,
            enable_kill,
            enable_quarantine,
            enable_tls_capture,
            enable_readline_capture,
            server: server.as_deref(),
            ipc_endpoint: &cfg.ipc.endpoint,
        }),
        Command::CaptureBaseline { output } => commands::cmd_capture_baseline(&output),
        Command::CaptureEvents { output } => commands::cmd_capture_events(&output),
    }
}
