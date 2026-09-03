//! `agent` — entry point of the Synthaea agent.
//!
//! Walking-skeleton scope (issue #8): sensor -> schema -> rules -> sinks in one
//! process. The correlator, ML scoring, and Sigma engines join the pipeline as their
//! crates are migrated (M2) — `DetectionSink` is where they plug in.
//!
//! Layout: `commands` carries all the `cfg(target_os)` (sensor selection, rule
//! seeding); `sink` the agent's `EventSink` wiring events into the detection engines
//! and the output sinks.

mod commands;
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
mod sink;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agent")]
struct Cli {
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
    },
    /// Captures a baseline of healthy activity to train the ML models: records the
    /// command lines of exec events that trigger no deterministic rule, as
    /// JSON-Lines consumable by synthaea_ml training. Run ~10 min on a clean host.
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match cli.command {
        Command::Status => commands::cmd_status(),
        Command::Run { alerts, events } => commands::cmd_run(&alerts, &events),
        Command::CaptureBaseline { output } => commands::cmd_capture_baseline(&output),
        Command::CaptureEvents { output } => commands::cmd_capture_events(&output),
    }
}
