//! # cli
//!
//! The admin command-line tool for the endpoint: status, sensor health,
//! recent detections, policy version, and policy-gated actions. A pure
//! client of the agent over `ipc`, exactly like the endpoint UI — it
//! holds no privileges of its own and works on headless hosts where no
//! UI ships.
//!
//! Two families of subcommands:
//!
//! - **`config`** — the local install configuration: `config init`
//!   writes the committed default template, `config check` / `config
//!   path` inspect it. No network involved. Cheap, always available.
//! - **`status` / `health` / `detections` / `policy`** — IPC calls to
//!   the running agent, over the endpoint declared in the config
//!   (`config.ipc.endpoint`). Every one of these exits with a non-zero
//!   code and a copy-pasteable message if the agent is unreachable or
//!   refuses the connection.
//!
//! Every IPC subcommand accepts `--json`; the flag toggles between a
//! human-readable output (default, meant for terminal use) and a
//! single-line JSON dump (meant for scripts / structured pipelines).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cli",
    about = "Admin command-line tool for the Synthaea agent",
    long_about = None,
)]
struct Cli {
    /// Path to the agent configuration file (TOML). See ADR-0013 for the
    /// discovery order (this flag, `SYNTHAEA_CONFIG` env, OS default).
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Emit output as one line of JSON instead of the human-readable
    /// default. Applies to every IPC subcommand (`status`, `health`,
    /// `detections`, `policy`); `config check` / `config path` ignore it.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Configuration subcommands. All of them go through `crates/config`;
    /// none of them read the file directly.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },

    /// Ask the running agent for its overall status: version, uptime
    /// bucket, pipeline health.
    Status,

    /// Ask the running agent for the current health of every attached
    /// sensor.
    Health,

    /// Ask the running agent for its most recent detections, oldest
    /// first.
    Detections {
        /// Maximum number of detections to return. The agent clamps
        /// beyond its own hard limit (see
        /// `ipc::RECENT_DETECTIONS_HARD_LIMIT`), so requesting a very
        /// high value is safe.
        #[arg(long, default_value = "20")]
        limit: u32,
    },

    /// Ask the running agent about the currently applied policy —
    /// schema/policy versions, signature verification state.
    Policy,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Write the committed default template to the path the discovery
    /// order resolves (`--config`, then `SYNTHAEA_CONFIG`, then the OS
    /// default), creating missing parent directories. Refuses to replace
    /// an existing file unless `--force` is given. The template's
    /// `# CHANGE ME` values must be filled in before the agent can reach a
    /// control plane; `config check` validates the result.
    Init {
        /// Replace an existing file at the target path.
        #[arg(long)]
        force: bool,
    },

    /// Discover, load, validate, and print a compact summary of the
    /// effective configuration. Fails with a copy-pasteable error if the
    /// discovery step finds no file or the file fails validation.
    Check,

    /// Print the path the discovery order picked, without reading the file.
    /// Useful in shell scripts and CI: `cli config path && cp $(cli config
    /// path) /tmp/backup.toml`. Exits 0 if a path is resolved (even when
    /// the file itself does not exist yet); the `Check` subcommand is the
    /// one that requires the file to be readable and valid.
    Path,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Config { cmd } => match cmd {
            ConfigCmd::Init { force } => cmd_config_init(cli.config.as_deref(), force),
            ConfigCmd::Check => cmd_config_check(cli.config.as_deref()),
            ConfigCmd::Path => cmd_config_path(cli.config.as_deref()),
        },
        Command::Status => cmd_status(cli.config.as_deref(), cli.json).await,
        Command::Health => cmd_health(cli.config.as_deref(), cli.json).await,
        Command::Detections { limit } => {
            cmd_detections(cli.config.as_deref(), cli.json, limit).await
        }
        Command::Policy => cmd_policy(cli.config.as_deref(), cli.json).await,
    }
}

// ── `config` family — local, sync ────────────────────────────────────────

fn cmd_config_init(cli_arg: Option<&std::path::Path>, force: bool) -> anyhow::Result<()> {
    let d = config::discover(cli_arg)?;
    config::write_default_template(&d.path, force)?;
    println!("Wrote the default configuration to {}.", d.path.display());
    println!("Next: fill in every value marked `# CHANGE ME`, then run `cli config check`.");
    Ok(())
}

fn cmd_config_check(cli_arg: Option<&std::path::Path>) -> anyhow::Result<()> {
    let cfg = config::load(cli_arg)?;
    println!("OK: configuration loaded and validated.");
    println!("  schema_version           = {}", cfg.schema_version);
    println!(
        "  server.control_plane_url = {}",
        cfg.server.control_plane_url
    );
    println!(
        "  server.offline_fallback  = {}",
        cfg.server.offline_fallback
    );
    println!("  log.dir                  = {}", cfg.log.dir.display());
    println!("  log.level                = {}", cfg.log.level);
    println!("  log.max_mb               = {}", cfg.log.max_mb);
    println!(
        "  storage.state_dir        = {}",
        cfg.storage.state_dir.display()
    );
    println!("  storage.spool_max_mb     = {}", cfg.storage.spool_max_mb);
    println!("  ipc.endpoint             = {}", cfg.ipc.endpoint);
    println!(
        "  resources.worker_threads = {}",
        cfg.resources.worker_threads
    );
    Ok(())
}

fn cmd_config_path(cli_arg: Option<&std::path::Path>) -> anyhow::Result<()> {
    let d = config::discover(cli_arg)?;
    println!("{}", d.path.display());
    Ok(())
}

// ── IPC family — async, one connection per invocation ────────────────────

/// Connect to the running agent using the endpoint from
/// `config.ipc.endpoint`. Every IPC subcommand goes through this so
/// there is exactly one place where "read config → open ipc client"
/// lives, and the error surface is uniform.
async fn ipc_client(cli_arg: Option<&std::path::Path>) -> anyhow::Result<ipc::Client> {
    let cfg = config::load(cli_arg)?;
    let client = ipc::Client::connect(&cfg.ipc.endpoint, "cli")
        .await
        .map_err(anyhow::Error::new)?;
    Ok(client)
}

async fn cmd_status(cli_arg: Option<&std::path::Path>, json: bool) -> anyhow::Result<()> {
    let mut client = ipc_client(cli_arg).await?;
    let s = client.status().await.map_err(anyhow::Error::new)?;
    if json {
        println!("{}", serde_json::to_string(&s)?);
    } else {
        println!("agent version    : {}", s.agent_version);
        println!("started at (ns)  : {}", s.started_at_ns);
        println!(
            "pipeline healthy : {}",
            if s.pipeline_healthy { "yes" } else { "no" }
        );
    }
    Ok(())
}

async fn cmd_health(cli_arg: Option<&std::path::Path>, json: bool) -> anyhow::Result<()> {
    let mut client = ipc_client(cli_arg).await?;
    let h = client.sensor_health().await.map_err(anyhow::Error::new)?;
    if json {
        println!("{}", serde_json::to_string(&h)?);
    } else if h.sensors.is_empty() {
        println!("no sensors attached (stub agent, or fresh install).");
    } else {
        println!("{:<40} {:<8} last heartbeat (ns)", "sensor", "state");
        println!("{}", "-".repeat(75));
        for s in &h.sensors {
            let state = match s.state {
                ipc::SensorState::Up => "up",
                ipc::SensorState::Silent => "silent",
                ipc::SensorState::Failed => "failed",
            };
            let hb = s
                .last_heartbeat_ns
                .map(|n| n.to_string())
                .unwrap_or_else(|| "(never)".to_string());
            println!("{:<40} {:<8} {}", s.name, state, hb);
        }
    }
    Ok(())
}

async fn cmd_detections(
    cli_arg: Option<&std::path::Path>,
    json: bool,
    limit: u32,
) -> anyhow::Result<()> {
    let mut client = ipc_client(cli_arg).await?;
    let r = client
        .recent_detections(limit)
        .await
        .map_err(anyhow::Error::new)?;
    if json {
        println!("{}", serde_json::to_string(&r)?);
    } else if r.detections.is_empty() {
        println!("no recent detections.");
    } else {
        println!("{:<24} {:<32} summary", "emitted at (ns)", "source");
        println!("{}", "-".repeat(90));
        for d in &r.detections {
            println!("{:<24} {:<32} {}", d.emitted_at_ns, d.source, d.summary);
        }
    }
    Ok(())
}

async fn cmd_policy(cli_arg: Option<&std::path::Path>, json: bool) -> anyhow::Result<()> {
    let mut client = ipc_client(cli_arg).await?;
    let p = client.policy_version().await.map_err(anyhow::Error::new)?;
    if json {
        println!("{}", serde_json::to_string(&p)?);
    } else {
        println!("schema_version     : {}", p.schema_version);
        println!(
            "policy_version     : {}",
            p.policy_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(none applied yet)".to_string())
        );
        println!(
            "signature_verified : {}",
            match p.signature_verified {
                Some(true) => "yes",
                Some(false) => "no (dev / warn-only mode)",
                None => "(no policy applied yet)",
            }
        );
        println!(
            "issued_at (ns)     : {}",
            p.issued_at_ns
                .map(|n| n.to_string())
                .unwrap_or_else(|| "(none)".to_string())
        );
    }
    Ok(())
}
