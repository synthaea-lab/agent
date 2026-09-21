//! # cli
//!
//! The admin command-line tool for the endpoint: status, sensor health, recent
//! detections, policy version, and policy-gated actions. A pure client of the
//! agent over `ipc`, exactly like the endpoint UI — it holds no privileges of
//! its own and works on headless hosts where no UI ships.
//!
//! ## Current scope
//!
//! IPC is issue #26 and not yet in the tree, so the only subcommands wired up
//! today are `config check` (validate the local install configuration and
//! report the effective values) and `config path` (print the file the
//! discovery order picked, without reading it — useful in shell scripts). The
//! other subcommands from #27's Done-when list (`status`, `health`,
//! `detections`, `policy`) land alongside `crates/ipc`.

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
}

#[derive(Subcommand)]
enum ConfigCmd {
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Config { cmd } => match cmd {
            ConfigCmd::Check => cmd_config_check(cli.config.as_deref()),
            ConfigCmd::Path => cmd_config_path(cli.config.as_deref()),
        },
    }
}

fn cmd_config_check(cli_arg: Option<&std::path::Path>) -> anyhow::Result<()> {
    let cfg = config::load(cli_arg)?;
    println!("OK: configuration loaded and validated.");
    println!("  schema_version           = {}", cfg.schema_version);
    println!("  server.control_plane_url = {}", cfg.server.control_plane_url);
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
    println!(
        "  storage.spool_max_mb     = {}",
        cfg.storage.spool_max_mb
    );
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
