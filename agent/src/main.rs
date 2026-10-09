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
mod content;
mod deception;
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
// Linux-only: `dpkg` has no Windows/macOS equivalent to fall back to (unlike
// `heartbeat`/`protected`, which compile everywhere and are just unwired
// elsewhere) — there is nothing this module could do on another platform, so
// it is gated out rather than kept as dead weight that always takes the
// "file not found" skip path.
#[cfg(target_os = "linux")]
mod inventory;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod ipc_handler;
#[cfg(target_os = "linux")]
mod journal_cursor;
#[cfg(target_os = "linux")]
mod kill_loudness;
#[cfg(target_os = "linux")]
mod log_sources;
#[cfg(target_os = "linux")]
mod memscan;
mod protected;
mod quarantine_cmd;
mod ransomware_join;
mod redact;
mod release;
mod shutdown;
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
        /// consumed by ML calibration and lab assertions). Off unless given: the
        /// file grows without bound and is no part of a production run, so the
        /// packaged service never writes it (#559).
        #[arg(long)]
        events: Option<std::path::PathBuf>,
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
        /// Enables DNS resolution capture via a `getaddrinfo(3)` uprobe (issue
        /// #267 Phase 1): query name + first resolved address, for DNS-based
        /// C2/tunneling/exfiltration visibility. Off by default, sensitive TLDs
        /// redacted. Linux only.
        #[arg(long)]
        enable_dns_capture: bool,
        /// Control-plane base URL, overriding `server.control_plane_url` from
        /// `agent.toml`. Left unset, the agent uploads to the configured control plane
        /// (store-and-forward, at-least-once; the spool sheds oldest past its byte cap),
        /// presenting `server.mtls_cert`/`mtls_key`. A server named here never receives
        /// the configured client certificate: pass `--cert`/`--key` for one that needs it.
        #[arg(long, conflicts_with = "standalone")]
        server: Option<String>,
        /// Run without uploading anything: events stay local, as before the agent read
        /// its control plane from `agent.toml`.
        #[arg(long)]
        standalone: bool,
        /// Client mTLS certificate (PEM) to present to the control plane, overriding the
        /// configured one.
        #[arg(long, requires = "key")]
        cert: Option<std::path::PathBuf>,
        /// Client mTLS private key (PEM). Required alongside `--cert`.
        #[arg(long, requires = "cert")]
        key: Option<std::path::PathBuf>,
        /// PEM bundle of the only CA(s) trusted for the control plane's certificate, for
        /// one on a private CA. Left unset, `server.ca_cert` from
        /// `agent.toml`; with neither, the built-in public roots.
        #[arg(long)]
        ca_cert: Option<std::path::PathBuf>,
        /// Where downloaded content lives (issue #30) — the detection sink
        /// loads Sigma/YARA rules from `<content-dir>/rules/{sigma,yara}`.
        /// Defaults to `<storage.state_dir>/content`, exactly like
        /// `apply-content-manifest`'s `--content-dir`, so what an apply
        /// writes is what this agent loads. To run against the in-repo
        /// content (`rules/sigma`, `rules/yara`) pass `--content-dir .`.
        #[arg(long)]
        content_dir: Option<std::path::PathBuf>,
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
    /// Fetches and verifies the content manifest for a ring (ADR-0016, issue
    /// #30/#73): reports which rules/models/policy entries have changed since
    /// this agent's last applied release. Does not download artifacts or apply
    /// anything — a first, real, testable slice of content distribution, not
    /// the full pipeline.
    CheckContentManifest {
        /// Control-plane base URL (e.g. `https://api.synthaea.example.com`).
        #[arg(long)]
        server: String,
        /// Canary ring this agent is assigned to (`canary_0`/`canary_1`/`canary_2`/`prod`).
        #[arg(long)]
        ring: String,
        /// Path to the client mTLS certificate (PEM). Omit to fetch without
        /// mTLS (a dev server, or a server that authenticates another way).
        #[arg(long)]
        cert: Option<std::path::PathBuf>,
        /// Path to the client mTLS private key (PEM). Required alongside `--cert`.
        #[arg(long)]
        key: Option<std::path::PathBuf>,
        /// PEM bundle of the CA(s) that signed the server's certificate, for a
        /// control plane on a private CA. When given, only these roots are
        /// trusted (the public roots are not).
        #[arg(long)]
        ca_cert: Option<std::path::PathBuf>,
        /// Where this agent's own record of already-applied content lives.
        /// Missing means a fresh install — every manifest entry is reported
        /// as needing a fetch.
        #[arg(long, default_value = "content-state.json")]
        state: std::path::PathBuf,
    },
    /// Fetches, verifies, downloads, and applies the content manifest for a
    /// ring (ADR-0016, issue #30/#73): everything `check-content-manifest`
    /// does, plus actually downloading each missing/stale entry from
    /// `/api/content/artifact`, verifying its SHA-256, and writing it under
    /// `--content-dir`. Does not reload anything into a running
    /// `DetectionSink` — that's a follow-up, not this slice.
    ApplyContentManifest {
        /// Control-plane base URL (e.g. `https://api.synthaea.example.com`).
        /// Left unset, the command uses `server.control_plane_url` and the
        /// `server.mtls_cert`/`mtls_key` pair from `agent.toml`; given, it
        /// talks to exactly that server with mTLS only if `--cert`/`--key`
        /// are given too.
        #[arg(long)]
        server: Option<String>,
        /// Canary ring this agent is assigned to (`canary_0`/`canary_1`/`canary_2`/`prod`).
        /// Left unset, `updates.ring` from `agent.toml`; with neither, the
        /// command refuses rather than guess a ring.
        #[arg(long)]
        ring: Option<String>,
        /// Path to the client mTLS certificate (PEM), overriding the config's.
        #[arg(long)]
        cert: Option<std::path::PathBuf>,
        /// Path to the client mTLS private key (PEM). Required alongside `--cert`.
        #[arg(long)]
        key: Option<std::path::PathBuf>,
        /// PEM bundle of the CA(s) that signed the server's certificate, for a
        /// control plane on a private CA. When given, only these roots are
        /// trusted (the public roots are not).
        #[arg(long)]
        ca_cert: Option<std::path::PathBuf>,
        /// Where downloaded content is written, mirroring each entry's
        /// manifest `path` underneath it (e.g. `rules/beacon.sigma`). Left
        /// unset, defaults to `content` under `storage.state_dir`. Given
        /// explicitly, must still resolve under `storage.state_dir` (PR #520
        /// review) — this agent refuses a path outside it.
        #[arg(long)]
        content_dir: Option<std::path::PathBuf>,
        /// Where this agent's own record of already-applied content lives.
        /// Missing means a fresh install — every manifest entry is
        /// downloaded and applied. Left unset, defaults to
        /// `content-state.json` under `storage.state_dir` — this file is the
        /// only thing standing between the agent and a replayed old signed
        /// manifest, so (like `--content-dir`) an explicit value must still
        /// resolve under `storage.state_dir` or this agent refuses to run.
        #[arg(long)]
        state: Option<std::path::PathBuf>,
    },
    /// Fetches the signed binary release the server offers, verifies it, stages it
    /// under `<state_dir>/versions/vN`, repoints `current` at it, and restarts the
    /// service onto it (ADR-0015, issue #30). The new release starts on
    /// probation: the watchdog rolls it back and bans it if the agent never shows
    /// progress. Linux only.
    ApplyRelease {
        /// Control-plane base URL, e.g. `https://edr.example.com`.
        #[arg(long)]
        server: String,
        /// PEM client certificate for mTLS.
        #[arg(long, requires = "key")]
        cert: Option<std::path::PathBuf>,
        /// PEM client private key for mTLS.
        #[arg(long, requires = "cert")]
        key: Option<std::path::PathBuf>,
        /// PEM bundle of the CA(s) that signed the server's certificate, for a
        /// control plane on a private CA. When given, only these roots are
        /// trusted (the public roots are not).
        #[arg(long)]
        ca_cert: Option<std::path::PathBuf>,
        /// Stage and promote only; do not restart the service. The release runs
        /// at the next service start.
        #[arg(long)]
        no_restart: bool,
        /// Acknowledge that this build verifies releases against the public test
        /// key, so anyone who can serve the release routes can get code run as
        /// root (ADR-0015 Deferred). Required until a production key is embedded;
        /// for lab and development use only.
        #[arg(long)]
        allow_test_key: bool,
    },
    /// Lists or restores payloads automated quarantine moved aside (issue #25).
    /// The quarantine directory is derived from `--alerts` exactly as `run`
    /// derives it, so pass the same path the running agent was given.
    Quarantine {
        /// The alert log of the agent whose quarantine to act on; restores are
        /// audited into it.
        #[arg(long, default_value = "alerts.ndjson", global = true)]
        alerts: std::path::PathBuf,
        #[command(subcommand)]
        action: QuarantineAction,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// Prints each quarantined payload's SHA-256 and original path.
    List,
    /// Puts a payload back at its original path. Refuses to overwrite a file
    /// that has taken its place, or to restore a payload altered since
    /// quarantine. The restored file stays read-only.
    Restore {
        /// The payload's SHA-256, as printed by `list`.
        sha256: String,
    },
}

fn main() -> std::process::ExitCode {
    match try_main() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn try_main() -> anyhow::Result<std::process::ExitCode> {
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

    let mut exit_code = std::process::ExitCode::SUCCESS;
    let result = match cli.command {
        Command::Status => commands::cmd_status(),
        Command::Run {
            alerts,
            events,
            enable_kill,
            enable_quarantine,
            enable_tls_capture,
            enable_readline_capture,
            enable_dns_capture,
            server,
            standalone,
            cert,
            key,
            ca_cert,
            content_dir,
        } => {
            let target =
                upload::resolve_run_target(server, standalone, cert, key, ca_cert, &cfg.server);
            let content_dir =
                content_dir.unwrap_or_else(|| content::default_content_dir(&cfg.storage.state_dir));
            commands::cmd_run(commands::RunOptions {
                alerts: &alerts,
                events: events.as_deref(),
                storage: &cfg.storage,
                enable_kill,
                enable_quarantine,
                enable_tls_capture,
                enable_readline_capture,
                enable_dns_capture,
                server: target.as_ref().map(upload::RunTarget::control_plane),
                ipc_endpoint: &cfg.ipc.endpoint,
                log_sources: &cfg.logs.sources,
                deception: &cfg.deception,
                content_dir: &content_dir,
            })
        }
        Command::CaptureBaseline { output } => commands::cmd_capture_baseline(&output),
        Command::CaptureEvents { output } => commands::cmd_capture_events(&output),
        Command::CheckContentManifest {
            server,
            ring,
            cert,
            key,
            ca_cert,
            state,
        } => content::cmd_check_content_manifest(
            &server,
            &ring,
            cert.as_deref(),
            key.as_deref(),
            content::resolve_ca_cert(ca_cert, &cfg.server).as_deref(),
            &state,
        ),
        Command::ApplyContentManifest {
            server,
            ring,
            cert,
            key,
            ca_cert,
            content_dir,
            state,
        } => {
            let (content_dir, state) =
                content::resolve_content_paths(&cfg.storage.state_dir, content_dir, state)?;
            let ring = content::resolve_ring(ring, &cfg.updates)?;
            let endpoint = content::resolve_endpoint(
                server,
                cert,
                key,
                content::resolve_ca_cert(ca_cert, &cfg.server),
                &cfg.server,
            );
            let outcome = content::cmd_apply_content_manifest(
                &endpoint,
                &ring,
                &content_dir,
                &state,
                &cfg.ipc.endpoint,
            )?;
            if outcome == content::ApplyOutcome::RingHalted {
                exit_code = std::process::ExitCode::from(apply_exit_status(outcome) as u8);
            }
            Ok(())
        }
        Command::Quarantine { alerts, action } => match action {
            QuarantineAction::List => {
                quarantine_cmd::cmd_quarantine_list(&alerts, &mut std::io::stdout().lock())
            }
            QuarantineAction::Restore { sha256 } => {
                quarantine_cmd::cmd_quarantine_restore(&alerts, &sha256)
            }
        },
        Command::ApplyRelease {
            server,
            cert,
            key,
            ca_cert,
            no_restart,
            allow_test_key,
        } => release::cmd_apply_release(
            &server,
            cert.as_deref(),
            key.as_deref(),
            content::resolve_ca_cert(ca_cert, &cfg.server).as_deref(),
            &cfg.storage.state_dir,
            !no_restart,
            allow_test_key,
        ),
    };
    result?;
    Ok(exit_code)
}

fn apply_exit_status(outcome: content::ApplyOutcome) -> i32 {
    if outcome == content::ApplyOutcome::RingHalted {
        content::EXIT_RING_HALTED
    } else {
        0
    }
}

#[cfg(test)]
mod exit_code_tests {
    use super::*;

    #[test]
    fn a_halted_content_ring_returns_exit_status_75() {
        assert_eq!(apply_exit_status(content::ApplyOutcome::RingHalted), 75);
        assert_eq!(apply_exit_status(content::ApplyOutcome::Done), 0);
    }
}
