//! Content-manifest fetch, verification, download, and apply (ADR-0016,
//! issue #30/#73): the agent-side half of "fetch a signed manifest for my
//! ring, verify it, download what changed, write it to disk."
//!
//! [`cmd_check_content_manifest`] does the fetch-and-verify-only report;
//! [`cmd_apply_content_manifest`] additionally downloads each missing/stale
//! entry via `GET /api/content/artifact` (already real server-side),
//! verifies its SHA-256 against the manifest, and writes it under a content
//! directory. Deliberately stops there — reloading rules/models into a
//! running `DetectionSink`, and any config-driven ring assignment or
//! periodic trigger, are follow-up work, not this slice.
//!
//! Composed here rather than in `crates/updater` because `updater` is a LEAF
//! crate and may not depend on `transport` (`tools/check-deps.py`) — see that
//! crate's module doc.
//!
//! **`--content-dir`/`--state` must resolve under `storage.state_dir`** (PR
//! #520 review): [`resolve_content_paths`] enforces this before any network
//! or filesystem work starts. `ContentState` is the only thing standing
//! between the agent and a replayed old signed manifest — a caller-chosen
//! path anywhere on disk would let anyone able to delete or rewrite that
//! file reset anti-rollback protection. This is a narrower mitigation than
//! real ACL enforcement (tracked separately as issue #103), not a
//! replacement for it.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use updater::{
    ContentEntry, ContentManifest, UpdaterError, fsutil::write_atomically, hash::hash_bytes,
};

/// Hard ceiling on a single content artifact's declared `size` (PR #520
/// review): `get_bytes` already bounds the *response* to the manifest's
/// declared size, but a manifest whose signed `size` field is itself huge
/// would still allocate that much before the SHA-256 check ever runs. Real
/// content is far smaller — ADR-0016's design notes put models around 10MB
/// and rules around 10KB — so 100MB leaves generous headroom for a larger
/// model without accepting an unbounded allocation driven by a single
/// manifest field.
const MAX_CONTENT_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;

/// What this agent has already applied for one ring — the local half of the
/// anti-rollback/dedup check. Persisted as plain JSON next to the agent's other
/// state (no signature: this is the agent's own record of its own state, not
/// something an adversary gains anything by forging locally — the same trust
/// boundary `updater::banlist` already accepts for its ban list).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ContentState {
    /// The highest `release_version` successfully applied, keyed by ring —
    /// per review (PR #509), a single shared counter would let an agent that
    /// is ever pointed at a different ring (a ring reassignment, or a
    /// mismatched manifest that predates the `plan` ring check) lock itself
    /// out of that ring's own real releases as "not newer than installed",
    /// even after the mismatch itself is caught. `None`/absent for a ring is
    /// day zero for it, same as `ReleaseManifest::check_release_version`'s
    /// `None` case.
    #[serde(default)]
    pub(crate) release_version: BTreeMap<String, u64>,
    /// path -> sha256 of every artifact currently applied.
    #[serde(default)]
    pub(crate) entries: BTreeMap<String, String>,
}

impl ContentState {
    /// Loads the persisted state from `path`. A missing file is a fresh
    /// install, not an error — same posture as `updater::banlist::BannedVersions::load`.
    pub(crate) fn load(path: &Path) -> Result<Self, std::io::Error> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// The last-applied `release_version` for `ring`, or `None` if this ring
    /// has never been applied.
    fn release_version_for(&self, ring: &str) -> Option<u64> {
        self.release_version.get(ring).copied()
    }
}

/// What a fetched manifest means for this agent, right now: whether it's
/// already fully applied, and if not, exactly which entries are missing or
/// stale.
#[derive(Debug, PartialEq)]
pub(crate) struct FetchPlan {
    pub(crate) release_version: u64,
    pub(crate) to_fetch: Vec<ContentEntry>,
}

/// Verifies `manifest` (signature + anti-rollback against `state`) and reports
/// which entries this agent still needs to fetch. Pure — no I/O, no network —
/// so it's unit-testable without a live server; `cmd_check_content_manifest`
/// is the thin composition that actually fetches and calls this.
///
/// # Errors
///
/// Propagates [`UpdaterError::SchemaVersionUnsupported`],
/// [`UpdaterError::SignatureInvalid`], [`UpdaterError::RingMismatch`] (checked
/// right after the signature — a valid signature only proves who signed the
/// manifest, not that it's the one for `ring`), or
/// [`UpdaterError::ReleaseNotNewer`] — the same checks a binary self-update
/// manifest gets, applied to content — or [`UpdaterError::UnsafeContentPath`]
/// if any entry's path would escape a local content root.
pub(crate) fn plan(
    manifest: &ContentManifest,
    ring: &str,
    state: &ContentState,
) -> Result<FetchPlan, UpdaterError> {
    manifest.verify_signature()?;
    manifest.check_ring(ring)?;
    manifest.check_release_version(state.release_version_for(ring))?;
    manifest.validate_entry_paths()?;
    let to_fetch = manifest
        .entries_to_fetch(&state.entries)
        .into_iter()
        .cloned()
        .collect();
    Ok(FetchPlan {
        release_version: manifest.release_version,
        to_fetch,
    })
}

/// Fetches the content manifest for `ring` from `server`, verifies it, and
/// prints a report of what has changed — does not download artifacts or apply
/// anything (see module doc). `state_path` is where this agent's own
/// [`ContentState`] is read from; a fresh install with no file yet reports
/// every entry in the manifest as needing a fetch.
///
/// # Errors
///
/// Returns an error if the server is unreachable, the manifest fails
/// verification, or it is not newer than the last-applied release for this
/// ring (an operator re-running the check sees this as "up to date", not a
/// crash — see the caller's own message mapping, `commands::content` on the
/// CLI side).
pub(crate) fn cmd_check_content_manifest(
    server: &str,
    ring: &str,
    cert: Option<&Path>,
    key: Option<&Path>,
    ca_cert: Option<&Path>,
    state_path: &Path,
) -> anyhow::Result<()> {
    let client = build_client(server, cert, key, ca_cert)?;
    let url = client.config().content_manifest_url(ring);
    let manifest: ContentManifest = client.get_json(&url)?;

    let state = ContentState::load(state_path)?;
    match plan(&manifest, ring, &state) {
        Ok(plan) => {
            println!(
                "ring {ring}: release {} available, {} entr{} to fetch",
                plan.release_version,
                plan.to_fetch.len(),
                if plan.to_fetch.len() == 1 { "y" } else { "ies" }
            );
            for entry in &plan.to_fetch {
                println!(
                    "  {} ({}, {} bytes, sha256={})",
                    entry.path, entry.content_type, entry.size, entry.sha256
                );
            }
        }
        Err(UpdaterError::ReleaseNotNewer { offered, current }) => {
            println!("ring {ring}: up to date (release {current}, server offers {offered})");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Builds a [`transport::TransportClient`] for `server`, with mTLS if both
/// `cert` and `key` are given, and trusting only `ca_cert`'s roots when it is
/// (a control plane on a private CA, #658) — shared by [`cmd_check_content_manifest`] and
/// [`cmd_apply_content_manifest`].
///
/// # Errors
///
/// Returns an error if mTLS certificates are configured but cannot be loaded.
fn build_client(
    server: &str,
    cert: Option<&Path>,
    key: Option<&Path>,
    ca_cert: Option<&Path>,
) -> anyhow::Result<transport::TransportClient> {
    let mut config = transport::TransportConfig::new(server);
    if let (Some(cert), Some(key)) = (cert, key) {
        config = config.with_client_cert(PathBuf::from(cert), PathBuf::from(key));
    }
    if let Some(ca_cert) = ca_cert {
        config = config.with_ca_cert(PathBuf::from(ca_cert));
    }
    Ok(transport::TransportClient::new(config)?)
}

/// Resolves `entry_path` (already checked safe by
/// [`ContentManifest::validate_entry_paths`], called from [`plan`]) onto
/// `root`, one path segment at a time — content paths are forward-slash-only
/// by contract (the field's own doc comment) regardless of the host's path
/// separator, so segments are joined individually rather than handing the
/// raw string to a single `Path::push`.
fn artifact_dest(root: &Path, entry_path: &str) -> PathBuf {
    let mut dest = root.to_path_buf();
    for segment in entry_path.split('/') {
        dest.push(segment);
    }
    dest
}

/// Downloads every entry in `fetch_plan.to_fetch` from the (already-real)
/// `/api/content/artifact` endpoint, verifies its SHA-256 against the
/// manifest's declared hash, and writes it under `content_dir`. Persists
/// `state` after each successful write — a crash or network failure partway
/// through leaves already-applied entries recorded, so a re-run's `plan()`
/// recomputes the diff against the updated file and only re-fetches what's
/// left. The ring's `release_version` is bumped and persisted only once
/// every entry has landed, so a caller retrying a partially-applied
/// manifest still passes `check_release_version` on the next attempt.
///
/// Deliberately stops there — does not reload anything into a running
/// `DetectionSink` (module doc).
///
/// # Errors
///
/// Returns an error if a download fails, a downloaded artifact's hash
/// doesn't match the manifest's declared value
/// ([`UpdaterError::StagedFileMismatch`]), a declared `size` exceeds
/// [`MAX_CONTENT_ARTIFACT_BYTES`], or a filesystem write fails.
fn download_and_apply(
    client: &transport::TransportClient,
    fetch_plan: &FetchPlan,
    ring: &str,
    content_dir: &Path,
    state_path: &Path,
    mut state: ContentState,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(content_dir)?;
    // The symlink check bounds itself to components under this root, not
    // the whole filesystem ancestry (see `updater::fsutil::reject_symlink_components`) — for
    // the state file, that root is its own containing directory.
    let state_root = state_path.parent().unwrap_or_else(|| Path::new("."));

    for entry in &fetch_plan.to_fetch {
        if entry.size > MAX_CONTENT_ARTIFACT_BYTES {
            anyhow::bail!(
                "entry {} declares size {} bytes, exceeding the {}-byte cap",
                entry.path,
                entry.size,
                MAX_CONTENT_ARTIFACT_BYTES
            );
        }

        let url = client.config().content_artifact_url();
        let bytes = client.get_bytes(
            &url,
            &[
                ("path", entry.path.as_str()),
                ("sha256", entry.sha256.as_str()),
            ],
            entry.size,
        )?;

        let actual = hash_bytes(&bytes);
        if actual != entry.sha256 {
            return Err(UpdaterError::StagedFileMismatch {
                path: PathBuf::from(&entry.path),
                expected: entry.sha256.clone(),
                actual,
            }
            .into());
        }

        let dest = artifact_dest(content_dir, &entry.path);
        write_atomically(content_dir, &dest, &bytes)?;

        state
            .entries
            .insert(entry.path.clone(), entry.sha256.clone());
        write_atomically(state_root, state_path, &serde_json::to_vec(&state)?)?;
    }

    state
        .release_version
        .insert(ring.to_string(), fetch_plan.release_version);
    write_atomically(state_root, state_path, &serde_json::to_vec(&state)?)?;
    Ok(())
}

/// Resolves `path`'s furthest already-existing ancestor via
/// [`Path::canonicalize`] (undoing `..` components and symlinks up to that
/// point), then rejoins whatever of `path` doesn't exist yet onto it
/// lexically — the non-existent tail can't be canonicalized, so this is the
/// closest containment check available before every directory involved is
/// guaranteed to exist yet. A path with no existing ancestor at all (a bare
/// relative path on an otherwise-empty filesystem) resolves against the
/// current working directory, matching how a relative path would actually
/// be interpreted.
///
/// Documented limitation: a component created *after* this check runs (a
/// TOCTOU symlink swap) is not caught here — [`updater::fsutil::reject_symlink_components`]
/// is the check that actually runs at write time and is what closes that
/// gap for content this agent writes.
fn resolve_as_far_as_possible(path: &Path) -> std::io::Result<PathBuf> {
    let mut existing = path;
    let mut remainder: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(mut base) => {
                for part in remainder.into_iter().rev() {
                    base.push(part);
                }
                return Ok(base);
            }
            Err(_) => {
                let Some(parent) = existing.parent() else {
                    return Ok(std::env::current_dir()?.join(path));
                };
                if let Some(name) = existing.file_name() {
                    remainder.push(name);
                }
                existing = parent;
            }
        }
    }
}

/// Refuses `path` unless it resolves under `state_dir` (PR #520 review:
/// `--state`/`--content-dir` were free-form caller-chosen paths, and the
/// content-state file is the only thing standing between a replayed old
/// signed manifest and the agent accepting it as new — anyone able to point
/// either flag outside the agent's own protected state directory, or delete
/// the file there, resets that protection). `state_dir` is
/// `cfg.storage.state_dir`, already documented as the one directory
/// "agent-writable... not operator-editable at runtime" (`StorageConfig`).
/// This is a narrower mitigation than real ACL enforcement (tracked
/// separately as issue #103) — it stops an operator or script from
/// accidentally or carelessly pointing these flags somewhere unprotected,
/// not a privileged local attacker who can also rewrite `state_dir` itself.
///
/// # Errors
///
/// Returns an error naming both the given path and `state_dir` if `path`
/// does not resolve under it.
fn ensure_within_state_dir(path: &Path, state_dir: &Path, flag_name: &str) -> anyhow::Result<()> {
    let resolved_root = resolve_as_far_as_possible(state_dir)?;
    let resolved_path = resolve_as_far_as_possible(path)?;
    if resolved_path.starts_with(&resolved_root) {
        Ok(())
    } else {
        anyhow::bail!(
            "--{flag_name} ({}) must be under storage.state_dir ({}); resolved to {} which is \
             outside {}",
            path.display(),
            state_dir.display(),
            resolved_path.display(),
            resolved_root.display()
        )
    }
}

/// Where applied content lives by default. The single definition shared by
/// `apply-content-manifest` (writer) and `run` (reader): they must agree, or
/// content that was downloaded and verified is never loaded.
pub(crate) fn default_content_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("content")
}

/// Resolves `--content-dir`/`--state` for `apply-content-manifest`: left
/// unset, each defaults to a fixed name under `state_dir`
/// (`cfg.storage.state_dir`); given explicitly, each must still resolve
/// under `state_dir` ([`ensure_within_state_dir`]) — see that function's
/// doc for why. Checked once, before any network or filesystem work starts.
///
/// # Errors
///
/// Returns an error if an explicit `content_dir` or `state_path` does not
/// resolve under `state_dir`.
pub(crate) fn resolve_content_paths(
    state_dir: &Path,
    content_dir: Option<PathBuf>,
    state_path: Option<PathBuf>,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let content_dir = match content_dir {
        Some(dir) => {
            ensure_within_state_dir(&dir, state_dir, "content-dir")?;
            dir
        }
        None => default_content_dir(state_dir),
    };
    let state_path = match state_path {
        Some(path) => {
            ensure_within_state_dir(&path, state_dir, "state")?;
            path
        }
        None => state_dir.join("content-state.json"),
    };
    Ok((content_dir, state_path))
}

/// Where and how to reach the control plane, after `--server`/`--cert`/`--key`
/// have been reconciled with `agent.toml` ([`resolve_endpoint`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) server: String,
    pub(crate) cert: Option<PathBuf>,
    pub(crate) key: Option<PathBuf>,
    /// PEM bundle of the only CA(s) trusted for the server's certificate.
    pub(crate) ca_cert: Option<PathBuf>,
}

/// Picks the control plane for `apply-content-manifest`. `--server` omitted
/// means "this install's own control plane": the configured URL with the
/// configured mTLS pair (an explicit `--cert`/`--key` still wins). `--server`
/// given means exactly that server, with mTLS only if the flags say so — the
/// config's client certificate is never presented to a server the operator
/// named by hand.
pub(crate) fn resolve_endpoint(
    server: Option<String>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    configured: &config::ServerConfig,
) -> Endpoint {
    match server {
        Some(server) => Endpoint {
            server,
            cert,
            key,
            ca_cert,
        },
        None => Endpoint {
            ca_cert,
            server: configured.control_plane_url.clone(),
            cert: Some(cert.unwrap_or_else(|| configured.mtls_cert.clone())),
            key: Some(key.unwrap_or_else(|| configured.mtls_key.clone())),
        },
    }
}

/// The CA bundle to trust for the control plane: `--ca-cert`, else `server.ca_cert`
/// from `agent.toml`, else none (the built-in roots). A CA is a trust anchor and not a
/// credential, so unlike the client certificate it applies to a server named by hand
/// too; it can only make verification stricter.
pub(crate) fn resolve_ca_cert(
    flag: Option<PathBuf>,
    configured: &config::ServerConfig,
) -> Option<PathBuf> {
    flag.or_else(|| configured.ca_cert.clone())
}

/// Picks the ring for `apply-content-manifest`: `--ring`, else
/// `updates.ring`. There is no default ring — an agent that lands in `prod`
/// by omission would bypass the canary rollout (ADR-0016).
///
/// # Errors
///
/// Returns an error when neither the flag nor the config names a ring.
pub(crate) fn resolve_ring(
    flag: Option<String>,
    updates: &config::UpdatesConfig,
) -> anyhow::Result<String> {
    flag.or_else(|| updates.ring.clone()).ok_or_else(|| {
        anyhow::anyhow!(
            "no content ring: pass --ring, or set `ring` under `[updates]` in agent.toml \
             (one of {})",
            config::CONTENT_RINGS.join(", ")
        )
    })
}

/// Fetches the content manifest for `ring`, verifies it exactly like
/// [`cmd_check_content_manifest`], and — unlike that command — actually
/// downloads and writes every entry that's missing or stale under
/// `content_dir`, then records what was applied in `state_path`. On
/// success, best-effort notifies an already-running `agent run` at
/// `ipc_endpoint` to reload the content it just applied (issue #30) — see
/// [`notify_running_agent`] for why a failed notification is not a hard
/// error here.
///
/// # Errors
///
/// Returns an error if the server is unreachable, the manifest fails
/// verification, or [`download_and_apply`] fails partway through (already-
/// applied entries stay recorded in `state_path` for the next attempt).
pub(crate) fn cmd_apply_content_manifest(
    endpoint: &Endpoint,
    ring: &str,
    content_dir: &Path,
    state_path: &Path,
    ipc_endpoint: &str,
) -> anyhow::Result<()> {
    let client = build_client(
        &endpoint.server,
        endpoint.cert.as_deref(),
        endpoint.key.as_deref(),
        endpoint.ca_cert.as_deref(),
    )?;
    let url = client.config().content_manifest_url(ring);
    let manifest: ContentManifest = client.get_json(&url)?;

    let state = ContentState::load(state_path)?;
    let fetch_plan = match plan(&manifest, ring, &state) {
        Ok(fetch_plan) => fetch_plan,
        Err(UpdaterError::ReleaseNotNewer { offered, current }) => {
            println!("ring {ring}: up to date (release {current}, server offers {offered})");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let fetched = fetch_plan.to_fetch.len();
    download_and_apply(&client, &fetch_plan, ring, content_dir, state_path, state)?;
    println!(
        "ring {ring}: applied release {} ({fetched} entr{} fetched)",
        fetch_plan.release_version,
        if fetched == 1 { "y" } else { "ies" }
    );

    match notify_running_agent(ipc_endpoint) {
        Ok(report) => {
            println!(
                "notified the running agent — reloaded (sigma: {}, yara: {})",
                describe_reload_count(report.sigma_rule_count),
                describe_reload_count(report.yara_rule_count),
            );
            for (engine, failed) in [
                ("sigma", report.sigma_reload_failed),
                ("yara", report.yara_reload_failed),
            ] {
                if failed {
                    eprintln!(
                        "warning: the {engine} content failed to load; the agent kept its \
                         previous {engine} rules (see the agent log)"
                    );
                }
            }
        }
        Err(e) => println!(
            "no running agent to notify at {ipc_endpoint} ({e}) — already applied to disk, \
             will be picked up on the agent's next start"
        ),
    }
    Ok(())
}

/// One line for a [`ipc::ReloadContentResponse`] count field: `None` means
/// that content subdirectory is absent, not an error.
fn describe_reload_count(count: Option<usize>) -> String {
    match count {
        Some(n) => format!("{n} rules"),
        None => "absent".to_string(),
    }
}

/// Tells an already-running `agent run` at `ipc_endpoint` to reload content
/// (issue #30) — a short-lived connection, exactly one request, then
/// dropped. Deliberately **not** treated as a hard error by the caller: the
/// content is already correctly downloaded, verified, and written to disk
/// regardless of whether a live agent happens to be listening right now (no
/// agent running yet, a stale/misconfigured endpoint, or the agent process
/// simply not up at this moment are all normal, not failures of this
/// command's own job).
///
/// # Errors
///
/// Returns an error (as a `String` — this is a best-effort notification,
/// not a typed API another caller pattern-matches on) if a short-lived
/// current-thread runtime cannot be built, the connection fails, or the
/// agent's own handler reports a failure.
fn notify_running_agent(ipc_endpoint: &str) -> Result<ipc::ReloadContentResponse, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let mut client = ipc::Client::connect(ipc_endpoint, "agent-apply-content-manifest")
            .await
            .map_err(|e| e.to_string())?;
        client.reload_content().await.map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured_server() -> config::ServerConfig {
        config::ServerConfig {
            control_plane_url: "https://cp.example".to_string(),
            mtls_cert: PathBuf::from("/etc/synthaea/certs/client.crt"),
            mtls_key: PathBuf::from("/etc/synthaea/certs/client.key"),
            mtls_passphrase: config::SecretRef::Invalid(String::new()),
            ca_cert: None,
            offline_fallback: true,
        }
    }

    fn ca(path: &str) -> Option<PathBuf> {
        Some(PathBuf::from(path))
    }

    #[test]
    fn resolve_ca_cert_takes_the_flag_the_config_or_both_with_the_flag_winning() {
        let mut server = configured_server();
        // Neither: the built-in roots.
        assert_eq!(resolve_ca_cert(None, &server), None);
        // Flag only.
        assert_eq!(
            resolve_ca_cert(ca("/lab/ca.pem"), &server),
            ca("/lab/ca.pem")
        );
        // Config only.
        server.ca_cert = ca("/etc/synthaea/certs/ca.pem");
        assert_eq!(
            resolve_ca_cert(None, &server),
            ca("/etc/synthaea/certs/ca.pem")
        );
        // Both: the flag wins.
        assert_eq!(
            resolve_ca_cert(ca("/lab/ca.pem"), &server),
            ca("/lab/ca.pem")
        );
    }

    #[test]
    fn a_ca_bundle_is_kept_for_the_configured_and_for_an_explicit_server() {
        let configured = resolve_endpoint(None, None, None, ca("/x/ca.pem"), &configured_server());
        let explicit = resolve_endpoint(
            Some("https://lab.example".to_string()),
            None,
            None,
            ca("/x/ca.pem"),
            &configured_server(),
        );
        assert_eq!(configured.ca_cert, ca("/x/ca.pem"));
        assert_eq!(explicit.ca_cert, ca("/x/ca.pem"));
    }

    #[test]
    fn omitting_server_uses_the_configured_control_plane_and_mtls_pair() {
        let endpoint = resolve_endpoint(None, None, None, None, &configured_server());
        assert_eq!(endpoint.server, "https://cp.example");
        assert_eq!(
            endpoint.cert.as_deref(),
            Some(Path::new("/etc/synthaea/certs/client.crt"))
        );
        assert_eq!(
            endpoint.key.as_deref(),
            Some(Path::new("/etc/synthaea/certs/client.key"))
        );
    }

    #[test]
    fn an_explicit_server_never_borrows_the_configured_client_certificate() {
        let endpoint = resolve_endpoint(
            Some("http://127.0.0.1:3000".to_string()),
            None,
            None,
            None,
            &configured_server(),
        );
        assert_eq!(endpoint.server, "http://127.0.0.1:3000");
        assert_eq!(endpoint.cert, None);
        assert_eq!(endpoint.key, None);
    }

    #[test]
    fn an_explicit_cert_overrides_the_configured_one_but_keeps_the_configured_key() {
        let endpoint = resolve_endpoint(
            None,
            Some(PathBuf::from("/tmp/other.crt")),
            None,
            None,
            &configured_server(),
        );
        assert_eq!(endpoint.cert.as_deref(), Some(Path::new("/tmp/other.crt")));
        assert_eq!(
            endpoint.key.as_deref(),
            Some(Path::new("/etc/synthaea/certs/client.key"))
        );
    }

    #[test]
    fn the_ring_flag_wins_over_the_configured_ring() {
        let updates = config::UpdatesConfig {
            ring: Some("canary_1".to_string()),
        };
        let ring = resolve_ring(Some("prod".to_string()), &updates).unwrap();
        assert_eq!(ring, "prod");
    }

    #[test]
    fn the_configured_ring_applies_when_no_flag_is_given() {
        let updates = config::UpdatesConfig {
            ring: Some("canary_1".to_string()),
        };
        assert_eq!(resolve_ring(None, &updates).unwrap(), "canary_1");
    }

    #[test]
    fn no_ring_anywhere_is_refused_rather_than_defaulted() {
        let err = resolve_ring(None, &config::UpdatesConfig::default()).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("--ring"), "{message}");
        assert!(message.contains("[updates]"), "{message}");
    }

    /// Builds a manifest and signs it exactly the way `updater::content`'s own
    /// tests do (this crate can't call that module's private signing helper
    /// directly): canonical bytes with `signature` forced empty, 2-space-indent
    /// JSON, Ed25519 over that, hex-encoded. Then round-trips through JSON so
    /// tests exercise what a real fetch would actually deserialize.
    fn signed_manifest_json(release_version: u64, entries: Vec<ContentEntry>) -> ContentManifest {
        signed_manifest_json_for_ring("canary_0", release_version, entries)
    }

    fn signed_manifest_json_for_ring(
        ring: &str,
        release_version: u64,
        entries: Vec<ContentEntry>,
    ) -> ContentManifest {
        let mut m = ContentManifest {
            entries,
            release_version,
            released_at: "2026-09-23T16:00:00Z".to_string(),
            ring: ring.to_string(),
            schema_version: updater::content::CONTENT_MANIFEST_SCHEMA_VERSION,
            signature: String::new(),
        };
        let bytes = serde_json::to_vec_pretty(&m).unwrap();
        let sig = updater::key::test_key_pair().sign(&bytes);
        m.signature = updater::hash::hex_encode(sig.as_ref());
        serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap()
    }

    fn entry(path: &str) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: "a".repeat(64),
            size: 10,
            content_type: "rule".to_string(),
        }
    }

    #[test]
    fn a_fresh_install_needs_every_entry() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let state = ContentState::default();
        let result = plan(&manifest, "canary_0", &state).unwrap();
        assert_eq!(result.release_version, 1);
        assert_eq!(result.to_fetch.len(), 1);
    }

    #[test]
    fn an_already_applied_entry_is_not_refetched() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let mut state = ContentState::default();
        state
            .entries
            .insert("rules/a.sigma".to_string(), "a".repeat(64));
        let result = plan(&manifest, "canary_0", &state).unwrap();
        assert!(result.to_fetch.is_empty());
    }

    #[test]
    fn a_manifest_no_newer_than_the_applied_release_is_rejected() {
        let manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        let mut state = ContentState::default();
        state.release_version.insert("canary_0".to_string(), 1);
        assert!(matches!(
            plan(&manifest, "canary_0", &state),
            Err(UpdaterError::ReleaseNotNewer {
                offered: 1,
                current: 1
            })
        ));
    }

    #[test]
    fn a_tampered_manifest_is_rejected_before_the_release_version_check() {
        let mut manifest = signed_manifest_json(1, vec![entry("rules/a.sigma")]);
        manifest.entries.push(entry("rules/injected.sigma"));
        let state = ContentState::default();
        assert!(matches!(
            plan(&manifest, "canary_0", &state),
            Err(UpdaterError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_correctly_signed_manifest_for_another_ring_is_rejected() {
        // Concrete attack this pins (PR #509 review): a prod agent requests
        // `prod` but is served (or a stale response cache/misrouted request
        // returns) a validly-signed `canary_0` manifest with a higher
        // release_version. Without a ring check this would verify and be
        // accepted, applying the least-vetted ring's content to a prod agent.
        let manifest = signed_manifest_json(99, vec![entry("rules/a.sigma")]);
        let state = ContentState::default();
        assert!(matches!(
            plan(&manifest, "prod", &state),
            Err(UpdaterError::RingMismatch { requested, found })
                if requested == "prod" && found == "canary_0"
        ));
    }

    #[test]
    fn anti_rollback_state_is_scoped_per_ring() {
        // A ring reassignment (or an agent that has fetched more than one
        // ring's manifest) must not have one ring's higher release_version
        // lock out another ring's own, independently-numbered releases.
        let mut state = ContentState::default();
        state.release_version.insert("canary_0".to_string(), 50);

        // release_version 10 for `prod` — lower than canary_0's 50, but prod
        // has never been applied in this state, so it must still pass.
        let prod_manifest = signed_manifest_json_for_ring("prod", 10, vec![entry("rules/a.sigma")]);

        let result = plan(&prod_manifest, "prod", &state).unwrap();
        assert_eq!(result.release_version, 10);
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("content-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn content_state_load_on_a_missing_file_is_a_fresh_default() {
        let dir = tmp("missing");
        let state = ContentState::load(&dir.join("does-not-exist.json")).unwrap();
        assert_eq!(state, ContentState::default());
    }

    #[test]
    fn content_state_round_trips_through_disk() {
        let dir = tmp("round-trip");
        let path = dir.join("content-state.json");
        let mut state = ContentState {
            release_version: BTreeMap::from([("canary_0".to_string(), 3)]),
            entries: BTreeMap::new(),
        };
        state
            .entries
            .insert("rules/a.sigma".to_string(), "a".repeat(64));
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();

        let loaded = ContentState::load(&path).unwrap();
        assert_eq!(loaded, state);
    }

    // ── artifact_dest ────────────────────────────────────────────────────

    #[test]
    fn artifact_dest_joins_forward_slash_segments_onto_root() {
        let root = std::path::Path::new("/var/lib/synthaea/content");
        assert_eq!(
            artifact_dest(root, "rules/beacon.sigma"),
            root.join("rules").join("beacon.sigma")
        );
    }

    // ── download_and_apply ──────────────────────────────────────────────
    //
    // A minimal one-shot HTTP server (std only, no new dev-dependency): the
    // agent-side download path issues one GET per entry, in `to_fetch`'s
    // order, so a fixed sequence of canned responses is enough to test it
    // without a real control plane.

    fn read_request(stream: &mut std::net::TcpStream) {
        use std::io::Read as _;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let Ok(n) = stream.read(&mut chunk) else {
                return;
            };
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).position(|w| w == b"\r\n\r\n").is_some() {
                return; // GET requests here carry no body
            }
            if n == 0 {
                return;
            }
        }
    }

    fn write_response(stream: &mut std::net::TcpStream, status: u16, body: &[u8]) {
        use std::io::Write as _;
        let reason = if status == 200 { "OK" } else { "NOPE" };
        let _ = write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(body);
    }

    /// Serves one canned `(status, body)` response per accepted connection,
    /// in order, then exits once the list is exhausted.
    fn artifact_server(responses: Vec<(u16, Vec<u8>)>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                read_request(&mut stream);
                write_response(&mut stream, status, &body);
            }
        });
        format!("http://{addr}")
    }

    fn entry_for(path: &str, bytes: &[u8]) -> ContentEntry {
        ContentEntry {
            metadata: None,
            path: path.to_string(),
            sha256: hash_bytes(bytes),
            size: bytes.len() as u64,
            content_type: "rule".to_string(),
        }
    }

    #[test]
    fn download_and_apply_writes_verified_entries_and_persists_state() {
        let dir = tmp("apply-happy-path");
        let content_dir = dir.join("content");
        let state_path = dir.join("content-state.json");

        let e1 = entry_for("rules/beacon.sigma", b"title: beacon\n");
        let e2 = entry_for("models/cmdline/model.pkl", b"\x00\x01binary-model-bytes");
        let url = artifact_server(vec![
            (200, b"title: beacon\n".to_vec()),
            (200, b"\x00\x01binary-model-bytes".to_vec()),
        ]);
        let client =
            transport::TransportClient::new(transport::TransportConfig::new(&url)).unwrap();
        let fetch_plan = FetchPlan {
            release_version: 7,
            to_fetch: vec![e1.clone(), e2.clone()],
        };

        download_and_apply(
            &client,
            &fetch_plan,
            "canary_0",
            &content_dir,
            &state_path,
            ContentState::default(),
        )
        .unwrap();

        assert_eq!(
            std::fs::read(content_dir.join("rules").join("beacon.sigma")).unwrap(),
            b"title: beacon\n"
        );
        assert_eq!(
            std::fs::read(content_dir.join("models").join("cmdline").join("model.pkl")).unwrap(),
            b"\x00\x01binary-model-bytes"
        );

        let state = ContentState::load(&state_path).unwrap();
        assert_eq!(state.entries.get("rules/beacon.sigma"), Some(&e1.sha256));
        assert_eq!(
            state.entries.get("models/cmdline/model.pkl"),
            Some(&e2.sha256)
        );
        assert_eq!(state.release_version.get("canary_0"), Some(&7));
    }

    #[test]
    fn download_and_apply_rejects_a_hash_mismatch_before_writing_it() {
        let dir = tmp("apply-hash-mismatch");
        let content_dir = dir.join("content");
        let state_path = dir.join("content-state.json");

        // The manifest declares this hash, but the server actually serves
        // different bytes — the concrete tamper/corruption case this check
        // exists for.
        let mut entry = entry_for("rules/beacon.sigma", b"title: beacon\n");
        entry.sha256 = "f".repeat(64);
        let url = artifact_server(vec![(200, b"title: beacon\n".to_vec())]);
        let client =
            transport::TransportClient::new(transport::TransportConfig::new(&url)).unwrap();
        let fetch_plan = FetchPlan {
            release_version: 1,
            to_fetch: vec![entry],
        };

        let err = download_and_apply(
            &client,
            &fetch_plan,
            "canary_0",
            &content_dir,
            &state_path,
            ContentState::default(),
        )
        .expect_err("a hash mismatch must not be silently written");
        assert!(err.to_string().contains("hash mismatch"));
        assert!(!content_dir.join("rules").join("beacon.sigma").exists());
    }

    #[test]
    fn download_and_apply_preserves_progress_when_a_later_entry_fails() {
        let dir = tmp("apply-partial-progress");
        let content_dir = dir.join("content");
        let state_path = dir.join("content-state.json");

        let e1 = entry_for("rules/first.sigma", b"first");
        let mut e2 = entry_for("rules/second.sigma", b"second");
        e2.sha256 = "f".repeat(64); // will mismatch what the server serves
        let url = artifact_server(vec![(200, b"first".to_vec()), (200, b"second".to_vec())]);
        let client =
            transport::TransportClient::new(transport::TransportConfig::new(&url)).unwrap();
        let fetch_plan = FetchPlan {
            release_version: 5,
            to_fetch: vec![e1.clone(), e2],
        };

        download_and_apply(
            &client,
            &fetch_plan,
            "canary_0",
            &content_dir,
            &state_path,
            ContentState::default(),
        )
        .expect_err("the second entry's hash mismatch must surface");

        // The first entry landed and was recorded before the second failed.
        assert!(content_dir.join("rules").join("first.sigma").exists());
        let state = ContentState::load(&state_path).unwrap();
        assert_eq!(state.entries.get("rules/first.sigma"), Some(&e1.sha256));
        assert!(!state.entries.contains_key("rules/second.sigma"));
        // The release isn't marked applied until every entry lands.
        assert!(!state.release_version.contains_key("canary_0"));
    }

    // ── MAX_CONTENT_ARTIFACT_BYTES (issue #30, PR #520 review) ──────────

    #[test]
    fn an_entry_declaring_a_size_over_the_cap_is_rejected_before_any_network_call() {
        let dir = tmp("size-cap");
        let content_dir = dir.join("content");
        let state_path = dir.join("content-state.json");

        let mut entry = entry_for("rules/huge.sigma", b"small actual bytes");
        entry.size = MAX_CONTENT_ARTIFACT_BYTES + 1;
        let fetch_plan = FetchPlan {
            release_version: 1,
            to_fetch: vec![entry],
        };
        // No server at all — if this reached `get_bytes` it would fail with
        // a connection error instead, so a config/network-shaped error here
        // would mean the cap check didn't run first.
        let client =
            transport::TransportClient::new(transport::TransportConfig::new("http://127.0.0.1:1"))
                .unwrap();

        let err = download_and_apply(
            &client,
            &fetch_plan,
            "canary_0",
            &content_dir,
            &state_path,
            ContentState::default(),
        )
        .expect_err("an oversized declared size must be rejected");
        assert!(err.to_string().contains("exceeding"), "got: {err}");
    }

    // ── resolve_content_paths / ensure_within_state_dir (issue #30, PR #520 review) ──

    #[test]
    fn unset_flags_default_to_paths_under_state_dir() {
        let state_dir = tmp("resolve-defaults");
        let (content_dir, state_path) = resolve_content_paths(&state_dir, None, None).unwrap();
        assert_eq!(content_dir, state_dir.join("content"));
        assert_eq!(state_path, state_dir.join("content-state.json"));
    }

    #[test]
    fn an_explicit_path_under_state_dir_is_accepted() {
        let state_dir = tmp("resolve-explicit-ok");
        let explicit_content = state_dir.join("my-content");
        let (content_dir, _) =
            resolve_content_paths(&state_dir, Some(explicit_content.clone()), None).unwrap();
        assert_eq!(content_dir, explicit_content);
    }

    #[test]
    fn an_explicit_content_dir_outside_state_dir_is_refused() {
        let state_dir = tmp("resolve-content-outside");
        let outside = tmp("resolve-content-outside-target");
        let err = resolve_content_paths(&state_dir, Some(outside), None)
            .expect_err("a content-dir outside state_dir must be refused");
        assert!(err.to_string().contains("--content-dir"), "got: {err}");
    }

    #[test]
    fn an_explicit_state_path_outside_state_dir_is_refused() {
        let state_dir = tmp("resolve-state-outside");
        let outside = tmp("resolve-state-outside-target").join("content-state.json");
        let err = resolve_content_paths(&state_dir, None, Some(outside))
            .expect_err("a --state path outside state_dir must be refused");
        assert!(err.to_string().contains("--state"), "got: {err}");
    }

    #[test]
    fn run_and_apply_default_to_the_same_content_dir() {
        // A default mismatch once left applied content on disk that the
        // running agent never read (issue #530).
        let state_dir = tmp("default-content-dir-agrees");
        let (apply_default, _) = resolve_content_paths(&state_dir, None, None).unwrap();
        assert_eq!(apply_default, default_content_dir(&state_dir));
    }

    #[test]
    fn a_not_yet_existing_subdirectory_under_state_dir_still_resolves_within_it() {
        // `resolve_as_far_as_possible` must not require the directory to
        // exist yet — the whole point is validating a path before it's
        // created.
        let state_dir = tmp("resolve-not-yet-existing");
        let future_content_dir = state_dir.join("content").join("not-created-yet");
        let (content_dir, _) =
            resolve_content_paths(&state_dir, Some(future_content_dir.clone()), None).unwrap();
        assert_eq!(content_dir, future_content_dir);
    }

    // ── notify_running_agent (issue #30) ────────────────────────────────

    /// The concrete case `cmd_apply_content_manifest`'s own doc comment
    /// names: no agent is running at `ipc_endpoint` (or it's a stale/wrong
    /// path). This must surface as an `Err` the caller can log and move on
    /// from, never a panic — content already reached disk regardless of
    /// whether a live agent is listening.
    #[test]
    fn notify_running_agent_returns_an_error_when_nothing_is_listening() {
        let endpoint = std::env::temp_dir()
            .join(format!(
                "synthaea-notify-test-nothing-here-{}.sock",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned();
        let result = notify_running_agent(&endpoint);
        assert!(
            result.is_err(),
            "connecting to a socket nothing listens on must fail, not panic"
        );
    }
}
