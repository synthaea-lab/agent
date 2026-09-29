//! The binary self-update trigger (ADR-0015, issue #30): fetch the signed release
//! manifest, verify it, stage the release, promote it, and restart the service
//! onto it. The watchdog's post-promotion health gate (`watchdog::probation`)
//! then decides whether the release stays.
//!
//! Composed here rather than in `crates/updater` because `updater` is a LEAF
//! crate and may not depend on `transport` (`tools/check-deps.py`), same as
//! [`crate::content`].
//!
//! Server contract (the server side is a separate slice; this is what it must
//! serve):
//! - `GET /api/release/manifest` → the signed [`updater::ReleaseManifest`] this
//!   agent is offered. No ring in the path: which release an agent gets is the
//!   server's decision from its mTLS identity, and the signature plus the
//!   monotone `release_version` are what the agent relies on.
//! - `GET /api/release/artifact?release_version=N&path=P&sha256=H` → the bytes of
//!   entry `P`.
//!
//! Nothing is promoted until every artifact has been downloaded, hash-checked
//! against the signed manifest, written into a hidden staging directory and
//! re-verified from disk; `current` moves only after that. Linux-only, like
//! `updater::layout` (ADR-0015 Deferred).

#[cfg(target_os = "linux")]
pub(crate) use linux::cmd_apply_release;

#[cfg(not(target_os = "linux"))]
pub(crate) fn cmd_apply_release(
    _server: &str,
    _cert: Option<&std::path::Path>,
    _key: Option<&std::path::Path>,
    _base_dir: &std::path::Path,
    _restart: bool,
) -> anyhow::Result<()> {
    anyhow::bail!("binary self-update is Linux-only (ADR-0015 Deferred)")
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};

    use updater::{
        ReleaseManifest, UpdaterError, banlist::BannedVersions,
        fsutil::write_executable_atomically, hash::hash_bytes, layout::Layout,
    };

    /// Hard ceiling on one release artifact. `ReleaseManifest` (unlike a content
    /// manifest) has no signed `size` per entry to bound a download with, so the
    /// bound is a constant: a statically linked agent with onnxruntime is on the
    /// order of 100MB, and this leaves headroom without accepting an unbounded
    /// allocation from a response.
    const MAX_RELEASE_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

    /// The service unit `packaging/linux/systemd` installs; restarting it starts
    /// the watchdog from the freshly promoted `current`.
    const SERVICE_UNIT: &str = "synthaea-agent";

    /// Name of the ban list directly under the layout's base directory.
    const BAN_LIST: &str = "banned_versions.json";

    /// What [`apply_release`] did.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Outcome {
        /// The server offered nothing newer than what is installed.
        UpToDate { offered: u64, current: u64 },
        /// `release_version` is staged and `current` now points at it.
        Promoted {
            release_version: u64,
            /// Artifacts fetched this run (`0` when a complete staged copy was
            /// already on disk from an earlier, interrupted run).
            downloaded: usize,
        },
    }

    /// Fetches, verifies, stages and promotes the release the server offers.
    ///
    /// # Errors
    ///
    /// Fails, leaving `current` untouched, if the layout is not a packaged
    /// install, the manifest's signature/schema/paths are invalid, the release
    /// is banned, a download fails or does not hash to the signed value, or the
    /// staged tree does not re-verify. A failure after the swap is not
    /// possible: `promote` is the last step.
    pub(super) fn apply_release(
        client: &transport::TransportClient,
        layout: &Layout,
    ) -> anyhow::Result<Outcome> {
        anyhow::ensure!(
            layout.bootstrap_dir().is_dir(),
            "{} does not exist: not a packaged install (ADR-0015 Decision 7)",
            layout.bootstrap_dir().display()
        );
        std::fs::create_dir_all(layout.versions_dir())?;

        let manifest: ReleaseManifest = client.get_json(&client.config().release_manifest_url())?;
        manifest.verify_signature()?;
        manifest.validate_entry_paths()?;

        BannedVersions::load(&ban_list_path(layout))?.check(manifest.release_version)?;
        match manifest.check_release_version(layout.current_release_version()) {
            Ok(()) => {}
            Err(UpdaterError::ReleaseNotNewer { offered, current }) => {
                return Ok(Outcome::UpToDate { offered, current });
            }
            Err(e) => return Err(e.into()),
        }

        let release_dir = layout.version_dir(manifest.release_version);
        let downloaded = if release_dir.is_dir() {
            // Complete by construction: a release directory only ever appears by
            // renaming a fully staged one into place.
            0
        } else {
            stage(client, layout, &manifest)?;
            manifest.entries.len()
        };

        if let Err(e) = layout.verify_staged(&manifest) {
            if downloaded > 0 {
                let _ = std::fs::remove_dir_all(&release_dir);
            }
            return Err(e.into());
        }
        layout.persist_manifest(&manifest)?;
        layout.promote(manifest.release_version)?;
        Ok(Outcome::Promoted {
            release_version: manifest.release_version,
            downloaded,
        })
    }

    fn ban_list_path(layout: &Layout) -> PathBuf {
        layout
            .versions_dir()
            .parent()
            .map_or_else(|| PathBuf::from(BAN_LIST), |base| base.join(BAN_LIST))
    }

    /// Downloads every entry into `versions/.stage-N`, then renames it to
    /// `versions/vN` in one step, so a crash mid-download never leaves a
    /// half-populated release directory that could later be picked as a rollback
    /// target. Any failure (network, hash, write) removes the staging directory
    /// before returning, so a server that keeps failing on one version cannot
    /// leave up to a release's worth of bytes per attempt lying around (PR #534
    /// review).
    fn stage(
        client: &transport::TransportClient,
        layout: &Layout,
        manifest: &ReleaseManifest,
    ) -> anyhow::Result<()> {
        let stage_dir = layout
            .versions_dir()
            .join(format!(".stage-{}", manifest.release_version));
        remove_leftover(&stage_dir)?;

        let staged = fetch_into(client, layout, manifest, &stage_dir).and_then(|()| {
            std::fs::rename(&stage_dir, layout.version_dir(manifest.release_version))
                .map_err(Into::into)
        });
        if staged.is_err() {
            // Best effort: the original error is the one worth reporting.
            let _ = std::fs::remove_dir_all(&stage_dir);
        }
        staged
    }

    /// Fetches, hash-checks and writes every manifest entry under `stage_dir`.
    fn fetch_into(
        client: &transport::TransportClient,
        layout: &Layout,
        manifest: &ReleaseManifest,
        stage_dir: &Path,
    ) -> anyhow::Result<()> {
        let versions_dir = layout.versions_dir();
        let release_version = manifest.release_version.to_string();
        for (path, expected) in &manifest.entries {
            let path_str = path.to_string_lossy();
            let bytes = client.get_bytes(
                &client.config().release_artifact_url(),
                &[
                    ("release_version", release_version.as_str()),
                    ("path", path_str.as_ref()),
                    ("sha256", expected.as_str()),
                ],
                MAX_RELEASE_ARTIFACT_BYTES,
            )?;
            let actual = hash_bytes(&bytes);
            if &actual != expected {
                return Err(UpdaterError::StagedFileMismatch {
                    path: path.clone(),
                    expected: expected.clone(),
                    actual,
                }
                .into());
            }
            let mut dest = stage_dir.to_path_buf();
            for segment in path_str.split('/') {
                dest.push(segment);
            }
            write_executable_atomically(&versions_dir, &dest, &bytes)?;
        }
        Ok(())
    }

    /// Removes a staging directory left by an interrupted run. A symlink at that
    /// name is removed as a link, never followed.
    fn remove_leftover(stage_dir: &Path) -> std::io::Result<()> {
        match std::fs::symlink_metadata(stage_dir) {
            Ok(meta) if meta.file_type().is_symlink() || meta.is_file() => {
                std::fs::remove_file(stage_dir)
            }
            Ok(_) => std::fs::remove_dir_all(stage_dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Subcommand `apply-release`: fetch, stage and promote the offered release,
    /// then restart the service onto it (unless `restart` is false).
    ///
    /// # Errors
    ///
    /// As [`apply_release`]; a failed restart is reported but is not an error —
    /// the release is promoted either way and starts at the next service start.
    pub(crate) fn cmd_apply_release(
        server: &str,
        cert: Option<&Path>,
        key: Option<&Path>,
        base_dir: &Path,
        restart: bool,
    ) -> anyhow::Result<()> {
        let mut config = transport::TransportConfig::new(server);
        if let (Some(cert), Some(key)) = (cert, key) {
            config = config.with_client_cert(PathBuf::from(cert), PathBuf::from(key));
        }
        let client = transport::TransportClient::new(config)?;
        let layout = Layout::new(base_dir);

        match apply_release(&client, &layout)? {
            Outcome::UpToDate { offered, current } => {
                println!("up to date (release {current}, server offers {offered})");
            }
            Outcome::Promoted {
                release_version,
                downloaded,
            } => {
                println!(
                    "promoted release {release_version} ({downloaded} artifact{} fetched)",
                    if downloaded == 1 { "" } else { "s" }
                );
                if restart {
                    restart_service();
                } else {
                    println!("not restarting (--no-restart): it starts at the next service start");
                }
            }
        }
        Ok(())
    }

    /// Asks systemd to restart the service so the watchdog starts from the new
    /// `current`, on probation. Best effort: a release that is promoted but not
    /// yet running is safe, so a failure here is a warning, not an error.
    fn restart_service() {
        match std::process::Command::new("systemctl")
            .args(["restart", SERVICE_UNIT])
            .status()
        {
            Ok(status) if status.success() => {
                println!("restarted {SERVICE_UNIT}; the new release is on probation");
            }
            Ok(status) => eprintln!(
                "warning: `systemctl restart {SERVICE_UNIT}` exited with {status}; the release is \
                 promoted and will run at the next service start"
            ),
            Err(e) => eprintln!(
                "warning: could not run systemctl ({e}); the release is promoted and will run at \
                 the next service start"
            ),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{collections::BTreeMap, io::Read as _, os::unix::fs::PermissionsExt as _};

        use updater::key::test_key_pair;

        use super::*;

        fn tmp(name: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("release-test-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// A packaged install: `bootstrap/` with `current -> bootstrap`, and any
        /// already-installed releases, the last of which is promoted.
        fn install(name: &str, installed: &[u64]) -> (PathBuf, Layout) {
            let base = tmp(name);
            let layout = Layout::new(&base);
            std::fs::create_dir_all(layout.bootstrap_dir()).unwrap();
            std::fs::create_dir_all(layout.versions_dir()).unwrap();
            std::os::unix::fs::symlink(layout.bootstrap_dir(), layout.current_link()).unwrap();
            for &v in installed {
                std::fs::create_dir_all(layout.version_dir(v)).unwrap();
                layout.promote(v).unwrap();
            }
            (base, layout)
        }

        fn signed(release_version: u64, files: &[(&str, &[u8])]) -> ReleaseManifest {
            let entries: BTreeMap<PathBuf, String> = files
                .iter()
                .map(|(path, bytes)| (PathBuf::from(path), hash_bytes(bytes)))
                .collect();
            let mut manifest = ReleaseManifest::new(release_version, entries);
            manifest.sign(&test_key_pair());
            manifest
        }

        /// Serves the manifest at `/api/release/manifest` and each `(path, body)`
        /// at `/api/release/artifact?...path=<path>...`, recording every request
        /// line, until the test drops the returned handle's listener thread.
        struct Server {
            url: String,
            requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        }

        fn serve(manifest: &ReleaseManifest, artifacts: Vec<(&str, Vec<u8>)>) -> Server {
            let manifest_json = serde_json::to_vec(manifest).unwrap();
            let artifacts: Vec<(String, Vec<u8>)> = artifacts
                .into_iter()
                .map(|(p, b)| (p.to_string(), b))
                .collect();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let log = requests.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let mut buf = [0_u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();
                    let line = request.lines().next().unwrap_or("").to_string();
                    log.lock().unwrap().push(line.clone());
                    let (status, body) = if line.contains("/api/release/manifest") {
                        (200, manifest_json.clone())
                    } else if let Some((_, body)) = artifacts
                        .iter()
                        .find(|(p, _)| line.contains(&format!("path={p}")))
                    {
                        (200, body.clone())
                    } else {
                        (404, b"not found".to_vec())
                    };
                    respond(&mut stream, status, &body);
                }
            });
            Server { url, requests }
        }

        fn respond(stream: &mut std::net::TcpStream, status: u16, body: &[u8]) {
            use std::io::Write as _;
            let reason = if status == 200 { "OK" } else { "NOPE" };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
        }

        fn client(url: &str) -> transport::TransportClient {
            transport::TransportClient::new(transport::TransportConfig::new(url)).unwrap()
        }

        #[test]
        fn a_newer_signed_release_is_staged_verified_and_promoted() {
            let (_base, layout) = install("happy", &[1]);
            let files: [(&str, &[u8]); 2] = [("agent", b"agent v2"), ("watchdog", b"watchdog v2")];
            let manifest = signed(2, &files);
            let server = serve(
                &manifest,
                files.iter().map(|(p, b)| (*p, b.to_vec())).collect(),
            );

            let outcome = apply_release(&client(&server.url), &layout).unwrap();

            assert_eq!(
                outcome,
                Outcome::Promoted {
                    release_version: 2,
                    downloaded: 2
                }
            );
            assert_eq!(layout.current_release_version(), Some(2));
            let agent = layout.version_dir(2).join("agent");
            assert_eq!(std::fs::read(&agent).unwrap(), b"agent v2");
            assert_eq!(
                std::fs::metadata(&agent).unwrap().permissions().mode() & 0o777,
                0o755,
                "release binaries must be executable"
            );
            assert_eq!(layout.read_manifest(2).unwrap(), manifest);
            assert!(
                !layout.versions_dir().join(".stage-2").exists(),
                "the staging directory is renamed away"
            );
        }

        #[test]
        fn a_tampered_artifact_is_never_promoted_and_leaves_nothing_behind() {
            let (_base, layout) = install("tampered", &[1]);
            let manifest = signed(2, &[("agent", b"the real agent")]);
            let server = serve(&manifest, vec![("agent", b"a swapped agent".to_vec())]);

            let err = apply_release(&client(&server.url), &layout).unwrap_err();

            assert!(
                matches!(
                    err.downcast_ref::<UpdaterError>(),
                    Some(UpdaterError::StagedFileMismatch { .. })
                ),
                "{err:#}"
            );
            assert_eq!(layout.current_release_version(), Some(1));
            assert!(!layout.version_dir(2).exists());
            assert!(!layout.versions_dir().join(".stage-2").exists());
        }

        #[test]
        fn a_download_that_fails_midway_leaves_no_staging_directory_behind() {
            let (_base, layout) = install("fail-midway", &[1]);
            let files: [(&str, &[u8]); 2] = [("agent", b"agent v2"), ("watchdog", b"watchdog v2")];
            let manifest = signed(2, &files);
            // `agent` downloads fine and is written; `watchdog` is a 404, so the
            // run fails after part of the release is already on disk.
            let server = serve(&manifest, vec![("agent", b"agent v2".to_vec())]);

            assert!(apply_release(&client(&server.url), &layout).is_err());
            assert_eq!(layout.current_release_version(), Some(1));
            assert!(!layout.version_dir(2).exists());
            assert!(
                !layout.versions_dir().join(".stage-2").exists(),
                "the partially written staging directory must be removed"
            );
        }

        #[test]
        fn a_manifest_with_a_bad_signature_is_rejected_before_any_download() {
            let (_base, layout) = install("badsig", &[1]);
            let mut manifest = signed(2, &[("agent", b"x")]);
            manifest
                .entries
                .insert(PathBuf::from("injected"), "b".repeat(64));
            let server = serve(&manifest, vec![]);

            let err = apply_release(&client(&server.url), &layout).unwrap_err();

            assert!(
                matches!(
                    err.downcast_ref::<UpdaterError>(),
                    Some(UpdaterError::SignatureInvalid)
                ),
                "{err:#}"
            );
            let requests = server.requests.lock().unwrap();
            assert!(
                requests.iter().all(|r| !r.contains("/artifact")),
                "no artifact may be requested for an unverified manifest: {requests:?}"
            );
        }

        #[test]
        fn a_signed_manifest_with_an_escaping_path_is_rejected_before_any_download() {
            let (_base, layout) = install("escape", &[1]);
            let manifest = signed(2, &[("../../etc/cron.d/x", b"x")]);
            let server = serve(&manifest, vec![]);

            let err = apply_release(&client(&server.url), &layout).unwrap_err();

            assert!(
                matches!(
                    err.downcast_ref::<UpdaterError>(),
                    Some(UpdaterError::UnsafeReleasePath(_))
                ),
                "{err:#}"
            );
            assert!(
                server
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|r| !r.contains("/artifact"))
            );
        }

        #[test]
        fn an_offer_that_is_not_newer_changes_nothing() {
            let (_base, layout) = install("not-newer", &[3]);
            let manifest = signed(3, &[("agent", b"x")]);
            let server = serve(&manifest, vec![("agent", b"x".to_vec())]);

            let outcome = apply_release(&client(&server.url), &layout).unwrap();

            assert_eq!(
                outcome,
                Outcome::UpToDate {
                    offered: 3,
                    current: 3
                }
            );
            assert_eq!(layout.current_release_version(), Some(3));
        }

        #[test]
        fn a_banned_release_is_refused_even_though_it_is_newer() {
            let (base, layout) = install("banned", &[1]);
            let mut bans = BannedVersions::default();
            bans.ban(2);
            bans.save(&base.join(BAN_LIST)).unwrap();
            let manifest = signed(2, &[("agent", b"x")]);
            let server = serve(&manifest, vec![("agent", b"x".to_vec())]);

            let err = apply_release(&client(&server.url), &layout).unwrap_err();

            assert!(
                matches!(
                    err.downcast_ref::<UpdaterError>(),
                    Some(UpdaterError::ReleaseBanned(2))
                ),
                "{err:#}"
            );
            assert_eq!(layout.current_release_version(), Some(1));
        }

        #[test]
        fn a_complete_staged_release_from_an_interrupted_run_is_reused_without_downloading() {
            let (_base, layout) = install("resume", &[1]);
            let files: [(&str, &[u8]); 1] = [("agent", b"agent v2")];
            let manifest = signed(2, &files);
            // The previous run got as far as the rename, then died before promote.
            std::fs::create_dir_all(layout.version_dir(2)).unwrap();
            std::fs::write(layout.version_dir(2).join("agent"), b"agent v2").unwrap();
            let server = serve(&manifest, vec![]);

            let outcome = apply_release(&client(&server.url), &layout).unwrap();

            assert_eq!(
                outcome,
                Outcome::Promoted {
                    release_version: 2,
                    downloaded: 0
                }
            );
            assert_eq!(layout.current_release_version(), Some(2));
            assert!(
                server
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|r| !r.contains("/artifact"))
            );
        }

        #[test]
        fn a_staged_release_that_no_longer_matches_its_manifest_is_refused_and_kept_for_inspection()
        {
            let (_base, layout) = install("resume-corrupt", &[1]);
            let manifest = signed(2, &[("agent", b"agent v2")]);
            std::fs::create_dir_all(layout.version_dir(2)).unwrap();
            std::fs::write(layout.version_dir(2).join("agent"), b"tampered on disk").unwrap();
            let server = serve(&manifest, vec![]);

            let err = apply_release(&client(&server.url), &layout).unwrap_err();

            assert!(
                matches!(
                    err.downcast_ref::<UpdaterError>(),
                    Some(UpdaterError::StagedFileMismatch { .. })
                ),
                "{err:#}"
            );
            assert_eq!(layout.current_release_version(), Some(1));
            assert!(
                layout.version_dir(2).exists(),
                "a directory this run did not create is not deleted"
            );
        }

        #[test]
        fn a_leftover_staging_directory_from_a_crashed_run_is_replaced() {
            let (_base, layout) = install("leftover", &[1]);
            let stale = layout.versions_dir().join(".stage-2");
            std::fs::create_dir_all(&stale).unwrap();
            std::fs::write(stale.join("agent"), b"half written").unwrap();
            let files: [(&str, &[u8]); 1] = [("agent", b"agent v2")];
            let manifest = signed(2, &files);
            let server = serve(&manifest, vec![("agent", b"agent v2".to_vec())]);

            apply_release(&client(&server.url), &layout).unwrap();

            assert_eq!(
                std::fs::read(layout.version_dir(2).join("agent")).unwrap(),
                b"agent v2"
            );
        }

        #[test]
        fn a_tree_that_is_not_a_packaged_install_is_refused() {
            let base = tmp("no-bootstrap");
            let layout = Layout::new(&base);
            let manifest = signed(1, &[("agent", b"x")]);
            let server = serve(&manifest, vec![]);

            let err = apply_release(&client(&server.url), &layout).unwrap_err();

            assert!(
                err.to_string().contains("not a packaged install"),
                "{err:#}"
            );
        }
    }
}
