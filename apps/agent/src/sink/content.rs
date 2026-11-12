//! Loading the agent's content (Sigma and YARA rules, the IOC feeds, the fleet's common-set
//! snapshot) from `<content_root>/`, at startup and on [`DetectionSink::reload_content`].

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{DetectionSink, start_memscan, start_yara};
use crate::sync::LockExt as _;

impl DetectionSink {
    /// Re-reads the content under [`Self::content_root`] and swaps it into the running pipeline
    /// (issue #30, IPC `ReloadContent`), so content `agent apply-content-manifest` just applied
    /// takes effect without a restart. Absent unloads an engine, broken keeps the previous one
    /// (`docs/detection/README.md#content-loading-and-reload`). YARA fails the whole set on one
    /// bad rule while Sigma skips it, so a partly broken Sigma set shows only in the count.
    pub(crate) fn reload_content(&self) -> ReloadReport {
        // Load before locking: the capture thread takes these locks for every exec and write-open.
        let sigma_loaded = load_sigma_rules(&self.content_root);
        let yara_loaded = start_yara(
            &self.content_root,
            self.alert_log.clone(),
            self.response.clone(),
            self.verdict.clone(),
        );
        let memscan_loaded = start_memscan(
            &self.content_root,
            self.alert_log.clone(),
            self.verdict.clone(),
        );

        let common_set_loaded = load_common_set(&self.content_root);

        // The replaced engines are dropped after the locks are released: a
        // `ScanQueue` joins its worker on drop, which must not stall capture.
        let mut sigma_slot = self.sigma.lock_recovering();
        let (sigma_reload_failed, old_sigma) = match sigma_loaded {
            Load::Loaded(engine) => (false, sigma_slot.replace(engine)),
            Load::Absent => (false, sigma_slot.take()),
            Load::Failed => (true, None),
        };
        let sigma_rule_count = sigma_slot.as_ref().map(sigma::SigmaEngine::rule_count);
        drop(sigma_slot);
        drop(old_sigma);

        let mut yara_slot = self.yara.lock_recovering();
        let (yara_reload_failed, old_yara) = match yara_loaded {
            Load::Loaded(loaded) => (false, yara_slot.replace(loaded)),
            Load::Absent => (false, yara_slot.take()),
            Load::Failed => (true, None),
        };
        let yara_rule_count = yara_slot.as_ref().map(|(_, count)| *count);
        drop(yara_slot);
        drop(old_yara);

        self.swap_common_set(common_set_loaded);
        self.ioc.reload(&self.content_root);

        // Same rules, same posture as the file scanner: absent unloads, broken keeps
        // the previous queue (its failure is already reported through `yara`).
        let mut memscan_slot = self.memscan.lock_recovering();
        let old_memscan = match memscan_loaded {
            Load::Loaded(queue) => memscan_slot.replace(queue),
            Load::Absent => memscan_slot.take(),
            Load::Failed => None,
        };
        drop(memscan_slot);
        drop(old_memscan);

        ReloadReport {
            sigma_rule_count,
            yara_rule_count,
            sigma_reload_failed,
            yara_reload_failed,
        }
    }

    /// Same posture as the rule directories for the snapshot: absent unloads (the evidence is
    /// withheld), broken keeps the previous one (its failure is logged by the loader).
    fn swap_common_set(&self, loaded: Load<ml::features::common_set::CommonSetSnapshot>) {
        let mut slot = self.common_set.lock_recovering();
        let old = match loaded {
            Load::Loaded(snapshot) => slot.replace(Arc::new(snapshot)),
            Load::Absent => slot.take(),
            Load::Failed => None,
        };
        drop(slot);
        drop(old);
    }

    /// Re-reads only the snapshot file, after the fetch loop wrote a new one (ADR-0033): the
    /// rule directories and models are untouched, so a daily snapshot does not rebuild the
    /// detection engines.
    pub(crate) fn reload_common_set(&self) {
        self.swap_common_set(load_common_set(&self.content_root));
    }

    /// The snapshot in force. Test-only: the enrichment worker reads the shared slot directly.
    #[cfg(test)]
    pub(super) fn common_set(&self) -> Option<Arc<ml::features::common_set::CommonSetSnapshot>> {
        self.common_set.lock_recovering().clone()
    }
}

/// What [`DetectionSink::reload_content`] (and, indirectly, [`DetectionSink::new`])
/// reports about what's loaded after a (re)load.
pub(crate) struct ReloadReport {
    /// Rules loaded *after* the reload (the previous set if the reload failed).
    pub(crate) sigma_rule_count: Option<usize>,
    pub(crate) yara_rule_count: Option<usize>,
    /// The content was present but failed to load; the previous engine kept running.
    pub(crate) sigma_reload_failed: bool,
    pub(crate) yara_reload_failed: bool,
}

/// Outcome of loading one content directory.
pub(super) enum Load<T> {
    /// The directory does not exist — not an error.
    Absent,
    Loaded(T),
    /// The directory exists but its content did not load (already logged).
    Failed,
}

impl<T> Load<T> {
    /// Startup posture: a broken directory leaves the engine unloaded.
    pub(super) fn into_option(self) -> Option<T> {
        match self {
            Self::Loaded(value) => Some(value),
            Self::Absent | Self::Failed => None,
        }
    }
}

/// Resolves `content_dir` to an actual directory to load content from: next
/// to the agent executable first, then the current working directory, same
/// fallback order the old hardcoded `rules/sigma`/`rules/yara` convention
/// used. A cwd-relative path alone breaks under service managers (systemd
/// runs with cwd=/, Windows services in System32), which silently disabled
/// Sigma and YARA exactly in production deployments (review finding this
/// preserves). An absolute `content_dir` is used as-is — no fallback search
/// needed when the caller already gave an unambiguous path.
pub(super) fn resolve_content_root(content_dir: &Path) -> PathBuf {
    if content_dir.is_absolute() {
        return content_dir.to_path_buf();
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(content_dir);
        if candidate.is_dir() {
            return candidate;
        }
    }
    content_dir.to_path_buf()
}

/// Loads the Sigma content of the platform this agent is built for, if the content directory
/// is present under `content_root`: only `rules/sigma/<platform>/`, so a rule written for
/// another platform never runs on this host (#980).
pub(super) fn load_sigma_rules(content_root: &Path) -> Load<sigma::SigmaEngine> {
    let rules_dir = content_root.join("rules/sigma");
    if !rules_dir.is_dir() {
        return Load::Absent;
    }
    let Some(platform) = sigma::Platform::host() else {
        tracing::warn!("sigma: no rules directory for this operating system, none loaded");
        return Load::Absent;
    };
    match sigma::SigmaEngine::load_dir_for(&rules_dir, platform) {
        Ok(engine) => {
            tracing::info!(
                rules = engine.rule_count(),
                platform = platform.dir_name(),
                "sigma: rules loaded"
            );
            Load::Loaded(engine)
        }
        Err(e) => {
            tracing::error!(error = %e, "sigma: load error");
            Load::Failed
        }
    }
}

/// The largest snapshot file the agent reads. The content manifest allows an artifact of up to
/// 100 MiB; a snapshot is a Bloom filter whose size the server caps when it builds it, so
/// anything near this is a malformed or hostile file, refused before it is read.
pub(crate) const MAX_COMMON_SET_BYTES: u64 = 64 * 1024 * 1024;

/// Loads `<content_root>/snapshots/common-set.bin`, the file the signed content manifest
/// delivers (ADR-0020). Absent is "no snapshot yet", not an error; unreadable, too large or
/// not a snapshot is [`Load::Failed`] (logged with the reason, never the bytes).
pub(super) fn load_common_set(
    content_root: &Path,
) -> Load<ml::features::common_set::CommonSetSnapshot> {
    load_common_set_capped(content_root, MAX_COMMON_SET_BYTES)
}

pub(super) fn load_common_set_capped(
    content_root: &Path,
    max_bytes: u64,
) -> Load<ml::features::common_set::CommonSetSnapshot> {
    use std::io::Read as _;

    let path = content_root.join("snapshots").join("common-set.bin");
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Load::Absent,
        Err(e) => {
            tracing::error!(error = %e, "common set: cannot open the snapshot file");
            return Load::Failed;
        }
    };
    // Read at most one byte past the cap: a file that grows between a size check and the read
    // still cannot make this allocate more than the cap.
    let mut bytes = Vec::new();
    if let Err(e) = file.take(max_bytes + 1).read_to_end(&mut bytes) {
        tracing::error!(error = %e, "common set: cannot read the snapshot file");
        return Load::Failed;
    }
    if bytes.len() as u64 > max_bytes {
        tracing::error!(max_bytes, "common set: snapshot file is over the size cap");
        return Load::Failed;
    }
    match ml::features::common_set::CommonSetSnapshot::parse(&bytes) {
        Ok(snapshot) => {
            let header = snapshot.header();
            tracing::info!(
                entries = header.entry_count,
                hosts_covered = header.hosts_covered,
                min_hosts = header.min_hosts,
                built_at = header.built_at,
                "common set: snapshot loaded"
            );
            Load::Loaded(snapshot)
        }
        Err(e) => {
            tracing::error!(error = %e, "common set: not a usable snapshot");
            Load::Failed
        }
    }
}
