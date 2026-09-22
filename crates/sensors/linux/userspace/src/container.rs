//! Container attribution: cgroup id → container id (cgroupfs walk, bounded
//! LRU cache) and container id → image/name (background Docker socket lookup,
//! shared cache). Everything here serves [`container_context`]; the drain loop
//! calls it per event. Split out of `sensor.rs` when that file had accumulated
//! five concerns.

use std::{
    collections::{HashMap, VecDeque},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex},
};

use schema::ContainerContext;

use crate::docker::DockerContainerInfo;

/// Extracts a container id from one `/proc/<pid>/cgroup` line's path (the part after
/// the last `:` — format is `hierarchy-id:controller-list:path`, and cgroup v2's
/// single-hierarchy line has an empty controller list, `0::/path`). Recognizes the
/// two layouts actually seen on this binding's targets:
///
/// - cgroup v1 / cgroupfs naming: a path segment that is exactly the 64 hex-char id
///   (`/docker/<id>`, `/docker/<id>/init`).
/// - cgroup v2 / systemd unit naming: `docker-<id>.scope` or `cri-containerd-<id>.scope`
///   (containerd without Docker in front — still relevant since #80 mentions the
///   containerd socket alongside Docker's).
///
/// Kubernetes' `kubepods` slice nesting is deliberately not special-cased (pod/
/// namespace context is out of scope for issue #80) — the container-id segment inside
/// it matches the same two patterns regardless of what wraps it.
fn extract_container_id(cgroup_path: &str) -> Option<String> {
    fn is_hex_id(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    cgroup_path.split('/').find_map(|segment| {
        let candidate = segment
            .strip_suffix(".scope")
            .and_then(|s| {
                s.strip_prefix("docker-")
                    .or_else(|| s.strip_prefix("cri-containerd-"))
            })
            .unwrap_or(segment);
        is_hex_id(candidate).then(|| candidate.to_string())
    })
}

/// Finds the container id owning cgroup id `cgroup_id` — the value
/// `bpf_get_current_cgroup_id()` captured kernel-side, at the moment the probe fired
/// (see `sensor_linux_wire::EventMeta::cgroup_id`) — by walking `cgroupfs_root` for
/// the directory whose inode matches, then extracting the id from that directory's
/// own path via [`extract_container_id`].
///
/// This is what actually closes issue #204's race. The approach it replaced read
/// `/proc/<pid>/cgroup` at drain time, which requires the *pid* to still exist —
/// reliably lost for a process whose entire lifetime is one syscall (e.g. a bare
/// `cat <path>`, confirmed against a real Docker daemon: `/proc/<pid>/cgroup` was
/// already gone on the very first attempt, every time). A container's own
/// directory under cgroupfs persists for the container's entire lifetime,
/// independent of any individual short-lived process inside it, so keying
/// attribution off the cgroup id — captured while the process was still executing
/// the syscall, not resolved lazily afterward — has nothing left to race against.
///
/// Split from [`CgroupIdCache::resolve`] so tests can point it at a fake directory
/// tree instead of the real `/sys/fs/cgroup`.
///
/// Assumes the cgroup v2 unified hierarchy: `bpf_get_current_cgroup_id()` always
/// reads the v2 `dfl_cgrp`, regardless of whether v1 controllers are also mounted,
/// and the labs this binding targets (Alpine/Debian/Arch, recent kernels) all
/// default to it. A host running cgroup v1 only would not find a match here — not
/// addressed, the same "known limitation, not this issue's scope" posture the rest
/// of this module's container attribution already has.
fn container_id_from_cgroupfs(cgroupfs_root: &Path, cgroup_id: u64) -> Option<String> {
    /// Cgroup trees are shallow in practice (a handful of slice/scope levels); this
    /// just bounds the recursion rather than expecting to ever hit it.
    const MAX_WALK_DEPTH: u8 = 12;

    fn walk(dir: &Path, cgroup_id: u64, depth: u8) -> Option<String> {
        if depth > MAX_WALK_DEPTH {
            return None;
        }
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_dir() {
                continue;
            }
            let path = entry.path();
            if metadata.ino() == cgroup_id {
                return extract_container_id(&path.to_string_lossy());
            }
            if let Some(id) = walk(&path, cgroup_id, depth + 1) {
                return Some(id);
            }
        }
        None
    }

    walk(cgroupfs_root, cgroup_id, 0)
}

/// The real cgroupfs mount this binding targets.
const CGROUPFS_ROOT: &str = "/sys/fs/cgroup";

/// Bounded cache over [`container_id_from_cgroupfs`], keyed by cgroup id rather
/// than pid — see that function's doc for why this is what closes issue #204's
/// race.
///
/// No retry logic, unlike the pid-keyed cache this replaces: a cgroup id captured
/// kernel-side at syscall time is already the process's real cgroup membership at
/// that exact instant, not a value that needs time to "settle" the way a later
/// `/proc` read did — there is nothing here to retry.
pub(crate) struct CgroupIdCache {
    entries: HashMap<u64, Option<String>>,
    order: VecDeque<u64>,
}

/// Arbitrary but generous, same rationale as the pid-keyed cache this replaces:
/// bound growth rather than let it grow forever. The number of *containers* a host
/// runs over its uptime is normally far smaller than the number of *pids* the old
/// cache had to bound, so this is not expected to ever actually fill up.
const CGROUP_ID_CACHE_CAP: usize = 4096;

impl CgroupIdCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn resolve(&mut self, cgroup_id: u64) -> Option<String> {
        // 0 is never a real container's cgroup id (the eBPF side falls back to it
        // when the helper is unavailable) — skip the walk rather than pay a full
        // cgroupfs scan just to cache a `None` for it.
        if cgroup_id == 0 {
            return None;
        }
        self.resolve_with(cgroup_id, |id| {
            container_id_from_cgroupfs(Path::new(CGROUPFS_ROOT), id)
        })
    }

    /// `resolve`'s actual logic, parameterized over the fetch so tests can inject a
    /// call-counting stub instead of walking a real cgroupfs.
    fn resolve_with(
        &mut self,
        cgroup_id: u64,
        fetch: impl Fn(u64) -> Option<String>,
    ) -> Option<String> {
        if let Some(cached) = self.entries.get(&cgroup_id) {
            return cached.clone();
        }

        let id = fetch(cgroup_id);
        self.entries.insert(cgroup_id, id.clone());
        self.order.push_back(cgroup_id);
        if self.order.len() > CGROUP_ID_CACHE_CAP
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        id
    }
}

/// One entry in [`DockerInfoCache`]: either a lookup is already running for this
/// container id (don't start a second one), or it finished with whatever it found
/// (`DockerContainerInfo`'s fields are already `Option` for "asked, got nothing").
pub(crate) enum DockerLookupState {
    Pending,
    Done(DockerContainerInfo),
}

/// Cache of Docker daemon socket lookups, keyed by container id, shared between the
/// event-processing loop and the background tasks it spawns to do the actual
/// lookups.
///
/// Unlike [`CgroupIdCache`] (per cgroup id, cheap, synchronous), resolving a
/// container id to its image/name needs a round trip to another daemon over
/// `/var/run/docker.sock` ([`crate::docker::lookup`]) — too slow to do inline on
/// the same task that drains ring buffers, so a first sighting of a container id
/// spawns a background task and the event that triggered it goes out with just the
/// id (image/name filled in once the lookup completes, for every event after
/// that).
///
/// Not bounded like `CgroupIdCache`: the number of *containers* a host runs over
/// its uptime is normally far smaller than the number of *pids* `CgroupIdCache`'s
/// predecessor had to bound, so unbounded growth here is a much smaller concern —
/// revisit if a host doing heavy container churn (a CI runner, say) ever makes
/// this show up in profiling, same as the pid-keyed cache was itself once a
/// deferred concern (issue #199).
pub(crate) type DockerInfoCache = Arc<Mutex<HashMap<String, DockerLookupState>>>;

/// Resolves `cgroup_id`'s full [`ContainerContext`] (id, plus image/name if the
/// Docker socket lookup for that id has completed): the id comes from
/// `container_ids` (cheap, synchronous, cached per cgroup id); on the id's first
/// sighting this spawns a background lookup into `docker_cache` and returns the id
/// alone for now — image/name catch up on the *next* event for the same
/// container, not this one.
pub(crate) fn container_context(
    cgroup_id: u64,
    container_ids: &mut CgroupIdCache,
    docker_cache: &DockerInfoCache,
) -> Option<ContainerContext> {
    let id = container_ids.resolve(cgroup_id)?;

    let info = {
        let mut cache = docker_cache.lock().unwrap();
        match cache.get(&id) {
            Some(DockerLookupState::Done(info)) => Some(info.clone()),
            Some(DockerLookupState::Pending) => None,
            None => {
                cache.insert(id.clone(), DockerLookupState::Pending);
                let cache = Arc::clone(docker_cache);
                let lookup_id = id.clone();
                tokio::task::spawn(async move {
                    let info = crate::docker::lookup(&lookup_id).await.unwrap_or_default();
                    cache
                        .lock()
                        .unwrap()
                        .insert(lookup_id, DockerLookupState::Done(info));
                });
                None
            }
        }
    };

    Some(ContainerContext {
        id,
        image: info.as_ref().and_then(|i| i.image.clone()),
        name: info.as_ref().and_then(|i| i.name.clone()),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::HashMap,
        os::unix::fs::MetadataExt,
        path::Path,
        sync::{Arc, Mutex},
    };

    use super::{
        CGROUP_ID_CACHE_CAP, CgroupIdCache, DockerInfoCache, DockerLookupState, container_context,
        container_id_from_cgroupfs, extract_container_id,
    };
    use crate::docker::DockerContainerInfo;

    const DOCKER_ID: &str = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456";

    #[test]
    fn cgroup_v1_docker_path() {
        assert_eq!(
            extract_container_id(&format!("/docker/{DOCKER_ID}")),
            Some(DOCKER_ID.to_string())
        );
        // A sub-cgroup under the container (e.g. `/docker/<id>/init`) still matches.
        assert_eq!(
            extract_container_id(&format!("/docker/{DOCKER_ID}/init")),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_v2_systemd_docker_scope() {
        assert_eq!(
            extract_container_id(&format!("/system.slice/docker-{DOCKER_ID}.scope")),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_v2_containerd_without_docker() {
        assert_eq!(
            extract_container_id(&format!("/system.slice/cri-containerd-{DOCKER_ID}.scope")),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_kubepods_nesting_still_matches() {
        // Pod/namespace context is out of scope (#80); the id inside the nesting is not.
        assert_eq!(
            extract_container_id(&format!(
                "/kubepods.slice/kubepods-burstable.slice/cri-containerd-{DOCKER_ID}.scope"
            )),
            Some(DOCKER_ID.to_string())
        );
    }

    #[test]
    fn cgroup_bare_metal_process_has_no_container() {
        assert_eq!(extract_container_id("/user.slice/user-1000.slice"), None);
        assert_eq!(extract_container_id("/init.scope"), None);
        assert_eq!(extract_container_id("/system.slice/sshd.service"), None);
    }

    #[test]
    fn cgroup_id_wrong_length_does_not_match() {
        // 63 hex chars — one short of a real id, must not false-positive.
        assert_eq!(extract_container_id("/docker/abc123"), None);
    }

    /// Builds `root/a/b/.../<id>` (one subdir per path segment) and returns the
    /// leaf's inode, so tests can drive [`container_id_from_cgroupfs`] against a
    /// fake cgroupfs tree instead of the real `/sys/fs/cgroup`. Callers clean up
    /// `root` themselves.
    fn make_cgroup_dir(root: &Path, relative_path: &str) -> u64 {
        let dir = root.join(relative_path.trim_start_matches('/'));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::metadata(&dir).unwrap().ino()
    }

    fn temp_cgroupfs_root(test_name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sensor-linux-cgroupfs-test-{test_name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn cgroupfs_walk_finds_a_matching_docker_scope_by_inode() {
        let root = temp_cgroupfs_root("finds-match");
        let target_ino = make_cgroup_dir(&root, &format!("system.slice/docker-{DOCKER_ID}.scope"));
        // A sibling directory the walk must not mistake for the target.
        make_cgroup_dir(&root, "system.slice/sshd.service");

        assert_eq!(
            container_id_from_cgroupfs(&root, target_ino),
            Some(DOCKER_ID.to_string())
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cgroupfs_walk_no_match_is_none() {
        let root = temp_cgroupfs_root("no-match");
        make_cgroup_dir(&root, "user.slice/user-1000.slice");

        // An inode that exists nowhere under `root`.
        assert_eq!(container_id_from_cgroupfs(&root, u64::MAX), None);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cgroup_id_cache_fetches_once_per_cgroup_id() {
        // Same reasoning as the pid-keyed cache this replaces (#199): resolving the
        // same cgroup id twice should not re-walk cgroupfs a second time.
        let mut cache = CgroupIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |_id: u64| {
            calls.set(calls.get() + 1);
            Some("abc".to_string())
        };

        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(cache.resolve_with(42, fetch), Some("abc".to_string()));
        assert_eq!(
            calls.get(),
            1,
            "second/third resolve of the same cgroup id must hit the cache, not fetch again"
        );
    }

    #[test]
    fn cgroup_id_cache_none_result_is_cached_too() {
        // A bare-metal process (no container) resolves to `None` — that negative
        // result must be cached too, same "no re-fetch" reasoning as a `Some`.
        // Unlike the pid-keyed cache this replaces, there is no retry window here:
        // a cgroup id captured at syscall time is already settled, so the very
        // first `None` is trusted immediately.
        let mut cache = CgroupIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |_id: u64| {
            calls.set(calls.get() + 1);
            None
        };

        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(cache.resolve_with(7, fetch), None);
        assert_eq!(
            calls.get(),
            1,
            "a None result must be cached on the very first fetch"
        );
    }

    #[test]
    fn cgroup_id_cache_distinct_ids_each_fetch_once() {
        let mut cache = CgroupIdCache::new();
        let calls = Cell::new(0u32);
        let fetch = |id: u64| {
            calls.set(calls.get() + 1);
            Some(format!("container-{id}"))
        };

        assert_eq!(
            cache.resolve_with(1, fetch),
            Some("container-1".to_string())
        );
        assert_eq!(
            cache.resolve_with(2, fetch),
            Some("container-2".to_string())
        );
        assert_eq!(
            cache.resolve_with(1, fetch),
            Some("container-1".to_string())
        );
        assert_eq!(
            calls.get(),
            2,
            "one fetch per distinct cgroup id, regardless of resolve order"
        );
    }

    #[test]
    fn cgroup_id_cache_evicts_oldest_once_over_capacity() {
        let mut cache = CgroupIdCache::new();
        let fetch = |id: u64| Some(format!("c{id}"));

        for id in 0..CGROUP_ID_CACHE_CAP as u64 {
            cache.resolve_with(id, fetch);
        }
        assert_eq!(cache.entries.len(), CGROUP_ID_CACHE_CAP);

        // One more id pushes the cache over capacity: the oldest (id 0) must be
        // evicted so the cache stays bounded rather than growing forever.
        cache.resolve_with(CGROUP_ID_CACHE_CAP as u64, fetch);
        assert_eq!(cache.entries.len(), CGROUP_ID_CACHE_CAP);
        assert!(
            !cache.entries.contains_key(&0),
            "oldest entry should have been evicted"
        );

        // Evicting id 0 means it is no longer cached — re-resolving it must fetch
        // again (proves eviction removed it from `entries`, not just `order`).
        let refetch_calls = Cell::new(0u32);
        let counting_fetch = |_id: u64| {
            refetch_calls.set(refetch_calls.get() + 1);
            Some("c0-again".to_string())
        };
        cache.resolve_with(0, counting_fetch);
        assert_eq!(refetch_calls.get(), 1);
    }

    #[test]
    fn cgroup_id_zero_never_walks_cgroupfs() {
        // 0 is the eBPF side's fallback when the helper is unavailable, never a
        // real cgroup's id — must short-circuit to `None` without even calling
        // `resolve_with`'s fetch.
        let mut cache = CgroupIdCache::new();
        assert_eq!(cache.resolve(0), None);
        assert!(
            !cache.entries.contains_key(&0),
            "id 0 must not even be cached"
        );
    }

    fn empty_docker_cache() -> DockerInfoCache {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn container_context_none_when_cgroup_id_has_no_container() {
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, None); // pre-seeded: resolved, no container
        let docker_cache = empty_docker_cache();

        assert_eq!(container_context(7, &mut ids, &docker_cache), None);
    }

    #[tokio::test]
    async fn container_context_returns_id_only_while_docker_lookup_pending() {
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, Some("abc123".to_string()));
        let docker_cache = empty_docker_cache();

        let ctx = container_context(7, &mut ids, &docker_cache).expect("has a container id");
        assert_eq!(ctx.id, "abc123");
        assert_eq!(ctx.image, None, "lookup was just spawned, not resolved yet");
        assert_eq!(ctx.name, None);

        // A second call for the same id, before the background lookup has had any
        // chance to run (no `.await` in between), must not spawn a second one —
        // observable as the cache entry staying a single `Pending`, not two
        // overlapping tasks racing to write their result.
        let ctx2 = container_context(7, &mut ids, &docker_cache).expect("still has a container id");
        assert_eq!(ctx2.image, None);
        assert!(matches!(
            docker_cache.lock().unwrap().get("abc123"),
            Some(DockerLookupState::Pending)
        ));
    }

    #[tokio::test]
    async fn container_context_uses_resolved_docker_info() {
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, Some("abc123".to_string()));
        let docker_cache = empty_docker_cache();
        docker_cache.lock().unwrap().insert(
            "abc123".to_string(),
            DockerLookupState::Done(DockerContainerInfo {
                image: Some("nginx:1.27".to_string()),
                name: Some("web1".to_string()),
            }),
        );

        let ctx = container_context(7, &mut ids, &docker_cache).expect("has a container id");
        assert_eq!(ctx.image.as_deref(), Some("nginx:1.27"));
        assert_eq!(ctx.name.as_deref(), Some("web1"));
    }

    #[tokio::test]
    async fn container_context_survives_a_failed_lookup() {
        // `Done(default)` — the shape a failed/negative lookup leaves behind — must
        // still produce a valid `ContainerContext` with just the id, not panic or
        // re-spawn a lookup forever.
        let mut ids = CgroupIdCache::new();
        ids.entries.insert(7, Some("abc123".to_string()));
        let docker_cache = empty_docker_cache();
        docker_cache.lock().unwrap().insert(
            "abc123".to_string(),
            DockerLookupState::Done(DockerContainerInfo::default()),
        );

        let ctx = container_context(7, &mut ids, &docker_cache).expect("has a container id");
        assert_eq!(ctx.id, "abc123");
        assert_eq!(ctx.image, None);
        assert_eq!(ctx.name, None);
    }
}
