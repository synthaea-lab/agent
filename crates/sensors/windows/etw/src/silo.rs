//! Container attribution for process-isolated Windows containers (#371): which
//! server silo a process runs in, and which container that silo is.
//!
//! A process-isolated container shares the host kernel, so the ETW session
//! already sees every process in it; what it lacks is the attribution. Three
//! steps, each degrading to "unknown" (`container: None`) rather than failing:
//!
//! 1. **pid → `ServerSiloId`** at `ProcessStart` (`winapi::read_server_silo_id`,
//!    `ProcessMembershipInformation`: Windows 11 22H2 / Server 2025 and later;
//!    older builds answer "unsupported" and every process stays `None`). A
//!    process already gone when its start is handled takes its parent's silo
//!    ([`exec_silo`]): a child is created in its parent's silo and cannot leave
//!    it. 0 is the host.
//! 2. **silo → container id**, from the Host Compute Service on a background
//!    thread ([`run_resolver`]): each container's process list is probed until
//!    one of its processes is found in a silo ([`match_containers`]). Until that
//!    answer arrives, the id is the provisional `silo:<n>` ([`provisional_id`]),
//!    so the event still says "containerized" rather than claiming the host.
//! 3. **teardown**: a Kernel-Process server-silo create or terminate record
//!    forgets the silo's mapping ([`SiloDirectory::forget`]), since a silo id
//!    can be reused by a later container.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Mutex,
        mpsc::{Receiver, TryRecvError},
    },
};

use schema::ContainerContext;

/// Silos remembered at once. A container host runs tens of containers; the cap
/// only bounds a host that churns through far more than that.
const SILO_CAP: usize = 256;

/// Teardowns remembered so a resolver pass can tell that a silo was forgotten while it ran.
/// A pass lasts seconds (HCS calls), so far more than the forgets of one pass; if the log
/// overflowed anyway the pass discards everything it found (see [`SiloDirectory::resolved_since`]).
const FORGET_LOG_CAP: usize = 1024;

/// How long an unresolved silo waits before it asks the resolver again: a
/// container's first processes start before the Host Compute Service lists them.
const RETRY_NS: u64 = 10 * 1_000_000_000;

/// Processes probed per container before giving up on it for this pass. The
/// first one normally answers; the bound keeps a pass cheap when it does not.
const PROBES_PER_CONTAINER: usize = 4;

/// The silo a newly started process runs in: its own, read live, or else its
/// parent's (the process exited before its start was handled, or could not be
/// opened). `None` when neither is known.
#[must_use]
pub(crate) fn exec_silo(own: Option<u32>, parent: Option<u32>) -> Option<u32> {
    own.or(parent)
}

/// The id a silo carries until the Host Compute Service names its container.
#[must_use]
pub(crate) fn provisional_id(silo: u32) -> String {
    format!("silo:{silo}")
}

struct SiloEntry {
    container_id: Option<String>,
    /// When the resolver was last asked about this silo (event time).
    requested_at_ns: Option<u64>,
    last_used: u64,
}

/// silo id → the container it is, bounded at [`SILO_CAP`] with
/// least-recently-used eviction (counted).
pub(crate) struct SiloDirectory {
    entries: HashMap<u32, SiloEntry>,
    tick: u64,
    evicted: u64,
    /// Counts every [`SiloDirectory::forget`]; a resolver pass notes it when it starts.
    epoch: u64,
    /// The last forgets, `(epoch, silo)`, oldest first.
    forgotten: VecDeque<(u64, u32)>,
}

impl SiloDirectory {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            tick: 0,
            evicted: 0,
            epoch: 0,
            forgotten: VecDeque::new(),
        }
    }

    /// The container context of a process in `silo` (never 0, the host), and
    /// whether the resolver should be asked about it now.
    pub(crate) fn lookup(&mut self, silo: u32, now_ns: u64) -> (ContainerContext, bool) {
        self.tick += 1;
        let tick = self.tick;
        if !self.entries.contains_key(&silo) {
            self.make_room();
        }
        let entry = self.entries.entry(silo).or_insert(SiloEntry {
            container_id: None,
            requested_at_ns: None,
            last_used: tick,
        });
        entry.last_used = tick;
        let ask = entry.container_id.is_none()
            && entry
                .requested_at_ns
                .is_none_or(|at| now_ns.saturating_sub(at) >= RETRY_NS);
        if ask {
            entry.requested_at_ns = Some(now_ns);
        }
        let id = entry
            .container_id
            .clone()
            .unwrap_or_else(|| provisional_id(silo));
        (
            ContainerContext {
                id,
                image: None,
                name: None,
            },
            ask,
        )
    }

    /// The request for `silo` never reached the resolver (its queue was
    /// full): the next event in that silo asks again instead of waiting out
    /// [`RETRY_NS`].
    pub(crate) fn request_dropped(&mut self, silo: u32) {
        if let Some(entry) = self.entries.get_mut(&silo) {
            entry.requested_at_ns = None;
        }
    }

    /// The silos events asked about that no container names yet: the only ones
    /// a resolver pass may map.
    pub(crate) fn pending(&self) -> HashSet<u32> {
        self.entries
            .iter()
            .filter(|(_, e)| e.container_id.is_none() && e.requested_at_ns.is_some())
            .map(|(silo, _)| *silo)
            .collect()
    }

    /// The resolver named the container of `silo`. A mapping is never
    /// overwritten and a silo no event asked about is not created, so a later
    /// claimant (a Hyper-V-isolated container's guest pid that happens to name
    /// a containerized host process) cannot relabel a container's events; only
    /// [`Self::forget`], on the silo's teardown, frees it. Returns whether the
    /// mapping was taken.
    pub(crate) fn resolved(&mut self, silo: u32, container_id: String) -> bool {
        self.tick += 1;
        let tick = self.tick;
        let Some(entry) = self.entries.get_mut(&silo) else {
            return false;
        };
        if entry.container_id.is_some() {
            return false;
        }
        entry.container_id = Some(container_id);
        entry.last_used = tick;
        true
    }

    /// The silo was created or torn down: whatever it was mapped to is stale.
    pub(crate) fn forget(&mut self, silo: u32) {
        self.entries.remove(&silo);
        self.epoch += 1;
        self.forgotten.push_back((self.epoch, silo));
        if self.forgotten.len() > FORGET_LOG_CAP {
            self.forgotten.pop_front();
        }
    }

    /// The forget count now: a resolver pass reads it before it looks at the containers.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Like [`SiloDirectory::resolved`], for an answer found by a pass that started at
    /// `since` (the [`SiloDirectory::epoch`] it read first). The pass probes containers
    /// without the lock, so `silo` may have been torn down and asked about again
    /// meanwhile (a reused id); its fresh entry is unmapped too, and installing what the
    /// pass saw would name the new container after the old one until the next teardown.
    /// Returns whether it was installed. When the log no longer reaches back to `since`,
    /// nothing can be proven and the answer is dropped: the silo stays provisional and is
    /// asked again.
    pub(crate) fn resolved_since(&mut self, silo: u32, container_id: String, since: u64) -> bool {
        let log_covers_pass = self.epoch - since <= self.forgotten.len() as u64;
        let forgotten_meanwhile = self
            .forgotten
            .iter()
            .any(|&(at, forgotten)| at > since && forgotten == silo);
        if !log_covers_pass || forgotten_meanwhile {
            return false;
        }
        self.resolved(silo, container_id)
    }

    /// The container ids already mapped, which a resolver pass need not probe.
    pub(crate) fn resolved_ids(&self) -> HashSet<String> {
        self.entries
            .values()
            .filter_map(|e| e.container_id.clone())
            .collect()
    }

    /// Entries dropped by the cap since creation.
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted
    }

    fn make_room(&mut self) {
        if self.entries.len() < SILO_CAP {
            return;
        }
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(silo, _)| *silo)
        {
            self.entries.remove(&oldest);
            self.evicted += 1;
            tracing::warn!(
                evicted_total = self.evicted,
                "silo directory hit its cap: least recently used silo forgotten"
            );
        }
    }
}

/// A container the Host Compute Service lists, and the processes it reports
/// in it (pid, image name).
pub(crate) struct HcsContainer {
    pub(crate) id: String,
    pub(crate) processes: Vec<(u32, String)>,
}

/// Which silo each container runs in. `probe(pid, image)` answers the live
/// process's silo when its image matches `image`, `None` otherwise: a pid from a
/// Hyper-V-isolated container's own kernel can name an unrelated host process,
/// and the image check keeps it from claiming that process's silo. A silo two
/// containers claim is left unmapped (it stays provisional) rather than guessed.
#[must_use]
pub(crate) fn match_containers(
    containers: &[HcsContainer],
    probe: impl Fn(u32, &str) -> Option<u32>,
) -> Vec<(u32, String)> {
    let mut claims: HashMap<u32, Vec<&str>> = HashMap::new();
    for container in containers {
        let silo = container
            .processes
            .iter()
            .take(PROBES_PER_CONTAINER)
            .find_map(|(pid, image)| probe(*pid, image).filter(|&silo| silo != 0));
        if let Some(silo) = silo {
            claims.entry(silo).or_default().push(&container.id);
        }
    }
    let mut mapping: Vec<(u32, String)> = claims
        .into_iter()
        .filter_map(|(silo, ids)| match ids.as_slice() {
            [id] => Some((silo, (*id).to_string())),
            _ => {
                tracing::warn!(
                    silo,
                    containers = ids.len(),
                    "silo claimed by several containers: left unmapped"
                );
                None
            }
        })
        .collect();
    mapping.sort_unstable();
    mapping
}

/// The ids of the containers in an `HcsEnumerateComputeSystems` result (a JSON
/// array of compute systems; virtual machines and anything unparseable are left
/// out).
#[must_use]
pub(crate) fn parse_container_ids(json: &str) -> Vec<String> {
    let Ok(serde_json::Value::Array(systems)) = serde_json::from_str(json) else {
        return Vec::new();
    };
    systems
        .iter()
        .filter(|s| s.get("SystemType").and_then(serde_json::Value::as_str) == Some("Container"))
        .filter_map(|s| s.get("Id").and_then(serde_json::Value::as_str))
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect()
}

/// The processes of an `HcsGetComputeSystemProperties` `ProcessList` result
/// (pid, image name). Entries without both are left out.
#[must_use]
pub(crate) fn parse_process_list(json: &str) -> Vec<(u32, String)> {
    let Ok(properties) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(list) = properties
        .get("ProcessList")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|p| {
            let pid = p
                .get("ProcessId")?
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())?;
            let image = p.get("ImageName")?.as_str()?;
            (pid != 0 && !image.is_empty()).then(|| (pid, image.to_string()))
        })
        .collect()
}

/// Where a resolver pass gets its containers from: the Host Compute Service on
/// a real host, a fake in tests.
pub(crate) trait ContainerSource {
    /// # Errors
    ///
    /// The service cannot be reached or answered an error.
    fn container_ids(&self) -> Result<Vec<String>, String>;
    /// # Errors
    ///
    /// The container is gone or the service answered an error.
    fn processes(&self, container_id: &str) -> Result<Vec<(u32, String)>, String>;
}

/// The resolver loop: each request (a silo id an event could not name) runs one
/// pass over every container not yet mapped, so one pass answers all the silos
/// queued behind it. Exits when every sender is gone.
pub(crate) fn run_resolver(
    requests: &Receiver<u32>,
    directory: &Mutex<SiloDirectory>,
    source: &impl ContainerSource,
    probe: impl Fn(u32, &str) -> Option<u32>,
) {
    while requests.recv().is_ok() {
        // The pass runs even when the senders went away meanwhile: those
        // requests were made, and the next `recv` ends the loop.
        while !matches!(
            requests.try_recv(),
            Err(TryRecvError::Empty | TryRecvError::Disconnected)
        ) {}
        resolve_pass(directory, source, &probe);
    }
}

fn resolve_pass(
    directory: &Mutex<SiloDirectory>,
    source: &impl ContainerSource,
    probe: &impl Fn(u32, &str) -> Option<u32>,
) {
    let (known, pending, since) = {
        let directory = directory.lock().unwrap();
        (
            directory.resolved_ids(),
            directory.pending(),
            directory.epoch(),
        )
    };
    if pending.is_empty() {
        return;
    }
    let ids = match source.container_ids() {
        Ok(ids) => ids,
        Err(error) => {
            tracing::debug!(%error, "container lookup: Host Compute Service unavailable");
            return;
        }
    };
    let containers: Vec<HcsContainer> = ids
        .into_iter()
        .filter(|id| !known.contains(id))
        .filter_map(|id| match source.processes(&id) {
            Ok(processes) => Some(HcsContainer { id, processes }),
            Err(error) => {
                tracing::debug!(%error, container = %id, "container lookup: no process list");
                None
            }
        })
        .collect();
    let mapping = match_containers(&containers, probe);
    tracing::debug!(
        probed = containers.len(),
        mapped = mapping.len(),
        "container lookup pass"
    );
    // The probes ran without the lock: a silo torn down and asked about again
    // meanwhile (the Kernel-Process callback calls `forget`) is not named after
    // what the pass saw.
    let mut directory = directory.lock().unwrap();
    for (silo, id) in mapping {
        if pending.contains(&silo) && !directory.resolved_since(silo, id, since) {
            tracing::debug!(
                silo,
                "container lookup: silo mapped or recreated meanwhile, answer dropped"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    const ID_A: &str = "4f2b1c0e9d8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c";
    const ID_B: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const SEC: u64 = 1_000_000_000;

    fn container(id: &str, processes: &[(u32, &str)]) -> HcsContainer {
        HcsContainer {
            id: id.to_string(),
            processes: processes
                .iter()
                .map(|(p, i)| (*p, (*i).to_string()))
                .collect(),
        }
    }

    #[test]
    fn a_process_gone_before_its_start_is_handled_takes_its_parents_silo() {
        assert_eq!(exec_silo(None, Some(7)), Some(7));
        assert_eq!(exec_silo(Some(0), Some(7)), Some(0));
        assert_eq!(exec_silo(Some(7), None), Some(7));
        assert_eq!(exec_silo(None, None), None);
    }

    #[test]
    fn an_unresolved_silo_is_containerized_with_a_provisional_id() {
        let mut dir = SiloDirectory::new();
        let (ctx, ask) = dir.lookup(1234, SEC);
        assert_eq!(ctx.id, "silo:1234");
        assert!(ask);
    }

    #[test]
    fn the_resolver_is_asked_once_per_retry_window() {
        let mut dir = SiloDirectory::new();
        assert!(dir.lookup(9, SEC).1);
        assert!(!dir.lookup(9, SEC + 1).1);
        assert!(!dir.lookup(9, SEC + RETRY_NS - 1).1);
        assert!(dir.lookup(9, SEC + RETRY_NS).1);
    }

    #[test]
    fn a_resolved_silo_carries_the_container_id_and_stops_asking() {
        let mut dir = SiloDirectory::new();
        dir.lookup(9, SEC);
        dir.resolved(9, ID_A.to_string());
        let (ctx, ask) = dir.lookup(9, SEC + 2 * RETRY_NS);
        assert_eq!(ctx.id, ID_A);
        assert!(!ask);
    }

    #[test]
    fn a_mapped_silo_is_never_relabelled_by_a_later_claimant() {
        let mut dir = SiloDirectory::new();
        dir.lookup(9, SEC);
        assert!(dir.resolved(9, ID_A.to_string()));
        assert!(!dir.resolved(9, ID_B.to_string()));
        assert_eq!(dir.lookup(9, SEC).0.id, ID_A);
    }

    #[test]
    fn a_silo_no_event_asked_about_is_not_mapped() {
        let mut dir = SiloDirectory::new();
        assert!(!dir.resolved(9, ID_A.to_string()));
        assert!(dir.pending().is_empty());
        assert_eq!(dir.lookup(9, SEC).0.id, "silo:9");
    }

    #[test]
    fn a_dropped_request_is_asked_again_on_the_next_event() {
        let mut dir = SiloDirectory::new();
        assert!(dir.lookup(9, SEC).1);
        dir.request_dropped(9);
        assert!(dir.lookup(9, SEC + 1).1);
    }

    #[test]
    fn a_forgotten_silo_is_provisional_again() {
        let mut dir = SiloDirectory::new();
        dir.lookup(9, SEC);
        dir.resolved(9, ID_A.to_string());
        dir.forget(9);
        let (ctx, ask) = dir.lookup(9, SEC);
        assert_eq!(ctx.id, "silo:9");
        assert!(ask);
    }

    #[test]
    fn the_silo_directory_never_grows_past_its_cap() {
        let mut dir = SiloDirectory::new();
        for silo in 1..=(SILO_CAP as u32 * 4) {
            dir.lookup(silo, SEC);
        }
        assert!(dir.entries.len() <= SILO_CAP);
        assert_eq!(dir.evicted(), SILO_CAP as u64 * 3);
    }

    #[test]
    fn a_container_maps_to_the_silo_of_its_first_matching_process() {
        let containers = [container(ID_A, &[(500, "smss.exe"), (612, "cmd.exe")])];
        let probe = |pid: u32, image: &str| (pid == 612 && image == "cmd.exe").then_some(41);
        assert_eq!(
            match_containers(&containers, probe),
            vec![(41, ID_A.to_string())]
        );
    }

    #[test]
    fn a_host_process_never_maps_a_container_to_the_host() {
        // A Hyper-V-isolated container reports pids of its own kernel; one can
        // match a host process (silo 0).
        let containers = [container(ID_A, &[(4, "System")])];
        assert!(match_containers(&containers, |_, _| Some(0)).is_empty());
    }

    #[test]
    fn a_silo_claimed_by_two_containers_stays_unmapped() {
        let containers = [
            container(ID_A, &[(500, "cmd.exe")]),
            container(ID_B, &[(600, "cmd.exe")]),
            container("other", &[(700, "ping.exe")]),
        ];
        let probe = |pid: u32, _: &str| Some(if pid == 700 { 8 } else { 41 });
        assert_eq!(
            match_containers(&containers, probe),
            vec![(8, "other".to_string())]
        );
    }

    #[test]
    fn probing_a_container_stops_after_a_few_processes() {
        let processes: Vec<(u32, &str)> = (1..=10).map(|pid| (pid, "x.exe")).collect();
        let containers = [container(ID_A, &processes)];
        let probed = std::cell::Cell::new(0);
        let _ = match_containers(&containers, |_, _| {
            probed.set(probed.get() + 1);
            None
        });
        assert_eq!(probed.get(), PROBES_PER_CONTAINER);
    }

    #[test]
    fn container_ids_come_from_container_compute_systems_only() {
        let json = format!(
            r#"[{{"Id":"{ID_A}","SystemType":"Container","Owner":"docker","State":"Running"}},
                {{"Id":"vm1","SystemType":"VirtualMachine"}},
                {{"SystemType":"Container"}},
                {{"Id":"","SystemType":"Container"}}]"#
        );
        assert_eq!(parse_container_ids(&json), vec![ID_A.to_string()]);
    }

    #[test]
    fn a_process_list_keeps_entries_with_a_pid_and_an_image() {
        let json = r#"{"ProcessList":[
            {"ProcessId":612,"ImageName":"cmd.exe","UserTime100ns":0},
            {"ProcessId":0,"ImageName":"Idle"},
            {"ProcessId":5000000000,"ImageName":"big.exe"},
            {"ImageName":"nopid.exe"},
            {"ProcessId":700}
        ]}"#;
        assert_eq!(parse_process_list(json), vec![(612, "cmd.exe".to_string())]);
    }

    #[test]
    fn malformed_service_output_yields_nothing() {
        for junk in [
            "",
            "null",
            "{",
            "[1,2]",
            r#"{"ProcessList":"x"}"#,
            "\u{0}\u{ffff}",
        ] {
            assert!(parse_container_ids(junk).is_empty(), "{junk:?}");
            assert!(parse_process_list(junk).is_empty(), "{junk:?}");
        }
    }

    struct FakeHcs {
        containers: Vec<HcsContainer>,
        listed: std::cell::RefCell<Vec<String>>,
    }

    impl ContainerSource for FakeHcs {
        fn container_ids(&self) -> Result<Vec<String>, String> {
            Ok(self.containers.iter().map(|c| c.id.clone()).collect())
        }
        fn processes(&self, container_id: &str) -> Result<Vec<(u32, String)>, String> {
            self.listed.borrow_mut().push(container_id.to_string());
            self.containers
                .iter()
                .find(|c| c.id == container_id)
                .map(|c| c.processes.clone())
                .ok_or_else(|| "gone".to_string())
        }
    }

    #[test]
    fn one_resolver_pass_names_every_queued_silo_and_skips_mapped_containers() {
        let directory = Mutex::new(SiloDirectory::new());
        {
            let mut dir = directory.lock().unwrap();
            dir.lookup(5, SEC);
            dir.resolved(5, ID_B.to_string());
            dir.lookup(41, SEC);
        }
        let hcs = FakeHcs {
            containers: vec![
                container(ID_A, &[(612, "cmd.exe")]),
                container(ID_B, &[(900, "ping.exe")]),
            ],
            listed: std::cell::RefCell::new(Vec::new()),
        };
        let (tx, rx) = mpsc::sync_channel(8);
        tx.send(41).unwrap();
        tx.send(41).unwrap();
        drop(tx);
        run_resolver(&rx, &directory, &hcs, |pid, _| (pid == 612).then_some(41));

        assert_eq!(*hcs.listed.borrow(), vec![ID_A.to_string()]);
        let mut dir = directory.lock().unwrap();
        assert_eq!(dir.lookup(41, SEC).0.id, ID_A);
        assert_eq!(dir.lookup(5, SEC).0.id, ID_B);
    }

    /// A source whose process listing is the moment the silo is torn down and its id
    /// reused by a new container an event already asked about, as the Kernel-Process
    /// callback and the event thread would do it on other threads.
    struct ReuseDuringPass<'a> {
        directory: &'a Mutex<SiloDirectory>,
        silo: u32,
        inner: FakeHcs,
    }

    impl ContainerSource for ReuseDuringPass<'_> {
        fn container_ids(&self) -> Result<Vec<String>, String> {
            self.inner.container_ids()
        }
        fn processes(&self, container_id: &str) -> Result<Vec<(u32, String)>, String> {
            let processes = self.inner.processes(container_id);
            let mut dir = self.directory.lock().unwrap();
            dir.forget(self.silo);
            dir.lookup(self.silo, 2 * SEC);
            processes
        }
    }

    /// Review of #709 (regression of `e70fd25`): the reused silo's fresh entry is
    /// unmapped and pending, which `resolved` alone accepts.
    #[test]
    fn a_silo_reused_during_a_pass_is_not_named_after_the_old_container() {
        let directory = Mutex::new(SiloDirectory::new());
        directory.lock().unwrap().lookup(41, SEC);
        let hcs = ReuseDuringPass {
            directory: &directory,
            silo: 41,
            inner: FakeHcs {
                containers: vec![container(ID_A, &[(612, "cmd.exe")])],
                listed: std::cell::RefCell::new(Vec::new()),
            },
        };
        resolve_pass(&directory, &hcs, &|pid, _| (pid == 612).then_some(41));
        let mut dir = directory.lock().unwrap();
        assert!(dir.pending().contains(&41));
        assert_eq!(dir.lookup(41, SEC).0.id, "silo:41");
    }

    #[test]
    fn a_reused_silo_does_not_stop_the_other_silos_of_the_same_pass() {
        let directory = Mutex::new(SiloDirectory::new());
        {
            let mut dir = directory.lock().unwrap();
            dir.lookup(41, SEC);
            dir.lookup(42, SEC);
        }
        let hcs = ReuseDuringPass {
            directory: &directory,
            silo: 41,
            inner: FakeHcs {
                containers: vec![
                    container(ID_A, &[(612, "cmd.exe")]),
                    container(ID_B, &[(900, "ping.exe")]),
                ],
                listed: std::cell::RefCell::new(Vec::new()),
            },
        };
        resolve_pass(&directory, &hcs, &|pid, _| match pid {
            612 => Some(41),
            900 => Some(42),
            _ => None,
        });
        let mut dir = directory.lock().unwrap();
        assert_eq!(dir.lookup(41, SEC).0.id, "silo:41");
        assert_eq!(dir.lookup(42, SEC).0.id, ID_B);
    }

    #[test]
    fn a_forget_before_the_pass_started_does_not_block_its_answer() {
        let mut dir = SiloDirectory::new();
        dir.forget(41);
        let since = dir.epoch();
        dir.lookup(41, SEC);
        assert!(dir.resolved_since(41, ID_A.to_string(), since));
        assert_eq!(dir.lookup(41, SEC).0.id, ID_A);
    }

    #[test]
    fn a_forget_log_that_no_longer_reaches_the_pass_drops_its_answers() {
        let mut dir = SiloDirectory::new();
        dir.lookup(41, SEC);
        let since = dir.epoch();
        for silo in 1000..1000 + FORGET_LOG_CAP as u32 + 1 {
            dir.forget(silo);
        }
        // Silo 41 was never forgotten, but the log lost its oldest entries: unprovable.
        assert!(!dir.resolved_since(41, ID_A.to_string(), since));
        assert_eq!(dir.lookup(41, SEC).0.id, "silo:41");
    }

    struct DownHcs;

    impl ContainerSource for DownHcs {
        fn container_ids(&self) -> Result<Vec<String>, String> {
            Err("0x80370114".to_string())
        }
        fn processes(&self, _: &str) -> Result<Vec<(u32, String)>, String> {
            unreachable!("no container was listed")
        }
    }

    /// Review of #709: a Hyper-V-isolated container is never mapped, so every
    /// pass probes it, and one of its guest pids can name a process in
    /// container A's silo. Once A holds the silo, that claim changes nothing.
    #[test]
    fn a_never_mapped_container_cannot_take_a_mapped_silo() {
        let directory = Mutex::new(SiloDirectory::new());
        {
            let mut dir = directory.lock().unwrap();
            dir.lookup(41, SEC);
            dir.resolved(41, ID_A.to_string());
            // Another container starting: its request runs a pass.
            dir.lookup(77, SEC);
        }
        let hcs = FakeHcs {
            containers: vec![
                container(ID_A, &[(612, "cmd.exe")]),
                container(ID_B, &[(612, "cmd.exe")]),
            ],
            listed: std::cell::RefCell::new(Vec::new()),
        };
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(77).unwrap();
        drop(tx);
        run_resolver(&rx, &directory, &hcs, |pid, _| (pid == 612).then_some(41));

        assert_eq!(*hcs.listed.borrow(), vec![ID_B.to_string()]);
        let mut dir = directory.lock().unwrap();
        assert_eq!(dir.lookup(41, SEC).0.id, ID_A);
        assert_eq!(dir.lookup(77, SEC).0.id, "silo:77");
    }

    #[test]
    fn an_unreachable_compute_service_leaves_silos_provisional() {
        let directory = Mutex::new(SiloDirectory::new());
        directory.lock().unwrap().lookup(41, SEC);
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(41).unwrap();
        drop(tx);
        run_resolver(&rx, &directory, &DownHcs, |_, _| Some(41));
        assert!(directory.lock().unwrap().pending().contains(&41));
        assert_eq!(directory.lock().unwrap().lookup(41, SEC).0.id, "silo:41");
    }
}
