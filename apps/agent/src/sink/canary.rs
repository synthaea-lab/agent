//! The deception canary gate (#81): which canary touches become findings. It owns the planted
//! tripwires, the allow list and its exec table, the hold that waits for a touch's `Exec`, and
//! the read cooldown. The sink records what [`CanaryGate::on_event`] returns and runs the
//! ransomware join on it. See `docs/detection/deception.md`, "Detection path".

use std::{
    borrow::Cow,
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use schema::Event;

use crate::{
    deception::{CanaryAllow, ExecImage, ExecImages},
    sync::LockExt as _,
};

/// The ATT&CK technique a canary hit reports: someone looked through files nothing
/// legitimate reads (T1083 file and directory discovery). The rule id names the provenance.
pub(super) const CANARY_TECHNIQUE: &str = "T1083";

/// `DetectionSource::Rule` id of a canary hit. `DetectionSource` is part of the
/// semi-frozen schema, so deception provenance rides in the rule id until a dedicated
/// variant is decided (#81).
pub(super) const CANARY_RULE_ID: &str = "DECEPTION-CANARY";

/// `(canary path, pid, process incarnation)`: the incarnation, when the sensor stamps one,
/// keeps a process that reuses the pid inside the cooldown from being absorbed as its
/// predecessor.
type CanaryKey = (PathBuf, u32, Option<u64>);

/// Open flags that mean write intent on Linux (`O_WRONLY | O_RDWR | O_CREAT`), the same
/// mask the YARA trigger uses. On a platform whose flags mean something else the mask can
/// only let more opens through, never absorb more.
const WRITE_INTENT_FLAGS: u32 = 0o103;

/// Whether a repeat of this touch may be absorbed by the cooldown. Only a read open may: a
/// delete, a rename or a write-intent open is the destructive touch an encryptor makes after
/// reading, and absorbing it behind the first open would hide the one finding an analyst
/// needs. Those always raise a detection (bounded by the number of canaries).
fn absorbable(touch: &deception::Touch) -> bool {
    matches!(touch, deception::Touch::Open { flags } if flags & WRITE_INTENT_FLAGS == 0)
}

/// How long one process's repeat touches of one canary are absorbed after a detection.
pub(super) const CANARY_COOLDOWN_NS: u64 = 60 * 1_000_000_000;

/// How long (event time) a canary touch by a process whose `Exec` the sink has not recorded
/// waits for it before it is judged on what is known. The merged stream can deliver an open
/// before the `exec` it follows (`docs/detection/deception.md`, "Holding a touch for its exec");
/// half a second is far longer than the lag seen and short for an uncorroborated detection.
pub(super) const CANARY_EXEC_HOLD_NS: u64 = 500_000_000;

/// Most touches held at once. A host with an allow list under an open flood must not grow
/// this without bound, and a flood must not be a way to delay findings: past the bound a
/// touch is judged at once, as it was before the hold existed.
pub(super) const MAX_HELD_CANARY_TOUCHES: usize = 256;

/// Most `(canary, pid)` pairs the cooldown remembers; the oldest are evicted first, which
/// at worst lets one more detection through.
const CANARY_COOLDOWN_KEYS: usize = 1024;

/// What the allow list makes of a canary touch.
enum CanaryVerdict {
    /// The toucher runs an allowed executable.
    Allowed,
    /// Not allowed by what the sink knows, and `/proc` names no executable (the process already
    /// exited): an `Exec` may still be on its way, either the first (none recorded) or the last of
    /// several. A process `/proc` shows running something else is not unknown, it is not allowed:
    /// `/proc` is read after the touch, so it shows the image the touch was made by or a later one.
    Unknown,
    /// Not allowed, and nothing more to wait for.
    Raise,
}

/// A canary touch waiting for the `Exec` of its process (#81).
struct HeldTouch {
    event: Event,
    /// Event time of the touch, ns: the hold runs from it, and only an `exec` at or before it
    /// can excuse the touch.
    since_ns: u64,
    /// The latest image of this incarnation exec'd at or before the touch, as far as the sink has
    /// seen one. The final verdict is taken on it, not on the table's newest entry, which a
    /// later `exec` (one the touch cannot have been made by) may have replaced.
    image: Option<ExecImage>,
}

/// A canary touch no allow-list entry excuses, for the sink to record.
pub(super) struct CanaryTouch<'e> {
    /// The touch: the event being dispatched, or a held one whose hold has ended.
    pub(super) event: Cow<'e, Event>,
    /// The process that touched the canary.
    pub(super) pid: u32,
    /// The touch waited out the hold. The ransomware reflex does not kill from it: `/proc`
    /// named nothing for the process when it was held, so by now it is gone or its pid is
    /// someone else's, and the reflex kills by pid.
    pub(super) late: bool,
    pub(super) outcome: TouchOutcome,
}

/// Whether a touch raises a detection of its own.
pub(super) enum TouchOutcome {
    /// A detection, with its message.
    Raise { message: String },
    /// A repeat read inside the cooldown: the touch that started the cooldown raised the
    /// finding. It still counts for the ransomware join.
    Absorbed,
}

/// Turns canary touches into findings (#81). Every field is behind `&self` for the same reason
/// as the sink's: `EventSink` only exposes `&self`.
pub(super) struct CanaryGate {
    /// The planted canary files, set once at start; empty of effect when the operator
    /// configured no `[deception]` directories.
    tripwires: OnceLock<deception::Tripwires>,
    /// Executables allowed to touch a canary without a detection (`[deception] allow_exe`),
    /// set once with the tripwires.
    allow: OnceLock<CanaryAllow>,
    /// The image each process was seen to execute, so `allow` need not read `/proc`.
    exec_images: Mutex<ExecImages>,
    /// Canary touches by a process whose `Exec` was not recorded yet, waiting for it, oldest
    /// first. Only filled when `allow` lists an executable.
    held: Mutex<VecDeque<HeldTouch>>,
    /// Length of `held`, so the common empty case costs no lock per event.
    held_len: AtomicUsize,
    /// When each `(canary, pid, incarnation of pid)` last raised a detection (event time,
    /// ns), so a tool that reads the same canary again and again raises one finding per
    /// cooldown, not one per open. Only read opens are absorbed (see [`absorbable`]);
    /// bounded; the hits it absorbs are counted in `hits_absorbed`.
    last_hit: Mutex<store::BoundedMap<CanaryKey, u64>>,
    hits_absorbed: AtomicU64,
    /// Touches judged at once because the hold queue was full, and touches raised after a hold
    /// that ended with no allowed exec: the two outcomes of the hold that bring the false
    /// positive back, counted and logged like `hits_absorbed` (#81 review).
    hold_overflow: AtomicU64,
    hold_expired: AtomicU64,
}

impl CanaryGate {
    pub(super) fn new() -> Self {
        Self {
            tripwires: OnceLock::new(),
            allow: OnceLock::new(),
            exec_images: Mutex::new(ExecImages::new()),
            held: Mutex::new(VecDeque::new()),
            held_len: AtomicUsize::new(0),
            last_hit: Mutex::new(store::BoundedMap::new(CANARY_COOLDOWN_KEYS)),
            hits_absorbed: AtomicU64::new(0),
            hold_overflow: AtomicU64::new(0),
            hold_expired: AtomicU64::new(0),
        }
    }

    /// Installs the planted canaries. A second call is ignored.
    pub(super) fn set_tripwires(&self, tripwires: deception::Tripwires) {
        let _ = self.tripwires.set(tripwires);
    }

    /// Installs the executables allowed to touch a canary. A second call is ignored.
    pub(super) fn set_allow(&self, allow: CanaryAllow) {
        let _ = self.allow.set(allow);
    }

    /// The touches `event` settles, oldest first: the held touches whose hold it ends, then
    /// `event` itself when it touches a canary and cannot wait.
    ///
    /// The hold runs on the clock of the stream that carries both the exec and the touch. The
    /// netlink poller, uprobes and log sources call the sink from their own threads with their
    /// own clocks: letting them expire the hold would end it before the exec had a chance to come.
    pub(super) fn on_event<'e>(&self, event: &'e Event) -> Vec<CanaryTouch<'e>> {
        let mut touches = Vec::new();
        if matches!(
            event,
            Event::Exec(_)
                | Event::FileOpen(_)
                | Event::FileDelete(_)
                | Event::FileRename(_)
                | Event::FileSetTime(_)
                | Event::RawVolumeOpen(_)
        ) {
            self.expire_held(event.meta().timestamp_ns, &mut touches);
        }
        touches.extend(self.detect(event));
        touches
    }

    /// Records the image an `Exec` ran, for the allow list and the held touches of its process.
    /// The table is filled only when an executable may be allowed: recording every exec of a
    /// host that allows none would take a lock and clone a path for nothing.
    pub(super) fn on_exec(&self, exec: &schema::ExecEvent) {
        if self.allow.get().is_some_and(|allow| !allow.is_empty()) {
            self.exec_images.lock_recovering().record(exec);
            self.record_exec_on_held(exec);
        }
    }

    /// A touch of a planted canary by any process but the agent itself (which writes them at
    /// start and verifies them later) is a finding, unless the allow list excuses it. An unknown
    /// process is held for its `Exec` instead ([`Self::hold`]).
    fn detect<'e>(&self, event: &'e Event) -> Option<CanaryTouch<'e>> {
        let hit = self.tripwires.get()?.matches(event)?;
        if hit.pid == std::process::id() {
            return None;
        }
        let seen = self.image_before(hit.pid, event);
        match self.verdict(hit.pid, seen.as_ref()) {
            CanaryVerdict::Allowed => {
                tracing::debug!(
                    pid = hit.pid,
                    "deception: canary touch by an allowed executable"
                );
                return None;
            }
            CanaryVerdict::Unknown if self.hold(event, seen) => return None,
            CanaryVerdict::Unknown | CanaryVerdict::Raise => {}
        }
        self.raise(Cow::Borrowed(event), false)
    }

    /// The image the table holds for the process that made `event`, when it exec'd at or before
    /// the touch: a later `exec` of the same process (an allowed `tar` run after an open by
    /// something else) must not excuse a touch it did not make.
    fn image_before(&self, pid: u32, event: &Event) -> Option<ExecImage> {
        let meta = event.meta();
        // Cloned out so the lock is not held across the `/proc` fallback inside `allows`:
        // `on_exec` takes it for every exec event.
        self.exec_images.lock_recovering().image_of_not_after(
            pid,
            meta.process_generation,
            meta.timestamp_ns,
        )
    }

    /// What the allow list says about the process `pid`, given the image it was seen to exec.
    fn verdict(&self, pid: u32, seen: Option<&ExecImage>) -> CanaryVerdict {
        let Some(allow) = self.allow.get() else {
            return CanaryVerdict::Raise;
        };
        if allow.allows(pid, seen) {
            CanaryVerdict::Allowed
        } else if !allow.is_empty()
            && !allow.refuses_outright(pid, seen)
            && !allow.proc_names_an_exe(pid)
        {
            CanaryVerdict::Unknown
        } else {
            CanaryVerdict::Raise
        }
    }

    /// Holds `event` until the hold runs out, for the `Exec` of its process to be recorded.
    /// False when the queue is full: the caller then judges the touch at once, and the
    /// overflow is counted (it brings the false positive back without a trace otherwise).
    fn hold(&self, event: &Event, image: Option<ExecImage>) -> bool {
        let mut held = self.held.lock_recovering();
        if held.len() >= MAX_HELD_CANARY_TOUCHES {
            let overflowed = self.hold_overflow.fetch_add(1, Ordering::Relaxed) + 1;
            if overflowed.is_power_of_two() {
                tracing::warn!(
                    overflowed_total = overflowed,
                    "deception: canary hold queue full, touch judged without waiting for its exec"
                );
            }
            return false;
        }
        held.push_back(HeldTouch {
            event: event.clone(),
            since_ns: event.meta().timestamp_ns,
            image,
        });
        self.held_len.store(held.len(), Ordering::Relaxed);
        true
    }

    /// Records this exec's image on the held touches of its incarnation when it happened at or
    /// before the touch; the latest such exec wins (`bash -c "tar ..."` is judged as `tar`). An
    /// exec without a generation never counts: a reused pid would match its previous life.
    /// The decision itself is taken when the hold ends ([`Self::judge_held`]).
    fn record_exec_on_held(&self, exec: &schema::ExecEvent) {
        let generation = exec.meta.process_generation;
        if generation.is_none() || self.held_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        let image = ExecImage::from_exec(exec);
        let mut held = self.held.lock_recovering();
        for touch in held.iter_mut() {
            let meta = touch.event.meta();
            if meta.pid == exec.meta.pid
                && meta.process_generation == generation
                && image.precedes(touch.since_ns)
                && touch
                    .image
                    .as_ref()
                    .is_none_or(|previous| previous.precedes(image.timestamp_ns()))
            {
                touch.image = Some(image.clone());
            }
        }
    }

    /// Judges the held touches older than the hold, at event time `now_ns`.
    fn expire_held(&self, now_ns: u64, touches: &mut Vec<CanaryTouch<'_>>) {
        if self.held_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        let due =
            self.take_held(|held| now_ns.saturating_sub(held.since_ns) >= CANARY_EXEC_HOLD_NS);
        touches.extend(self.judge_held(due));
    }

    /// Removes and returns the held touches `pick` selects, oldest first.
    fn take_held(&self, pick: impl Fn(&HeldTouch) -> bool) -> Vec<HeldTouch> {
        let mut held = self.held.lock_recovering();
        let mut taken = Vec::new();
        let mut kept = VecDeque::new();
        for touch in held.drain(..) {
            if pick(&touch) {
                taken.push(touch);
            } else {
                kept.push_back(touch);
            }
        }
        *held = kept;
        self.held_len.store(held.len(), Ordering::Relaxed);
        taken
    }

    /// The final decision on touches that waited: allowed ones are dropped, every other is
    /// raised (and counted as expired), whether its exec arrived or not.
    fn judge_held<'e>(&self, touches: Vec<HeldTouch>) -> Vec<CanaryTouch<'e>> {
        let mut raised = Vec::new();
        for held in touches {
            let pid = held.event.meta().pid;
            if matches!(
                self.verdict(pid, held.image.as_ref()),
                CanaryVerdict::Allowed
            ) {
                tracing::debug!(pid, "deception: held canary touch by an allowed executable");
                continue;
            }
            let expired = self.hold_expired.fetch_add(1, Ordering::Relaxed) + 1;
            if expired.is_power_of_two() {
                tracing::info!(
                    expired_total = expired,
                    "deception: held canary touch raised, no allowed exec before it"
                );
            }
            raised.extend(self.raise(Cow::Owned(held.event), true));
        }
        raised
    }

    /// The touch no allow-list entry excuses, raised or absorbed by the cooldown.
    fn raise<'e>(&self, event: Cow<'e, Event>, late: bool) -> Option<CanaryTouch<'e>> {
        let hit = self.tripwires.get()?.matches(&event)?;
        let meta = event.meta();
        let outcome = if absorbable(&hit.touch)
            && self.in_cooldown(
                (hit.canary.path.clone(), hit.pid, meta.process_generation),
                meta.timestamp_ns,
            ) {
            let absorbed = self.hits_absorbed.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(
                pid = hit.pid,
                absorbed,
                "deception: repeat canary touch absorbed"
            );
            TouchOutcome::Absorbed
        } else {
            TouchOutcome::Raise {
                message: format!(
                    "canary file touched: {} ({:?}) by pid {} ({})",
                    hit.canary.path.display(),
                    hit.touch,
                    hit.pid,
                    meta.comm
                ),
            }
        };
        let pid = hit.pid;
        Some(CanaryTouch {
            event,
            pid,
            late,
            outcome,
        })
    }

    /// True when `key` already raised a detection within the cooldown; otherwise records
    /// this touch as the one that did.
    fn in_cooldown(&self, key: CanaryKey, now_ns: u64) -> bool {
        let mut last = self.last_hit.lock_recovering();
        if let Some(&at) = last.peek(&key)
            && now_ns.saturating_sub(at) < CANARY_COOLDOWN_NS
        {
            return true;
        }
        last.insert(key, now_ns);
        false
    }

    #[cfg(test)]
    pub(super) fn hits_absorbed(&self) -> u64 {
        self.hits_absorbed.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn hold_expired(&self) -> u64 {
        self.hold_expired.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn hold_overflow(&self) -> u64 {
        self.hold_overflow.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn exec_image_of(&self, pid: u32, generation: Option<u64>) -> Option<ExecImage> {
        self.exec_images.lock_recovering().image_of(pid, generation)
    }
}

impl Drop for CanaryGate {
    /// Touches still held when the sink goes away are not judged (the hold runs on event time and
    /// nothing flushes it); say how many, so the loss is not silent.
    fn drop(&mut self) {
        let held = self
            .held
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        if held > 0 {
            tracing::warn!(
                held,
                "deception: canary touches still held at shutdown are not reported"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use schema::Event;

    use super::{CanaryGate, TouchOutcome};

    /// A gate watching one freshly planted canary, and that canary's path.
    fn gate_watching_canary(dir: &std::path::Path) -> (CanaryGate, String) {
        let planted = dir.join("canaries");
        std::fs::create_dir_all(&planted).unwrap();
        let tripwires = crate::deception::start(
            &config::DeceptionConfig {
                canary_dirs: vec![planted.clone()],
                ..Default::default()
            },
            &dir.join("state"),
        )
        .unwrap();
        let canary = std::fs::read_dir(&planted)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .display()
            .to_string();
        let gate = CanaryGate::new();
        gate.set_tripwires(tripwires);
        (gate, canary)
    }

    fn read_by(path: &str, pid: u32, timestamp_ns: u64) -> Event {
        let mut open = schema::fixtures::file_open();
        open.path = path.into();
        open.flags = 0;
        open.meta.pid = pid;
        open.meta.timestamp_ns = timestamp_ns;
        Event::FileOpen(open)
    }

    #[test]
    fn a_gate_without_tripwires_reports_nothing() {
        let gate = CanaryGate::new();
        assert!(gate.on_event(&read_by("/srv/x", 4242, 1)).is_empty());
    }

    #[test]
    fn a_first_read_is_raised_on_the_dispatched_event_and_a_repeat_is_absorbed() {
        let dir = tempfile::tempdir().unwrap();
        let (gate, canary) = gate_watching_canary(dir.path());
        let pid = std::process::id() + 1;
        let first = read_by(&canary, pid, 5);
        let touches = gate.on_event(&first);
        assert_eq!(touches.len(), 1);
        let touch = &touches[0];
        assert!(
            matches!(touch.event, Cow::Borrowed(_)),
            "no copy of the event"
        );
        assert_eq!(touch.pid, pid);
        assert!(!touch.late);
        assert!(
            matches!(&touch.outcome, TouchOutcome::Raise { message } if message.contains("canary file touched"))
        );
        let second = read_by(&canary, pid, 6);
        let repeat = gate.on_event(&second);
        assert_eq!(repeat.len(), 1, "an absorbed touch is still reported");
        assert!(matches!(repeat[0].outcome, TouchOutcome::Absorbed));
        assert_eq!(gate.hits_absorbed(), 1);
    }

    #[test]
    fn the_agent_touching_its_own_canary_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (gate, canary) = gate_watching_canary(dir.path());
        assert!(
            gate.on_event(&read_by(&canary, std::process::id(), 5))
                .is_empty()
        );
    }
}
