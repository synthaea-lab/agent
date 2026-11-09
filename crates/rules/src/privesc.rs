//! SETUID-ROOT-REQUEST (T1548.001, #1041): a process that is not root asks the kernel for uid 0
//! (`setuid(0)`, or `setresuid` with 0 in any slot) and is not one of the setuid-root programs
//! seen doing it. The classic finishing step of a local privilege-escalation `PoC` is a
//! `setuid(0); setgid(0); exec /bin/sh` once the kernel or a setuid binary has been abused.
//!
//! What the telemetry is (#266, `IdentityChangeEvent`): the sensor reports the call at syscall
//! **entry**, with the caller's real uid in `meta.user` and the requested ids as arguments. It
//! cannot say whether the call succeeded, so a refused `setuid(0)` (EPERM, the unprivileged
//! attempt) looks like a granted one.
//!
//! **What the lab measured (Fedora 43, 2026-10-29).** Over a
//! quiet host plus ssh logins, `sudo`, `su`, `crontab` and a root cron job, the callers that
//! request uid 0 from a non-root real uid are `sudo`, `su`, `crontab`, `sshd-session` and
//! `sshd-auth` ([`SETUID_ROOT_PROGRAMS`]). A copy of `python3` renamed `sudo` and placed in
//! `/tmp` made the same request with `comm = sudo`, so the **process name is not evidence**: the
//! rule goes by the image the pid was exec'd from, and the image must be under a system path
//! and be named like a measured program (`policy::name_exclusion_applies`).
//!
//! **Not covered, on purpose or by limit:**
//! - An exploit run *inside* a listed binary (a heap overflow in `sudo` itself) makes the same
//!   request as the real one: silent.
//! - A pid whose exec the agent did not see (it started before the agent) has no image: silent,
//!   since "unknown" is not evidence against `sudo`. A child that forked and never exec'd takes
//!   its **parent's** image (`RuleState::reader_image`): the `fork()`ed winner of a race-window
//!   exploit alerts as the exploit, and `sshd`'s privilege-separated children resolve to
//!   `sshd-session`. Only **one** level is followed: a grandchild forked twice without an exec
//!   has no image and is silent.
//! - `setreuid` is not in [`schema::IdentityChangeKind`]: an exploit that finishes with it is
//!   not seen. Group ids and `setfsuid` are not read.
//! - Other setuid programs (`pkexec`, `newuidmap`, polkit helpers, `unix_chkpwd`, `fusermount`,
//!   container tooling) were run with `--version`/`--help` only, and none of them asked for uid 0
//!   there; their real operation was **not measured**, so each may alert. That is why the rule is
//!   **Low** and the list provisional.
//! - One alert per process (a `PoC` calls `setuid`, `setresuid`, ... in a row).
//!
//! **The image is the one the pid had *at the event's time*, and the judgment waits for it.**
//! The exec event reaches the rules later than the raw identity events of the same process (the
//! sensor reads `/proc` for the exec before emitting it), so reading the pid's image on arrival
//! saw the pid's *previous* exec (`bash -c '... sudo ...'` keeps its pid), its *next* one (sudo's
//! forked child calls `setuid(0)` before it execs `unix_chkpwd`) or none (then the parent's: every
//! `sudo` run from a shell alerted as `/usr/bin/bash` under an exec burst, live-tested by
//! Jihair54 on #1054). So a request is queued (it is rare: the pre-filter runs first) and judged
//! once the stream clock, the latest timestamp of any identity or exec event, is
//! [`IDENTITY_DEFER_NS`] past it, against the latest exec of the pid (else of its parent) with a
//! timestamp **at or before** the request. The delay is a bound on the exec's latency, **not
//! measured**: an exec that arrives later than it is not seen and the request is silent. A quiet
//! host where nothing else happens does not advance the clock, so the finding waits for the next
//! event; a queue overflow drops the oldest request; requests still queued at shutdown are not
//! judged.

use std::collections::VecDeque;

use schema::{ExecEvent, IdentityChangeEvent, IdentityChangeKind, User, detection::Severity};
use store::BoundedMap;

use crate::{Alert, state::PID_COMM_CAP};

/// How long past a request the stream clock must be before it is judged, so the exec of its
/// process has had time to arrive (5 s). Provisional: the exec latency under load was not
/// measured, only seen to exceed the identity events' by a few lines of a capture.
pub(crate) const IDENTITY_DEFER_NS: u64 = 5_000_000_000;

/// Requests waiting to be judged; the oldest is dropped past it.
pub(crate) const IDENTITY_PENDING_CAP: usize = 1024;

/// Execs remembered per pid (a shell that execs a command keeps its pid).
pub(crate) const EXEC_HISTORY_PER_PID: usize = 4;

/// The kernel's `(uid_t)-1`: "leave this id unchanged" in `setresuid`.
const UNCHANGED: u32 = u32::MAX;

/// Setuid-root programs measured requesting uid 0 from a non-root real uid, by file name; the
/// image must also be under a system path. Lab-measured on Fedora 43 (OpenSSH 10 with the split
/// `sshd-session`/`sshd-auth`), not a survey of every distribution.
pub(crate) const SETUID_ROOT_PROGRAMS: &[&str] =
    &["sudo", "su", "crontab", "sshd-session", "sshd-auth"];

/// The caller's real uid when it is a non-root Unix user.
fn non_root_uid(event: &IdentityChangeEvent) -> Option<u32> {
    match event.meta.user {
        User::Unix { uid, .. } if uid != 0 => Some(uid),
        _ => None,
    }
}

/// Whether this event asks for uid 0 and comes from a non-root caller.
#[must_use]
pub(crate) fn requests_root_as_non_root(event: &IdentityChangeEvent) -> bool {
    if non_root_uid(event).is_none() {
        return false;
    }
    let asks = |id: Option<u32>| id.is_some_and(|id| id == 0);
    match event.kind {
        IdentityChangeKind::SetUid => event.real == 0,
        IdentityChangeKind::SetResUid => [Some(event.real), event.effective, event.saved]
            .into_iter()
            .any(|id| id != Some(UNCHANGED) && asks(id)),
        _ => false,
    }
}

/// Whether `image` is a measured setuid-root program at a system path.
#[must_use]
pub(crate) fn is_known_setuid_root_program(image: &str) -> bool {
    let name = image.rsplit('/').next().unwrap_or("");
    policy::name_exclusion_applies(Some(image)) && SETUID_ROOT_PROGRAMS.contains(&name)
}

/// The alert for `event` raised by a process exec'd from `image`.
#[must_use]
pub(crate) fn alert(event: &IdentityChangeEvent, image: &str) -> Alert {
    Alert {
        technique: "T1548.001",
        severity: Severity::Low,
        message: format!(
            "pid={} comm={} (uid {}, image {image}) requests uid 0 ({:?} real={} effective={:?} saved={:?}) \
             and is not a setuid-root program seen doing it; the request is reported at syscall entry, \
             so it may have been refused",
            event.meta.pid,
            event.meta.comm,
            non_root_uid(event).unwrap_or(0),
            event.kind,
            event.real,
            event.effective,
            event.saved,
        ),
    }
}

/// One exec of a pid, for the as-of-time image lookup of SETUID-ROOT-REQUEST (#1041).
struct ExecRecord {
    timestamp_ns: u64,
    generation: Option<u64>,
    image: String,
}

/// The deferred SETUID-ROOT-REQUEST judgement: the queued requests, the stream clock that
/// releases them, and the exec history their image is read from.
pub(crate) struct IdentityRequests {
    /// pid → generation of the process that already raised SETUID-ROOT-REQUEST (T1548.001,
    /// #1041): one alert per process, since a `PoC` calls `setuid`, `setresuid`, ... in a row.
    /// LRU-bounded like `RuleState`'s pid tables.
    setuid_root_alerted: BoundedMap<u32, Option<u64>>,
    /// pid → its latest execs (image, time, incarnation): SETUID-ROOT-REQUEST reads the image
    /// a pid had *as of* an event's time, which `RuleState`'s `pid_image_path` (latest only)
    /// cannot give.
    exec_history: BoundedMap<u32, Vec<ExecRecord>>,
    /// Identity requests for uid 0 waiting for their process's exec to arrive (#1041).
    pending_identity: VecDeque<IdentityChangeEvent>,
    /// The latest timestamp of any identity or exec event seen: the stream's clock.
    identity_clock_ns: u64,
}

impl IdentityRequests {
    pub(crate) fn new() -> Self {
        Self {
            setuid_root_alerted: BoundedMap::new(PID_COMM_CAP),
            exec_history: BoundedMap::new(PID_COMM_CAP),
            pending_identity: VecDeque::new(),
            identity_clock_ns: 0,
        }
    }

    /// Remembers this exec for [`Self::on_identity_change`], and moves the stream clock.
    pub(crate) fn record_exec(&mut self, event: &ExecEvent) {
        self.identity_clock_ns = self.identity_clock_ns.max(event.meta.timestamp_ns);
        let history = self
            .exec_history
            .get_or_insert_with(event.meta.pid, Vec::new);
        if history.len() >= EXEC_HISTORY_PER_PID {
            history.remove(0);
        }
        history.push(ExecRecord {
            timestamp_ns: event.meta.timestamp_ns,
            generation: event.meta.process_generation,
            image: event.image_path.clone(),
        });
    }

    /// The image `pid` (incarnation `generation`) had at `at_ns`: its latest exec at or before
    /// that time. An exec of another incarnation of the pid does not count.
    fn image_as_of(&self, pid: u32, generation: Option<u64>, at_ns: u64) -> Option<&str> {
        self.exec_history
            .peek(&pid)?
            .iter()
            .rev()
            .find(|record| {
                record.timestamp_ns <= at_ns
                    && match (record.generation, generation) {
                        (Some(recorded), Some(wanted)) => recorded == wanted,
                        _ => true,
                    }
            })
            .map(|record| record.image.as_str())
    }

    /// Queues `event` when it asks for uid 0, moves the stream clock, and returns the requests
    /// now due: see [`crate::RuleState::on_identity_change`].
    pub(crate) fn on_identity_change(
        &mut self,
        event: &IdentityChangeEvent,
    ) -> Vec<(IdentityChangeEvent, Alert)> {
        self.identity_clock_ns = self.identity_clock_ns.max(event.meta.timestamp_ns);
        if requests_root_as_non_root(event) {
            if self.pending_identity.len() >= IDENTITY_PENDING_CAP {
                self.pending_identity.pop_front();
            }
            self.pending_identity.push_back(event.clone());
        }
        self.take_due()
    }

    /// The queued identity requests whose wait is over, judged: see [`Self::on_identity_change`].
    pub(crate) fn take_due(&mut self) -> Vec<(IdentityChangeEvent, Alert)> {
        let mut due = Vec::new();
        while let Some(front) = self.pending_identity.front() {
            if front.meta.timestamp_ns.saturating_add(IDENTITY_DEFER_NS) > self.identity_clock_ns {
                break;
            }
            let Some(event) = self.pending_identity.pop_front() else {
                break;
            };
            if let Some(alert) = self.judge(&event) {
                due.push((event, alert));
            }
        }
        due
    }

    fn judge(&mut self, event: &IdentityChangeEvent) -> Option<Alert> {
        let meta = &event.meta;
        let at = meta.timestamp_ns;
        let image = self
            .image_as_of(meta.pid, meta.process_generation, at)
            .or_else(|| self.image_as_of(meta.ppid, meta.parent_process_generation, at))?
            .to_owned();
        if image.is_empty() || is_known_setuid_root_program(&image) {
            return None;
        }
        if self
            .setuid_root_alerted
            .peek(&meta.pid)
            .is_some_and(|recorded| *recorded == meta.process_generation)
        {
            return None;
        }
        self.setuid_root_alerted
            .insert(meta.pid, meta.process_generation);
        Some(alert(event, &image))
    }
}
