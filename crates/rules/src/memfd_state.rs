//! T1620 memfd exec, the [`crate::RuleState`] rule that correlates a `memfd_create(2)` with
//! an exec through `/dev/fd/<n>` or `/proc/(self|<pid>)/fd/<n>`.

use schema::{ExecEvent, MemfdCreateEvent, detection::Severity};
use store::BoundedMap;

use crate::{Alert, exclusions::MEMFD_EXEC_WINDOW_NS, state::PID_COMM_CAP};

/// See [`MemfdState::pending_proc_fd_exec`].
struct PendingProcFdExec {
    path: String,
    /// The `<n>` of the `/proc/.../fd/<n>` path: the descriptor the exec ran.
    fd: i32,
    comm: String,
    timestamp_ns: u64,
}

/// Memfd creations remembered per pid (see `MemfdState::recent_memfd_creates`). A real
/// fileless-exec process creates one or two; a process making more than this inside
/// the correlation window is not something a longer list would catch better.
const MEMFD_CREATES_PER_PID: usize = 8;

/// The per-pid memfd creations and the `/proc/.../fd/<n>` execs still waiting for one.
pub(crate) struct MemfdState {
    /// pid → the most recent `(timestamp, fd)` pairs of `MemfdCreateEvent`s seen
    /// for it (T1620, issues #497/#510): the evidence [`Self::check_memfd_exec`]
    /// requires before treating an exec via `/proc/(self|<pid>)/fd/<n>` as a
    /// memfd-exec, since that path shape alone (unlike `/dev/fd/<n>` + a
    /// `memfd:`-prefixed `comm`) is not reliable evidence on its own — see that
    /// method's doc. The exec's `<n>` must equal one of these fds. A process can
    /// legitimately hold several memfds, so this keeps up to
    /// [`MEMFD_CREATES_PER_PID`] (oldest dropped) rather than only the latest.
    /// LRU-bounded like `RuleState`'s `pid_comm`, same key space.
    recent_memfd_creates: BoundedMap<u32, Vec<(u64, i32)>>,
    /// pid → a `/proc/.../fd/<n>` exec seen with no corroborating
    /// `MemfdCreateEvent` yet (#503 review): held instead of dropped, since
    /// the creation may still arrive after the exec despite always preceding
    /// it at the kernel's own timestamp — two ring buffers drained
    /// independently don't guarantee delivery order. [`Self::on_memfd_create`]
    /// checks this and fires retroactively. LRU-bounded like `RuleState`'s `pid_comm`, same
    /// key space.
    pending_proc_fd_exec: BoundedMap<u32, PendingProcFdExec>,
}

impl MemfdState {
    pub(crate) fn new() -> Self {
        Self {
            recent_memfd_creates: BoundedMap::new(PID_COMM_CAP),
            pending_proc_fd_exec: BoundedMap::new(PID_COMM_CAP),
        }
    }

    /// To be called for every `MemfdCreateEvent` in the stream (Linux, issue
    /// #265). `memfd_create(2)` alone is common in legitimate code (glibc,
    /// systemd, browser sandboxing); it's the *exec* that's the technique, not
    /// the creation, so this mostly just records the timestamp
    /// `check_memfd_exec` consumes as corroborating evidence for its
    /// `/proc/.../fd/<n>` shape.
    ///
    /// Can still produce an alert directly (#503 review, Nikolas): the kernel
    /// always creates the memfd before executing it, but userspace drains the
    /// `memfd_create` and `exec` ring buffers independently
    /// (`crates/sensors/linux/userspace`'s `tokio::select!`), so the *exec*
    /// event can be processed here first despite the kernel-side ordering.
    /// `check_memfd_exec` holds that exec as [`Self::pending_proc_fd_exec`]
    /// instead of dropping it outright; this method checks for one on every
    /// creation and fires retroactively if it's still within
    /// [`MEMFD_EXEC_WINDOW_NS`].
    ///
    /// The kernel always creates the memfd before the exec, so a creation
    /// timestamped *after* the pending exec can only mean the process made an
    /// unrelated `memfd_create` call later — not proof of anything (#503
    /// review, Jihair, caught live: an on-disk `/proc/self/fd` exec followed
    /// 8s later, same pid, by an unrelated `memfd_create` wrongly fired).
    /// `saturating_sub` alone can't tell the two orderings apart (a
    /// too-late creation saturates to a delta of 0, which trivially passes
    /// the window check), so the ordering itself is checked first.
    pub(crate) fn on_memfd_create(&mut self, event: &MemfdCreateEvent) -> Vec<Alert> {
        let creates = self
            .recent_memfd_creates
            .get_or_insert_with(event.meta.pid, Vec::new);
        if creates.len() >= MEMFD_CREATES_PER_PID {
            creates.remove(0);
        }
        creates.push((event.meta.timestamp_ns, event.fd));
        if let Some(pending) = self.pending_proc_fd_exec.peek(&event.meta.pid)
            && pending.fd == event.fd
            && event.meta.timestamp_ns <= pending.timestamp_ns
            && pending.timestamp_ns - event.meta.timestamp_ns <= MEMFD_EXEC_WINDOW_NS
        {
            let alert =
                memfd_proc_fd_exec_alert(event.meta.pid, &pending.comm, &pending.path, pending.fd);
            self.pending_proc_fd_exec.remove(&event.meta.pid);
            return vec![alert];
        }
        Vec::new()
    }

    /// T1620 — Reflective Code Loading: executing a payload that never touches
    /// disk via `memfd_create(2)` + `execveat(fd, "", ..., AT_EMPTY_PATH)`
    /// (issue #85's Linux scope).
    ///
    /// `ExecEvent::image_path` is `bprm->filename` at the kernel's
    /// `sched_process_exec` tracepoint (`crates/sensors/linux/ebpf`, #111) —
    /// **not** `/proc/<pid>/exe`. Traced against a live kernel (Alpine
    /// 6.18.50, #85 review) with a memfd copy of `/bin/true`, two distinct
    /// shapes, evidenced differently (#497 review — the first cut treated
    /// either shape alone as sufficient, which false-positived on every
    /// container start):
    /// - `execveat(fd, "", AT_EMPTY_PATH)`: `bprm->filename` is `/dev/fd/<n>`,
    ///   and the kernel names the task after the memfd dentry, so `comm`
    ///   reliably starts with `memfd:`. The path shape plus that `comm`
    ///   prefix together are the evidence — nothing else produces this exact
    ///   combination.
    /// - `execv` via `/proc/self/fd/<n>` (or `/proc/<pid>/fd/<n>`): `comm` is
    ///   whatever the caller set, not reliably `memfd:` — the path shape
    ///   *alone* is not evidence of a memfd. Confirmed live: `runc`'s own
    ///   CVE-2019-5736 self-protection re-execs `runc init` via
    ///   `/proc/self/fd/<n>` on every container start (any Docker/containerd/
    ///   Kubernetes host), with `comm` truncated to the fd number and no
    ///   memfd anywhere in the picture; a plain `open()` + `execveat(fd, "",
    ///   AT_EMPTY_PATH)` of a real on-disk binary produces the same path
    ///   shape too. This shape now requires corroborating evidence: a
    ///   `MemfdCreateEvent` for the same pid within
    ///   [`MEMFD_EXEC_WINDOW_NS`] — real memfd-exec creates, writes, then
    ///   execs its own payload back-to-back in one short-lived process,
    ///   while `runc init` and an on-disk exec via `/proc/self/fd` never
    ///   called `memfd_create` at all. This is deliberately not a
    ///   `parent_comm`-keyed exclusion for `runc` specifically (spoofable,
    ///   same reasoning `check_burst_write_volume`'s doc gives for avoiding
    ///   name-keyed exclusions) — the evidence gate handles it structurally.
    ///
    /// Neither shape ever produces `/memfd:<name> (deleted)` — that string is
    /// only what `readlink /proc/<pid>/exe` shows, which the sensor doesn't
    /// read. An earlier version of this check matched on that string and
    /// never fired on real telemetry.
    ///
    /// The `/proc/.../fd/<n>` shape used to be correlation by pid and time
    /// only (#503 review, Nikolas): a process that created a memfd for a
    /// legitimate reason and then exec'd an ordinary on-disk binary through a
    /// different, unrelated fd within the same window matched. Since #510 the
    /// sensor reports the descriptor `memfd_create(2)` returned
    /// ([`MemfdCreateEvent::fd`]), and the exec's `<n>` must equal it: the
    /// executed fd *is* the created memfd, not merely a neighbour. The path's pid
    /// component must also be `self` or the exec'ing pid itself — `/proc/<other>/fd/<n>`
    /// names a descriptor in a different process's table, which this pid's memfds
    /// say nothing about.
    ///
    /// What remains unproven is fd *reuse*: a process that closes its memfd, opens
    /// an on-disk binary onto the same number and execs it inside the window would
    /// still match. That takes close/dup tracking for a shape no fileless-exec
    /// tool produces, so it is accepted.
    pub(crate) fn check_memfd_exec(&mut self, event: &ExecEvent) -> Option<Alert> {
        let path = &event.image_path;
        if is_dev_fd_path(path) {
            if !event.meta.comm.starts_with("memfd:") {
                return None;
            }
            return Some(memfd_dev_fd_exec_alert(
                event.meta.pid,
                &event.meta.comm,
                path,
            ));
        }
        if let Some(fd) = proc_fd_number(path, event.meta.pid) {
            let created = self
                .recent_memfd_creates
                .peek(&event.meta.pid)
                .is_some_and(|creates| {
                    creates.iter().any(|&(created_ts, created_fd)| {
                        created_fd == fd
                            && created_ts <= event.meta.timestamp_ns
                            && event.meta.timestamp_ns - created_ts <= MEMFD_EXEC_WINDOW_NS
                    })
                });
            if created {
                return Some(memfd_proc_fd_exec_alert(
                    event.meta.pid,
                    &event.meta.comm,
                    path,
                    fd,
                ));
            }
            // No corroborating creation seen yet — it may still arrive after
            // this exec (#503 review). Hold it instead of dropping it;
            // `on_memfd_create` checks for it. One pending exec per pid, same
            // reasoning `recent_memfd_creates` gives for tracking only the
            // latest creation: a second `/proc/fd` exec for the same pid
            // before the first resolves is rare enough not to warrant a list.
            self.pending_proc_fd_exec.insert(
                event.meta.pid,
                PendingProcFdExec {
                    path: path.clone(),
                    fd,
                    comm: event.meta.comm.clone(),
                    timestamp_ns: event.meta.timestamp_ns,
                },
            );
        }
        None
    }
}

/// The `/dev/fd/<n>` + `comm` starting with `memfd:` shape: structural
/// evidence (see `check_memfd_exec`'s doc), strong enough to say the payload
/// never touched disk.
fn memfd_dev_fd_exec_alert(pid: u32, comm: &str, path: &str) -> Alert {
    Alert {
        technique: "T1620",
        severity: Severity::High,
        message: format!(
            "pid={pid} comm={comm}: executed from a file descriptor ({path}), not a real \
             path — no payload ever touched disk",
        ),
    }
}

/// The `/proc/.../fd/<n>` shape, corroborated only by a same-pid
/// `MemfdCreateEvent` within the window (see `check_memfd_exec`'s doc for why
/// that's timing correlation, not proof the executed fd is the created one).
fn memfd_proc_fd_exec_alert(pid: u32, comm: &str, path: &str, fd: i32) -> Alert {
    Alert {
        technique: "T1620",
        severity: Severity::High,
        message: format!(
            "pid={pid} comm={comm}: executed from file descriptor {fd} ({path}), the memfd \
             this process created moments earlier — a payload that never touched disk",
        ),
    }
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Matches `/dev/fd/<n>` — `execveat(fd, "", AT_EMPTY_PATH)`'s `bprm->filename`
/// shape, see `check_memfd_exec`'s doc.
fn is_dev_fd_path(path: &str) -> bool {
    path.strip_prefix("/dev/fd/").is_some_and(is_all_digits)
}

/// The descriptor number `<n>` of `/proc/self/fd/<n>` or `/proc/<own_pid>/fd/<n>` — an
/// exec through one of the *exec'ing process's own* descriptors, see
/// `check_memfd_exec`'s doc. `None` for anything else, including
/// `/proc/<other pid>/fd/<n>` (a descriptor in a different table) and a number that
/// doesn't fit an `i32`.
fn proc_fd_number(path: &str, own_pid: u32) -> Option<i32> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid_or_self, fd) = rest.split_once("/fd/")?;
    let own = pid_or_self == "self"
        || (is_all_digits(pid_or_self) && pid_or_self.parse::<u32>().ok() == Some(own_pid));
    if !own || !is_all_digits(fd) {
        return None;
    }
    fd.parse().ok()
}
