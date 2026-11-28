//! Command lines the kernel recorded with each process creation, kept until the process
//! start that could not read its own asks for one. See "Command line" in
//! `docs/sensors/windows/etw-enrichment.md`.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{shed::ShedCounter, sync::LockExt};

/// How long a record is kept for a process start that has not asked for it. The start is
/// delivered by another session, usually within a second or two; past this the record can
/// only be taken for a later process under the same pid. Provisional: not measured.
const MAX_AGE_NS: u64 = 10_000_000_000;

/// How far apart the creation record and the process start may be stamped and still be
/// taken for the same creation. The two share no identifier but the pid, and the kernel
/// writes both while it creates the process, so only a pid reused within this distance can
/// be given the previous process's command line. Provisional: the real distance between the
/// two stamps has not been measured.
const PAIRING_TOLERANCE_NS: u64 = 100_000_000;

/// How long a process start whose PEB read failed waits for its creation record once the
/// creation session was asked to flush. The wait is spent on the thread that delivers every
/// record of the main session, so it has to stay short. After a flush the record arrived in
/// 0.2 to 1.4 ms (Windows 11 lab, 50 probes, 2026-11-28), except the first record of a
/// session that had just started, about 250 ms: this bound covers the first with a wide
/// margin and gives up on the second. Measured on an idle machine only; the real-session
/// test `process_creation` fails with the measured time when this is too tight.
pub(crate) const CREATION_CMDLINE_WAIT: Duration = Duration::from_millis(50);

/// The least time between two flushes of the creation session. A flush delivers every
/// record written so far, so the failed reads of one burst need one flush, not one each;
/// a failed read inside the interval only waits. Provisional: chosen to cap the flushes at
/// 100 a second, not from a measured cost.
const MIN_FLUSH_INTERVAL: Duration = Duration::from_millis(10);

/// Decides which failed reads flush the creation session: at most one per
/// [`MIN_FLUSH_INTERVAL`].
#[derive(Debug, Default)]
struct FlushLimiter {
    last_flush: Option<Instant>,
}

impl FlushLimiter {
    /// Whether a flush may be issued at `now`; when it may, `now` is remembered as its time.
    fn claim(&mut self, now: Instant) -> bool {
        let due = self
            .last_flush
            .is_none_or(|last| now.saturating_duration_since(last) >= MIN_FLUSH_INTERVAL);
        if due {
            self.last_flush = Some(now);
        }
        due
    }
}

/// Asks ETW to deliver what the creation session has buffered; the error is the Win32 status.
type FlushSession = Box<dyn Fn() -> Result<(), u32> + Send + Sync>;

/// The creation records as a process start reads them: a session delivers its buffers when
/// they fill or on a one-second timer, and the creation session fills its buffers slowly,
/// so a record is about a second behind its process (lab, 2026-11-28) unless the session is
/// flushed. A start that needs a record therefore asks for the flush itself.
pub(crate) struct OnDemandCmdlines {
    records: Arc<CreationCmdlines>,
    flush_session: FlushSession,
    limiter: Mutex<FlushLimiter>,
    flush_failure_reported: AtomicBool,
}

impl OnDemandCmdlines {
    pub(crate) fn new(records: Arc<CreationCmdlines>, flush_session: FlushSession) -> Self {
        Self {
            records,
            flush_session,
            limiter: Mutex::new(FlushLimiter::default()),
            flush_failure_reported: AtomicBool::new(false),
        }
    }

    /// The records of `session`, flushed through `ControlTraceW`.
    #[cfg(windows)]
    pub(crate) fn flushing_session(records: Arc<CreationCmdlines>, session: String) -> Self {
        Self::new(
            records,
            Box::new(move || crate::etw_sessions::flush_session(&session)),
        )
    }

    /// Removes and returns the command line of the process started as `pid` at `started_ns`.
    /// When its record is not there yet, the session is flushed (within the limiter's rate)
    /// and the record is waited for, up to [`CREATION_CMDLINE_WAIT`].
    pub(crate) fn cmdline_of(&self, pid: u32, started_ns: u64) -> Option<String> {
        let already_delivered = self.records.take_within(pid, started_ns, Duration::ZERO);
        if already_delivered.is_some() {
            return already_delivered;
        }
        self.flush_when_due(Instant::now());
        self.records
            .take_within(pid, started_ns, CREATION_CMDLINE_WAIT)
    }

    fn flush_when_due(&self, now: Instant) {
        if !self.limiter.lock_or_recover().claim(now) {
            return;
        }
        if let Err(status) = (self.flush_session)()
            && !self.flush_failure_reported.swap(true, Ordering::Relaxed)
        {
            // Once: a session that is gone fails every flush the same way. The wait still
            // runs, so a record the timer delivers in time is not lost.
            tracing::warn!(
                status,
                "the process creation session could not be flushed; \
                 its records arrive on the session's own timer"
            );
        }
    }

    /// Drops what is kept for `pid`: the process ended, and the pid may be reused.
    pub(crate) fn forget(&self, pid: u32) {
        self.records.forget(pid);
    }
}

struct CreationRecord {
    pid: u32,
    created_ns: u64,
    cmdline: String,
}

/// pid → command line at creation, oldest first, never more than its cap. Written by the
/// creation session's consumer thread and read by the main session's, which is why it locks
/// itself and can wait for a record that is still on its way.
pub(crate) struct CreationCmdlines {
    records: Mutex<VecDeque<CreationRecord>>,
    arrived: Condvar,
    cap: usize,
    shed: ShedCounter,
}

impl CreationCmdlines {
    /// A store whose records dropped at the cap are counted into `shed`.
    ///
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    pub(crate) fn counting(cap: usize, shed: ShedCounter) -> Self {
        assert!(cap >= 1, "creation command lines cap must be >= 1");
        Self {
            records: Mutex::new(VecDeque::new()),
            arrived: Condvar::new(),
            cap,
            shed,
        }
    }

    /// Keeps the command line of the process created as `pid` at `created_ns`. An empty one
    /// is not kept: it says less than the image path the caller falls back to.
    pub(crate) fn record(&self, pid: u32, created_ns: u64, cmdline: String) {
        if cmdline.is_empty() {
            return;
        }
        {
            let mut records = self.records.lock_or_recover();
            drop_expired(&mut records, created_ns);
            if records.len() >= self.cap {
                records.pop_front();
                self.count_shed_record();
            }
            records.push_back(CreationRecord {
                pid,
                created_ns,
                cmdline,
            });
        }
        self.arrived.notify_all();
    }

    fn count_shed_record(&self) {
        let shed_total = self.shed.add();
        // Once per doubling, so a sustained creation storm writes O(log n) lines.
        if shed_total.is_power_of_two() {
            tracing::warn!(
                cap = self.cap,
                shed_total,
                "creation command lines hit their cap; oldest record dropped"
            );
        }
    }

    /// Removes and returns the command line of the process started as `pid` at `started_ns`,
    /// waiting up to `patience` for a record that has not been delivered yet. The record
    /// stamped closest to the start is the one taken, and only within the pairing tolerance:
    /// what an earlier process left under the same pid is never returned.
    pub(crate) fn take_within(
        &self,
        pid: u32,
        started_ns: u64,
        patience: Duration,
    ) -> Option<String> {
        let (mut records, _) = self
            .arrived
            .wait_timeout_while(self.records.lock_or_recover(), patience, |records| {
                closest_record(records, pid, started_ns).is_none()
            })
            .unwrap_or_else(PoisonError::into_inner);
        let index = closest_record(&records, pid, started_ns)?;
        records.remove(index).map(|record| record.cmdline)
    }

    /// Drops what is kept for `pid`: the process ended, and the pid may be reused.
    pub(crate) fn forget(&self, pid: u32) {
        self.records
            .lock_or_recover()
            .retain(|record| record.pid != pid);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.records.lock_or_recover().len()
    }
}

/// Records arrive in the order their session stamped them, so the expired ones are at the front.
fn drop_expired(records: &mut VecDeque<CreationRecord>, now_ns: u64) {
    while records
        .front()
        .is_some_and(|oldest| now_ns.saturating_sub(oldest.created_ns) > MAX_AGE_NS)
    {
        records.pop_front();
    }
}

fn closest_record(records: &VecDeque<CreationRecord>, pid: u32, started_ns: u64) -> Option<usize> {
    records
        .iter()
        .enumerate()
        .filter(|(_, record)| record.pid == pid)
        .map(|(index, record)| (record.created_ns.abs_diff(started_ns), index))
        .filter(|(distance_ns, _)| *distance_ns <= PAIRING_TOLERANCE_NS)
        .min()
        .map(|(_, index)| index)
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread, time::Instant};

    use super::*;

    const PID: u32 = 4242;
    const CREATED_NS: u64 = 1_000_000_000_000;
    const NO_WAIT: Duration = Duration::ZERO;

    fn store(cap: usize) -> CreationCmdlines {
        CreationCmdlines::counting(cap, ShedCounter::default())
    }

    #[test]
    fn taking_a_command_line_removes_it() {
        let cmdlines = store(8);
        cmdlines.record(PID, CREATED_NS, "reg.exe save HKLM\\SYSTEM s".to_owned());

        assert_eq!(
            cmdlines.take_within(PID, CREATED_NS + 1_000, NO_WAIT),
            Some("reg.exe save HKLM\\SYSTEM s".to_owned())
        );
        assert_eq!(cmdlines.take_within(PID, CREATED_NS + 1_000, NO_WAIT), None);
        assert_eq!(cmdlines.len(), 0);
    }

    #[test]
    fn another_pid_gets_nothing() {
        let cmdlines = store(8);
        cmdlines.record(PID, CREATED_NS, "a.exe --flag".to_owned());

        assert_eq!(cmdlines.take_within(PID + 1, CREATED_NS, NO_WAIT), None);
    }

    #[test]
    fn a_recycled_pid_does_not_get_the_previous_process_command_line() {
        let cmdlines = store(8);
        cmdlines.record(PID, CREATED_NS, "previous.exe --secret".to_owned());
        let recycled_at_ns = CREATED_NS + PAIRING_TOLERANCE_NS + 1;

        assert_eq!(cmdlines.take_within(PID, recycled_at_ns, NO_WAIT), None);
    }

    #[test]
    fn a_recycled_pid_gets_its_own_command_line_when_both_are_kept() {
        let cmdlines = store(8);
        let recycled_at_ns = CREATED_NS + PAIRING_TOLERANCE_NS / 2;
        cmdlines.record(PID, CREATED_NS, "previous.exe".to_owned());
        cmdlines.record(PID, recycled_at_ns, "current.exe".to_owned());

        assert_eq!(
            cmdlines.take_within(PID, recycled_at_ns + 1_000, NO_WAIT),
            Some("current.exe".to_owned())
        );
    }

    #[test]
    fn a_stopped_process_leaves_nothing_behind() {
        let cmdlines = store(8);
        cmdlines.record(PID, CREATED_NS, "a.exe --flag".to_owned());
        cmdlines.record(PID + 1, CREATED_NS, "b.exe".to_owned());

        cmdlines.forget(PID);

        assert_eq!(cmdlines.take_within(PID, CREATED_NS, NO_WAIT), None);
        assert_eq!(cmdlines.len(), 1);
    }

    #[test]
    fn a_record_past_the_age_bound_is_dropped_when_a_newer_one_arrives() {
        let shed = ShedCounter::default();
        let cmdlines = CreationCmdlines::counting(8, shed.clone());
        cmdlines.record(PID, CREATED_NS, "old.exe".to_owned());

        cmdlines.record(PID + 1, CREATED_NS + MAX_AGE_NS + 1, "new.exe".to_owned());

        assert_eq!(cmdlines.len(), 1);
        assert_eq!(cmdlines.take_within(PID, CREATED_NS, NO_WAIT), None);
        assert_eq!(shed.get(), 0, "ageing out is not a loss");
    }

    #[test]
    fn the_cap_drops_the_oldest_record_and_counts_it() {
        let shed = ShedCounter::default();
        let cmdlines = CreationCmdlines::counting(2, shed.clone());
        for offset in 0..3u32 {
            cmdlines.record(PID + offset, CREATED_NS, format!("p{offset}.exe"));
        }

        assert_eq!(cmdlines.len(), 2);
        assert_eq!(shed.get(), 1);
        assert_eq!(cmdlines.take_within(PID, CREATED_NS, NO_WAIT), None);
        assert_eq!(
            cmdlines.take_within(PID + 2, CREATED_NS, NO_WAIT),
            Some("p2.exe".to_owned())
        );
    }

    #[test]
    fn an_empty_command_line_is_not_kept() {
        let cmdlines = store(8);
        cmdlines.record(PID, CREATED_NS, String::new());

        assert_eq!(cmdlines.len(), 0);
    }

    #[test]
    fn the_wait_returns_as_soon_as_the_record_arrives() {
        let cmdlines = Arc::new(store(8));
        let writer = {
            let cmdlines = Arc::clone(&cmdlines);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                cmdlines.record(PID, CREATED_NS, "late.exe --flag".to_owned());
            })
        };
        let far_bound = Duration::from_secs(30);
        let asked_at = Instant::now();

        let taken = cmdlines.take_within(PID, CREATED_NS, far_bound);

        assert_eq!(taken, Some("late.exe --flag".to_owned()));
        assert!(asked_at.elapsed() < far_bound / 2);
        writer.join().expect("writer thread");
    }

    #[test]
    fn the_wait_is_not_ended_by_another_process_record() {
        let cmdlines = Arc::new(store(8));
        let writer = {
            let cmdlines = Arc::clone(&cmdlines);
            thread::spawn(move || cmdlines.record(PID + 1, CREATED_NS, "other.exe".to_owned()))
        };
        writer.join().expect("writer thread");

        assert_eq!(
            cmdlines.take_within(PID, CREATED_NS, Duration::from_millis(20)),
            None
        );
    }

    /// Creation records behind a session whose flushes are counted and answer `flush_result`.
    fn on_demand(
        records: &Arc<CreationCmdlines>,
        flush_result: Result<(), u32>,
    ) -> (OnDemandCmdlines, ShedCounter) {
        let flushes = ShedCounter::default();
        let counted = flushes.clone();
        let source = OnDemandCmdlines::new(
            Arc::clone(records),
            Box::new(move || {
                counted.add();
                flush_result
            }),
        );
        (source, flushes)
    }

    #[test]
    fn a_record_already_delivered_is_taken_without_a_flush() {
        let records = Arc::new(store(8));
        records.record(PID, CREATED_NS, "a.exe --flag".to_owned());
        let (source, flushes) = on_demand(&records, Ok(()));

        assert_eq!(
            source.cmdline_of(PID, CREATED_NS),
            Some("a.exe --flag".to_owned())
        );
        assert_eq!(flushes.get(), 0);
    }

    #[test]
    fn a_process_end_drops_its_record_before_a_start_under_the_same_pid_asks() {
        let records = Arc::new(store(8));
        records.record(PID, CREATED_NS, "ended.exe --secret".to_owned());
        let (source, _) = on_demand(&records, Ok(()));

        source.forget(PID);

        assert_eq!(source.cmdline_of(PID, CREATED_NS), None);
    }

    #[test]
    fn a_missing_record_flushes_the_session_and_is_taken_when_the_flush_delivers_it() {
        let records = Arc::new(store(8));
        let delivered_by_the_flush = Arc::clone(&records);
        let source = OnDemandCmdlines::new(
            Arc::clone(&records),
            Box::new(move || {
                delivered_by_the_flush.record(PID, CREATED_NS, "late.exe --flag".to_owned());
                Ok(())
            }),
        );

        assert_eq!(
            source.cmdline_of(PID, CREATED_NS),
            Some("late.exe --flag".to_owned())
        );
    }

    #[test]
    fn a_failed_flush_still_waits_for_the_record_and_then_gives_up() {
        const ERROR_WMI_INSTANCE_NOT_FOUND: u32 = 4201;
        let records = Arc::new(store(8));
        let (source, flushes) = on_demand(&records, Err(ERROR_WMI_INSTANCE_NOT_FOUND));
        let asked_at = Instant::now();

        assert_eq!(source.cmdline_of(PID, CREATED_NS), None);
        assert!(asked_at.elapsed() >= CREATION_CMDLINE_WAIT);
        assert_eq!(flushes.get(), 1);
    }

    #[test]
    fn a_burst_of_missing_records_flushes_once_per_interval() {
        let records = Arc::new(store(8));
        let (source, flushes) = on_demand(&records, Ok(()));
        let burst_at = Instant::now();

        for _ in 0..100 {
            source.flush_when_due(burst_at);
        }
        assert_eq!(flushes.get(), 1);

        source.flush_when_due(burst_at + MIN_FLUSH_INTERVAL);
        assert_eq!(flushes.get(), 2);
    }

    #[test]
    fn the_limiter_allows_the_first_flush_and_the_next_one_an_interval_later() {
        let mut limiter = FlushLimiter::default();
        let first = Instant::now();

        assert!(limiter.claim(first));
        assert!(!limiter.claim(first));
        assert!(!limiter.claim(first + MIN_FLUSH_INTERVAL - Duration::from_nanos(1)));
        assert!(limiter.claim(first + MIN_FLUSH_INTERVAL));
        assert!(!limiter.claim(first + MIN_FLUSH_INTERVAL + Duration::from_nanos(1)));
    }

    #[test]
    fn a_refused_flush_does_not_postpone_the_next_one() {
        let mut limiter = FlushLimiter::default();
        let first = Instant::now();
        limiter.claim(first);

        limiter.claim(first + MIN_FLUSH_INTERVAL / 2);

        assert!(limiter.claim(first + MIN_FLUSH_INTERVAL));
    }

    #[test]
    fn the_wait_gives_up_after_its_bound() {
        let cmdlines = store(8);
        let bound = Duration::from_millis(30);
        let asked_at = Instant::now();

        assert_eq!(cmdlines.take_within(PID, CREATED_NS, bound), None);
        assert!(asked_at.elapsed() >= bound);
    }
}
