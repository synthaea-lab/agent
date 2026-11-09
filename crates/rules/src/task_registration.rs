//! T1053.005 scheduled-task creation, deduplicated across the two channels that report it
//! ([`TaskRegistrations::check`]).

use schema::{FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN, FileOpenEvent};
use store::BoundedMap;

use crate::{Alert, exclusions::TASK_REGISTRATION_DEDUP_WINDOW_NS, state::COUNTER_CAP};

struct ReportedTaskRegistration {
    timestamp_ns: u64,
    /// The reported action list, `None` for an unknown-action report (its path
    /// is only the sensor's placeholder).
    actions: Option<String>,
}

/// Task leaf name → last reported T1053.005 registration, so one registration seen on both
/// Security 4698 and TaskScheduler/Operational 106 alerts once (#422). LRU-bounded like the
/// counters.
pub(crate) struct TaskRegistrations {
    reported: BoundedMap<String, ReportedTaskRegistration>,
}

impl TaskRegistrations {
    pub(crate) fn new() -> Self {
        Self {
            reported: BoundedMap::new(COUNTER_CAP),
        }
    }

    /// T1053.005 creation (`check_scheduled_task_persistence`), reported once per
    /// registration. With both channels up, one `schtasks /Create` yields a 4698 and
    /// a 106 for the same task, in either order a few seconds apart; the sensor
    /// reads the 106's actions back from the task file, so the two usually match.
    ///
    /// A registration of an already-reported task inside
    /// [`TASK_REGISTRATION_DEDUP_WINDOW_NS`] is suppressed only when it adds
    /// nothing: an unknown-action report, or the same action list. A different
    /// action list alerts (a re-registration with a new payload), and so does a
    /// known action list after an unknown-action report, so the first-arriving
    /// 106 whose task file was unreadable never hides the 4698's actions.
    pub(crate) fn check(&mut self, event: &FileOpenEvent) -> Option<Alert> {
        let alert = crate::stateless::check_scheduled_task_persistence(event)?;
        let actions =
            (event.flags & FLAG_PERSISTENCE_TASK_ACTION_UNKNOWN == 0).then(|| event.path.clone());
        let now = event.meta.timestamp_ns;
        let duplicate = self
            .reported
            .peek(&event.meta.comm)
            .is_some_and(|previous| {
                previous.timestamp_ns.abs_diff(now) <= TASK_REGISTRATION_DEDUP_WINDOW_NS
                    && (actions.is_none() || actions == previous.actions)
            });
        if duplicate {
            return None;
        }
        self.reported.insert(
            event.meta.comm.clone(),
            ReportedTaskRegistration {
                timestamp_ns: now,
                actions,
            },
        );
        Some(alert)
    }
}
