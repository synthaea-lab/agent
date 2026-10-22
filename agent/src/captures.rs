//! The optional uprobe captures, widenable at run time (#62 box 2, ADR-0035 first slice).
//!
//! `--enable-tls-capture`, `--enable-readline-capture` and `--enable-dns-capture` are read once
//! at start. A [`CaptureSet`] keeps what the operator configured and, on top of it, what a live
//! posture overlay widened; the effective set is the union of the two.
//!
//! **Heighten-only is a property of the API, not of the caller.** The only operations are
//! [`CaptureSet::widen`] (a union) and [`CaptureSet::reset`] (back to the configured set):
//! nothing can remove a capture the operator turned on, and nothing can turn one off that is not
//! widened. There is no overlay, no signature and no expiry here: the composition of several
//! overlays comes with the document that carries them (ADR-0035, third slice).
//!
//! The uprobes thread cannot change its captures while it runs (`UprobesSensor::run_async`
//! reads its config once and attaches the probes once), so a change restarts the thread with the
//! new set. **The restart leaves a gap in capture** while the eBPF object is unloaded and loaded
//! again, on the way up and again on the way down when a widening ends. [`plan`] decides what
//! the supervisor in `commands/linux.rs` does.
//!
//! Applying an overlay on a host under a compliance mode (`UprobesConfig::with_compliance_mode`,
//! which the agent does not call today) is not decided here: it belongs to the slice that applies
//! overlays.

use std::sync::{Arc, Condvar, Mutex};

/// Which of the three optional captures are on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Captures {
    pub(crate) tls: bool,
    pub(crate) readline: bool,
    pub(crate) dns: bool,
}

impl Captures {
    pub(crate) const NONE: Self = Self {
        tls: false,
        readline: false,
        dns: false,
    };

    pub(crate) fn union(self, other: Self) -> Self {
        Self {
            tls: self.tls || other.tls,
            readline: self.readline || other.readline,
            dns: self.dns || other.dns,
        }
    }

    pub(crate) fn is_empty(self) -> bool {
        self == Self::NONE
    }

    /// True when every capture on in `other` is on in `self`.
    #[cfg(test)]
    pub(crate) fn contains(self, other: Self) -> bool {
        self.union(other) == self
    }
}

struct State {
    configured: Captures,
    widened: Captures,
}

impl State {
    fn effective(&self) -> Captures {
        self.configured.union(self.widened)
    }
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

/// The configured captures, widened by whatever is live. Cloning shares the state.
#[derive(Clone)]
pub(crate) struct CaptureSet {
    shared: Arc<Shared>,
}

impl CaptureSet {
    pub(crate) fn new(configured: Captures) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    configured,
                    widened: Captures::NONE,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    /// The captures that should be running now: the configured ones plus the widened ones.
    pub(crate) fn effective(&self) -> Captures {
        self.shared.state.lock().unwrap().effective()
    }

    /// Adds `extra` to what is widened. Returns whether the effective set changed.
    // Nothing calls this until the overlay slice (ADR-0035, third slice) applies a document.
    #[allow(dead_code)]
    pub(crate) fn widen(&self, extra: Captures) -> bool {
        self.change(|state| state.widened = state.widened.union(extra))
    }

    /// Drops what was widened, back to the configured set. Returns whether the effective set
    /// changed.
    #[allow(dead_code)]
    pub(crate) fn reset(&self) -> bool {
        self.change(|state| state.widened = Captures::NONE)
    }

    fn change(&self, edit: impl FnOnce(&mut State)) -> bool {
        let mut state = self.shared.state.lock().unwrap();
        let before = state.effective();
        edit(&mut state);
        let changed = state.effective() != before;
        if changed {
            self.shared.changed.notify_all();
        }
        changed
    }

    /// Blocks until the effective set differs from `current`, and returns it. Returns at once
    /// when it already differs. A widening that is reset before the caller looks does not wake
    /// it: only the set it would act on counts.
    pub(crate) fn wait_until_differs(&self, current: Captures) -> Captures {
        let guard = self.shared.state.lock().unwrap();
        let guard = self
            .shared
            .changed
            .wait_while(guard, |state| state.effective() == current)
            .unwrap();
        guard.effective()
    }
}

/// What the supervisor does to bring the running uprobes thread to the wanted set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UprobesAction {
    /// Already running what is wanted, or nothing running and nothing wanted.
    Idle,
    /// Nothing is running and something is wanted: start the thread, register its heartbeat with
    /// the silence monitor.
    Start(Captures),
    /// Running with another set: stop the thread, start a new one. Capture has a gap in between.
    Restart(Captures),
    /// Something is running and nothing is wanted: stop the thread and stop watching its
    /// heartbeat, or a capture that was switched off would read as a silent sensor.
    Stop,
}

/// `running` is [`Captures::NONE`] when no thread runs.
pub(crate) fn plan(running: Captures, wanted: Captures) -> UprobesAction {
    match (running.is_empty(), wanted.is_empty()) {
        _ if running == wanted => UprobesAction::Idle,
        (true, false) => UprobesAction::Start(wanted),
        (false, true) => UprobesAction::Stop,
        (false, false) => UprobesAction::Restart(wanted),
        (true, true) => UprobesAction::Idle,
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Duration};

    use super::*;

    /// Every combination of the three captures.
    fn all() -> Vec<Captures> {
        (0..8u8)
            .map(|bits| Captures {
                tls: bits & 1 != 0,
                readline: bits & 2 != 0,
                dns: bits & 4 != 0,
            })
            .collect()
    }

    const TLS: Captures = Captures {
        tls: true,
        readline: false,
        dns: false,
    };
    const READLINE: Captures = Captures {
        tls: false,
        readline: true,
        dns: false,
    };
    const DNS: Captures = Captures {
        tls: false,
        readline: false,
        dns: true,
    };

    #[test]
    fn a_new_set_is_what_was_configured() {
        for configured in all() {
            assert_eq!(CaptureSet::new(configured).effective(), configured);
        }
    }

    #[test]
    fn widening_is_the_union_with_the_configured_set() {
        for configured in all() {
            for extra in all() {
                let set = CaptureSet::new(configured);
                set.widen(extra);
                assert_eq!(set.effective(), configured.union(extra));
            }
        }
    }

    #[test]
    fn two_widenings_add_up_until_a_reset() {
        for configured in all() {
            let set = CaptureSet::new(configured);
            set.widen(DNS);
            set.widen(READLINE);
            assert_eq!(set.effective(), configured.union(DNS).union(READLINE));
            set.reset();
            assert_eq!(set.effective(), configured);
        }
    }

    #[test]
    fn widening_reports_whether_anything_changed() {
        let set = CaptureSet::new(TLS);

        assert!(!set.widen(TLS), "already configured");
        assert!(!set.widen(Captures::NONE), "an empty widening");
        assert!(set.widen(DNS));
        assert!(!set.widen(DNS), "already widened");
        assert!(set.widen(READLINE));
    }

    #[test]
    fn reset_goes_back_to_the_configured_set_and_never_below_it() {
        for configured in all() {
            for extra in all() {
                let set = CaptureSet::new(configured);
                set.widen(extra);
                let changed = set.reset();
                assert_eq!(set.effective(), configured);
                assert_eq!(changed, !configured.contains(extra));
            }
        }
    }

    #[test]
    fn reset_with_nothing_widened_changes_nothing() {
        let set = CaptureSet::new(TLS);

        assert!(!set.reset());
        assert_eq!(set.effective(), TLS);
    }

    #[test]
    fn nothing_the_api_offers_can_turn_a_configured_capture_off() {
        // Every sequence of up to four operations, each one a widening by any set or a reset.
        let ops: Vec<Option<Captures>> = std::iter::once(None)
            .chain(all().into_iter().map(Some))
            .collect();
        for configured in all() {
            let mut sequences: Vec<Vec<Option<Captures>>> = vec![vec![]];
            for _ in 0..4 {
                let mut next = Vec::new();
                for seq in &sequences {
                    for op in &ops {
                        let mut extended = seq.clone();
                        extended.push(*op);
                        next.push(extended);
                    }
                }
                sequences = next;
                for seq in &sequences {
                    let set = CaptureSet::new(configured);
                    for op in seq {
                        match op {
                            Some(extra) => {
                                set.widen(*extra);
                            }
                            None => {
                                set.reset();
                            }
                        }
                        assert!(
                            set.effective().contains(configured),
                            "{configured:?} lost after {seq:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_clone_shares_the_state() {
        let set = CaptureSet::new(Captures::NONE);
        let other = set.clone();

        other.widen(DNS);

        assert_eq!(set.effective(), DNS);
    }

    #[test]
    fn waiting_returns_at_once_when_the_set_already_differs() {
        let set = CaptureSet::new(TLS);

        assert_eq!(set.wait_until_differs(Captures::NONE), TLS);
    }

    #[test]
    fn waiting_wakes_when_the_set_is_widened() {
        let set = CaptureSet::new(TLS);
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let waiter = {
            let set = set.clone();
            thread::spawn(move || {
                waiting_tx.send(()).unwrap();
                set.wait_until_differs(TLS)
            })
        };
        waiting_rx.recv().unwrap();
        // The waiter may or may not be parked yet: the predicate is re-checked, so both orders
        // return the widened set.
        thread::sleep(Duration::from_millis(20));

        set.widen(READLINE);

        assert_eq!(waiter.join().unwrap(), TLS.union(READLINE));
    }

    #[test]
    fn a_widening_reset_before_the_waiter_looks_does_not_wake_it() {
        let set = CaptureSet::new(TLS);
        set.widen(DNS);
        set.reset();

        // The set is back to what the waiter acts on: only a real difference returns.
        let (tx, rx) = mpsc::channel();
        let waiter = {
            let set = set.clone();
            thread::spawn(move || tx.send(set.wait_until_differs(TLS)).unwrap())
        };
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "it must still wait"
        );

        set.widen(READLINE);

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            TLS.union(READLINE)
        );
        waiter.join().unwrap();
    }

    #[test]
    fn plan_starts_a_thread_when_something_is_wanted_and_nothing_runs() {
        assert_eq!(plan(Captures::NONE, TLS), UprobesAction::Start(TLS));
    }

    #[test]
    fn plan_restarts_with_the_new_set_when_the_running_one_differs() {
        assert_eq!(
            plan(TLS, TLS.union(DNS)),
            UprobesAction::Restart(TLS.union(DNS)),
            "widened"
        );
        assert_eq!(
            plan(TLS.union(DNS), TLS),
            UprobesAction::Restart(TLS),
            "a widening ended"
        );
    }

    #[test]
    fn plan_stops_when_nothing_is_wanted_any_more() {
        assert_eq!(plan(TLS, Captures::NONE), UprobesAction::Stop);
    }

    #[test]
    fn plan_does_nothing_when_the_running_set_is_the_wanted_one() {
        for set in all() {
            assert_eq!(plan(set, set), UprobesAction::Idle);
        }
    }

    #[test]
    fn plan_never_starts_a_thread_for_an_empty_set() {
        for running in all() {
            for wanted in all() {
                if let UprobesAction::Start(set) | UprobesAction::Restart(set) =
                    plan(running, wanted)
                {
                    assert!(!set.is_empty(), "{running:?} -> {wanted:?}");
                    assert_eq!(set, wanted);
                }
            }
        }
    }

    #[test]
    fn plan_registers_the_heartbeat_only_while_something_runs() {
        // The supervisor registers on `Start` and unregisters on `Stop`; a `Restart` keeps the
        // registration (the sensor is expected to run again within the silence deadline).
        for running in all() {
            for wanted in all() {
                let after = match plan(running, wanted) {
                    UprobesAction::Idle => running,
                    UprobesAction::Start(set) | UprobesAction::Restart(set) => set,
                    UprobesAction::Stop => Captures::NONE,
                };
                assert_eq!(after, wanted, "{running:?} -> {wanted:?}");
            }
        }
    }
}
