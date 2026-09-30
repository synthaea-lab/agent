//! Automated process termination on a high-confidence correlated verdict (issue #25).
//!
//! Platform-neutral by construction: `response` is base-tier-only
//! (`tools/check-deps.py` — leaf crates depend on `schema`+`policy` alone), and
//! CLAUDE.md reserves `#[cfg(target_os = ...)]`/platform-only deps for
//! `crates/sensors/*`. The actual OS-level termination call is therefore injected by
//! the caller (`agent`, which already dispatches per-platform in `commands/`) rather
//! than living here — this module owns only the policy gate and the outcome shape.

use policy::ResponsePolicy;

/// What happened to a kill attempt — returned whether or not policy allowed it to
/// actually run, so a caller auditing the outcome has one shape either way (issue
/// #25's "policy off = observe-only" acceptance criterion: observing is not a
/// different code path from acting, just a different variant of the same result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillOutcome {
    /// The process was signaled; `terminate` reported success.
    Killed { pid: u32 },
    /// `policy.kill_enabled` was false — no signal was sent.
    ObserveOnly { pid: u32 },
    /// `policy.kill_enabled` was true, but `terminate` failed (already exited,
    /// permission denied, ...). `error` is `terminate`'s error rendered to a string,
    /// not a structured type — this crate has no opinion on the caller's OS error type.
    Failed { pid: u32, error: String },
    /// The pid is one this crate never signals, whatever the policy says (see
    /// [`protected_reason`]). Reported instead of [`KillOutcome::ObserveOnly`]
    /// even with kill disabled, so the audit line says the truth: it would not
    /// have been killed, rather than that it would have.
    Refused { pid: u32, reason: &'static str },
}

/// Why `pid` must never be handed to `terminate`, or `None` when it may be.
///
/// The pid comes from telemetry, and `terminate` is a privileged `SIGKILL` by
/// number, so a wrong number must fail closed. On Unix `kill(0, ..)` signals the
/// caller's whole process group and a negative pid signals a group or every
/// process: a `u32` that does not fit `pid_t` wraps to exactly that. Killing init
/// or the agent itself is never the intended response.
fn protected_reason(pid: u32, own_pid: u32) -> Option<&'static str> {
    if pid == 0 {
        Some("pid 0 addresses a process group, not a process")
    } else if i32::try_from(pid).is_err() {
        Some("pid does not fit a signed pid_t and would address a process group")
    } else if pid == 1 {
        Some("pid 1 is init")
    } else if pid == own_pid {
        Some("the agent's own pid")
    } else {
        None
    }
}

/// Policy-gates a process kill, after refusing the pids [`protected_reason`]
/// names. When disabled, `terminate` is never called — the
/// verdict that would have triggered a kill still produces a real outcome to audit,
/// just [`KillOutcome::ObserveOnly`] instead of an actual signal.
///
/// # Errors
///
/// Never returns `Err`; a `terminate` failure is reported as
/// [`KillOutcome::Failed`], not propagated, so a caller auditing every outcome
/// doesn't also need a separate error path for the same event.
#[must_use]
pub fn kill_process(
    pid: u32,
    policy: &ResponsePolicy,
    terminate: impl FnOnce(u32) -> std::io::Result<()>,
) -> KillOutcome {
    if let Some(reason) = protected_reason(pid, std::process::id()) {
        return KillOutcome::Refused { pid, reason };
    }
    if !policy.kill_enabled {
        return KillOutcome::ObserveOnly { pid };
    }
    match terminate(pid) {
        Ok(()) => KillOutcome::Killed { pid },
        Err(e) => KillOutcome::Failed {
            pid,
            error: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_disabled_never_calls_terminate() {
        let policy = ResponsePolicy {
            kill_enabled: false,
            quarantine_enabled: false,
        };
        let outcome = kill_process(1234, &policy, |_| {
            panic!("terminate must not be called when kill is disabled")
        });
        assert_eq!(outcome, KillOutcome::ObserveOnly { pid: 1234 });
    }

    #[test]
    fn policy_enabled_calls_terminate_and_reports_success() {
        let policy = ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
        };
        let outcome = kill_process(1234, &policy, |pid| {
            assert_eq!(pid, 1234);
            Ok(())
        });
        assert_eq!(outcome, KillOutcome::Killed { pid: 1234 });
    }

    #[test]
    fn a_terminate_failure_is_reported_not_propagated() {
        let policy = ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
        };
        let outcome = kill_process(1234, &policy, |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such process",
            ))
        });
        assert_eq!(
            outcome,
            KillOutcome::Failed {
                pid: 1234,
                error: "no such process".to_string()
            }
        );
    }

    #[test]
    fn a_protected_pid_is_refused_and_never_terminated_even_with_kill_enabled() {
        let policy = ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
        };
        for pid in [
            0,
            1,
            std::process::id(),
            u32::from(u16::MAX) + i32::MAX as u32,
        ] {
            let outcome = kill_process(pid, &policy, |_| {
                panic!("terminate must not be called for protected pid {pid}")
            });
            assert!(
                matches!(outcome, KillOutcome::Refused { pid: p, .. } if p == pid),
                "pid {pid}: {outcome:?}"
            );
        }
    }

    #[test]
    fn pid_zero_is_refused_not_reported_as_observe_only_when_kill_is_off() {
        // `kill(0, ..)` signals the caller's process group: even the audit line
        // for a disabled policy must not claim it "would have been killed".
        let outcome = kill_process(0, &ResponsePolicy::default(), |_| Ok(()));
        assert!(
            matches!(outcome, KillOutcome::Refused { pid: 0, .. }),
            "{outcome:?}"
        );
    }

    #[test]
    fn the_largest_valid_pid_is_not_protected() {
        let policy = ResponsePolicy {
            kill_enabled: true,
            quarantine_enabled: false,
        };
        let pid = i32::MAX as u32;
        assert_eq!(
            kill_process(pid, &policy, |_| Ok(())),
            KillOutcome::Killed { pid }
        );
    }
}
