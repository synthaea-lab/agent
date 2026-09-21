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
}

/// Policy-gates a process kill. When disabled, `terminate` is never called — the
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
}
