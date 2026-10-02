//! Escalation: the first response decision that reads the fused per-entity verdict
//! (issue #612) instead of a single engine's raw output.
//!
//! Deliberately non-destructive: escalating raises an audit alert for analyst
//! attention and never touches a process or a file, so it needs no policy flag and
//! is safe on a severity that is still partly placeholder (built-in rules carry a
//! default until they get real severity). The kill gate stays on the correlator's
//! own `BAYES` crossing: the fused severity is a sticky max over everything ever
//! seen for an entity, too coarse to gate a destructive action on.
//!
//! `response` is base-tier-only, so the decision takes the verdict's severity as
//! data rather than depending on the `verdict` crate.

use schema::detection::Severity;

/// The lowest fused severity that warrants analyst escalation.
pub const ESCALATION_THRESHOLD: Severity = Severity::High;

/// Whether an entity whose fused verdict has reached `severity` should be escalated.
#[must_use]
pub fn should_escalate(severity: Severity) -> bool {
    severity >= ESCALATION_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_high_and_critical_fused_severity_escalates() {
        assert!(!should_escalate(Severity::Low));
        assert!(!should_escalate(Severity::Medium));
        assert!(should_escalate(Severity::High));
        assert!(should_escalate(Severity::Critical));
    }
}
