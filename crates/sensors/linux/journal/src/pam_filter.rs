//! The two adjustments made to PAM authentication failures before they leave the crate.
//!
//! [`ClassifiedJournal`](crate::ClassifiedJournal) reads lines and classifies them; this stage
//! decides which of the `PamAuthFailure`s it classified are real:
//!
//! - A `pam_sss` failure is held for one more record, in case that record says the user is
//!   unknown to sssd (`PAM_USER_UNKNOWN`, [`pam_sss_reports_user_unknown`]). Then it was never a
//!   failed password (#881). A failure still held when the stream ends was never refuted and is
//!   released by [`PamFailureFilter::finish`].
//! - A failure from the same pid as an earlier one, logged by a **different** PAM module within
//!   [`DOUBLE_LOG_DEDUP_WINDOW_US`], is the same attempt logged twice by two stacked modules and
//!   is dropped.
//!
//! The stage is pure: records in, records out, no I/O and no clock.

use std::collections::VecDeque;

use crate::{JournalEvent, JournalRecord, classify::pam_sss_reports_user_unknown};

/// Distinct `(pid, module, realtime_us)` entries remembered for
/// [`PamFailureFilter::is_duplicate`]. Small on purpose: only recent, nearby-in-time
/// entries are ever looked up, so nothing is lost by evicting the oldest once a
/// host has enough concurrent `sudo`/`su` invocations in flight to fill this.
const RECENT_PAM_FAILURES_CAP: usize = 64;

/// How close two `PamAuthFailure`s from the same pid but **different** PAM
/// modules have to be to treat the second as the first double-logged by a
/// second stacked module, not a second real attempt (#881 review,
/// `SherlockOmss` 2026-10-22: `pam_unix` and `pam_sss` both authenticating one
/// account would otherwise double-count one wrong password toward `sudo.rs`'s
/// T1548.003 threshold). Module, not just pid, is the signal that matters here:
/// `sudo`'s own password retries reuse the *same* pid and the *same* module for
/// each real attempt (see `agent`'s `sudo_join_tests::five_failed_sudo_passwords_then_a_success_alert_once`,
/// which spaces five genuine same-module failures exactly one second apart on
/// one pid) — pid alone would have wrongly folded those into one. Two PAM
/// modules stacked for the one account instead both log their own failure line
/// from within the *same* libpam stack evaluation, microseconds apart; one
/// second is a reasoned guess at a safe upper bound on that gap, not a
/// measurement from a real stacked host — nothing here has verified it against
/// a real sssd-stacked `sudo`.
const DOUBLE_LOG_DEDUP_WINDOW_US: u64 = 1_000_000;

/// Which PAM module logged a `PamAuthFailure` line — the signal
/// [`PamFailureFilter::is_duplicate`] keys on, since only a *different* module for the same
/// pid in the same instant indicates one attempt double-logged by two stacked authenticators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PamModule {
    Unix,
    Sss,
}

/// The PAM module that logged `message`, if any — `None` for a record this
/// crate doesn't otherwise treat as PAM-sourced.
fn pam_module(message: &str) -> Option<PamModule> {
    if message.starts_with("pam_unix(") {
        Some(PamModule::Unix)
    } else if message.starts_with("pam_sss(") {
        Some(PamModule::Sss)
    } else {
        None
    }
}

/// A record and the event it classified as, ready to leave the crate.
pub(crate) type Classified = (JournalRecord, JournalEvent);

/// Holds back and drops `PamAuthFailure`s that are not real, and passes everything else through
/// in order. See the module doc.
#[derive(Default)]
pub(crate) struct PamFailureFilter {
    /// A `pam_sss` `PamAuthFailure` classified but not yet released, waiting to see whether the
    /// next record is its own "received for user ...: 10 (...)" line. Carries the normalized
    /// service (`"sudo"`/`"su"`) the failure matched, to compare against
    /// [`pam_sss_reports_user_unknown`].
    pending_sss_failure: Option<(JournalRecord, JournalEvent, String)>,
    /// `(pid, module, realtime_us)` of recently released `PamAuthFailure`s, oldest first.
    recent_pam_failures: VecDeque<(u32, PamModule, u64)>,
}

impl PamFailureFilter {
    /// Takes the next record and the event it classified as (`None` for a record the allowlist
    /// does not match) and returns what can leave the crate now, in order: usually nothing or
    /// one item, two when this record releases a held failure and passes itself on.
    ///
    /// A record without an event still matters: it can be the line that refutes a held failure.
    pub(crate) fn push(
        &mut self,
        record: JournalRecord,
        event: Option<JournalEvent>,
    ) -> Vec<Classified> {
        let mut out = Vec::new();

        if let Some((held_record, held_event, held_service)) = self.pending_sss_failure.take() {
            if pam_sss_reports_user_unknown(&record.message, &held_service) {
                // Confirmed PAM_USER_UNKNOWN: the held failure was never a real one, and this
                // "received for user" line is not an event of its own. Drop both.
                return out;
            }
            // Not a confirmation: the held failure stands, and `record` is handled below as
            // the fresh record it is.
            if !self.is_duplicate(&held_record) {
                out.push((held_record, held_event));
            }
        }

        // Allowlist miss: nothing to yield, only matches leave the crate.
        let Some(event) = event else {
            return out;
        };

        if record.message.starts_with("pam_sss(")
            && let JournalEvent::PamAuthFailure { service, .. } = &event
        {
            let service = service.clone();
            self.pending_sss_failure = Some((record, event, service));
            return out;
        }

        if matches!(event, JournalEvent::PamAuthFailure { .. }) && self.is_duplicate(&record) {
            return out;
        }

        out.push((record, event));
        out
    }

    /// Releases a held failure at the end of the stream. A failure whose confirming line never
    /// came was never refuted: the journal stopping right after it is not a refutation. It still
    /// goes through the double-log dedup.
    pub(crate) fn finish(&mut self) -> Vec<Classified> {
        let Some((record, event, _)) = self.pending_sss_failure.take() else {
            return Vec::new();
        };
        if self.is_duplicate(&record) {
            Vec::new()
        } else {
            vec![(record, event)]
        }
    }

    /// True when `record` shares a pid with an already-released `PamAuthFailure` from a
    /// **different** PAM module, close enough in time to be the same attempt double-logged by a
    /// second stacked module rather than a second real one — and, if not, remembers this one for
    /// the next call. Two failures from the same pid and the *same* module (e.g. `sudo`'s own
    /// password retries, all `pam_unix`) are never treated as duplicates regardless of spacing:
    /// pid alone doesn't distinguish a double-log from a second real attempt, only the module
    /// does. A record with no parseable `_PID`, or no recognized PAM module prefix, is never
    /// treated as a duplicate: there is nothing to correlate it against, and silently dropping
    /// an event over a missing optional field is worse than double-counting it.
    fn is_duplicate(&mut self, record: &JournalRecord) -> bool {
        let Some(pid) = record.pid.as_deref().and_then(|p| p.parse::<u32>().ok()) else {
            return false;
        };
        let Some(module) = pam_module(&record.message) else {
            return false;
        };
        let is_duplicate =
            self.recent_pam_failures
                .iter()
                .any(|&(seen_pid, seen_module, seen_us)| {
                    seen_pid == pid
                        && seen_module != module
                        && record.realtime_us.saturating_sub(seen_us) <= DOUBLE_LOG_DEDUP_WINDOW_US
                });
        if !is_duplicate {
            self.recent_pam_failures
                .push_back((pid, module, record.realtime_us));
            if self.recent_pam_failures.len() > RECENT_PAM_FAILURES_CAP {
                self.recent_pam_failures.pop_front();
            }
        }
        is_duplicate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{classify, parse_record};

    fn feed(filter: &mut PamFailureFilter, line: &str) -> Vec<String> {
        let record = parse_record(line).unwrap();
        let event = classify(&record);
        filter
            .push(record, event)
            .into_iter()
            .map(|(record, _)| record.cursor)
            .collect()
    }

    fn failure(cursor: &str, us: u64, pid: u32, module: &str) -> String {
        format!(
            r#"{{"__CURSOR":"{cursor}","__REALTIME_TIMESTAMP":"{us}","SYSLOG_IDENTIFIER":"sudo","_PID":"{pid}","MESSAGE":"{module}(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}}"#
        )
    }

    #[test]
    fn a_pam_unix_failure_is_released_at_once() {
        let mut filter = PamFailureFilter::default();
        assert_eq!(
            feed(&mut filter, &failure("c1", 1, 100, "pam_unix")),
            ["c1"]
        );
        assert!(filter.finish().is_empty());
    }

    #[test]
    fn a_pam_sss_failure_is_held_until_the_next_record() {
        let mut filter = PamFailureFilter::default();
        assert!(feed(&mut filter, &failure("c1", 1, 100, "pam_sss")).is_empty());

        let unrelated = r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","_PID":"1","JOB_TYPE":"stop","JOB_RESULT":"done","UNIT":"x.service","MESSAGE":"Stopped x.service."}"#;
        assert_eq!(feed(&mut filter, unrelated), ["c1", "c2"]);
    }

    #[test]
    fn a_refuting_record_without_an_event_drops_the_held_failure() {
        let mut filter = PamFailureFilter::default();
        assert!(feed(&mut filter, &failure("c1", 1, 100, "pam_sss")).is_empty());

        let refutation = r#"{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2","SYSLOG_IDENTIFIER":"sudo","_PID":"100","MESSAGE":"pam_sss(sudo:auth): received for user omss: 10 (User not known to the underlying authentication module)"}"#;
        let record = parse_record(refutation).unwrap();
        assert!(classify(&record).is_none(), "the refuting line is no event");
        assert!(filter.push(record, None).is_empty());
        assert!(filter.finish().is_empty(), "nothing is left held");
    }

    #[test]
    fn finish_releases_a_held_failure_that_was_never_refuted() {
        let mut filter = PamFailureFilter::default();
        assert!(feed(&mut filter, &failure("c1", 1, 100, "pam_sss")).is_empty());

        let released = filter.finish();
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].0.cursor, "c1");
        assert!(filter.finish().is_empty(), "released once");
    }

    #[test]
    fn a_stacked_module_inside_the_window_is_a_double_log_and_outside_it_is_not() {
        let mut filter = PamFailureFilter::default();
        assert_eq!(
            feed(&mut filter, &failure("c1", 1_000_000, 100, "pam_unix")),
            ["c1"]
        );
        // `pam_sss` is held, then judged when the stream ends.
        assert!(feed(&mut filter, &failure("c2", 1_500_000, 100, "pam_sss")).is_empty());
        assert!(filter.finish().is_empty(), "0.5 s apart: the same attempt");

        assert!(feed(&mut filter, &failure("c3", 9_000_000, 100, "pam_sss")).is_empty());
        let released = filter.finish();
        assert_eq!(released.len(), 1, "8 s apart: a second real attempt");
        assert_eq!(released[0].0.cursor, "c3");
    }

    #[test]
    fn a_record_without_a_pid_is_never_a_duplicate() {
        let mut filter = PamFailureFilter::default();
        let no_pid = |cursor: &str, module: &str| {
            format!(
                r#"{{"__CURSOR":"{cursor}","__REALTIME_TIMESTAMP":"1000000","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"{module}(sudo:auth): authentication failure; logname=omss uid=1000 euid=0 tty=/dev/pts/2 ruser=omss rhost=  user=omss"}}"#
            )
        };
        assert_eq!(feed(&mut filter, &no_pid("c1", "pam_unix")), ["c1"]);
        assert!(feed(&mut filter, &no_pid("c2", "pam_sss")).is_empty());
        assert_eq!(filter.finish().len(), 1);
    }
}
