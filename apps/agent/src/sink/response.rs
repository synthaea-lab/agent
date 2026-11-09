//! Automated response (issue #25): the hooks `enable_response` installs, the kill gate, the
//! ransomware reflex and its damage manifest. The mechanism is described in
//! `docs/response.md`.

use std::{path::PathBuf, sync::OnceLock};

use ::response::KillOutcome;
use policy::ResponsePolicy;
use schema::Event;

use super::DetectionSink;
use crate::sync::LockExt as _;

/// What `enable_response` installs: the policy, the injected kill call and the quarantine
/// directory.
pub(super) struct ResponseHooks {
    pub(super) policy: ResponsePolicy,
    /// The actual OS-level kill call, injected by the caller: `response` is
    /// base-tier-only and platform dispatch belongs to the binary (CLAUDE.md).
    pub(super) terminate: Box<dyn Fn(u32) -> std::io::Result<()> + Send + Sync>,
    pub(super) quarantine_dir: PathBuf,
}

/// The hooks, set at most once. A cell rather than a constructor argument because the YARA
/// worker's callback is built inside `DetectionSink::new`, before a caller can configure
/// the sink. Empty on a platform that never calls `enable_response`.
pub(super) type ResponseCell = OnceLock<ResponseHooks>;

/// The reason the audit line gives when the ransomware reflex kills (#82). A trigger of its
/// own, never severity or the Bayes gate: it needs both the burst rule and a canary touch
/// from the same process (`crate::ransomware_join`).
const RANSOMWARE_REFLEX_REASON: &str =
    "a corroborated ransomware signal (burst rule + canary touch)";

/// Most renames and deletions a ransomware detection carries beyond its triggering event.
/// A bound on the size of one detection: the correlator window is 60 s, and a fast
/// encryptor renames far more than this in it. The trigger plus the manifest must fit in
/// [`super::SERVER_MAX_EVENTS`], or the server drops the tail of the manifest.
pub(super) const DAMAGE_MANIFEST_MAX: usize = 100;

/// Whether an alert raised by the correlator makes its process eligible for a kill: only
/// the correlator's belief crossing (`BAYES`), never a severity, which is an analyst-facing
/// ranking (issue #131 follow-up). See `docs/response.md`, "What can trigger a kill".
pub(super) fn crosses_kill_gate(technique: &str) -> bool {
    technique == "BAYES"
}

/// Why the kill gate refuses a system service's main process (#652, ADR-0028).
// Review of #755 (2026-10-19): it states only what `service_main_path_is_trusted` checks
// (where the image lives, who started it), never "package-owned", which nothing verifies.
const SERVICE_MAIN_REFUSAL: &str = "main process of a system service (image under a system path, started by init); escalated, not killed";

/// Why the kill gate refuses the process holding a login session (<https://github.com/synthaea-lab/agent/issues/50>, ADR-0028).
/// Same care as [`SERVICE_MAIN_REFUSAL`]: it states what was checked (the image and
/// its parent's image), not that the session is legitimate, nor that the parent was
/// started by init: the listener's exec is usually never seen.
const LOGIN_SESSION_REFUSAL: &str = "holds a login session (sshd-session, or sshd before OpenSSH 9.8, exec'd by sshd, both images under a system path); escalated, not killed";

/// The refusal reason the kill gate records for `shield`.
fn shield_refusal(shield: correlator::KillShield) -> &'static str {
    match shield {
        correlator::KillShield::ServiceMain => SERVICE_MAIN_REFUSAL,
        correlator::KillShield::LoginSession => LOGIN_SESSION_REFUSAL,
    }
}

impl DetectionSink {
    /// Activates issue #25's automated response: process kill on a high-confidence
    /// correlated (`BAYES`) verdict or the ransomware reflex, quarantine on a confirmed
    /// YARA match. Until it is called, every kill and quarantine path returns without
    /// acting or writing an audit line. The first call wins; a later one is ignored with a
    /// warning, so the policy in force cannot change under a running agent.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn enable_response(
        &self,
        policy: ResponsePolicy,
        terminate: impl Fn(u32) -> std::io::Result<()> + Send + Sync + 'static,
        quarantine_dir: PathBuf,
    ) {
        let hooks = ResponseHooks {
            policy,
            terminate: Box::new(terminate),
            quarantine_dir,
        };
        if self.response.set(hooks).is_err() {
            tracing::warn!("response: already enabled, the first policy stays in force");
        }
    }

    /// The kill for a high-confidence correlated verdict. `shield` is the correlator's
    /// provenance verdict for `pid` (a system service's main process, a login-session
    /// holder): it refuses the kill, in observe mode too, whatever the evidence (ADR-0028).
    /// See `docs/response.md`, "Shields: refusing by what the process is".
    pub(super) fn maybe_kill(&self, pid: u32, shield: Option<correlator::KillShield>) {
        self.kill_for(pid, "a high-confidence correlated verdict", shield);
    }

    /// The policy-gated kill behind every automated trigger; `reason` names which one, in
    /// the audit line (`RESPONSE-KILL`). `shield` makes it refuse (ADR-0028); only the
    /// correlator's verdict sets it, a trigger with its own evidence (the ransomware reflex)
    /// passes `None`.
    fn kill_for(&self, pid: u32, reason: &str, shield: Option<correlator::KillShield>) {
        let Some(hooks) = self.response.get() else {
            return;
        };
        let outcome = if let Some(shield) = shield {
            KillOutcome::Refused {
                pid,
                reason: shield_refusal(shield),
            }
        } else {
            ::response::kill_process(pid, &hooks.policy, |p| (hooks.terminate)(p))
        };
        let message = match outcome {
            KillOutcome::Killed { pid } => format!("killed pid {pid} on {reason}"),
            KillOutcome::ObserveOnly { pid } => {
                format!("pid {pid} would have been killed on {reason} (observe-only)")
            }
            KillOutcome::Failed { pid, error } => {
                format!("failed to kill pid {pid} on {reason}: {error}")
            }
            KillOutcome::Refused { pid, reason: why } => {
                format!("refused to kill pid {pid} on {reason}: {why}")
            }
        };
        self.emit("RESPONSE-KILL", &message);
    }

    /// The process behind `event` raised the ransomware burst rule (#82). True when it also
    /// touched a canary in the window: the corroborated signal. The caller records the
    /// detection first and then calls [`Self::ransomware_reflex`].
    pub(super) fn note_ransomware_burst(&self, event: &Event) -> bool {
        let meta = event.meta();
        self.ransomware_join.lock_recovering().note_burst(
            meta.pid,
            meta.process_generation,
            meta.timestamp_ns,
        )
    }

    /// The reflex: the policy-gated kill of the corroborated process. Observe-only unless
    /// kill is enabled, like every other automated kill.
    pub(super) fn ransomware_reflex(&self, pid: u32) {
        self.kill_for(pid, RANSOMWARE_REFLEX_REASON, None);
    }

    /// The damage manifest of a ransomware alert (issue #82): the file renames and
    /// deletions of the alerting process incarnation that the rule state remembers (the
    /// newest `DAMAGE_MANIFEST_MAX`), oldest first, without the triggering event (which is
    /// the detection's first event already). It rides in `Detection::events`, so no schema
    /// change: the control plane keeps events after the first as the detection's further
    /// triggering events, and a restoration tool reads the scope from them.
    ///
    /// Takes the rule-state lock: callers must not hold it (see `detect_file_rename`).
    pub(super) fn damage_manifest(&self, trigger: &Event) -> Vec<Event> {
        let meta = trigger.meta();
        let mut touched = self
            .rule_state
            .lock_recovering()
            .touched_files(meta.pid, meta.process_generation);
        touched.retain(|e| e != trigger);
        let excess = touched.len().saturating_sub(DAMAGE_MANIFEST_MAX);
        touched.drain(..excess);
        touched
    }
}
