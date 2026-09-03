//! Naive Bayes filter — per-entity (ppid, comm) compromise belief.
//!
//! Each update starts from the current [`crate::behavior::BehaviorVector`]: the
//! per-feature log-likelihood ratios (LLRs) are summed under the naive independence
//! assumption, with an exponential decay toward the prior during periods of
//! inactivity. The LLRs are calibrated empirically by the ML pipeline's LLR
//! calibration (which regenerates the body of `log_likelihood_ratio`).

use crate::behavior::BehaviorVector;

/// Prior at ~1% compromise probability: log(0.01 / 0.99).
pub(crate) const PRIOR_LOG_ODDS: f32 = -4.6;
/// Decay toward the prior over ~5 min of inactivity.
const DECAY_TAU_S: f32 = 300.0;
/// Alert threshold: log_odds > 2.0 → P(compromised) ≈ 88%.
pub(crate) const BAYES_THRESHOLD: f32 = 2.0;

/// Bayesian belief state for an entity (ppid, comm).
/// Keyed by (ppid, comm) rather than pid so it survives respawns:
/// fork+exec = new pid, same (ppid, comm) → belief preserved.
#[derive(Debug, Clone)]
pub struct BeliefState {
    /// Log of the odds ratio P(malicious) / P(benign).
    /// Initial value: PRIOR_LOG_ODDS (~1%).
    pub log_odds: f32,
    /// Timestamp of the last update — used to compute the decay.
    pub last_update_ns: u64,
    /// true if an alert has already been emitted for this threshold crossing.
    /// Reset to false when log_odds drops back below BAYES_THRESHOLD (decay).
    pub(crate) alerted: bool,
}

impl BeliefState {
    pub(crate) fn new(now_ns: u64) -> Self {
        Self {
            log_odds: PRIOR_LOG_ODDS,
            last_update_ns: now_ns,
            alerted: false,
        }
    }

    /// Current compromise probability (0.0–1.0).
    pub fn probability(&self) -> f32 {
        let odds = self.log_odds.exp();
        odds / (1.0 + odds)
    }
}

/// Log-likelihood ratio for the feature at index `idx`.
/// Calibrated empirically on the NjRAT capture (n_benign=97, n_malicious=23) on
/// 2026-08-28. Naive independence assumption: the LLRs are summed.
fn log_likelihood_ratio(idx: usize, value: f32) -> f32 {
    match idx {
        // 0 — has_exec: neutral — data artifact (PIDs seeded without an Exec in the window)
        0 => 0.0,
        // 1 — has_connect: moderate signal — malware almost always connects
        1 => {
            if value > 0.5 {
                1.19
            } else {
                -0.93
            }
        }
        // 2 — has_filewrite: no empirical signal (few FileOpen events captured)
        2 => 0.0,
        // 3 — time_exec_to_connect_ms: quick connection after spawn → highly suspicious
        3 => {
            if value > 0.0 && value < 2_000.0 {
                1.90
            } else if value > 0.0 {
                -0.22
            } else {
                -0.09
            } // absent
        }
        // 4 — time_exec_to_filewrite_ms: no empirical signal
        4 => 0.0,
        // 5 — is_suspicious_path: AppData/Temp/Desktop → very strong signal
        5 => {
            if value > 0.5 {
                3.60
            } else {
                -0.20
            }
        }
        // 6 — connect_count: repeated beaconing → signal grows in steps
        6 => {
            if value == 0.0 {
                -0.96
            } else if value < 5.0 {
                0.41
            } else if value < 15.0 {
                2.22
            } else {
                0.87
            }
        }
        // 7 — distinct_dports: empirically not very discriminating
        7 => {
            if value <= 1.0 {
                0.02
            } else if value <= 3.0 {
                -0.54
            } else {
                0.0
            }
        }
        // 8 — dest_is_external: connection to a public IP → strong signal
        8 => {
            if value > 0.5 {
                1.23
            } else {
                -0.44
            }
        }
        _ => 0.0,
    }
}

/// Updates an entity's belief with the current BehaviorVector.
/// First applies the exponential decay toward the prior, then the Bayesian update.
pub(crate) fn update_belief(state: &mut BeliefState, v: &BehaviorVector, now_ns: u64) {
    // Exponential decay toward the prior when inactive
    let dt_s = (now_ns.saturating_sub(state.last_update_ns)) as f32 / 1e9;
    let decay = 1.0 - (-dt_s / DECAY_TAU_S).exp();
    state.log_odds += (PRIOR_LOG_ODDS - state.log_odds) * decay;

    // Naive Bayesian update: sum of the per-feature LLRs
    for (i, &value) in v.to_vec().iter().enumerate() {
        state.log_odds += log_likelihood_ratio(i, value);
    }

    state.last_update_ns = now_ns;
}
