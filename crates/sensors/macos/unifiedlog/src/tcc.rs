//! Joins tccd's two-record decision trail: `AUTHREQ_CTX` (service, keyed by
//! tccd's own message id) with the later `AUTHREQ_RESULT` (verdict, same key).
//! The unified log emits them as separate records — only the pair is a
//! [`schema::TccDecisionEvent`].
//!
//! State is bounded and observable per the house rule (CLAUDE.md): pending
//! contexts are capped with FIFO shedding, and both shed contexts and
//! unmatched results are counted rather than silently dropped. This crate
//! cannot depend on `store` (`sensor-*` crates depend only on `schema`), so
//! the bounded map is local — a `HashMap` plus insertion-order queue, the
//! same shape as `store::BoundedMap`.

use std::collections::{HashMap, VecDeque};

/// Pending contexts to hold. tccd answers requests in milliseconds — a
/// context outliving hundreds of successors is orphaned (its result was
/// filtered, lost, or never came), not still pending.
const MAX_PENDING: usize = 512;

/// Joins TCC context/result records. One per stream — msgIDs are unique per
/// tccd instance and namespaced by its pid prefix (`"988.7025"`), so a single
/// joiner serves both the system and per-user daemons.
#[derive(Debug, Default)]
pub struct TccJoiner {
    pending: HashMap<String, String>,
    order: VecDeque<String>,
    /// Contexts shed by the cap before their result arrived.
    pub shed_contexts: u64,
    /// Results with no pending context (context filtered/predates the tail —
    /// e.g. the stream attached between the two records).
    pub unmatched_results: u64,
}

impl TccJoiner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a context (service for a message id).
    pub fn on_context(&mut self, msg_id: String, service: String) {
        if self.pending.len() >= MAX_PENDING
            && !self.pending.contains_key(&msg_id)
            && let Some(oldest) = self.order.pop_front()
        {
            self.pending.remove(&oldest);
            self.shed_contexts += 1;
        }
        if self.pending.insert(msg_id.clone(), service).is_none() {
            self.order.push_back(msg_id);
        }
    }

    /// Resolves a result against its context: `Some(service)` when the pair
    /// joined, `None` (counted) when no context was pending.
    pub fn on_result(&mut self, msg_id: &str) -> Option<String> {
        match self.pending.remove(msg_id) {
            Some(service) => {
                self.order.retain(|k| k != msg_id);
                Some(service)
            }
            None => {
                self.unmatched_results += 1;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_then_result_joins_to_the_service() {
        let mut joiner = TccJoiner::new();
        joiner.on_context("988.1".into(), "kTCCServiceScreenCapture".into());
        assert_eq!(
            joiner.on_result("988.1").as_deref(),
            Some("kTCCServiceScreenCapture")
        );
        // The pair is consumed — a duplicate result no longer joins.
        assert_eq!(joiner.on_result("988.1"), None);
        assert_eq!(joiner.unmatched_results, 1);
    }

    #[test]
    fn result_without_context_is_counted_not_fabricated() {
        let mut joiner = TccJoiner::new();
        assert_eq!(joiner.on_result("438.631"), None);
        assert_eq!(joiner.unmatched_results, 1);
    }

    #[test]
    fn pending_contexts_are_bounded_with_counted_shedding() {
        let mut joiner = TccJoiner::new();
        for i in 0..(MAX_PENDING + 10) {
            joiner.on_context(format!("1.{i}"), "kTCCServiceCamera".into());
        }
        assert_eq!(joiner.pending.len(), MAX_PENDING);
        assert_eq!(joiner.shed_contexts, 10);
        // The oldest were shed; the newest still join.
        assert_eq!(joiner.on_result("1.0"), None);
        assert!(
            joiner
                .on_result(&format!("1.{}", MAX_PENDING + 9))
                .is_some()
        );
    }

    #[test]
    fn re_contexting_the_same_msg_id_updates_without_growing() {
        let mut joiner = TccJoiner::new();
        joiner.on_context("2.1".into(), "kTCCServiceCamera".into());
        joiner.on_context("2.1".into(), "kTCCServiceMicrophone".into());
        assert_eq!(joiner.order.len(), 1);
        assert_eq!(
            joiner.on_result("2.1").as_deref(),
            Some("kTCCServiceMicrophone")
        );
    }
}
