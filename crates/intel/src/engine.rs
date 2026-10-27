//! The handle the agent holds: the current set, replaced whole.

use std::{
    net::IpAddr,
    sync::{Arc, PoisonError, RwLock},
};

use crate::set::{IndicatorSet, Match};

/// The loaded indicator set, replaceable while lookups run.
///
/// A reload is a swap of one `Arc`: a lookup in flight finishes on the set it started with, and
/// the next one sees the new set, so there is no moment with a half-loaded set and no restart.
/// Counters belong to a set, so they start again at a reload.
#[derive(Debug)]
pub struct Intel {
    current: RwLock<Arc<IndicatorSet>>,
}

impl Default for Intel {
    fn default() -> Self {
        Self::new()
    }
}

impl Intel {
    /// An engine with no indicators: it matches nothing until a set is loaded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: RwLock::new(Arc::new(IndicatorSet::empty())),
        }
    }

    /// Replaces the set, returning the one it replaced.
    pub fn load(&self, set: IndicatorSet) -> Arc<IndicatorSet> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *current, Arc::new(set))
    }

    /// The set in force now, for several lookups on one consistent view or for its stats.
    #[must_use]
    pub fn snapshot(&self) -> Arc<IndicatorSet> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Matches a file hash written as hex against the current set.
    #[must_use]
    pub fn lookup_sha256_hex(&self, hex: &str) -> Option<Match> {
        self.snapshot().lookup_sha256_hex(hex)
    }

    /// Matches an address against the current set.
    #[must_use]
    pub fn lookup_ip(&self, address: IpAddr) -> Option<Match> {
        self.snapshot().lookup_ip(address)
    }
}
