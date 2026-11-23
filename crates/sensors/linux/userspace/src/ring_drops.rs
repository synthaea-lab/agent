//! Events the probes lost to a full ring buffer (#304), read from the eBPF map `RING_DROPS` and
//! reported as one log line per ring that lost events since the last report, instead of the
//! aya-log line per lost event the probes used to emit.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use aya::maps::{MapData, PerCpuArray};
use schema::sensor::SensorError;
use sensor_linux_wire::ring;

use crate::ebpf::err;

/// The running drop totals the agent reports in its health beacon (#335), refreshed at each
/// report. Cumulative since the sensor started, like the counters in the map.
#[derive(Debug, Default)]
pub struct RingDropTotals {
    all: AtomicU64,
    exec: AtomicU64,
}

impl RingDropTotals {
    /// Events lost to a full ring, summed over every ring.
    #[must_use]
    pub fn all(&self) -> u64 {
        self.all.load(Ordering::Relaxed)
    }

    /// Events lost to a full `EXEC_EVENTS` ring alone: process starts the rules never saw.
    #[must_use]
    pub fn exec(&self) -> u64 {
        self.exec.load(Ordering::Relaxed)
    }

    fn publish(&self, totals: &[u64]) {
        let all = totals.iter().fold(0u64, |sum, n| sum.saturating_add(*n));
        self.all.store(all, Ordering::Relaxed);
        self.exec
            .store(totals[ring::EXEC as usize], Ordering::Relaxed);
    }
}

/// The per-ring drop counters and the totals already reported.
pub(crate) struct RingDrops {
    map: PerCpuArray<MapData, u64>,
    seen: [u64; ring::COUNT as usize],
    published: Arc<RingDropTotals>,
}

impl RingDrops {
    /// Takes `RING_DROPS` out of the loaded object.
    ///
    /// # Errors
    ///
    /// Returns [`SensorError`] when the map is missing or is not a per-CPU array of `u64`.
    pub(crate) fn take(
        ebpf: &mut aya::Ebpf,
        published: Arc<RingDropTotals>,
    ) -> Result<Self, SensorError> {
        let map = ebpf
            .take_map("RING_DROPS")
            .ok_or_else(|| err("map RING_DROPS not found in eBPF object".to_string()))?;
        let map = PerCpuArray::try_from(map)
            .map_err(|e| err(format!("RING_DROPS is not a per-CPU u64 array: {e}")))?;
        Ok(Self {
            map,
            seen: [0; ring::COUNT as usize],
            published,
        })
    }

    /// Logs one warning per ring whose drop count grew since the last call, and publishes the
    /// totals for the health beacon.
    pub(crate) fn report(&mut self) {
        let mut totals = [0u64; ring::COUNT as usize];
        for (slot, total) in (0..ring::COUNT).zip(totals.iter_mut()) {
            // A slot that cannot be read keeps its last total, so it reports nothing this time.
            *total = self
                .map
                .get(&slot, 0)
                .map_or(self.seen[slot as usize], |per_cpu| {
                    per_cpu.iter().fold(0u64, |sum, n| sum.saturating_add(*n))
                });
        }
        self.published.publish(&totals);
        for (slot, dropped, total) in grown(&mut self.seen, &totals) {
            tracing::warn!(
                ring = ring::NAMES[slot],
                dropped,
                total,
                "sensor-linux: ring buffer full, events dropped"
            );
        }
    }
}

/// The slots whose total grew past `seen`, with the growth and the new total; `seen` takes the
/// new totals. A total below `seen` (it cannot shrink while the object is loaded) is taken as the
/// new baseline without a report.
fn grown(seen: &mut [u64], totals: &[u64]) -> Vec<(usize, u64, u64)> {
    let mut out = Vec::new();
    for (slot, (last, &total)) in seen.iter_mut().zip(totals).enumerate() {
        if total > *last {
            out.push((slot, total - *last, total));
        }
        *last = total;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ring_is_reported_once_per_growth_with_the_events_lost_since_the_last_report() {
        let mut seen = [0u64; 3];
        assert_eq!(grown(&mut seen, &[0, 5, 0]), vec![(1, 5, 5)]);
        assert_eq!(grown(&mut seen, &[0, 5, 0]), vec![]);
        assert_eq!(grown(&mut seen, &[2, 9, 0]), vec![(0, 2, 2), (1, 4, 9)]);
        assert_eq!(seen, [2, 9, 0]);
    }

    #[test]
    fn a_total_below_the_last_one_is_a_new_baseline_not_a_report() {
        let mut seen = [7u64];
        assert_eq!(grown(&mut seen, &[3]), vec![]);
        assert_eq!(grown(&mut seen, &[4]), vec![(0, 1, 4)]);
    }

    #[test]
    fn the_published_totals_are_the_sum_of_every_ring_and_the_exec_ring_alone() {
        let totals = RingDropTotals::default();
        let mut slots = [0u64; ring::COUNT as usize];
        slots[ring::EXEC as usize] = 4;
        slots[ring::FILE_OPEN as usize] = 1_000;
        slots[ring::NAMESPACE as usize] = u64::MAX;
        totals.publish(&slots);
        assert_eq!((totals.all(), totals.exec()), (u64::MAX, 4));
        slots[ring::NAMESPACE as usize] = 0;
        totals.publish(&slots);
        assert_eq!((totals.all(), totals.exec()), (1_004, 4));
    }
}
