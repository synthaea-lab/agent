//! A counter that says when a loss is worth a log line.

/// Counts events of one kind and returns the total on the powers of two (1, 2, 4, 8, …), the
/// moments to warn: a stream of bad records must not flood the log, and the total is never reset,
/// so the warnings thin out as it grows.
#[derive(Debug, Default)]
pub(crate) struct ThrottledCount(u64);

impl ThrottledCount {
    /// Counts one more event. Returns the new total when it is a power of two.
    pub(crate) fn bump(&mut self) -> Option<u64> {
        self.0 += 1;
        self.0.is_power_of_two().then_some(self.0)
    }

    /// How many events were counted.
    #[cfg(test)]
    pub(crate) fn total(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_the_total_on_powers_of_two_only() {
        let mut count = ThrottledCount::default();
        let reported: Vec<_> = (0..10).filter_map(|_| count.bump()).collect();
        assert_eq!(reported, [1, 2, 4, 8]);
        assert_eq!(count.total(), 10);
    }

    #[test]
    fn a_new_counter_has_counted_nothing() {
        assert_eq!(ThrottledCount::default().total(), 0);
    }
}
