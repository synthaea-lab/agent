//! Emission budget of one access-log source (ADR-0022 §3): a per-source rate cap with a
//! drop counter, so a flood of matching requests cannot fill the shared spool.
//!
//! The budget is **per signature**, not per source. A scanner that sends a thousand SQL
//! injection probes in a minute must not use up the allowance for the request that
//! matters, a `.php` file that just appeared answering with 200 (webshell-like), which is
//! what the T1505.003 correlation waits for. Requests over budget are still counted in the
//! window summary: only the per-request event is shed, and the shedding is counted here.

use schema::HttpSignature;

use crate::WINDOW_SECS;

/// Signature events one source may emit per signature per window. A site under a real
/// attack shows the pattern within the first few; the rest is volume.
pub const PER_SIGNATURE_PER_WINDOW: u32 = 30;

const SIGNATURES: [HttpSignature; 4] = [
    HttpSignature::PathTraversal,
    HttpSignature::SqlInjection,
    HttpSignature::ScannerUserAgent,
    HttpSignature::WebshellLike,
];

fn slot(signature: HttpSignature) -> usize {
    SIGNATURES.iter().position(|s| *s == signature).unwrap_or(0)
}

/// Events shed in the window that just ended, per signature, for the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {
    pub path_traversal: u32,
    pub sql_injection: u32,
    pub scanner_user_agent: u32,
    pub webshell_like: u32,
}

impl Dropped {
    /// All signatures together.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.path_traversal
            .saturating_add(self.sql_injection)
            .saturating_add(self.scanner_user_agent)
            .saturating_add(self.webshell_like)
    }
}

/// Per-signature allowance for the current window.
#[derive(Debug, Default)]
pub struct SignatureBudget {
    window_start_ns: Option<u64>,
    emitted: [u32; 4],
    dropped: [u32; 4],
}

impl SignatureBudget {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether one more event of this signature may be emitted in the current window.
    /// A refusal is counted.
    pub fn allow(&mut self, signature: HttpSignature, now_ns: u64) -> bool {
        self.window_start_ns.get_or_insert(now_ns);
        let i = slot(signature);
        if self.emitted[i] < PER_SIGNATURE_PER_WINDOW {
            self.emitted[i] += 1;
            true
        } else {
            self.dropped[i] = self.dropped[i].saturating_add(1);
            false
        }
    }

    /// Ends the window once it is a full [`WINDOW_SECS`] old and returns what it shed,
    /// if anything. Call it once per poll, before reading the new lines, so a window's
    /// lines are judged against that window's allowance.
    pub fn tick(&mut self, now_ns: u64) -> Option<Dropped> {
        let start = self.window_start_ns?;
        if now_ns.saturating_sub(start) < u64::from(WINDOW_SECS) * 1_000_000_000 {
            return None;
        }
        let dropped = Dropped {
            path_traversal: self.dropped[slot(HttpSignature::PathTraversal)],
            sql_injection: self.dropped[slot(HttpSignature::SqlInjection)],
            scanner_user_agent: self.dropped[slot(HttpSignature::ScannerUserAgent)],
            webshell_like: self.dropped[slot(HttpSignature::WebshellLike)],
        };
        self.window_start_ns = None;
        self.emitted = [0; 4];
        self.dropped = [0; 4];
        (dropped.total() > 0).then_some(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn a_signature_is_allowed_up_to_its_budget_and_then_shed_and_counted() {
        let mut b = SignatureBudget::new();
        for _ in 0..PER_SIGNATURE_PER_WINDOW {
            assert!(b.allow(HttpSignature::SqlInjection, SEC));
        }
        assert!(!b.allow(HttpSignature::SqlInjection, 2 * SEC));
        assert!(!b.allow(HttpSignature::SqlInjection, 3 * SEC));
        let dropped = b.tick(61 * SEC).expect("two were shed");
        assert_eq!((dropped.sql_injection, dropped.total()), (2, 2));
    }

    #[test]
    fn a_flood_of_one_signature_does_not_use_up_another() {
        let mut b = SignatureBudget::new();
        for _ in 0..1000 {
            b.allow(HttpSignature::SqlInjection, SEC);
        }
        assert!(
            b.allow(HttpSignature::WebshellLike, 2 * SEC),
            "the webshell request still gets its own allowance"
        );
    }

    #[test]
    fn the_allowance_comes_back_with_the_next_window() {
        let mut b = SignatureBudget::new();
        for _ in 0..=PER_SIGNATURE_PER_WINDOW {
            b.allow(HttpSignature::PathTraversal, SEC);
        }
        assert!(b.tick(30 * SEC).is_none(), "the window is not over");
        assert!(b.tick(61 * SEC).is_some());
        assert!(b.allow(HttpSignature::PathTraversal, 62 * SEC));
    }

    #[test]
    fn a_quiet_window_reports_nothing() {
        let mut b = SignatureBudget::new();
        assert!(b.tick(100 * SEC).is_none(), "no window opened yet");
        b.allow(HttpSignature::ScannerUserAgent, SEC);
        assert!(b.tick(61 * SEC).is_none(), "nothing was shed");
    }
}
