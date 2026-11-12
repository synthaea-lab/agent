//! Per-PID behavioral vector, extracted from the sliding window.
//!
//! Consumed by the Bayes filter ([`crate::bayes`]) as its feature source, and
//! mirrored on the Python side by the ML pipeline's behavior features (LLR
//! calibration). It is NOT merged with the cmdline vector used by ML scoring —
//! decision from 2026-08-27 (old design doc, correlation/ML vector): two distinct
//! feature spaces, never a shared model.

use std::{collections::HashSet, net::IpAddr};

use schema::{ConnectEvent, Event};

use crate::event::is_file_write;

/// Per-PID behavioral vector — 9 features extracted from the sliding window.
#[derive(Debug, Clone, PartialEq)]
pub struct BehaviorVector {
    /// 1.0 if there is at least one `ExecEvent` in the window for this PID.
    pub has_exec: f32,
    /// 1.0 if there is at least one `ConnectEvent` in the window for this PID.
    pub has_connect: f32,
    /// 1.0 if there is at least one `FileOpenEvent` with a write flag for this PID.
    pub has_filewrite: f32,
    /// Delay in ms between the first Exec and the first Connect (0.0 if either is absent).
    pub time_exec_to_connect_ms: f32,
    /// Delay in ms between the first Exec and the first `FileWrite` (0.0 if either is absent).
    pub time_exec_to_filewrite_ms: f32,
    /// 1.0 if the `ExecEvent` comes from a suspicious path (AppData/Temp/Downloads/Desktop).
    pub is_suspicious_path: f32,
    /// Number of `ConnectEvents` in the window.
    pub connect_count: f32,
    /// Number of distinct destination ports among the `ConnectEvents`.
    pub distinct_dports: f32,
    /// 1.0 if there is at least one `ConnectEvent` to a non-RFC1918, non-loopback IP.
    pub dest_is_external: f32,
}

impl BehaviorVector {
    /// Features as an ordered vector, compatible with the format expected
    /// by the ML pipeline's behavior features and the LLR calibration.
    #[must_use]
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.has_exec,
            self.has_connect,
            self.has_filewrite,
            self.time_exec_to_connect_ms,
            self.time_exec_to_filewrite_ms,
            self.is_suspicious_path,
            self.connect_count,
            self.distinct_dports,
            self.dest_is_external,
        ]
    }

    /// Computes the vector for the events of a single PID (already filtered by the
    /// caller). Returns `None` if the slice is empty — a PID with no events has no
    /// behavior.
    pub(crate) fn from_window(events: &[&Event]) -> Option<Self> {
        if events.is_empty() {
            return None;
        }
        let connect_events: Vec<&ConnectEvent> = events
            .iter()
            .filter_map(|e| {
                if let Event::Connect(c) = e {
                    Some(c)
                } else {
                    None
                }
            })
            .collect();

        let (distinct_dports, dest_is_external) = connect_features(&connect_events);
        let (time_exec_to_connect_ms, time_exec_to_filewrite_ms) =
            timing_features(events, &connect_events);

        Some(BehaviorVector {
            has_exec: bool_feature(events.iter().any(|e| matches!(e, Event::Exec(_)))),
            has_connect: bool_feature(!connect_events.is_empty()),
            has_filewrite: bool_feature(events.iter().any(|e| is_file_write(e))),
            time_exec_to_connect_ms,
            time_exec_to_filewrite_ms,
            is_suspicious_path: suspicious_path_feature(events),
            connect_count: connect_events.len() as f32,
            distinct_dports,
            dest_is_external: bool_feature(dest_is_external),
        })
    }
}

fn bool_feature(b: bool) -> f32 {
    if b { 1.0 } else { 0.0 }
}

/// (distinct destination ports, any-external-destination) over the window.
fn connect_features(connect_events: &[&ConnectEvent]) -> (f32, bool) {
    let mut dports: HashSet<u16> = HashSet::new();
    let mut dest_is_external = false;
    for c in connect_events {
        dports.insert(c.dport);
        let external = match c.daddr {
            IpAddr::V4(v4) => !is_private_ipv4(v4.octets()),
            // Review finding: IPv6 was skipped entirely, so public IPv6 C2 was
            // systematically underscored. Non-global v6 classes are excluded
            // explicitly; everything else counts as external.
            IpAddr::V6(v6) => !is_non_global_ipv6(v6),
        };
        if external {
            dest_is_external = true;
        }
    }
    (dports.len() as f32, dest_is_external)
}

/// (exec→first connect, exec→first file write) deltas in milliseconds; 0 when
/// either endpoint is absent from the window.
fn timing_features(events: &[&Event], connect_events: &[&ConnectEvent]) -> (f32, f32) {
    let first_exec_ns = events.iter().find_map(|e| {
        if let Event::Exec(x) = e {
            Some(x.meta.timestamp_ns)
        } else {
            None
        }
    });
    let first_connect_ns = connect_events.first().map(|c| c.meta.timestamp_ns);
    let first_filewrite_ns = events
        .iter()
        .find(|e| is_file_write(e))
        .map(|e| e.meta().timestamp_ns);

    let delta_ms = |from: Option<u64>, to: Option<u64>| match (from, to) {
        (Some(f), Some(t)) => (t.saturating_sub(f) as f32) / 1_000_000.0,
        _ => 0.0,
    };
    (
        delta_ms(first_exec_ns, first_connect_ns),
        delta_ms(first_exec_ns, first_filewrite_ns),
    )
}

/// Suspicious path — judged on the first `ExecEvent` of the PID within the window.
fn suspicious_path_feature(events: &[&Event]) -> f32 {
    events
        .iter()
        .find_map(|e| {
            if let Event::Exec(x) = e {
                Some(bool_feature(is_suspicious_image_path(&x.image_path)))
            } else {
                None
            }
        })
        .unwrap_or(0.0)
}

/// Returns true if the path contains a directory considered suspicious
/// for an execution. Mirror of the suspicious-path feature in `crates/ml`.
fn is_suspicious_image_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ["appdata", "\\temp\\", "downloads", "desktop", "\\public\\"]
        .iter()
        .any(|s| lower.contains(s))
}

/// Returns true if the IPv4 address belongs to a private range, is loopback, or is
/// not a real destination (unspecified address `0.0.0.0`).
/// `0.0.0.0` has no place in RFC1918 but must not count as "external" either —
/// observed on 2026-08-31 on `sshd` (`daddr=0.0.0.0`, cause of the `connect()` still
/// unidentified): without this exclusion, the unspecified address was classified as
/// external by default, contributing to `dest_is_external` Bayesian LLR on traffic
/// unrelated to any real C2.
/// Loopback, unspecified, link-local (`fe80::/10`), unique-local (`fc00::/7`),
/// multicast (`ff00::/8`) — the non-global classes legitimate local traffic uses.
fn is_non_global_ipv6(addr: std::net::Ipv6Addr) -> bool {
    let seg = addr.segments();
    addr.is_loopback()
        || addr.is_unspecified()
        || (seg[0] & 0xffc0) == 0xfe80
        || (seg[0] & 0xfe00) == 0xfc00
        || (seg[0] & 0xff00) == 0xff00
}

fn is_private_ipv4(addr: [u8; 4]) -> bool {
    matches!(
        addr,
        [0, 0, 0, 0] | [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [127, ..]
    )
}

#[cfg(test)]
mod golden_tests {
    //! Python/Rust golden parity test for [`BehaviorVector`] (agent#202, ml#32).
    //!
    //! Consumes `ml/tests/fixtures/behavior_golden.jsonl`, generated by
    //! `ml/tests/fixtures/generators/gen_behavior_golden.py` from
    //! `synthaea_ml.features.behavior`. The Python counterpart is
    //! `ml/tests/test_behavior_golden.py`. Rust is the runtime reference for the rules the
    //! two sides used to disagree on (agent#203, `docs/correlation.md`): the golden follows
    //! it, so a global IPv6 destination, `0.0.0.0`/`::` and ASCII-only path casing are in it.
    //!
    //! If this breaks, `BehaviorVector::from_window` and the Python extractor have drifted:
    //! the Bayes filter's LLR calibration would score vectors it was never calibrated on.

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use schema::{Event, fixtures};
    use serde_json::Value;

    use super::BehaviorVector;

    /// In the `ml` sibling repo; read at run time, the test skips without it.
    const GOLDEN_PATH: &str = "tests/fixtures/behavior_golden.jsonl";

    /// The golden file is f64 (Python); the Rust side computes in f32. Tolerance is loose
    /// relative to f32 rounding (~1e-7) but strict relative to any real definition drift.
    fn close(got: f32, expected: f64) -> bool {
        let expected32 = expected as f32;
        (got - expected32).abs() <= 1e-4 * expected32.abs().max(1.0)
    }

    /// Builds the event of one golden row. The rows use the Python wire shape: `cmdline` is
    /// NUL-separated. The exec's path is the row's `image_path` when it has one (an empty
    /// string is a value, not a fallback); a row without it pins the mirror's documented
    /// fallback, the first `cmdline` argument.
    fn event(row: &Value) -> Event {
        let ts_ns = row["ts_ns"].as_u64().expect("ts_ns field");
        match row["type"].as_str().expect("type field") {
            "exec" => {
                let cmdline = row["cmdline"].as_str().expect("cmdline field");
                let mut e = fixtures::exec();
                e.meta.timestamp_ns = ts_ns;
                e.image_path = row.get("image_path").map_or_else(
                    || cmdline.split('\0').next().unwrap_or_default().to_owned(),
                    |v| v.as_str().expect("image_path is a string").to_owned(),
                );
                e.cmdline = cmdline.to_owned();
                Event::Exec(e)
            }
            "connect" => {
                let daddr = if row["is_ipv6"].as_bool().expect("is_ipv6 field") {
                    let text = row["daddr_v6"].as_str().expect("daddr_v6 field");
                    IpAddr::V6(text.parse::<Ipv6Addr>().expect("valid IPv6 text"))
                } else {
                    let octets: Vec<u8> = row["daddr_v4"]
                        .as_array()
                        .expect("daddr_v4 field")
                        .iter()
                        .map(|v| u8::try_from(v.as_u64().expect("octet")).expect("octet fits u8"))
                        .collect();
                    let octets: [u8; 4] = octets.try_into().expect("four octets");
                    IpAddr::V4(Ipv4Addr::from(octets))
                };
                let mut e = fixtures::connect();
                e.meta.timestamp_ns = ts_ns;
                e.daddr = daddr;
                e.dport = u16::try_from(row["dport"].as_u64().expect("dport field"))
                    .expect("dport fits u16");
                Event::Connect(e)
            }
            "fileopen" => {
                let mut e = fixtures::file_open();
                e.meta.timestamp_ns = ts_ns;
                e.flags = u32::try_from(row["flags"].as_u64().expect("flags field"))
                    .expect("flags fit u32");
                Event::FileOpen(e)
            }
            other => panic!("unknown golden event type `{other}`"),
        }
    }

    #[test]
    fn parity_with_behavior_py() {
        let golden = siblings::require!("ml", GOLDEN_PATH);
        let mut cases = 0;
        for line in golden.lines().filter(|l| !l.trim().is_empty()) {
            let row: Value = serde_json::from_str(line).expect("invalid golden line");
            let name = row["name"].as_str().expect("name field");
            let events: Vec<Event> = row["events"]
                .as_array()
                .expect("events field")
                .iter()
                .map(event)
                .collect();
            let refs: Vec<&Event> = events.iter().collect();
            let expected: Vec<f64> = row["features"]
                .as_array()
                .expect("features field")
                .iter()
                .map(|v| v.as_f64().expect("non-numeric feature"))
                .collect();
            assert_eq!(
                expected.len(),
                9,
                "case `{name}`: the vector has 9 features"
            );

            // No events: the Rust side has no vector, the Python side an all-zero one.
            let got =
                BehaviorVector::from_window(&refs).map_or_else(|| vec![0.0; 9], |v| v.to_vec());
            for (i, (g, e)) in got.iter().zip(&expected).enumerate() {
                assert!(
                    close(*g, *e),
                    "case `{name}`, feature #{i} drifted from behavior.py: Rust={g} Python={e} \
                     — see ml/tests/fixtures/generators/gen_behavior_golden.py",
                );
            }
            cases += 1;
        }
        // Guardrail: an empty or mis-pathed golden file must not pass silently.
        assert!(cases >= 20, "suspicious golden file: only {cases} cases");
    }
}
