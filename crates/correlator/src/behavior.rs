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

        let has_exec = events.iter().any(|e| matches!(e, Event::Exec(_)));
        let has_filewrite = events.iter().any(|e| is_file_write(e));

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

        let has_connect = !connect_events.is_empty();
        let connect_count = connect_events.len() as f32;

        let mut dports: HashSet<u16> = HashSet::new();
        let mut dest_is_external = false;
        for c in &connect_events {
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

        let time_exec_to_connect_ms = match (first_exec_ns, first_connect_ns) {
            (Some(e), Some(c)) => (c.saturating_sub(e) as f32) / 1_000_000.0,
            _ => 0.0,
        };
        let time_exec_to_filewrite_ms = match (first_exec_ns, first_filewrite_ns) {
            (Some(e), Some(f)) => (f.saturating_sub(e) as f32) / 1_000_000.0,
            _ => 0.0,
        };

        // Suspicious path — first ExecEvent of the PID within the window
        let is_suspicious_path = events
            .iter()
            .find_map(|e| {
                if let Event::Exec(x) = e {
                    Some(if is_suspicious_image_path(&x.image_path) {
                        1.0f32
                    } else {
                        0.0f32
                    })
                } else {
                    None
                }
            })
            .unwrap_or(0.0);

        Some(BehaviorVector {
            has_exec: if has_exec { 1.0 } else { 0.0 },
            has_connect: if has_connect { 1.0 } else { 0.0 },
            has_filewrite: if has_filewrite { 1.0 } else { 0.0 },
            time_exec_to_connect_ms,
            time_exec_to_filewrite_ms,
            is_suspicious_path,
            connect_count,
            distinct_dports: dports.len() as f32,
            dest_is_external: if dest_is_external { 1.0 } else { 0.0 },
        })
    }
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
