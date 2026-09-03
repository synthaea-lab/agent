//! # sinks
//!
//! Local output sinks for events and alerts: JSON-Lines files today, syslog/CEF as
//! follow-up sinks ("not a SIEM — we export to yours"). Composable, agent-independent;
//! the agent hosts and wires them.
//!
//! Migrated from `old/agent` (sinks.rs, jsonl.rs), with one deliberate format change:
//! the old hand-built JSON (and its `escape_json_str`) existed because the agent
//! embedded no serialization crate. `schema` types now derive serde, so events are
//! written in the schema's canonical serialization — the exact format pinned by
//! `schema`'s golden fixtures — and consumers (`ml/` capture parsing) use plain
//! `json.loads` instead of a bespoke format. Escaping of hostile strings (a process
//! renamed via `prctl(PR_SET_NAME, ...)` to contain quotes or control bytes) is
//! serde_json's job, covered by tests here.
//!
//! Scope rule: the agent speaks only neutral formats (JSONL here, syslog/CEF and
//! OCSF/ECS mappings as additional sinks in this crate). Vendor-specific SIEM
//! connectors (Splunk HEC, Sentinel, Elastic) live in the control plane's export
//! module — one fleet-level integration point forwarding enriched cases, never
//! per-agent clients.

use std::{
    fs::OpenOptions,
    io::{BufWriter, Write as _},
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use schema::{Event, sensor::EventSink};
use serde::{Deserialize, Serialize};

/// JSON-Lines writer shared between threads (the `EventSink` trait requires
/// `Send + Sync` and only exposes `&self`).
pub struct JsonlWriter {
    inner: Mutex<BufWriter<std::fs::File>>,
}

impl JsonlWriter {
    /// Opens a JSON-Lines file in append mode (created if it does not exist).
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            inner: Mutex::new(BufWriter::new(f)),
        })
    }

    /// Writes one serialized value as one line, silently ignoring a write error —
    /// a missed line in a local log must not bring down the capture. Flushed per line:
    /// these logs are read while the agent runs (tail, lab assertions), and losing
    /// buffered lines on a crash would cost more than the syscall.
    pub fn write<T: Serialize>(&self, value: &T) {
        let Ok(line) = serde_json::to_string(value) else {
            return;
        };
        if let Ok(mut w) = self.inner.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
            let _ = w.flush();
        }
    }
}

/// One alert as written to `alerts.ndjson`. Defined here (not in `rules`) so the
/// on-disk record stays a sink concern: the agent converts whatever its detection
/// engines emit into this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub timestamp_ns: u64,
    pub technique: String,
    pub message: String,
}

/// JSON-Lines sink for every normalized event — the raw capture consumed offline by
/// the ML pipeline (baselines, calibration) and by lab assertions. No filtering, no
/// detection: one `Event` in, one line out.
pub struct JsonlEventSink {
    writer: JsonlWriter,
    count: AtomicU64,
}

impl JsonlEventSink {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            writer: JsonlWriter::open(path)?,
            count: AtomicU64::new(0),
        })
    }

    /// Events written so far — for progress reporting by the host (the sink itself
    /// never prints).
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl EventSink for JsonlEventSink {
    fn on_event(&self, event: Event) {
        self.writer.write(&event);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
