//! Correlator tests — everything goes through the public API
//! ([`CorrelationEngine::on_event`]), except reading the Bayesian prior (internal
//! constant). Shared event builders here; `rules` holds the co-occurrence rule
//! tests (R1–R4), `behavior` the `BehaviorVector` and naive-Bayes tests.

use std::time::Duration;

use schema::{ConnectEvent, Event, EventMeta, ExecEvent, FileOpenEvent, User};

use crate::{CorrelationEngine, bayes::PRIOR_LOG_ODDS};

fn meta(pid: u32, ts_ns: u64) -> EventMeta {
    meta_full(pid, 0, "", ts_ns)
}

fn meta_full(pid: u32, ppid: u32, comm: &str, ts_ns: u64) -> EventMeta {
    EventMeta {
        pid,
        ppid,
        user: User::Unknown,
        timestamp_ns: ts_ns,
        comm: comm.to_string(),
    }
}

fn exec_event(pid: u32, ts_ns: u64) -> Event {
    exec_with_meta(meta(pid, ts_ns), "")
}

fn exec_with_meta(meta: EventMeta, image_path: &str) -> Event {
    Event::Exec(ExecEvent {
        meta,
        image_path: image_path.to_string(),
        cmdline: String::new(),
        argv: vec![],
        parent_comm: None,
        parent_image_path: None,
        sha256: None,
        signature: None,
    })
}

fn connect_event(pid: u32, ts_ns: u64) -> Event {
    connect_to(meta(pid, ts_ns), [1, 2, 3, 4], 4444)
}

fn connect_to(meta: EventMeta, daddr: [u8; 4], dport: u16) -> Event {
    Event::Connect(ConnectEvent {
        meta,
        daddr: std::net::IpAddr::V4(daddr.into()),
        dport,
    })
}

fn file_write_event(pid: u32, ts_ns: u64) -> Event {
    const O_WRONLY: u32 = 0o1;
    const O_CREAT: u32 = 0o100;
    // Path simulating a payload in a temp directory — needed to trigger
    // the is_payload_file() filter of the T1105 rules.
    Event::FileOpen(FileOpenEvent {
        meta: meta(pid, ts_ns),
        path: "C:\\Windows\\Temp\\payload.exe".to_string(),
        flags: O_WRONLY | O_CREAT,
    })
}

fn file_read_event(pid: u32, ts_ns: u64) -> Event {
    Event::FileOpen(FileOpenEvent {
        meta: meta(pid, ts_ns),
        path: String::new(),
        flags: 0o0, // O_RDONLY
    })
}

mod behavior;
mod rules;
