//! Correlator tests — everything goes through the public API
//! ([`CorrelationEngine::on_event`]), except reading the Bayesian prior (internal
//! constant). Shared event builders here; `rules` holds the co-occurrence rule
//! tests (R1–R4), `behavior` the `BehaviorVector` and naive-Bayes tests.

use std::time::Duration;

use schema::{
    AssemblyLoadEvent, ConnectEvent, DnsQueryEvent, Event, EventMeta, ExecEvent, FileOpenEvent,
    SmbConnectEvent,
};

use crate::{CorrelationEngine, bayes::PRIOR_LOG_ODDS};

fn meta(pid: u32, ts_ns: u64) -> EventMeta {
    meta_full(pid, 0, "", ts_ns)
}

fn meta_full(pid: u32, ppid: u32, comm: &str, ts_ns: u64) -> EventMeta {
    EventMeta {
        pid,
        ppid,
        timestamp_ns: ts_ns,
        comm: comm.to_string(),
        ..schema::fixtures::meta()
    }
}

fn exec_event(pid: u32, ts_ns: u64) -> Event {
    exec_with_meta(meta(pid, ts_ns), "")
}

fn exec_with_meta(meta: EventMeta, image_path: &str) -> Event {
    Event::Exec(ExecEvent {
        meta,
        image_path: image_path.to_string(),
        ..schema::fixtures::exec()
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

fn assembly_load_event(pid: u32, ts_ns: u64) -> Event {
    Event::AssemblyLoad(AssemblyLoadEvent {
        meta: meta(pid, ts_ns),
        assembly_name: "MyPayload, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null"
            .to_string(),
        flags: 0x2, // dynamic / in-memory
    })
}

fn smb_connect_event(pid: u32, ts_ns: u64) -> Event {
    Event::SmbConnect(SmbConnectEvent {
        meta: meta(pid, ts_ns),
        server_name: r"\\WIN-TARGET".to_string(),
    })
}

fn dns_query_event(pid: u32, ts_ns: u64, query: &str) -> Event {
    Event::DnsQuery(DnsQueryEvent {
        meta: meta(pid, ts_ns),
        query: query.to_string(),
        qtype: 1, // A
        ..schema::fixtures::dns_query()
    })
}

mod behavior;
mod rules;
