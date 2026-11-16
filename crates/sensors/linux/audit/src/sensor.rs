//! `AuditSensor`: `schema::sensor::Sensor` implementation.

use std::sync::Arc;

use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use tokio::sync::Notify;

use crate::{
    AuditSocket, classify,
    execve::{AssembledExec, ExecveAssembler},
    normalize, parse,
};

/// Records read per readiness wakeup before yielding back to `select!`. One
/// exec is 7 records on the lab kernel (SYSCALL, EXECVE, CWD, PATH ×2,
/// PROCTITLE, EOE), so this covers a ~36-exec burst per wakeup without letting
/// a flood starve the stop signal.
const DRAIN_BUDGET: usize = 256;

pub struct AuditSensor {
    stop: Arc<Notify>,
    /// The agent's state directory, where a marker with this instance's pid lets the next one
    /// attribute a `SIGKILL` from auditd's log (#275). `None`: no replay.
    state_dir: Option<std::path::PathBuf>,
    /// The audit log files read for that replay; [`crate::killrec::default_log_paths`] unless a
    /// test says otherwise.
    log_paths: Vec<std::path::PathBuf>,
}

impl AuditSensor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(Notify::new()),
            state_dir: None,
            log_paths: crate::killrec::default_log_paths(),
        }
    }

    /// Keeps a marker in `state_dir` and, at start, replays a `SIGKILL` of the previous instance
    /// found in auditd's log as an `Event::Signal` (#275). It finds one only when the operator
    /// loaded `packaging/linux/audit/synthaea-kill.rules`; without the rule it reports nothing.
    #[must_use]
    pub fn with_state_dir(mut self, state_dir: std::path::PathBuf) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    /// Reads the previous instance's marker, writes this one's, and emits the replayed kill, if any.
    fn replay_previous_sigkill(&self, sink: &dyn EventSink) {
        let Some(dir) = &self.state_dir else {
            return;
        };
        let own_pid = std::process::id();
        let now_ns = schema::time::now_ns();
        let previous = crate::killrec::read_marker(dir);
        if let Err(e) = crate::killrec::write_marker(dir, own_pid, now_ns) {
            tracing::warn!(error = %e, "sensor-linux-audit: could not write the instance marker, a SIGKILL of this agent will not be attributed");
        }
        if let Some(record) =
            crate::killrec::previous_instance_kill(previous, own_pid, now_ns, &self.log_paths)
        {
            tracing::warn!(
                sender_pid = record.sender_pid,
                target_pid = record.target_pid,
                "sensor-linux-audit: the previous agent instance was sent SIGKILL, reporting it"
            );
            sink.on_event(normalize::sigkill_event(
                &record,
                std::env::current_exe()
                    .ok()
                    .map(|exe| exe.to_string_lossy().into_owned()),
            ));
        }
    }

    async fn run_async(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let socket = AuditSocket::open().map_err(|e| format!("audit socket open: {e}"))?;

        // SAFETY: `socket`'s fd comes from `socket(2)` in `AuditSocket::open` (checked
        // for -1), so it is valid and open. `AuditSocket` keeps it in a private field
        // that is never reassigned, exposes no `into_raw_fd`/close, and closes it only in
        // its `Drop` — which runs when the `AsyncFd` that now owns the socket is dropped.
        // So it stays open and the same descriptor for the `AsyncFd`'s whole life, and
        // `as_raw_fd` always returns it.
        let mut async_socket = unsafe {
            tokio::io::unix::AsyncFd::register_with_interest(socket, tokio::io::Interest::READABLE)
        }
        .map_err(|e| format!("AsyncFd: {e}"))?;

        tracing::info!("sensor-linux-audit: listening for exec/connect");
        self.replay_previous_sigkill(sink.as_ref());

        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);

        let mut buf = vec![0u8; crate::socket::RECV_BUFFER_LEN];
        // A record this parser can't read is skipped and counted, never fatal:
        // returning the parse error here once stopped the sensor on the first
        // record it received (#504).
        let mut unparsed: u64 = 0;
        let mut overruns: u64 = 0;
        let mut execve = ExecveAssembler::default();
        let mut truncated: u64 = 0;
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = async_socket.readable_mut() => {
                    let mut guard = guard.map_err(|e| format!("poll: {e}"))?;
                    // Drain what is queued before re-arming: readiness is edge-
                    // triggered, and clearing it after a single recv left the rest
                    // queued until the next record arrived, so the sensor fell
                    // further behind with every burst and lost the tail on exit
                    // (#504). Bounded per wakeup so a flood can't starve `stop`;
                    // readiness stays set when the budget runs out.
                    for _ in 0..DRAIN_BUDGET {
                        match guard.get_inner_mut().recv(&mut buf) {
                            Ok(received) => {
                                if received.truncated {
                                    truncated += 1;
                                    if truncated.is_power_of_two() {
                                        tracing::warn!(
                                            truncated_total = truncated,
                                            "sensor-linux-audit: record longer than the receive buffer, parsed cut"
                                        );
                                    }
                                }
                                match parse::parse_audit_message(&buf[..received.len]) {
                                    Ok(record) => forward(&record, &mut execve, sink.as_ref()),
                                    Err(e) => {
                                        unparsed += 1;
                                        // Powers of two only: a stream of bad records must not flood the log.
                                        if unparsed.is_power_of_two() {
                                            tracing::warn!(
                                                error = %e,
                                                unparsed_total = unparsed,
                                                "sensor-linux-audit: unparseable record skipped"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(crate::AuditError::Netlink(errno))
                                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK =>
                            {
                                guard.clear_ready();
                                break;
                            }
                            // The kernel dropped records because the socket buffer
                            // overflowed; the socket itself is still usable.
                            Err(crate::AuditError::Netlink(libc::ENOBUFS)) => {
                                overruns += 1;
                                if overruns.is_power_of_two() {
                                    tracing::warn!(
                                        overruns_total = overruns,
                                        "sensor-linux-audit: kernel dropped records (socket buffer overrun)"
                                    );
                                }
                            }
                            Err(e) => {
                                return Err(format!("recv: {e}").into());
                            }
                        }
                    }
                }
            }
        }

        for exec in execve.finish() {
            emit_exec(exec, sink.as_ref());
        }
        // A clean stop: nothing killed this instance, so the next one has nothing to attribute.
        if let Some(dir) = &self.state_dir {
            crate::killrec::remove_marker(dir);
        }
        tracing::info!("sensor-linux-audit: exiting");
        Ok(())
    }
}

impl Default for AuditSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for AuditSensor {
    fn name(&self) -> &str {
        "linux-audit"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            exec_events: true,
            file_events: false, // Phase 2: fanotify
            connect_events: true,
            auth_events: false, // journal sensor's domain
            user_attribution: true,
            parent_lineage: false, // HONEST: auditd doesn't track ppid
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        rt.block_on(self.run_async(sink))
    }

    fn stop(&mut self) {
        self.stop.notify_one();
    }
}

/// Classifies one parsed record and hands the resulting event, if any, to `sink`.
/// `EXECVE` records go to `execve`, which hands back each exec once its records end.
fn forward(record: &parse::AuditRecord, execve: &mut ExecveAssembler, sink: &dyn EventSink) {
    for exec in execve.push(record) {
        emit_exec(exec, sink);
    }
    if record.record_type == classify::AUDIT_EXECVE {
        return;
    }
    let Some(event) = classify::classify(record) else {
        return;
    };
    let timestamp_ns = audit_ts_to_epoch_ns(record.timestamp_sec, record.timestamp_ms);
    let schema_event = match &event {
        crate::AuditEvent::Exec { .. } => normalize::exec_event(&event, timestamp_ns),
        crate::AuditEvent::Connect { .. } => normalize::connect_event(&event, timestamp_ns),
        crate::AuditEvent::PolicyDenial { .. } => {
            normalize::policy_denial_event(&event, timestamp_ns)
        }
    };
    sink.on_event(schema_event);
}

fn emit_exec(exec: AssembledExec, sink: &dyn EventSink) {
    let timestamp_ns = audit_ts_to_epoch_ns(exec.timestamp_sec, exec.timestamp_ms);
    sink.on_event(normalize::exec_event(&exec.event, timestamp_ns));
}

pub(crate) fn audit_ts_to_epoch_ns(sec: u64, ms: u32) -> u64 {
    sec * 1_000_000_000 + (ms as u64) * 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_conversion() {
        let ns = audit_ts_to_epoch_ns(1234567890, 123);
        assert_eq!(ns, 1_234_567_890_123_000_000);
    }

    #[derive(Default)]
    struct Collect(std::sync::Mutex<Vec<schema::Event>>);

    impl EventSink for Collect {
        fn on_event(&self, event: schema::Event) {
            self.0.lock().expect("test sink lock").push(event);
        }
    }

    fn wire(record_type: u16, seq: u64, fields: &str) -> parse::AuditRecord {
        let raw = parse::build_wire_message(record_type, &format!("audit(1000.5:{seq}): {fields}"));
        parse::parse_audit_message(&raw).expect("test record parses")
    }

    #[test]
    fn interleaved_split_execs_reach_the_sink_whole() {
        // #51 at the sensor boundary: two execs' records interleaved as on a multi-CPU
        // host, one of them split into pieces, plus a connect in between.
        let script = "x".repeat(9000);
        let encoded: String = script.bytes().map(|b| format!("{b:02X}")).collect();
        let (p0, p1) = encoded.split_at(7400);
        let head = format!(
            "argc=2 a0=\"/bin/true\" a1_len={} a1[0]={p0}",
            encoded.len()
        );
        let tail = format!("a1[1]={p1}");
        let sink = Collect::default();
        let mut execve = ExecveAssembler::default();
        for record in [
            wire(1300, 10, "syscall=59"),
            wire(1309, 10, &head),
            wire(1309, 11, "argc=1 a0=\"/bin/id\""),
            wire(1306, 12, "saddr=02001F907F000001"),
            wire(1309, 10, &tail),
            wire(1307, 11, "cwd=\"/\""),
            wire(1307, 10, "cwd=\"/\""),
            wire(1309, 13, "argc=1 a0=\"/bin/ls\""),
        ] {
            forward(&record, &mut execve, &sink);
        }
        for exec in execve.finish() {
            emit_exec(exec, &sink);
        }
        let events = sink.0.into_inner().expect("test sink lock");
        let execs: Vec<(Vec<String>, bool)> = events
            .iter()
            .filter_map(|e| match e {
                schema::Event::Exec(x) => Some((x.argv.clone(), x.cmdline_truncated)),
                _ => None,
            })
            .collect();
        assert_eq!(
            execs,
            [
                (vec!["/bin/id".to_string()], false),
                (vec!["/bin/true".to_string(), script], false),
                (vec!["/bin/ls".to_string()], false),
            ]
        );
        assert_eq!(events.len(), 4, "the connect is forwarded too");
    }

    #[test]
    fn capabilities_honest_about_gaps() {
        let sensor = AuditSensor::new();
        let caps = sensor.capabilities();
        assert!(caps.exec_events);
        assert!(caps.connect_events);
        assert!(caps.user_attribution);
        assert!(!caps.parent_lineage); // Honest: audit doesn't provide ppid
        assert!(!caps.file_events); // Phase 2
        assert!(!caps.auth_events); // journal owns this
    }

    /// A `SIGKILL` record of pid 0xff by pid 20 at `1000.500`, as auditd logs it.
    fn kill_line(target_hex: &str) -> String {
        format!(
            "type=SYSCALL msg=audit(1000.500:7): arch=c000003e syscall=62 success=yes exit=0 a0={target_hex} a1=9 a2=0 a3=0 items=0 ppid=10 pid=20 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4 comm=\"sh\" exe=\"/bin/sh\" key=\"{}\"",
            crate::killrec::KILL_KEY
        )
    }

    fn sensor_in(dir: &std::path::Path, log: std::path::PathBuf) -> AuditSensor {
        let mut sensor = AuditSensor::new().with_state_dir(dir.to_path_buf());
        sensor.log_paths = vec![log];
        sensor
    }

    #[test]
    fn a_restart_after_a_sigkill_reports_the_kill_as_a_signal_event_once() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        std::fs::write(&log, format!("{}\n", kill_line("ff"))).unwrap();
        // The previous instance (pid 255) started at t=500 s and left its marker: the kill at
        // t=1000.5 s is after that. "Now" is read from the clock, so the marker is written with
        // a start time shortly before the record's timestamp is made current.
        let own = std::process::id();
        assert_ne!(own, 0xff);
        let now = schema::time::now_ns();
        // Rewrite the log's record to a timestamp just before `now`, inside the replay window.
        let at = now / 1_000_000_000 - 5;
        std::fs::write(
            &log,
            kill_line("ff").replace("audit(1000.500:7)", &format!("audit({at}.500:7)")) + "\n",
        )
        .unwrap();
        crate::killrec::write_marker(dir.path(), 0xff, (at - 100) * 1_000_000_000).unwrap();

        let sensor = sensor_in(dir.path(), log);
        let sink = Collect::default();
        sensor.replay_previous_sigkill(&sink);
        let events = sink.0.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "{events:?}");
        let schema::Event::Signal(signal) = &events[0] else {
            panic!("not a Signal event: {events:?}");
        };
        assert_eq!(signal.signal, 9);
        assert_eq!(signal.target_pid, 0xff);
        assert_eq!(signal.meta.pid, 20, "the sender is the meta");
        assert_eq!(signal.meta.comm, "sh");

        // The marker now names this instance: a second start with no new kill reports nothing.
        assert_eq!(
            crate::killrec::read_marker(dir.path()).map(|m| m.0),
            Some(own)
        );
        let again = Collect::default();
        sensor.replay_previous_sigkill(&again);
        assert!(again.0.lock().unwrap().is_empty());
    }

    #[test]
    fn no_marker_or_no_state_dir_reports_nothing_and_a_stop_removes_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        std::fs::write(&log, format!("{}\n", kill_line("ff"))).unwrap();
        // First start ever: nothing to attribute, but the marker is written.
        let sensor = sensor_in(dir.path(), log);
        let sink = Collect::default();
        sensor.replay_previous_sigkill(&sink);
        assert!(sink.0.lock().unwrap().is_empty());
        assert!(crate::killrec::read_marker(dir.path()).is_some());
        // Without a state directory the sensor does nothing at all.
        let none = AuditSensor::new();
        let sink = Collect::default();
        none.replay_previous_sigkill(&sink);
        assert!(sink.0.lock().unwrap().is_empty());
    }
}
