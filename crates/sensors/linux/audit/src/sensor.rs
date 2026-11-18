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
    /// The marker as written, kept to refresh its thread list.
    marker: std::sync::Mutex<Option<crate::killrec::Marker>>,
}

/// How the start-up replay ended.
#[derive(Debug, PartialEq, Eq)]
enum ReplayOutcome {
    /// No state directory, no marker, this instance's own pid, or another boot: nothing to look for.
    NothingToLookFor,
    /// A record of the kill was found and emitted.
    Reported,
    /// The marker survived and no record accounts for the previous instance (warned).
    NoRecord,
}

/// How often the marker's thread list is compared with `/proc/self/task`: the runtime starts
/// workers on demand, and a `kill(<tid>, 9)` of one that the marker lacks is not attributed.
const THREAD_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);

/// This process's group id: `kill -9 -<pgid>` aims at it.
fn process_group() -> u32 {
    // SAFETY: `getpgrp(2)` takes no argument, cannot fail and touches no memory.
    let pgid = unsafe { libc::getpgrp() };
    u32::try_from(pgid).unwrap_or(0)
}

impl AuditSensor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(Notify::new()),
            state_dir: None,
            log_paths: crate::killrec::default_log_paths(),
            marker: std::sync::Mutex::new(None),
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
    ///
    /// Synchronous, on the runtime thread, once at start-up and before the listening loop: it
    /// reads the tail of each audit log file (2 x 16 MiB at most per file, and the walk stops at
    /// the first file older than the previous instance), which is brief next to the start. It
    /// is not moved to `spawn_blocking`: the sink is borrowed, and the replay must have been
    /// emitted before the first live record.
    fn replay_previous_sigkill(&self, sink: &dyn EventSink) -> ReplayOutcome {
        let Some(dir) = &self.state_dir else {
            return ReplayOutcome::NothingToLookFor;
        };
        let own_pid = std::process::id();
        let boot_id = crate::killrec::current_boot_id();
        let previous = crate::killrec::read_marker(dir);
        let this = crate::killrec::Marker {
            pid: own_pid,
            pgid: process_group(),
            started_ns: schema::time::now_ns(),
            boot_id: boot_id.clone(),
            tids: crate::killrec::current_thread_ids(),
            // SAFETY: `getuid(2)` takes no argument, cannot fail and touches no memory.
            uid: Some(unsafe { libc::getuid() }),
            anchor: crate::killrec::newest_anchor(&self.log_paths),
        };
        *self.marker.lock().unwrap_or_else(|e| e.into_inner()) = Some(this.clone());
        if let Err(e) = crate::killrec::write_marker(dir, &this) {
            tracing::warn!(error = %e, "sensor-linux-audit: could not write the instance marker, a SIGKILL of this agent will not be attributed");
        }
        let Some(replay) = crate::killrec::previous_instance_kill(
            previous.as_ref(),
            own_pid,
            boot_id.as_deref(),
            &self.log_paths,
        ) else {
            return ReplayOutcome::NothingToLookFor;
        };
        let previous_pid = previous.as_ref().map_or(0, |m| m.pid);
        let Some(record) = replay.record else {
            // The marker survived, so the previous instance did not stop on its own, and no
            // record accounts for it: a kill the rule does not see (`systemctl kill`, a signal
            // sent another way, no rule loaded, a record rotated out of reach) or a crash.
            tracing::warn!(
                previous_pid,
                read = ?replay.read,
                unreadable = ?replay.unreadable,
                truncated = ?replay.truncated,
                "sensor-linux-audit: the previous agent instance did not stop cleanly and auditd's log holds no SIGKILL record for it"
            );
            return ReplayOutcome::NoRecord;
        };
        tracing::warn!(
            sender_pid = record.sender_pid,
            target_pid = previous_pid,
            "sensor-linux-audit: the previous agent instance was sent SIGKILL, reporting it"
        );
        sink.on_event(normalize::sigkill_event(
            &record,
            previous_pid,
            std::env::current_exe()
                .ok()
                .map(|exe| exe.to_string_lossy().into_owned()),
        ));
        ReplayOutcome::Reported
    }

    /// Rewrites the marker when the process's thread ids changed since it was written.
    fn refresh_marker_threads(&self) {
        let Some(dir) = &self.state_dir else {
            return;
        };
        let mut guard = self.marker.lock().unwrap_or_else(|e| e.into_inner());
        let Some(marker) = guard.as_mut() else {
            return;
        };
        let tids = crate::killrec::current_thread_ids();
        if tids.is_empty() || tids == marker.tids {
            return;
        }
        marker.tids = tids;
        if let Err(e) = crate::killrec::write_marker(dir, marker) {
            tracing::warn!(error = %e, "sensor-linux-audit: could not refresh the thread list of the instance marker");
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
        let _ = self.replay_previous_sigkill(sink.as_ref());

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
        let mut threads = tokio::time::interval(THREAD_REFRESH);
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = threads.tick() => self.refresh_marker_threads(),
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

    /// A marker for the previous instance (pid 255) that started at `started_s`, in this boot.
    fn previous_marker(dir: &std::path::Path, pid: u32, started_s: u64) {
        crate::killrec::write_marker(
            dir,
            &crate::killrec::Marker {
                pid,
                pgid: pid,
                started_ns: started_s * 1_000_000_000,
                boot_id: crate::killrec::current_boot_id(),
                // SAFETY: `getuid(2)` takes no argument, cannot fail and touches no memory.
                uid: Some(unsafe { libc::getuid() }),
                ..crate::killrec::Marker::default()
            },
        )
        .unwrap();
    }

    fn replayed(sensor: &AuditSensor) -> Vec<schema::Event> {
        replayed_with_outcome(sensor).0
    }

    fn replayed_with_outcome(sensor: &AuditSensor) -> (Vec<schema::Event>, ReplayOutcome) {
        let sink = Collect::default();
        let outcome = sensor.replay_previous_sigkill(&sink);
        (sink.0.lock().unwrap().clone(), outcome)
    }

    #[test]
    fn a_restart_after_a_sigkill_reports_the_kill_as_a_signal_event_once() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        // The previous instance (pid 255) started at t=900 s; the kill is logged at t=1000.5 s,
        // after that start.
        std::fs::write(&log, format!("{}\n", kill_line("ff"))).unwrap();
        let own = std::process::id();
        assert_ne!(own, 0xff);
        previous_marker(dir.path(), 0xff, 900);

        let sensor = sensor_in(dir.path(), log);
        let events = replayed(&sensor);
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
            crate::killrec::read_marker(dir.path()).map(|m| m.pid),
            Some(own)
        );
        assert!(replayed(&sensor).is_empty());
    }

    #[test]
    fn a_group_kill_of_the_previous_instance_is_reported_against_its_pid() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        // `kill -9 -255`: a0 is the 32-bit -255.
        std::fs::write(&log, format!("{}\n", kill_line("ffffff01"))).unwrap();
        previous_marker(dir.path(), 0xff, 900);
        let events = replayed(&sensor_in(dir.path(), log));
        let [schema::Event::Signal(signal)] = events.as_slice() else {
            panic!("expected one Signal event: {events:?}");
        };
        assert_eq!(
            signal.target_pid, 0xff,
            "the old instance's pid, not the group id"
        );
    }

    #[test]
    fn a_marker_with_no_record_reports_no_event() {
        // The outcome is the one that triggers the "did not stop cleanly" warning.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        std::fs::write(&log, format!("{}\n", kill_line("aa"))).unwrap();
        previous_marker(dir.path(), 0xff, 900);
        let (events, outcome) = replayed_with_outcome(&sensor_in(dir.path(), log));
        assert!(events.is_empty());
        assert_eq!(outcome, ReplayOutcome::NoRecord);
    }

    #[test]
    fn no_marker_or_no_state_dir_reports_nothing_and_a_stop_removes_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        std::fs::write(&log, format!("{}\n", kill_line("ff"))).unwrap();
        // First start ever: nothing to attribute, but the marker is written.
        let sensor = sensor_in(dir.path(), log);
        let sink = Collect::default();
        assert_eq!(
            sensor.replay_previous_sigkill(&sink),
            ReplayOutcome::NothingToLookFor
        );
        assert!(sink.0.lock().unwrap().is_empty());
        let written = crate::killrec::read_marker(dir.path()).unwrap();
        assert!(written.tids.contains(&std::process::id()));
        assert!(written.uid.is_some());
        // Without a state directory the sensor does nothing at all.
        let none = AuditSensor::new();
        let sink = Collect::default();
        assert_eq!(
            none.replay_previous_sigkill(&sink),
            ReplayOutcome::NothingToLookFor
        );
        assert!(sink.0.lock().unwrap().is_empty());
    }

    #[test]
    fn a_thread_started_later_is_added_to_the_marker_and_a_kill_of_it_is_attributed() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let sensor = sensor_in(dir.path(), log.clone());
        let _ = replayed(&sensor);
        let before = crate::killrec::read_marker(dir.path()).unwrap();
        // A new thread, alive while the marker is refreshed; its tid is then what is killed.
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            // SAFETY: `gettid` takes no argument and cannot fail.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            tid_tx.send(u32::try_from(tid).unwrap()).unwrap();
            let _ = done_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        assert!(!before.tids.contains(&tid));
        sensor.refresh_marker_threads();
        let after = crate::killrec::read_marker(dir.path()).unwrap();
        assert!(after.tids.contains(&tid));
        // `kill -9 <worker tid>` of that process, replayed by its successor (another pid).
        std::fs::write(&log, format!("{}\n", kill_line(&format!("{tid:x}")))).unwrap();
        let mut previous = after;
        previous.pid = 0xff;
        previous.started_ns = 0;
        previous.anchor = None;
        crate::killrec::write_marker(dir.path(), &previous).unwrap();
        let events = replayed(&sensor_in(dir.path(), log));
        assert_eq!(events.len(), 1, "{events:?}");
        done_tx.send(()).unwrap();
        worker.join().unwrap();
    }
}
