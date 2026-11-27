//! Process records: exec, signals, and one process reaching into another.

use super::{comm_opt, meta};
use schema::{
    ContainerContext, Event, ExecEvent, MemfdCreateEvent, ProcessVmReadEvent, ProcessVmWriteEvent,
    PtraceEvent, SignalEvent,
};
use sensor_linux_wire as wire;

/// `image_path` is the authoritative image the kernel loaded (`ExecEvent::image`, from
/// the `sched_process_exec` tracepoint), never `argv[0]`. `argv` is passed in by the
/// caller — the Linux sensor reads it from `/proc/<pid>/cmdline` when it drains the
/// event (issue #152; empty for a process that already exited). `cmdline` is a
/// space-joined rendering of `argv` for display and Sigma matching; consumers that
/// need the exact tokens use `argv` (or `ExecEvent::ml_cmdline`). `parent_comm` is the
/// fork-lineage entry, or `None` when the parent predated the probe and priming
/// missed it. `env_security` is passed in by the caller the same way as `argv` — the
/// Linux sensor reads it from `/proc/<pid>/environ` when it drains the event (issue
/// #363; same drain-time-read tradeoffs as `argv`, see `read_proc_environ_security`),
/// already filtered to the security-relevant allowlist. `argv` is cut to
/// [`schema::ARGV_CAPTURE_BUDGET`] here, the one place every exec passes (#1112).
#[must_use]
pub fn exec(
    event: &wire::ExecEvent,
    boot_epoch_offset_ns: u64,
    mut argv: Vec<String>,
    argv_omitted_bytes: Option<u32>,
    env_security: Vec<(String, String)>,
    container: Option<ContainerContext>,
) -> Event {
    let image_raw = &event.image[..(event.image_len as usize).min(wire::MAX_PATH_LEN)];
    let image_end = image_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(image_raw.len());
    let image_path = String::from_utf8_lossy(&image_raw[..image_end]).into_owned();
    // ADR-0045's truth table: the flag is set exactly when bytes are known to be missing, from
    // the probe's windows (`Some(n > 0)`) or from the budget cut, whose size is not measured.
    let budget_cut = schema::bound_argv(&mut argv);
    let argv_omitted_bytes = if budget_cut { None } else { argv_omitted_bytes };
    let cmdline_truncated = budget_cut || argv_omitted_bytes.is_some_and(|n| n > 0);

    Event::Exec(ExecEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        image_path,
        cmdline: argv.join(" "),
        argv,
        cmdline_truncated,
        argv_omitted_bytes,
        parent_comm: comm_opt(&event.pcomm),
        // eBPF has the parent comm but not its full path: the sensor fills it from its
        // pid-to-image cache (`parent_image`, #768).
        parent_image_path: None,
        sha256: None,
        signature: None,
        original_file_name: None, // filled by the agent's enrichment stage (#983); Linux has no PE resource anyway
        company_name: None,
        file_description: None,
        product_name: None,
        image_file_id: None,
        env_security,
    })
}

/// Resolves the renaming process's own executable path (#459 part 1) via
/// `readlink /proc/<pid>/exe`, so `rules`' T1486 mass-rename check can gate a
/// name-keyed exclusion (`sed`/`perl` in-place-edit-with-backup) on evidence
/// instead of trusting `comm` alone — the wire event carries no image path of
/// its own (unlike `ExecEvent`, `rename(2)` isn't an exec, nothing in the
/// kernel hands the probe an image path to read at the tracepoint).
///
/// Two honest limitations, both resulting in `None` rather than a wrong
/// answer: this is a `/proc` read at *normalize* time, after the ring buffer
/// has already delivered the event, so a very short-lived process can have
/// already exited (`ENOENT`) — same race any `/proc/<pid>/*` read from
/// userspace has, unavoidable without kernel-side `d_path` resolution at the
/// tracepoint itself. And unlike `ExecEvent::image_path` (read once, already
/// in hand from the exec tracepoint), this is one extra syscall per
/// `FileRenameEvent` — acceptable at rename-event rates (#82's own write-
/// volume work says the same about `FileWriteEvent`, an even higher-rate
/// event, needing no such read), revisit if a real workload makes it not.
pub(super) fn exe_path_for_pid(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

/// What the sensor resolved about a signal's two processes, which the wire event carries only as
/// pids. `target_image_path` is the caller's, not the wire event's — see this module's
/// `WIRE_VERSION` v12 changelog for why. So is `target_unit` (#1103): the unit the sensor
/// resolved from the cgroup when it put the target on the watch list. `sender_is_watchdog` is
/// the sensor's check of the sender against the agent's watchdog (#322).
#[derive(Debug, Default)]
pub struct SignalParties {
    /// The target's executable.
    pub target_image_path: Option<String>,
    /// The listed security unit the target belongs to.
    pub target_unit: Option<String>,
    /// The sender is the agent's own watchdog.
    pub sender_is_watchdog: bool,
}

/// A wire signal event, with what the sensor resolved about its sender and target.
#[must_use]
pub fn signal(
    event: &wire::SignalEvent,
    boot_epoch_offset_ns: u64,
    parties: SignalParties,
    container: Option<ContainerContext>,
) -> Event {
    Event::Signal(SignalEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        signal: event.signal & !wire::SIGNAL_SENDER_UNRELIABLE,
        target_pid: event.target_pid,
        target_image_path: parties.target_image_path,
        target_unit: parties.target_unit,
        sender_is_watchdog: parties.sender_is_watchdog,
        sender_unreliable: event.signal & wire::SIGNAL_SENDER_UNRELIABLE != 0,
        signals_lost: 0,
    })
}

/// Signals to security tools the signal ring buffer had no room for, since the last report
/// (`SIGNAL_TOOL_DROPS`, #1103): a `SignalEvent` with `signals_lost` set, which the rules turn into
/// a finding, since a flood ahead of a kill is how a tool is ended unseen. It has no signal and no
/// target (`signal` and `target_pid` are 0, which no kernel event has). `timestamp_ns` is
/// wall-clock time.
#[must_use]
pub fn signals_lost(lost: u64, agent_pid: u32, timestamp_ns: u64) -> Event {
    Event::Signal(SignalEvent {
        meta: schema::EventMeta {
            pid: agent_pid,
            ppid: 0,
            user: schema::User::Unknown,
            timestamp_ns,
            comm: "signal_generate".to_owned(),
            container: None,
            process_generation: None,
            parent_process_generation: None,
        },
        signal: 0,
        target_pid: 0,
        target_image_path: None,
        target_unit: None,
        sender_is_watchdog: false,
        sender_unreliable: false,
        signals_lost: lost,
    })
}

/// Maps a `wire::PtraceEvent` to `Event::Ptrace`. `request`, `addr` and `data` are the raw `ptrace(2)`
/// arguments, unfiltered. `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn ptrace(
    event: &wire::PtraceEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::Ptrace(PtraceEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        request: event.request,
        target_pid: event.target_pid,
        addr: event.addr,
        data: event.data,
    })
}

/// Maps a `wire::ProcessVmReadEvent` to `Event::ProcessVmRead`: the target pid and the local and remote
/// iovec counts. `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn process_vm_read(
    event: &wire::ProcessVmReadEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::ProcessVmRead(ProcessVmReadEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        target_pid: event.target_pid,
        local_iov_count: event.local_iov_count,
        remote_iov_count: event.remote_iov_count,
        remote_iov_len: event.remote_iov_len,
    })
}

/// Maps a `wire::ProcessVmWriteEvent` to `Event::ProcessVmWrite`: the target pid and the local and remote
/// iovec counts. `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn process_vm_write(
    event: &wire::ProcessVmWriteEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    Event::ProcessVmWrite(ProcessVmWriteEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        target_pid: event.target_pid,
        local_iov_count: event.local_iov_count,
        remote_iov_count: event.remote_iov_count,
        remote_iov_len: event.remote_iov_len,
    })
}

/// Maps a `wire::MemfdCreateEvent` to `Event::MemfdCreate`; `name` is the label passed to `memfd_create(2)`,
/// not a path. `boot_epoch_offset_ns` and `container` as in [`file_open`](super::file_open).
#[must_use]
pub fn memfd_create(
    event: &wire::MemfdCreateEvent,
    boot_epoch_offset_ns: u64,
    container: Option<ContainerContext>,
) -> Event {
    let raw = &event.name[..(event.name_len as usize).min(wire::MAX_PATH_LEN)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Event::MemfdCreate(MemfdCreateEvent {
        meta: meta(&event.meta, boot_epoch_offset_ns, container),
        name: String::from_utf8_lossy(&raw[..end]).into_owned(),
        flags: event.flags,
        fd: event.fd,
    })
}
