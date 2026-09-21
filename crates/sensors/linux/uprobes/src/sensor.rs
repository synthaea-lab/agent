//! Uprobe sensor: loads eBPF programs, attaches uprobes to SSL/readline functions,
//! drains ring buffers. Symbol resolution via [`crate::symbol_resolver`].
//!
//! **Status (Phase 6):** Full implementation with configuration - symbol resolution,
//! uprobe attachment, ring buffer draining, normalization, and budget enforcement.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use aya::{
    Ebpf,
    maps::RingBuf,
    programs::{UProbe, uprobe::UProbeScope},
};
use log::{debug, info, warn};
use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use sensor_linux_wire::{ReadlineInputEvent, TASK_COMM_LEN, TlsCaptureEvent};
use tokio::sync::Notify;

use crate::{
    config::UprobesConfig,
    normalize,
    symbol_resolver::{self, SymbolInfo},
};

fn err(msg: String) -> SensorError {
    msg.into()
}

/// Difference between the epoch clock and `CLOCK_MONOTONIC` (which the probes stamp
/// events with), computed once at startup — see `normalize`.
fn boot_epoch_offset_ns() -> u64 {
    let epoch_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain FFI call with a valid pointer to a stack-owned timespec
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        log::warn!("sensor-linux-uprobes: clock_gettime(CLOCK_MONOTONIC) failed");
        return 0;
    }
    let monotonic_ns = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    epoch_ns.saturating_sub(monotonic_ns)
}

/// Per-process budget tracking for TLS capture (sliding window).
struct TlsBudgetTracker {
    /// Budget: bytes per process per second.
    bytes_per_sec: u32,
    /// Sliding window: `(pid, timestamp, bytes_captured)`.
    windows: HashMap<u32, Vec<(Instant, u32)>>,
    /// Cleanup interval (remove old entries every N checks).
    cleanup_counter: u32,
}

impl TlsBudgetTracker {
    fn new(bytes_per_sec: u32) -> Self {
        Self {
            bytes_per_sec,
            windows: HashMap::new(),
            cleanup_counter: 0,
        }
    }

    /// Check if pid can capture `bytes` without exceeding budget.
    /// Returns true if allowed, false if budget exceeded.
    fn check_and_record(&mut self, pid: u32, bytes: u32) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(1);

        // Get or create window for this pid
        let entries = self.windows.entry(pid).or_default();

        // Remove entries older than 1 second
        entries.retain(|(ts, _)| now.duration_since(*ts) < window);

        // Sum bytes in current window
        let bytes_in_window: u32 = entries.iter().map(|(_, b)| b).sum();

        // Check budget
        if bytes_in_window + bytes > self.bytes_per_sec {
            return false;
        }

        // Record this capture
        entries.push((now, bytes));

        // Periodic cleanup of old PIDs (every 100 checks)
        self.cleanup_counter += 1;
        if self.cleanup_counter >= 100 {
            self.cleanup_counter = 0;
            self.windows.retain(|_, entries| !entries.is_empty());
        }

        true
    }
}

/// Per-process budget tracking for readline capture (sliding window).
struct ReadlineBudgetTracker {
    /// Budget: commands per process per second.
    commands_per_sec: u32,
    /// Sliding window: (pid, timestamps).
    windows: HashMap<u32, Vec<Instant>>,
    /// Cleanup interval.
    cleanup_counter: u32,
}

impl ReadlineBudgetTracker {
    fn new(commands_per_sec: u32) -> Self {
        Self {
            commands_per_sec,
            windows: HashMap::new(),
            cleanup_counter: 0,
        }
    }

    /// Check if pid can capture one more command without exceeding budget.
    fn check_and_record(&mut self, pid: u32) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(1);

        let entries = self.windows.entry(pid).or_default();
        entries.retain(|ts| now.duration_since(*ts) < window);

        if entries.len() >= self.commands_per_sec as usize {
            return false;
        }

        entries.push(now);

        self.cleanup_counter += 1;
        if self.cleanup_counter >= 100 {
            self.cleanup_counter = 0;
            self.windows.retain(|_, entries| !entries.is_empty());
        }

        true
    }
}

/// Loads the embedded eBPF object from the main sensor-linux-ebpf crate.
/// Uprobes share the same eBPF object as tracepoints (built in `sensor-linux-ebpf`).
///
/// # Errors
///
/// Returns [`SensorError`] if the eBPF object fails to load.
#[cfg(ebpf_embedded)]
fn load_ebpf() -> Result<Ebpf, SensorError> {
    // Bump memlock rlimit (needed for older kernels)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: plain FFI call with a valid pointer to a stack-owned rlimit struct
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("sensor-linux-uprobes: setrlimit(RLIMIT_MEMLOCK) failed: {ret}");
    }

    // Load the eBPF object (built by sensor-linux-ebpf, shared with tracepoints)
    let ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sensor-linux-ebpf"
    )))
    .map_err(|e| err(format!("failed to load eBPF object: {e}")))?;
    Ok(ebpf)
}

/// This build carries no embedded probes (bpf-linker was absent at build time).
///
/// # Errors
///
/// Always errors — the message says how to provision the toolchain.
#[cfg(not(ebpf_embedded))]
fn load_ebpf() -> Result<Ebpf, SensorError> {
    Err(err(
        "sensor-linux-uprobes was built without embedded eBPF probes (bpf-linker not on PATH \
         at build time) — provision the eBPF toolchain and rebuild"
            .to_string(),
    ))
}

/// Attaches a uprobe to the given function in the target binary.
///
/// # Errors
///
/// Returns [`SensorError`] if the program is not found or attachment fails.
///
/// # Note
///
/// The `loaded_programs` parameter tracks which programs have already been loaded
/// to avoid calling `program.load()` multiple times for the same program name.
/// This is critical when attaching to multiple symbol offsets (e.g., both `SSL_write`
/// and `SSL_write_ex` in OpenSSL 3.x) which must share the same eBPF program instance.
fn attach_uprobe(
    ebpf: &mut Ebpf,
    program_name: &str,
    symbol: &SymbolInfo,
    loaded_programs: &mut std::collections::HashSet<String>,
) -> Result<(), SensorError> {
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| err(format!("program `{program_name}` not found in eBPF object")))?
        .try_into()
        .map_err(|e| err(format!("`{program_name}` is not a uprobe: {e}")))?;

    // Load program only once per unique program name
    // (critical fix: OpenSSL 3.x exports both SSL_write and SSL_write_ex,
    // both must attach to the same "ssl_write_openssl" program instance)
    if !loaded_programs.contains(program_name) {
        program
            .load()
            .map_err(|e| err(format!("kernel verifier rejected `{program_name}`: {e}")))?;
        loaded_programs.insert(program_name.to_string());
        log::debug!("sensor-linux-uprobes: loaded program {program_name}");
    }

    // Attach uprobe: point = offset, target = library path, scope = all processes
    // (can attach same program to multiple offsets)
    program
        .attach(
            symbol.offset,
            &symbol.library_path,
            UProbeScope::AllProcesses,
        )
        .map_err(|e| {
            err(format!(
                "failed to attach uprobe `{program_name}` to {}:{} @ 0x{:x}: {e}",
                symbol.library_path.display(),
                symbol.name,
                symbol.offset
            ))
        })?;

    log::info!(
        "sensor-linux-uprobes: attached {program_name} to {}:{} @ 0x{:x}",
        symbol.library_path.display(),
        symbol.name,
        symbol.offset
    );
    Ok(())
}

/// Reads one `repr(C)` wire struct out of a ring-buffer item, or `None` when the
/// item is too short. Kept as a named function rather than inline in the drain
/// macros: `undocumented_unsafe_blocks` cannot associate a `// SAFETY:` comment
/// with an unsafe block through a macro expansion, and this is the only raw read
/// the drains need.
fn read_wire_event<T: Copy>(item: &[u8]) -> Option<T> {
    if item.len() < core::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: length checked above; T is a repr(C) POD wire struct (Copy, no
    // padding invariants) and read_unaligned handles arbitrary alignment.
    Some(unsafe { core::ptr::read_unaligned(item.as_ptr().cast::<T>()) })
}

/// Drains TLS capture events from the ring buffer and emits normalized schema events.
/// Applies budget enforcement and allowlist filtering.
macro_rules! drain_tls {
    ($guard:expr, $sink:expr, $offset:expr, $config:expr, $budget:expr, $dropped:expr) => {{
        let mut guard = $guard.map_err(|e| err(format!("TLS ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            if let Some(event) = read_wire_event::<TlsCaptureEvent>(&item) {
                // Allowlist check: if allowlist is non-empty, only allow listed processes
                if !$config.tls.process_allowlist.is_empty() {
                    let comm = comm_str(&event.meta.comm);
                    if !$config.tls.process_allowlist.contains(&comm) {
                        debug!(
                            "sensor-linux-uprobes: TLS capture dropped (allowlist): pid={} comm={}",
                            event.meta.pid, comm
                        );
                        $dropped += 1;
                        continue;
                    }
                }

                // Budget enforcement: check if pid hasn't exceeded bytes/sec budget
                if !$budget.check_and_record(event.meta.pid, event.bytes_len) {
                    debug!(
                        "sensor-linux-uprobes: TLS capture dropped (budget): pid={} bytes={}",
                        event.meta.pid, event.bytes_len
                    );
                    $dropped += 1;
                    continue;
                }

                // Normalize and emit to sink
                // TODO: container_id from /proc/<pid>/cgroup (issue #80)
                let schema_event = normalize::tls_capture(&event, $offset, None);
                $sink.on_event(schema_event);
            }
        }
        guard.clear_ready();
    }};
}

/// Helper to decode comm from wire format (shared with drain macros).
fn comm_str(comm: &[u8; TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Drains readline events from the ring buffer and emits normalized schema events.
/// Applies budget enforcement and allowlist filtering.
macro_rules! drain_readline {
    ($guard:expr, $sink:expr, $offset:expr, $config:expr, $budget:expr, $dropped:expr) => {{
        let mut guard =
            $guard.map_err(|e| err(format!("readline ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            if let Some(event) = read_wire_event::<ReadlineInputEvent>(&item) {
                // Allowlist check: if allowlist is non-empty, only allow listed shells
                if !$config.readline.process_allowlist.is_empty() {
                    let comm = comm_str(&event.meta.comm);
                    if !$config.readline.process_allowlist.contains(&comm) {
                        debug!(
                            "sensor-linux-uprobes: readline dropped (allowlist): pid={} comm={}",
                            event.meta.pid, comm
                        );
                        $dropped += 1;
                        continue;
                    }
                }

                // Budget enforcement: check if pid hasn't exceeded commands/sec budget
                if !$budget.check_and_record(event.meta.pid) {
                    debug!(
                        "sensor-linux-uprobes: readline dropped (budget): pid={}",
                        event.meta.pid
                    );
                    $dropped += 1;
                    continue;
                }

                // Normalize and emit to sink
                // TODO: container_id from /proc/<pid>/cgroup (issue #80)
                let schema_event = normalize::readline_input(&event, $offset, None);
                $sink.on_event(schema_event);
            }
        }
        guard.clear_ready();
    }};
}

/// Uprobe sensor. `run` blocks until Ctrl-C or [`Sensor::stop`].
pub struct UprobesSensor {
    stop: Arc<Notify>,
    config: UprobesConfig,
}

impl Default for UprobesSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl UprobesSensor {
    /// Creates a new uprobe sensor with default configuration (all captures disabled).
    #[must_use]
    pub fn new() -> Self {
        Self {
            stop: Arc::new(Notify::new()),
            config: UprobesConfig::new(),
        }
    }

    /// Creates a new uprobe sensor with the given configuration.
    #[must_use]
    pub fn with_config(config: UprobesConfig) -> Self {
        Self {
            stop: Arc::new(Notify::new()),
            config,
        }
    }

    async fn run_async(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        // Check if any capture is enabled
        if !self.config.tls.enabled && !self.config.readline.enabled {
            info!("sensor-linux-uprobes: all captures disabled, exiting");
            return Ok(());
        }

        let mut ebpf = load_ebpf()?;
        let offset = boot_epoch_offset_ns();

        // Initialize budget trackers
        let mut tls_budget = TlsBudgetTracker::new(self.config.tls.bytes_per_process_per_sec);
        let mut readline_budget =
            ReadlineBudgetTracker::new(self.config.readline.commands_per_process_per_sec);
        let mut tls_dropped = 0u64;
        let mut readline_dropped = 0u64;

        // Initialize eBPF logger
        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                warn!("sensor-linux-uprobes: failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                        .map_err(|e| err(format!("eBPF logger fd: {e}")))?;
                tokio::task::spawn(async move {
                    loop {
                        // No unwrap: nothing holds this task's JoinHandle, so a
                        // panic here would be swallowed silently. An fd error
                        // means the logger fd is gone — stop draining, loudly.
                        let mut guard = match logger.readable_mut().await {
                            Ok(guard) => guard,
                            Err(e) => {
                                warn!("eBPF log drain stopped: {e}");
                                break;
                            }
                        };
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        // Track which eBPF programs have been loaded (to avoid duplicate load() calls)
        let mut loaded_programs = HashSet::new();

        // Resolve and attach TLS uprobes (only if enabled)
        if self.config.tls.enabled {
            info!("sensor-linux-uprobes: TLS capture enabled, resolving symbols...");
            let tls_symbols = symbol_resolver::resolve_tls_symbols()
                .map_err(|e| err(format!("TLS symbol resolution failed: {e}")))?;

            for symbol in &tls_symbols {
                // Skip libraries in denylist
                if self
                    .config
                    .tls
                    .library_denylist
                    .contains(&symbol.library_path)
                {
                    info!(
                        "sensor-linux-uprobes: skipping denylisted library: {}",
                        symbol.library_path.display()
                    );
                    continue;
                }

                // Attach ssl_write to SSL_write/SSL_write_ex (per-library probe function)
                if symbol.name == "SSL_write" || symbol.name == "SSL_write_ex" {
                    let probe_name = match symbol.library_type {
                        symbol_resolver::LibraryType::OpenSSL => "ssl_write_openssl",
                        symbol_resolver::LibraryType::BoringSSL => "ssl_write_boringssl",
                        symbol_resolver::LibraryType::GnuTLS => "ssl_write_gnutls",
                        symbol_resolver::LibraryType::Unknown => "ssl_write_openssl", // Default to OpenSSL
                    };
                    if let Err(e) =
                        attach_uprobe(&mut ebpf, probe_name, symbol, &mut loaded_programs)
                    {
                        warn!("sensor-linux-uprobes: failed to attach {probe_name}: {e}");
                    }
                }
                // GnuTLS uses gnutls_record_send instead of SSL_write
                if symbol.name == "gnutls_record_send"
                    && let Err(e) =
                        attach_uprobe(&mut ebpf, "ssl_write_gnutls", symbol, &mut loaded_programs)
                {
                    warn!("sensor-linux-uprobes: failed to attach ssl_write_gnutls: {e}");
                }
                // Attach ssl_read_entry to SSL_read/SSL_read_ex (per-library probe function)
                if symbol.name == "SSL_read" || symbol.name == "SSL_read_ex" {
                    let probe_name = match symbol.library_type {
                        symbol_resolver::LibraryType::OpenSSL => "ssl_read_entry_openssl",
                        symbol_resolver::LibraryType::BoringSSL => "ssl_read_entry_boringssl",
                        symbol_resolver::LibraryType::GnuTLS => "ssl_read_entry_gnutls",
                        symbol_resolver::LibraryType::Unknown => "ssl_read_entry_openssl", // Default
                    };
                    if let Err(e) =
                        attach_uprobe(&mut ebpf, probe_name, symbol, &mut loaded_programs)
                    {
                        warn!("sensor-linux-uprobes: failed to attach {probe_name}: {e}");
                    }
                }
                // GnuTLS uses gnutls_record_recv instead of SSL_read
                if symbol.name == "gnutls_record_recv"
                    && let Err(e) = attach_uprobe(
                        &mut ebpf,
                        "ssl_read_entry_gnutls",
                        symbol,
                        &mut loaded_programs,
                    )
                {
                    warn!("sensor-linux-uprobes: failed to attach ssl_read_entry_gnutls: {e}");
                }
                // Also attach the uretprobe (ssl_read_exit_*) - per-library function
                if symbol.name == "SSL_read" || symbol.name == "SSL_read_ex" {
                    let probe_name = match symbol.library_type {
                        symbol_resolver::LibraryType::OpenSSL => "ssl_read_exit_openssl",
                        symbol_resolver::LibraryType::BoringSSL => "ssl_read_exit_boringssl",
                        symbol_resolver::LibraryType::GnuTLS => "ssl_read_exit_gnutls",
                        symbol_resolver::LibraryType::Unknown => "ssl_read_exit_openssl", // Default
                    };
                    if let Err(e) =
                        attach_uprobe(&mut ebpf, probe_name, symbol, &mut loaded_programs)
                    {
                        warn!("sensor-linux-uprobes: failed to attach {probe_name}: {e}");
                    }
                }
                // GnuTLS uretprobe for gnutls_record_recv
                if symbol.name == "gnutls_record_recv"
                    && let Err(e) = attach_uprobe(
                        &mut ebpf,
                        "ssl_read_exit_gnutls",
                        symbol,
                        &mut loaded_programs,
                    )
                {
                    warn!("sensor-linux-uprobes: failed to attach ssl_read_exit_gnutls: {e}");
                }
            }
        } else {
            info!("sensor-linux-uprobes: TLS capture disabled");
        }

        // Resolve and attach readline uprobes (only if enabled)
        if self.config.readline.enabled {
            info!("sensor-linux-uprobes: readline capture enabled, resolving symbols...");
            let readline_symbols = symbol_resolver::resolve_readline_symbols()
                .map_err(|e| err(format!("readline symbol resolution failed: {e}")))?;

            for symbol in &readline_symbols {
                if symbol.name == "readline"
                    && let Err(e) =
                        attach_uprobe(&mut ebpf, "readline_exit", symbol, &mut loaded_programs)
                {
                    warn!("sensor-linux-uprobes: failed to attach readline_exit: {e}");
                }
            }
        } else {
            info!("sensor-linux-uprobes: readline capture disabled");
        }

        // Open ring buffers (only for enabled captures)
        let mut ring = |map: &str| -> Result<_, SensorError> {
            let m = ebpf
                .take_map(map)
                .ok_or_else(|| err(format!("map {map} not found in eBPF object")))?;
            let rb = RingBuf::try_from(m)
                .map_err(|e| err(format!("map {map} is not a ring buffer: {e}")))?;
            tokio::io::unix::AsyncFd::with_interest(rb, tokio::io::Interest::READABLE)
                .map_err(|e| err(format!("ring buffer fd for {map}: {e}")))
        };

        let mut tls_ring_buf = if self.config.tls.enabled {
            Some(ring("TLS_CAPTURE_EVENTS")?)
        } else {
            None
        };

        let mut readline_ring_buf = if self.config.readline.enabled {
            Some(ring("READLINE_EVENTS")?)
        } else {
            None
        };

        info!("sensor-linux-uprobes: listening for uprobe events");

        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                _ = &mut ctrl_c => break,
                _ = self.stop.notified() => break,
                guard = async {
                    if let Some(ref mut rb) = tls_ring_buf {
                        rb.readable_mut().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    drain_tls!(guard, sink, offset, self.config, tls_budget, tls_dropped);
                }
                guard = async {
                    if let Some(ref mut rb) = readline_ring_buf {
                        rb.readable_mut().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    drain_readline!(guard, sink, offset, self.config, readline_budget, readline_dropped);
                }
            }
        }

        // Log budget enforcement statistics
        if tls_dropped > 0 {
            info!(
                "sensor-linux-uprobes: TLS captures dropped (budget/allowlist): {}",
                tls_dropped
            );
        }
        if readline_dropped > 0 {
            info!(
                "sensor-linux-uprobes: readline captures dropped (budget/allowlist): {}",
                readline_dropped
            );
        }

        info!("sensor-linux-uprobes: exiting");
        Ok(())
    }
}

impl Sensor for UprobesSensor {
    fn name(&self) -> &str {
        "linux-uprobes"
    }

    fn capabilities(&self) -> Capabilities {
        // Phase 5: report actual capabilities when normalization is implemented
        Capabilities {
            exec_events: false,
            file_events: false,
            connect_events: false,
            auth_events: false,     // No authentication events
            user_attribution: true, // EventMeta includes uid/gid
            parent_lineage: true,   // EventMeta includes ppid/parent_comm
        }
    }

    fn run(&mut self, sink: Box<dyn EventSink>) -> Result<(), SensorError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| err(format!("failed to create tokio runtime: {e}")))?
            .block_on(self.run_async(sink))
    }

    fn stop(&mut self) {
        self.stop.notify_one();
    }
}
