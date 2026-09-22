//! Uprobe sensor: loads eBPF programs, attaches uprobes to SSL/readline functions,
//! drains ring buffers. Symbol resolution via [`crate::symbol_resolver`].
//!
//! **Status (Phase 6):** Full implementation with configuration - symbol resolution,
//! uprobe attachment, ring buffer draining, normalization, and budget enforcement.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use aya::{
    Ebpf,
    maps::RingBuf,
    programs::{UProbe, uprobe::UProbeScope},
};
use schema::sensor::{Capabilities, EventSink, Sensor, SensorError};
use sensor_linux_wire::{ReadlineInputEvent, TlsCaptureEvent, comm_str};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::{
    config::{TlsConfig, UprobesConfig},
    container::{CgroupIdCache, DockerInfoCache, container_context},
    normalize,
    symbol_resolver::{self, SymbolInfo},
};

fn err(msg: String) -> SensorError {
    msg.into()
}

/// See `sensor_linux_wire::boot_epoch_offset_ns` — computed once at startup.
fn boot_epoch_offset_ns() -> u64 {
    sensor_linux_wire::boot_epoch_offset_ns()
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
        debug!(
            ret,
            "sensor-linux-uprobes: setrlimit(RLIMIT_MEMLOCK) failed"
        );
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
        debug!(
            program = program_name,
            "sensor-linux-uprobes: loaded program"
        );
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

    info!(
        program = program_name,
        library = %symbol.library_path.display(),
        symbol = %symbol.name,
        offset = format_args!("0x{:x}", symbol.offset),
        "sensor-linux-uprobes: attached uprobe"
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

/// Upper bound on items one drain call takes from a ring buffer before returning
/// control to `select!` — see `sensor_linux::MAX_ITEMS_PER_DRAIN` (issue #326) for
/// why an unbounded `while let Some(item) = rb.next()` loop can starve this sensor's
/// other branch (and the reactor) indefinitely under sustained producer load.
const MAX_ITEMS_PER_DRAIN: usize = 256;

/// Drains up to [`MAX_ITEMS_PER_DRAIN`] TLS capture events from the ring buffer and
/// emits normalized schema events. Applies budget enforcement and allowlist filtering.
macro_rules! drain_tls {
    ($guard:expr, $sink:expr, $offset:expr, $config:expr, $budget:expr, $dropped:expr, $container_ids:expr, $docker_cache:expr) => {{
        let mut guard = $guard.map_err(|e| err(format!("TLS ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        let mut drained = 0usize;
        while drained < MAX_ITEMS_PER_DRAIN {
            let Some(item) = rb.next() else { break };
            drained += 1;
            if let Some(event) = read_wire_event::<TlsCaptureEvent>(&item) {
                // Allowlist check: if allowlist is non-empty, only allow listed processes
                if !$config.tls.process_allowlist.is_empty() {
                    let comm = comm_str(&event.meta.comm);
                    if !$config.tls.process_allowlist.contains(&comm) {
                        debug!(
                            pid = event.meta.pid,
                            comm, "sensor-linux-uprobes: TLS capture dropped (allowlist)"
                        );
                        $dropped += 1;
                        continue;
                    }
                }

                // Budget enforcement: check if pid hasn't exceeded bytes/sec budget
                if !$budget.check_and_record(event.meta.pid, event.bytes_len) {
                    debug!(
                        pid = event.meta.pid,
                        bytes = event.bytes_len,
                        "sensor-linux-uprobes: TLS capture dropped (budget)"
                    );
                    $dropped += 1;
                    continue;
                }

                // Normalize and emit to sink
                let container =
                    container_context(event.meta.cgroup_id, $container_ids, $docker_cache);
                let schema_event = normalize::tls_capture(&event, $offset, container);
                $sink.on_event(schema_event);
            }
        }
        // See `drain!` in `sensor_linux::sensor` (issue #326): only clear readiness
        // once the buffer actually ran dry, so a buffer still at the cap keeps
        // getting re-polled on the next `select!` iteration instead of starving.
        if drained < MAX_ITEMS_PER_DRAIN {
            guard.clear_ready();
        }
    }};
}

/// Drains up to [`MAX_ITEMS_PER_DRAIN`] readline events from the ring buffer and
/// emits normalized schema events. Applies budget enforcement and allowlist filtering.
macro_rules! drain_readline {
    ($guard:expr, $sink:expr, $offset:expr, $config:expr, $budget:expr, $dropped:expr, $container_ids:expr, $docker_cache:expr) => {{
        let mut guard =
            $guard.map_err(|e| err(format!("readline ring buffer poll failed: {e}")))?;
        let rb = guard.get_inner_mut();
        let mut drained = 0usize;
        while drained < MAX_ITEMS_PER_DRAIN {
            let Some(item) = rb.next() else { break };
            drained += 1;
            if let Some(event) = read_wire_event::<ReadlineInputEvent>(&item) {
                // Allowlist check: if allowlist is non-empty, only allow listed shells
                if !$config.readline.process_allowlist.is_empty() {
                    let comm = comm_str(&event.meta.comm);
                    if !$config.readline.process_allowlist.contains(&comm) {
                        debug!(
                            pid = event.meta.pid,
                            comm, "sensor-linux-uprobes: readline dropped (allowlist)"
                        );
                        $dropped += 1;
                        continue;
                    }
                }

                // Budget enforcement: check if pid hasn't exceeded commands/sec budget
                if !$budget.check_and_record(event.meta.pid) {
                    debug!(
                        pid = event.meta.pid,
                        "sensor-linux-uprobes: readline dropped (budget)"
                    );
                    $dropped += 1;
                    continue;
                }

                // Normalize and emit to sink
                let container =
                    container_context(event.meta.cgroup_id, $container_ids, $docker_cache);
                let schema_event = normalize::readline_input(&event, $offset, container);
                $sink.on_event(schema_event);
            }
        }
        if drained < MAX_ITEMS_PER_DRAIN {
            guard.clear_ready();
        }
    }};
}

/// Spawns the detached eBPF-log drain task, or warns and continues without it —
/// probe logging is diagnostics, never worth failing the sensor over. Only a
/// broken `AsyncFd` registration (the tokio reactor itself) is a hard error.
fn spawn_ebpf_log_drain(ebpf: &mut aya::Ebpf) -> Result<(), SensorError> {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            warn!(error = %e, "sensor-linux-uprobes: failed to initialize eBPF logger");
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
                            warn!(error = %e, "eBPF log drain stopped");
                            break;
                        }
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    Ok(())
}

/// The eBPF programs to attach for one resolved TLS symbol: per-library probe
/// variants, entry+exit for the read path (the exit uretprobe carries the
/// plaintext once `SSL_read` has filled the buffer). One table instead of the
/// six hand-copied match blocks this used to be — `Unknown` defaults to the
/// OpenSSL-shaped probes, the dominant ABI.
fn tls_probes_for(symbol_name: &str, lib: symbol_resolver::LibraryType) -> &'static [&'static str] {
    use symbol_resolver::LibraryType::{BoringSSL, GnuTLS, OpenSSL, Unknown};
    match symbol_name {
        "SSL_write" | "SSL_write_ex" => match lib {
            OpenSSL | Unknown => &["ssl_write_openssl"],
            BoringSSL => &["ssl_write_boringssl"],
            GnuTLS => &["ssl_write_gnutls"],
        },
        "gnutls_record_send" => &["ssl_write_gnutls"],
        "SSL_read" | "SSL_read_ex" => match lib {
            OpenSSL | Unknown => &["ssl_read_entry_openssl", "ssl_read_exit_openssl"],
            BoringSSL => &["ssl_read_entry_boringssl", "ssl_read_exit_boringssl"],
            GnuTLS => &["ssl_read_entry_gnutls", "ssl_read_exit_gnutls"],
        },
        "gnutls_record_recv" => &["ssl_read_entry_gnutls", "ssl_read_exit_gnutls"],
        _ => &[],
    }
}

/// Resolves TLS symbols and attaches every applicable probe. A single failed
/// attach warns and moves on (one hardened library must not disable TLS
/// capture for the rest); failed symbol *resolution* is a hard error — with no
/// symbols at all, enabling TLS capture was a configuration mistake worth
/// surfacing.
fn attach_tls_uprobes(
    config: &TlsConfig,
    ebpf: &mut aya::Ebpf,
    loaded_programs: &mut HashSet<String>,
) -> Result<(), SensorError> {
    let tls_symbols = symbol_resolver::resolve_tls_symbols()
        .map_err(|e| err(format!("TLS symbol resolution failed: {e}")))?;

    for symbol in &tls_symbols {
        if config.library_denylist.contains(&symbol.library_path) {
            info!(
                library = %symbol.library_path.display(),
                "sensor-linux-uprobes: skipping denylisted library"
            );
            continue;
        }
        for probe_name in tls_probes_for(&symbol.name, symbol.library_type) {
            if let Err(e) = attach_uprobe(ebpf, probe_name, symbol, loaded_programs) {
                warn!(probe = probe_name, error = %e, "sensor-linux-uprobes: failed to attach uprobe");
            }
        }
    }
    Ok(())
}

/// Same contract as [`attach_tls_uprobes`], for the shell readline probe.
fn attach_readline_uprobes(
    ebpf: &mut aya::Ebpf,
    loaded_programs: &mut HashSet<String>,
) -> Result<(), SensorError> {
    let readline_symbols = symbol_resolver::resolve_readline_symbols()
        .map_err(|e| err(format!("readline symbol resolution failed: {e}")))?;

    for symbol in &readline_symbols {
        if symbol.name == "readline"
            && let Err(e) = attach_uprobe(ebpf, "readline_exit", symbol, loaded_programs)
        {
            warn!(probe = "readline_exit", error = %e, "sensor-linux-uprobes: failed to attach uprobe");
        }
    }
    Ok(())
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
        let mut container_ids = CgroupIdCache::new();
        let docker_cache: DockerInfoCache = Arc::new(Mutex::new(HashMap::new()));

        spawn_ebpf_log_drain(&mut ebpf)?;

        // Track which eBPF programs have been loaded (to avoid duplicate load() calls)
        let mut loaded_programs = HashSet::new();

        if self.config.tls.enabled {
            info!("sensor-linux-uprobes: TLS capture enabled, resolving symbols...");
            attach_tls_uprobes(&self.config.tls, &mut ebpf, &mut loaded_programs)?;
        } else {
            info!("sensor-linux-uprobes: TLS capture disabled");
        }

        if self.config.readline.enabled {
            info!("sensor-linux-uprobes: readline capture enabled, resolving symbols...");
            attach_readline_uprobes(&mut ebpf, &mut loaded_programs)?;
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
                    drain_tls!(guard, sink, offset, self.config, tls_budget, tls_dropped, &mut container_ids, &docker_cache);
                }
                guard = async {
                    if let Some(ref mut rb) = readline_ring_buf {
                        rb.readable_mut().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    drain_readline!(guard, sink, offset, self.config, readline_budget, readline_dropped, &mut container_ids, &docker_cache);
                }
            }
        }

        // Log budget enforcement statistics
        if tls_dropped > 0 {
            info!(
                dropped = tls_dropped,
                "sensor-linux-uprobes: TLS captures dropped (budget/allowlist)"
            );
        }
        if readline_dropped > 0 {
            info!(
                dropped = readline_dropped,
                "sensor-linux-uprobes: readline captures dropped (budget/allowlist)"
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
