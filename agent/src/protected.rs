//! Protected-resource monitoring (issue #71, capability 3): the agent watches its own
//! on-disk footprint through the live event stream, and treats a write-intent open of
//! one of those paths by any process other than itself as a high-severity detection.
//!
//! Scope is deliberately limited to paths this agent process can know for certain at
//! its own runtime: its own executable (`std::env::current_exe`), its config file
//! (the path `config::discover` resolved at startup — the same file ADR-0013 makes
//! the agent fail fast over if it's missing, so it is worth protecting even though
//! operator-edited, not updater-managed), plus the alerts/events/heartbeat files it
//! was launched with. It does **not** cover the watchdog binary or the systemd
//! unit/OpenRC install surface — those live in `watchdog`'s own path resolution
//! (`watchdog/src/service/linux.rs`), and naming them here would mean either guessing
//! the packaging layout or a cross-binary dependency, neither of which this pass takes
//! on; `watchdog::tamper` (#103) already covers that surface from the install/supervise
//! side. True deletion is also out of scope: `FileOpenEvent` only observes `open(2)`,
//! so this catches a foreign write, truncate, or overwrite, not a foreign `rm`/`rename`
//! — both gaps stay tracked by issue #71 rather than being silently implied as covered.
//!
//! ## No `updater` allowlist (and why one line of #71 is stale)
//!
//! #71 originally called for treating `updater` as the one legitimate non-self writer
//! of these paths, since no updater existed yet to name. #30 shipped it since, and
//! turns out not to need the exception: `agent::release::cmd_apply_release` (ADR-0015)
//! downloads and verifies a new release into its own `versions/<N>/` directory and only
//! then swaps the `current` symlink — it never writes into the version directory the
//! running process's `current_exe` already resolves to, and it does not touch the
//! config file, alerts, events, or heartbeat paths at all (those are runtime/operator
//! state, not release artifacts). So a real self-update never opens a path this module
//! watches for write, and there is nothing today for an allowlist to legitimately admit.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use schema::{Event, sensor::EventSink};

use crate::sink::DetectionSink;

/// Builds the set of paths this process treats as its own protected resources.
/// Best-effort on the executable path: `current_exe` can fail (rare — e.g. the binary
/// was unlinked out from under a running process), in which case the binary just isn't
/// watched rather than failing agent startup over a self-protection nicety.
/// `config_path` is the path `config::discover` actually resolved at startup (not a
/// recomputed guess) — passing it rather than re-deriving it here keeps this module
/// agreeing with whichever of `--config`/`SYNTHAEA_CONFIG`/the OS default won.
///
/// Every path is made absolute here (via [`absolute_or_given`]) before it is
/// returned, whatever form the caller passed in. `matches_protected` below is a
/// path-*suffix* comparison against the absolute path a real `FileOpenEvent`
/// reports, so a still-relative protected path (`--config agent.toml`, `--alerts
/// alerts.ndjson` from a non-default working directory) would never match
/// anything and leave that resource silently unwatched — a real finding from
/// PR #770's review, caught on `config_path` specifically but just as true of
/// `alerts`/`events`, which is why the fix sits here rather than on one caller.
pub(crate) fn protected_paths(
    alerts: &Path,
    events: Option<&Path>,
    config_path: &Path,
) -> Vec<PathBuf> {
    let mut paths = vec![
        absolute_or_given(alerts),
        absolute_or_given(&crate::heartbeat::heartbeat_path_for(alerts)),
        absolute_or_given(config_path),
    ];
    paths.extend(events.map(absolute_or_given));
    if let Ok(exe) = std::env::current_exe() {
        // Already absolute by construction (the OS resolves it to a real path,
        // never the argv0 fragment a shell found via `$PATH`) — no second pass.
        paths.push(exe);
    }
    paths
}

/// `std::path::absolute(path)` resolved against the current directory, falling
/// back to `path` unchanged on the rare failure (an invalid path on this
/// platform, or `getcwd` itself failing) rather than dropping the path from
/// coverage entirely. Unlike `canonicalize`, this never touches the filesystem
/// and does not require the path to exist yet — true at startup for `alerts`/
/// `events`, which the agent itself creates.
fn absolute_or_given(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Wraps an inner [`EventSink`]: every event is forwarded unchanged, but a
/// [`Event::FileOpen`] is first checked against `protected` — a write-intent open of
/// one of those paths from any pid other than this process's own fires a real alert
/// through `sink`, the same `alerts.ndjson` path a rule/correlator/Sigma finding uses.
pub(crate) struct ProtectedResourceGuard<S> {
    inner: S,
    own_pid: u32,
    protected: Arc<[PathBuf]>,
    sink: Arc<DetectionSink>,
}

impl<S> ProtectedResourceGuard<S> {
    pub(crate) fn new(inner: S, protected: Vec<PathBuf>, sink: Arc<DetectionSink>) -> Self {
        Self {
            inner,
            own_pid: std::process::id(),
            protected: protected.into(),
            sink,
        }
    }
}

impl<S: EventSink> EventSink for ProtectedResourceGuard<S> {
    fn on_event(&self, event: Event) {
        if let Event::FileOpen(ref open) = event
            && open.meta.pid != self.own_pid
            && rules::has_write_intent(open.flags)
            && self
                .protected
                .iter()
                .any(|p| matches_protected(p, &open.path))
        {
            self.sink.emit(
                "T1562",
                &format!(
                    "pid {} (`{}`) opened protected agent resource {} for write",
                    open.meta.pid, open.meta.comm, open.path
                ),
            );
        }
        self.inner.on_event(event);
    }
}

/// `observed` may be relative to an unresolved directory file descriptor (the same
/// known eBPF-collector limitation `rules::check_persistence_write` tolerates) —
/// matching by path-component suffix, rather than full equality, handles a shortened
/// fragment while still comparing whole components (unlike a raw string suffix, which
/// would wrongly match `"myagent"` against a protected path ending in `"agent"`).
fn matches_protected(protected: &Path, observed: &str) -> bool {
    !observed.is_empty() && protected.ends_with(Path::new(observed))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingSink(Arc<AtomicUsize>);

    impl EventSink for CountingSink {
        fn on_event(&self, _event: Event) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn open_event(pid: u32, comm: &str, path: &str, flags: u32) -> Event {
        Event::FileOpen(schema::FileOpenEvent {
            meta: schema::EventMeta {
                pid,
                ppid: 1,
                comm: comm.to_string(),
                ..schema::fixtures::meta()
            },
            path: path.to_string(),
            flags,
        })
    }

    const O_WRONLY: u32 = 0o1;
    const O_RDONLY: u32 = 0o0;

    fn config() -> &'static Path {
        Path::new("/etc/synthaea/agent.toml")
    }

    /// Resolves `p` the same way `protected_paths` now does internally, so a test
    /// comparing its output against a literal does not depend on this platform's
    /// absolute-path spelling (`/var/...` resolves differently on Windows than on
    /// Linux once `std::path::absolute` runs it through the current directory).
    fn abs(p: &str) -> PathBuf {
        std::path::absolute(p).unwrap()
    }

    #[test]
    fn protected_paths_skip_the_events_file_when_there_is_none() {
        let alerts = std::path::Path::new("/var/log/synthaea/alerts.ndjson");
        let without = protected_paths(alerts, None, config());
        assert!(without.iter().all(|p| !p.ends_with("events.jsonl")));
        assert!(without.contains(&abs("/var/log/synthaea/alerts.ndjson")));
        let with = protected_paths(alerts, Some(std::path::Path::new("/tmp/e")), config());
        assert!(with.contains(&abs("/tmp/e")));
    }

    #[test]
    fn protected_paths_includes_the_resolved_config_path() {
        let alerts = std::path::Path::new("/var/log/synthaea/alerts.ndjson");
        let paths = protected_paths(alerts, None, config());
        assert!(
            paths.contains(&abs("/etc/synthaea/agent.toml")),
            "the config path `config::discover` resolved must be watched too"
        );
    }

    #[test]
    fn a_relative_config_path_is_still_watched() {
        // PR #770's review: `matches_protected` is a suffix comparison against an
        // *absolute* path a real `FileOpenEvent` reports, so a still-relative
        // `--config agent.toml` used to leave the config unwatched no matter what
        // actually opened it. `protected_paths` must resolve it before returning.
        let alerts = Path::new("/var/log/synthaea/alerts.ndjson");
        let relative = Path::new("agent.toml");
        let paths = protected_paths(alerts, None, relative);
        assert!(
            paths.iter().all(|p| p.is_absolute()),
            "every protected path must be absolute: {paths:?}"
        );
        let resolved = std::path::absolute(relative).unwrap();
        let observed = resolved.to_str().unwrap();
        assert!(
            paths.iter().any(|p| matches_protected(p, observed)),
            "a relative --config must still match the absolute path a real open reports: {paths:?}"
        );
    }

    #[test]
    fn matches_protected_needs_both_sides_resolved_the_same_way() {
        // Pins why `a_relative_config_path_is_still_watched` above matters: this
        // is not a bug in `matches_protected` itself (it is documented as a
        // suffix match), but a trap for any caller — `protected_paths`, not this
        // function — that does not make its protected paths absolute first.
        assert!(!matches_protected(
            Path::new("agent.toml"),
            "/home/u/agent.toml"
        ));
        assert!(matches_protected(
            Path::new("/etc/synthaea/agent.toml"),
            "/etc/synthaea/agent.toml"
        ));
    }

    #[test]
    fn matches_protected_tolerates_a_dfd_relative_suffix() {
        assert!(matches_protected(Path::new("/opt/synthaea/agent"), "agent"));
        assert!(!matches_protected(
            Path::new("/opt/synthaea/agent"),
            "myagent"
        ));
        assert!(!matches_protected(Path::new("/opt/synthaea/agent"), ""));
    }

    #[test]
    fn a_foreign_write_to_a_protected_path_fires_an_alert() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let alerts_dir =
            std::env::temp_dir().join(format!("protected-test-{}", std::process::id()));
        std::fs::create_dir_all(&alerts_dir).unwrap();
        let alerts = alerts_dir.join("alerts.ndjson");
        let events = alerts_dir.join("events.jsonl");
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &alerts,
                Some(&events),
                None,
                None,
                &alerts_dir.join("content"),
                &alerts_dir.join("ml-registry"),
            )
            .unwrap(),
        );

        let guard = ProtectedResourceGuard::new(
            CountingSink(forwarded.clone()),
            protected_paths(&alerts, Some(&events), config()),
            sink,
        );

        guard.on_event(open_event(9999, "evil", "alerts.ndjson", O_WRONLY));

        assert_eq!(
            forwarded.load(Ordering::Relaxed),
            1,
            "must still forward the event"
        );
        let written = std::fs::read_to_string(&alerts).unwrap();
        assert!(
            written.contains("T1562"),
            "expected a T1562 alert, got: {written}"
        );
        assert!(written.contains("evil"));

        let _ = std::fs::remove_dir_all(&alerts_dir);
    }

    #[test]
    fn a_foreign_write_to_the_config_file_fires_an_alert() {
        // The gap #71 explicitly flagged as uncovered: `agent.toml` is operator-edited,
        // not updater-managed, but a foreign process rewriting it (disabling rules,
        // pointing the agent at a rogue control plane) is exactly the kind of tamper
        // this module exists to catch — same as the binary or alerts path.
        let forwarded = Arc::new(AtomicUsize::new(0));
        let alerts_dir =
            std::env::temp_dir().join(format!("protected-test-config-{}", std::process::id()));
        std::fs::create_dir_all(&alerts_dir).unwrap();
        let alerts = alerts_dir.join("alerts.ndjson");
        let events = alerts_dir.join("events.jsonl");
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &alerts,
                Some(&events),
                None,
                None,
                &alerts_dir.join("content"),
                &alerts_dir.join("ml-registry"),
            )
            .unwrap(),
        );

        let guard = ProtectedResourceGuard::new(
            CountingSink(forwarded.clone()),
            protected_paths(&alerts, Some(&events), config()),
            sink,
        );

        guard.on_event(open_event(9999, "evil", "agent.toml", O_WRONLY));

        let written = std::fs::read_to_string(&alerts).unwrap();
        assert!(
            written.contains("T1562"),
            "expected a T1562 alert for the config write, got: {written}"
        );

        let _ = std::fs::remove_dir_all(&alerts_dir);
    }

    #[test]
    fn own_writes_never_alert() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let alerts_dir =
            std::env::temp_dir().join(format!("protected-test-self-{}", std::process::id()));
        std::fs::create_dir_all(&alerts_dir).unwrap();
        let alerts = alerts_dir.join("alerts.ndjson");
        let events = alerts_dir.join("events.jsonl");
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &alerts,
                Some(&events),
                None,
                None,
                &alerts_dir.join("content"),
                &alerts_dir.join("ml-registry"),
            )
            .unwrap(),
        );

        let guard = ProtectedResourceGuard::new(
            CountingSink(forwarded.clone()),
            protected_paths(&alerts, Some(&events), config()),
            sink,
        );

        guard.on_event(open_event(
            std::process::id(),
            "agent",
            "alerts.ndjson",
            O_WRONLY,
        ));

        let written = std::fs::read_to_string(&alerts).unwrap();
        assert!(
            !written.contains("T1562"),
            "must not alert on its own writes, got: {written}"
        );

        let _ = std::fs::remove_dir_all(&alerts_dir);
    }

    #[test]
    fn a_read_only_open_never_alerts() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let alerts_dir =
            std::env::temp_dir().join(format!("protected-test-read-{}", std::process::id()));
        std::fs::create_dir_all(&alerts_dir).unwrap();
        let alerts = alerts_dir.join("alerts.ndjson");
        let events = alerts_dir.join("events.jsonl");
        let sink = Arc::new(
            DetectionSink::new(
                rules::RuleState::new(),
                &alerts,
                Some(&events),
                None,
                None,
                &alerts_dir.join("content"),
                &alerts_dir.join("ml-registry"),
            )
            .unwrap(),
        );

        let guard = ProtectedResourceGuard::new(
            CountingSink(forwarded.clone()),
            protected_paths(&alerts, Some(&events), config()),
            sink,
        );

        guard.on_event(open_event(9999, "cat", "alerts.ndjson", O_RDONLY));

        let written = std::fs::read_to_string(&alerts).unwrap();
        assert!(
            !written.contains("T1562"),
            "a mere read must not alert, got: {written}"
        );

        let _ = std::fs::remove_dir_all(&alerts_dir);
    }
}
