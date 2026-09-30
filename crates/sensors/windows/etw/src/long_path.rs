//! 8.3 short-name expansion for sensor paths (#489).
//!
//! Kernel-File reports one file under both its short form
//! (`C:\Users\JIHAIR~1\AppData\Local\Temp\x.exe`) and its long form, so every
//! string comparison downstream (the `FileQuarantine` dedup, the T1105/T1204.002
//! joins) saw two files where there is one — 946 events for 400 marks in the
//! 2026-09-25 lab run. Expanding once here, before any event carries the path,
//! gives consumers a single form.
//!
//! The expansion runs on the ETW callback thread, so it is shaped to stay cheap:
//! only a local drive-letter path with a `~` in it is touched, the parent
//! directory's expansion is cached (a host has few short-named directories),
//! and only a `~` in the leaf itself costs an uncached lookup. UNC paths are
//! never resolved: a lookup against a slow share would stall every Kernel-File
//! event behind it (#439's lesson). A path that can't be resolved (already
//! deleted, access denied) keeps its raw form — consumers must still tolerate
//! a mismatch.

use std::{collections::HashMap, sync::Mutex};

/// Short-form directory → its long form, never larger than its cap.
///
/// Full, it is cleared rather than LRU-evicted: short-named directories are a
/// small, stable set per host (profiles with spaces, `Program Files`), so a
/// full cache means an unusual host, and one miss per directory to refill it is
/// cheap. Each clear is counted and logged.
pub(crate) struct LongPathCache {
    dirs: HashMap<String, String>,
    cap: usize,
    cleared: u64,
}

impl LongPathCache {
    /// # Panics
    ///
    /// Panics when `cap` is 0 — a configuration bug, not a runtime condition.
    pub(crate) fn new(cap: usize) -> Self {
        assert!(cap >= 1, "LongPathCache cap must be >= 1");
        Self {
            dirs: HashMap::new(),
            cap,
            cleared: 0,
        }
    }

    fn insert(&mut self, short: String, long: String) {
        if self.dirs.len() >= self.cap {
            self.dirs.clear();
            self.cleared += 1;
            tracing::warn!(
                cap = self.cap,
                cleared_total = self.cleared,
                "long-path cache hit its cap — cleared"
            );
        }
        self.dirs.insert(short, long);
    }

    /// Times the cap forced a clear since creation.
    #[cfg_attr(not(test), allow(dead_code))] // read by a future health surface
    pub(crate) fn cleared(&self) -> u64 {
        self.cleared
    }
}

/// `path` with its 8.3 components expanded through `resolve` (the
/// `GetLongPathNameW` wrapper on Windows). Unresolvable parts stay raw.
pub(crate) fn expand(
    path: &str,
    cache: &Mutex<LongPathCache>,
    resolve: impl Fn(&str) -> Option<String>,
) -> String {
    if !is_local_drive_path(path) || !path.contains('~') {
        return path.to_owned();
    }
    let Some((parent, leaf)) = path.rsplit_once('\\') else {
        return path.to_owned();
    };
    let long_parent = if parent.contains('~') {
        expand_dir(parent, cache, &resolve)
    } else {
        parent.to_owned()
    };
    let long_leaf = if leaf.contains('~') {
        expand_leaf(&long_parent, leaf, &resolve)
    } else {
        leaf.to_owned()
    };
    format!("{long_parent}\\{long_leaf}")
}

/// `X:\…` — the only form a volume-map normalized local path takes. Rejects
/// UNC (`\\server\share`), `\\?\` and unmapped `\Device\…` paths.
fn is_local_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn expand_dir(
    dir: &str,
    cache: &Mutex<LongPathCache>,
    resolve: &impl Fn(&str) -> Option<String>,
) -> String {
    if let Some(long) = lock(cache).dirs.get(dir) {
        return long.clone();
    }
    // Resolved outside the lock: a slow lookup must not serialize other callers.
    // A failure is not cached — a directory that exists again later resolves.
    let Some(long) = resolve(dir) else {
        return dir.to_owned();
    };
    lock(cache).insert(dir.to_owned(), long.clone());
    long
}

/// The leaf's long name, keeping an alternate-data-stream suffix
/// (`PAYLOA~1.EXE:Zone.Identifier`) — the stream itself has no short name, and
/// the mark's host path must match the file's `FileOpen` path.
fn expand_leaf(long_parent: &str, leaf: &str, resolve: &impl Fn(&str) -> Option<String>) -> String {
    let (file, stream) = leaf.split_at(leaf.find(':').unwrap_or(leaf.len()));
    resolve(&format!("{long_parent}\\{file}"))
        .and_then(|long| {
            long.rsplit_once('\\')
                .map(|(_, name)| format!("{name}{stream}"))
        })
        .unwrap_or_else(|| leaf.to_owned())
}

/// A poisoned lock only means another callback panicked mid-insert; the map
/// itself is still a valid cache.
fn lock(cache: &Mutex<LongPathCache>) -> std::sync::MutexGuard<'_, LongPathCache> {
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// A fake filesystem: short form → long form, case-insensitively like NTFS.
    fn fs(entries: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = entries
            .iter()
            .map(|(s, l)| (s.to_lowercase(), (*l).to_owned()))
            .collect();
        move |p| map.get(&p.to_lowercase()).cloned()
    }

    fn cache() -> Mutex<LongPathCache> {
        Mutex::new(LongPathCache::new(64))
    }

    const PROFILE: (&str, &str) = (r"C:\Users\JIHAIR~1", r"C:\Users\Jihair Cyber");
    const TEMP: (&str, &str) = (
        r"C:\Users\JIHAIR~1\AppData\Local\Temp",
        r"C:\Users\Jihair Cyber\AppData\Local\Temp",
    );

    #[test]
    fn short_and_long_forms_of_one_file_normalize_to_one_path() {
        let resolve = fs(&[PROFILE, TEMP]);
        let cache = cache();
        let short = expand(
            r"C:\Users\JIHAIR~1\AppData\Local\Temp\x.exe",
            &cache,
            &resolve,
        );
        let long = expand(
            r"C:\Users\Jihair Cyber\AppData\Local\Temp\x.exe",
            &cache,
            &resolve,
        );
        assert_eq!(short, r"C:\Users\Jihair Cyber\AppData\Local\Temp\x.exe");
        assert_eq!(short, long);
    }

    #[test]
    fn program_files_short_form_expands() {
        let resolve = fs(&[(r"C:\PROGRA~1\Vendor", r"C:\Program Files\Vendor")]);
        assert_eq!(
            expand(r"C:\PROGRA~1\Vendor\app.exe", &cache(), &resolve),
            r"C:\Program Files\Vendor\app.exe"
        );
    }

    #[test]
    fn mark_stream_host_matches_the_expanded_file_path() {
        let resolve = fs(&[
            TEMP,
            (
                r"C:\Users\Jihair Cyber\AppData\Local\Temp\PAYLOA~1.EXE",
                r"C:\Users\Jihair Cyber\AppData\Local\Temp\payload_installer.exe",
            ),
        ]);
        let cache = cache();
        let stream = expand(
            r"C:\Users\JIHAIR~1\AppData\Local\Temp\PAYLOA~1.EXE:Zone.Identifier",
            &cache,
            &resolve,
        );
        assert_eq!(
            stream,
            r"C:\Users\Jihair Cyber\AppData\Local\Temp\payload_installer.exe:Zone.Identifier"
        );
    }

    #[test]
    fn the_mark_dedup_admits_a_short_and_long_form_write_once() {
        use crate::zone_identifier::{QuarantineDedup, parse, stream_host_path};

        let resolve = fs(&[PROFILE, TEMP]);
        let cache = cache();
        let mut dedup = QuarantineDedup::new(60_000_000_000, 64);
        let zone = parse(b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/x.exe\r\n");
        let admitted = [
            r"C:\Users\JIHAIR~1\AppData\Local\Temp\x.exe:Zone.Identifier",
            r"C:\Users\Jihair Cyber\AppData\Local\Temp\x.exe:Zone.Identifier",
        ]
        .iter()
        .filter(|raw| {
            let path = expand(raw, &cache, &resolve);
            let host = stream_host_path(&path).expect("a Zone.Identifier stream");
            dedup.admit(host, zone.clone(), 1_000).is_some()
        })
        .count();
        assert_eq!(admitted, 1);
    }

    #[test]
    fn parent_directory_is_resolved_once() {
        let calls = Cell::new(0);
        let inner = fs(&[TEMP]);
        let resolve = |p: &str| {
            calls.set(calls.get() + 1);
            inner(p)
        };
        let cache = cache();
        for i in 0..100 {
            expand(&format!(r"{}\f{i}.tmp", TEMP.0), &cache, resolve);
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn paths_without_a_tilde_never_hit_the_filesystem() {
        let resolve = |_: &str| -> Option<String> { panic!("no lookup expected") };
        let path = r"C:\Windows\System32\cmd.exe";
        assert_eq!(expand(path, &cache(), resolve), path);
    }

    #[test]
    fn unc_paths_are_never_resolved() {
        let resolve = |_: &str| -> Option<String> { panic!("no lookup on a share") };
        let path = r"\\fileserver\PUBLIC~1\drop.exe";
        assert_eq!(expand(path, &cache(), resolve), path);
    }

    #[test]
    fn an_unresolvable_path_keeps_its_raw_form() {
        let path = r"C:\Users\GONE~1\Temp\x.exe";
        assert_eq!(expand(path, &cache(), fs(&[])), path);
    }

    #[test]
    fn a_failed_lookup_is_retried_later() {
        let cache = cache();
        let path = r"C:\Users\JIHAIR~1\x.exe";
        assert_eq!(expand(path, &cache, fs(&[])), path);
        assert_eq!(
            expand(path, &cache, fs(&[PROFILE])),
            r"C:\Users\Jihair Cyber\x.exe"
        );
    }

    #[test]
    fn cache_never_grows_past_its_cap() {
        let cache = Mutex::new(LongPathCache::new(8));
        let resolve = |p: &str| Some(p.replace('~', "_"));
        for i in 0..100 {
            expand(&format!(r"C:\D{i}~1\f.txt"), &cache, resolve);
        }
        let cache = cache.lock().unwrap();
        assert!(cache.dirs.len() <= 8);
        assert!(cache.cleared() > 0);
    }
}
