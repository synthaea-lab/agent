//! On-device IOC matching, wired (issue #60, ADR-0038): loads the indicator feeds in the
//! content directory and turns a match on an exec image's hash or on a connect's destination
//! address into a finding.
//!
//! Feeds are files in `<content_root>/ioc/`: each `*.txt` is one feed, named by its file stem
//! and written as the line format of [`intel::SetBuilder::add_lines`]; an optional `VERSION`
//! file names the release they came from (`unversioned` without one). Signed delivery of these
//! files through the content manifest is not built yet (it waits on the production signing keys,
//! #753), so today a feed is a file somebody put there, which is why a match is Medium or High
//! and never kills anything.
//!
//! The set and its feed names are swapped together, so a match never reports another feed's
//! name. A reload that cannot read or fit a feed keeps the previous set; an absent directory
//! unloads.

use std::{
    io::Read as _,
    net::IpAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use intel::{DEFAULT_MEMORY_BUDGET_BYTES, FeedId, IndicatorKind, IndicatorSet, SetBuilder};
use schema::detection::{IocKind, Severity};

/// The label an IOC finding carries where other engines carry an ATT&CK technique. Not a
/// technique: an indicator says a thing is known bad, not which tactic it served.
pub(crate) const IOC_TECHNIQUE: &str = "IOC";

const FEED_DIR: &str = "ioc";
const VERSION_FILE: &str = "VERSION";
const UNVERSIONED: &str = "unversioned";
/// Longest feed name and version kept; they travel in every detection.
const MAX_LABEL_CHARS: usize = 64;
/// A feed file larger than this is not read (the set budget is the real bound; this stops a
/// huge file being buffered before it is counted).
const MAX_FEED_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// An indicator that already raised a finding raises no other for this long, so a hash run in a
/// loop or an address polled every second is one finding, not thousands. **Provisional.**
const COOLDOWN_NS: u64 = 10 * 60 * 1_000_000_000;
/// Indicators whose cooldown is remembered at once; the least recently seen is forgotten first
/// (and may alert again, which is counted by nobody: it is a repeat, not a loss).
const COOLDOWN_KEYS: usize = 4096;

/// The indicator set in force and the feeds its ids name.
struct Loaded {
    set: IndicatorSet,
    feeds: Vec<String>,
    version: String,
}

/// What reading the content directory yielded.
pub(crate) enum LoadOutcome {
    /// No `ioc/` directory: not an error, and it unloads.
    Absent,
    Loaded,
    /// Present but unusable (already logged): the previous set stays.
    Failed,
}

/// A confirmed match, ready to become a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IocHit {
    pub(crate) kind: IocKind,
    pub(crate) indicator: String,
    pub(crate) feed: String,
    pub(crate) feed_version: String,
}

impl IocHit {
    pub(crate) fn severity(&self) -> Severity {
        match self.kind {
            // A known-bad file ran.
            IocKind::Sha256 | IocKind::Sha1 | IocKind::Md5 => Severity::High,
            // Address feeds are noisy (shared hosting, recycled addresses).
            _ => Severity::Medium,
        }
    }

    pub(crate) fn message(&self, comm: &str) -> String {
        let what = match self.kind {
            IocKind::Sha256 => "executed image hash",
            IocKind::Ip => "connection to address",
            IocKind::Domain => "DNS query under domain",
            _ => "indicator",
        };
        format!(
            "comm={comm} {what} {} is in indicator feed {} ({})",
            self.indicator, self.feed, self.feed_version
        )
    }
}

/// Counters for health reporting.
#[derive(Debug, Default)]
pub(crate) struct IocStats {
    /// Matches that raised a finding.
    pub(crate) raised: AtomicU64,
    /// Matches absorbed by the per-indicator cooldown.
    pub(crate) cooled_down: AtomicU64,
}

/// The agent's IOC matcher.
pub(crate) struct IocMatcher {
    current: Mutex<Option<Arc<Loaded>>>,
    cooldown: Mutex<store::BoundedMap<String, u64>>,
    stats: IocStats,
}

impl IocMatcher {
    /// A matcher with whatever `<content_root>/ioc/` holds now.
    pub(crate) fn new(content_root: &Path) -> Self {
        let matcher = Self {
            current: Mutex::new(None),
            cooldown: Mutex::new(store::BoundedMap::new(COOLDOWN_KEYS)),
            stats: IocStats::default(),
        };
        matcher.reload(content_root);
        matcher
    }

    /// Re-reads the feeds: present replaces, absent unloads, unusable keeps what is loaded.
    pub(crate) fn reload(&self, content_root: &Path) -> LoadOutcome {
        let outcome = load(&content_root.join(FEED_DIR));
        let (loaded, count) = match outcome {
            Ok(Some(loaded)) => (Some(Arc::new(loaded)), LoadOutcome::Loaded),
            Ok(None) => (None, LoadOutcome::Absent),
            Err(()) => return LoadOutcome::Failed,
        };
        let old = std::mem::replace(&mut *self.current.lock().unwrap(), loaded);
        drop(old);
        count
    }

    /// Indicators in force, `0` while none is loaded.
    pub(crate) fn indicator_count(&self) -> usize {
        self.current
            .lock()
            .unwrap()
            .as_ref()
            .map_or(0, |loaded| loaded.set.len())
    }

    /// The counters the health beacon reports.
    pub(crate) fn stats(&self) -> &IocStats {
        &self.stats
    }

    /// An executed image's hash, as enrichment reports it, against the hash indicators.
    pub(crate) fn check_exec_image(&self, sha256: Option<&str>, now_ns: u64) -> Option<IocHit> {
        let sha256 = sha256?.to_ascii_lowercase();
        let loaded = self.current.lock().unwrap().clone()?;
        let found = loaded.set.lookup_sha256_hex(&sha256)?;
        self.hit(&loaded, found, IocKind::Sha256, sha256, now_ns)
    }

    /// A queried name against the domain indicators. A listed domain covers its subdomains, so
    /// the finding names the listed domain that matched, not the name the host asked for.
    pub(crate) fn check_dns_query(&self, name: &str, now_ns: u64) -> Option<IocHit> {
        let loaded = self.current.lock().unwrap().clone()?;
        // One lookup rejects almost every name; the suffix walk below runs on a hit only.
        loaded.set.lookup_domain(name)?;
        let (indicator, found) = listed_domain(&loaded.set, &intel::normalize_domain(name).ok()?)?;
        self.hit(&loaded, found, IocKind::Domain, indicator, now_ns)
    }

    /// A connection's destination against the address indicators.
    pub(crate) fn check_connect(&self, address: IpAddr, now_ns: u64) -> Option<IocHit> {
        let loaded = self.current.lock().unwrap().clone()?;
        let found = loaded.set.lookup_ip(address)?;
        let indicator = address.to_canonical().to_string();
        self.hit(&loaded, found, IocKind::Ip, indicator, now_ns)
    }

    fn hit(
        &self,
        loaded: &Loaded,
        found: intel::Match,
        kind: IocKind,
        indicator: String,
        now_ns: u64,
    ) -> Option<IocHit> {
        debug_assert!(matches!(
            (found.kind, kind),
            (IndicatorKind::Sha256, IocKind::Sha256)
                | (IndicatorKind::Ip, IocKind::Ip)
                | (IndicatorKind::Domain, IocKind::Domain)
        ));
        // One key space for every kind: `IocKind` is a schema enum without `Hash`.
        if self.in_cooldown(format!("{kind:?}:{indicator}"), now_ns) {
            self.stats.cooled_down.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.stats.raised.fetch_add(1, Ordering::Relaxed);
        Some(IocHit {
            kind,
            indicator,
            feed: loaded
                .feeds
                .get(usize::from(found.feed.0))
                .cloned()
                .unwrap_or_default(),
            feed_version: loaded.version.clone(),
        })
    }

    /// True when `key` raised a finding within the cooldown; otherwise records this one.
    fn in_cooldown(&self, key: String, now_ns: u64) -> bool {
        let mut last = self.cooldown.lock().unwrap();
        if let Some(&at) = last.peek(&key)
            && now_ns.saturating_sub(at) < COOLDOWN_NS
        {
            return true;
        }
        last.insert(key, now_ns);
        false
    }
}

/// The shortest suffix of `name`, on a label boundary, that is itself matched: the listed domain,
/// since nothing shorter is, with the match of that suffix. Indicator and feed come from the same
/// suffix: `lookup_domain` on the whole name reports the lowest feed id among every listed suffix,
/// which can be another indicator's feed. Runs on a hit only, at most one lookup per label.
fn listed_domain(set: &IndicatorSet, name: &str) -> Option<(String, intel::Match)> {
    let suffixes: Vec<&str> =
        std::iter::successors(Some(name), |s| s.split_once('.').map(|(_, rest)| rest)).collect();
    suffixes.iter().rev().find_map(|suffix| {
        set.lookup_domain(suffix)
            .map(|found| (suffix.to_string(), found))
    })
}

/// The `*.txt` paths among the directory entries. One entry that cannot be read fails the whole
/// listing: a set built from the rest would silently drop a feed and replace a complete one.
fn feed_files(
    entries: impl Iterator<Item = std::io::Result<std::path::PathBuf>>,
) -> Result<Vec<std::path::PathBuf>, ()> {
    let mut files = Vec::new();
    for entry in entries {
        match entry {
            Ok(path) if path.extension().is_some_and(|ext| ext == "txt") => files.push(path),
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "ioc: cannot list the feed directory");
                return Err(());
            }
        }
    }
    Ok(files)
}

/// `Ok(None)`: no directory. `Err(())`: unusable, already logged.
fn load(dir: &Path) -> Result<Option<Loaded>, ()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            tracing::error!(error = %e, "ioc: cannot read the feed directory");
            return Err(());
        }
    };
    let mut files = feed_files(entries.map(|entry| entry.map(|entry| entry.path())))?;
    // Feed ids follow the sorted names, so two agents with the same files agree on which feed
    // wins an overlap (the lowest id).
    files.sort();
    if files.len() > usize::from(u16::MAX) {
        tracing::error!(feeds = files.len(), "ioc: too many feed files");
        return Err(());
    }

    let mut builder = SetBuilder::new(DEFAULT_MEMORY_BUDGET_BYTES);
    let mut feeds = Vec::with_capacity(files.len());
    for (index, path) in files.iter().enumerate() {
        let Some(text) = read_capped(path) else {
            return Err(());
        };
        let name = label(path.file_stem().and_then(|s| s.to_str()).unwrap_or("feed"));
        let id = FeedId(u16::try_from(index).map_err(|_| ())?);
        let report = builder.add_lines(id, &text);
        tracing::info!(
            feed = %name,
            added = report.added,
            rejected = report.rejected,
            over_budget = report.over_budget,
            "ioc: feed read"
        );
        feeds.push(name);
    }
    let set = match builder.build() {
        Ok(set) => set,
        Err(e) => {
            tracing::error!(error = %e, "ioc: the indicator set was refused, keeping the previous one");
            return Err(());
        }
    };
    let version = read_capped(&dir.join(VERSION_FILE))
        .and_then(|text| text.lines().next().map(label))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| UNVERSIONED.to_string());
    tracing::info!(
        indicators = set.len(),
        memory_bytes = set.memory_bytes(),
        version = %version,
        "ioc: indicator set loaded"
    );
    Ok(Some(Loaded {
        set,
        feeds,
        version,
    }))
}

/// A name or version as it travels in a detection: trimmed, bounded, printable.
fn label(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect()
}

fn read_capped(path: &Path) -> Option<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::error!(error = %e, "ioc: cannot open a feed file");
            return None;
        }
    };
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_FEED_FILE_BYTES + 1).read_to_end(&mut bytes) {
        tracing::error!(error = %e, "ioc: cannot read a feed file");
        return None;
    }
    if bytes.len() as u64 > MAX_FEED_FILE_BYTES {
        tracing::error!(
            max_bytes = MAX_FEED_FILE_BYTES,
            "ioc: a feed file is over the size cap"
        );
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const SEC: u64 = 1_000_000_000;

    fn dir_with(files: &[(&str, &str)]) -> tempfile_dir::Dir {
        let dir = tempfile_dir::Dir::new();
        std::fs::create_dir_all(dir.path().join(FEED_DIR)).unwrap();
        for (name, text) in files {
            std::fs::write(dir.path().join(FEED_DIR).join(name), text).unwrap();
        }
        dir
    }

    /// A throw-away directory removed on drop (the agent has no `tempfile` dependency).
    mod tempfile_dir {
        use std::{
            path::{Path, PathBuf},
            sync::atomic::{AtomicU64, Ordering},
        };

        static NEXT: AtomicU64 = AtomicU64::new(0);

        pub(super) struct Dir(PathBuf);

        impl Dir {
            pub(super) fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "agent-ioc-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }

            pub(super) fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn no_feed_directory_matches_nothing() {
        let dir = tempfile_dir::Dir::new();
        let matcher = IocMatcher::new(dir.path());
        assert_eq!(matcher.indicator_count(), 0);
        assert!(matcher.check_exec_image(Some(HASH), 0).is_none());
        assert!(
            matcher
                .check_connect("203.0.113.9".parse().unwrap(), 0)
                .is_none()
        );
    }

    #[test]
    fn a_domain_hit_reports_the_feed_of_the_indicator_it_names() {
        // Two feeds list overlapping suffixes. Whatever `lookup_domain` reports for the whole
        // name, the finding names one listed domain and that domain's own feed.
        let dir = dir_with(&[
            ("aa-narrow.txt", "domain:evil.example.com\n"),
            ("bb-broad.txt", "domain:example.com\n"),
        ]);
        let matcher = IocMatcher::new(dir.path());
        let overlap = matcher.check_dns_query("x.Evil.Example.com.", 0).unwrap();
        assert_eq!(
            (overlap.indicator.as_str(), overlap.feed.as_str()),
            ("example.com", "bb-broad"),
            "the shortest listed suffix is the indicator, and its own feed the source"
        );
        let only_broad = matcher
            .check_dns_query("www.example.com", COOLDOWN_NS)
            .unwrap();
        assert_eq!(
            (only_broad.indicator.as_str(), only_broad.feed.as_str()),
            ("example.com", "bb-broad")
        );
    }

    #[test]
    fn a_narrow_listing_alone_names_its_own_feed() {
        let dir = dir_with(&[
            ("aa-other.txt", "domain:unrelated.test\n"),
            ("bb-narrow.txt", "domain:evil.example.com\n"),
        ]);
        let matcher = IocMatcher::new(dir.path());
        let hit = matcher.check_dns_query("x.evil.example.com", 0).unwrap();
        assert_eq!(
            (hit.indicator.as_str(), hit.feed.as_str()),
            ("evil.example.com", "bb-narrow")
        );
    }

    #[test]
    fn a_listing_error_fails_the_whole_listing() {
        let entries = vec![
            Ok(std::path::PathBuf::from("a.txt")),
            Err(std::io::Error::other("transient")),
            Ok(std::path::PathBuf::from("b.txt")),
        ];
        assert!(feed_files(entries.into_iter()).is_err());
    }

    #[test]
    fn only_txt_entries_are_feeds() {
        let entries = vec![
            Ok(std::path::PathBuf::from("a.txt")),
            Ok(std::path::PathBuf::from("VERSION")),
            Ok(std::path::PathBuf::from("b.txt.bak")),
        ];
        assert_eq!(
            feed_files(entries.into_iter()),
            Ok(vec![std::path::PathBuf::from("a.txt")])
        );
    }

    #[test]
    fn a_listed_hash_reports_its_feed_and_version() {
        let dir = dir_with(&[
            ("zz-second.txt", &format!("sha256:{HASH}\n")),
            ("aa-first.txt", "ip:203.0.113.9\n"),
            ("VERSION", "2026-10-26.3\nignored second line\n"),
        ]);
        let matcher = IocMatcher::new(dir.path());
        let hit = matcher
            .check_exec_image(Some(&HASH.to_uppercase()), 0)
            .unwrap();
        assert_eq!(hit.kind, IocKind::Sha256);
        assert_eq!(hit.indicator, HASH, "the indicator is the normalised form");
        assert_eq!(hit.feed, "zz-second");
        assert_eq!(hit.feed_version, "2026-10-26.3");
        assert_eq!(hit.severity(), Severity::High);
        let ip = matcher
            .check_connect("::ffff:203.0.113.9".parse().unwrap(), 0)
            .unwrap();
        assert_eq!(
            (ip.kind, ip.indicator.as_str(), ip.feed.as_str()),
            (IocKind::Ip, "203.0.113.9", "aa-first")
        );
        assert_eq!(ip.severity(), Severity::Medium);
    }

    #[test]
    fn an_unlisted_hash_or_address_and_a_missing_hash_match_nothing() {
        let dir = dir_with(&[("f.txt", &format!("sha256:{HASH}\nip:203.0.113.9\n"))]);
        let matcher = IocMatcher::new(dir.path());
        assert!(matcher.check_exec_image(Some(&"0".repeat(64)), 0).is_none());
        assert!(matcher.check_exec_image(None, 0).is_none());
        assert!(
            matcher
                .check_connect("203.0.113.10".parse().unwrap(), 0)
                .is_none()
        );
    }

    #[test]
    fn a_repeat_inside_the_cooldown_is_absorbed_and_counted_then_alerts_again() {
        let dir = dir_with(&[("f.txt", &format!("sha256:{HASH}\n"))]);
        let matcher = IocMatcher::new(dir.path());
        assert!(matcher.check_exec_image(Some(HASH), 100 * SEC).is_some());
        assert!(matcher.check_exec_image(Some(HASH), 101 * SEC).is_none());
        assert!(
            matcher
                .check_exec_image(Some(HASH), 100 * SEC + COOLDOWN_NS - 1)
                .is_none()
        );
        assert!(
            matcher
                .check_exec_image(Some(HASH), 100 * SEC + COOLDOWN_NS)
                .is_some()
        );
        let stats = matcher.stats();
        assert_eq!(stats.raised.load(Ordering::Relaxed), 2);
        assert_eq!(stats.cooled_down.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn the_cooldown_is_per_indicator() {
        let other = "0".repeat(63) + "1";
        let dir = dir_with(&[("f.txt", &format!("sha256:{HASH}\nsha256:{other}\n"))]);
        let matcher = IocMatcher::new(dir.path());
        assert!(matcher.check_exec_image(Some(HASH), 0).is_some());
        assert!(matcher.check_exec_image(Some(&other), 1).is_some());
    }

    #[test]
    fn a_reload_replaces_a_removed_directory_unloads_and_a_broken_feed_keeps_the_old_set() {
        let dir = dir_with(&[("f.txt", &format!("sha256:{HASH}\n"))]);
        let matcher = IocMatcher::new(dir.path());
        assert_eq!(matcher.indicator_count(), 1);

        // A feed that does not fit: the directory is unusable, the old set stays.
        let feed = dir.path().join(FEED_DIR).join("f.txt");
        std::fs::remove_file(&feed).unwrap();
        std::fs::create_dir(&feed).unwrap();
        assert!(matches!(matcher.reload(dir.path()), LoadOutcome::Failed));
        assert_eq!(
            matcher.indicator_count(),
            1,
            "a broken reload keeps the previous set"
        );
        std::fs::remove_dir(&feed).unwrap();

        // The directory is gone: unload.
        std::fs::remove_dir_all(dir.path().join(FEED_DIR)).unwrap();
        assert!(matches!(matcher.reload(dir.path()), LoadOutcome::Absent));
        assert_eq!(matcher.indicator_count(), 0);
        assert!(matcher.check_exec_image(Some(HASH), 0).is_none());
    }

    #[test]
    fn a_missing_version_file_is_unversioned_and_labels_are_bounded_and_printable() {
        let long = "x".repeat(200);
        let dir = dir_with(&[
            (&format!("{long}.txt"), &format!("sha256:{HASH}\n")),
            ("VERSION", "\n"),
        ]);
        let matcher = IocMatcher::new(dir.path());
        let hit = matcher.check_exec_image(Some(HASH), 0).unwrap();
        assert_eq!(hit.feed_version, UNVERSIONED);
        assert_eq!(hit.feed.chars().count(), MAX_LABEL_CHARS);
        assert_eq!(label("a\u{7}b\nc"), "abc");
    }

    #[test]
    fn the_message_names_the_indicator_the_feed_and_the_version_but_not_a_path() {
        let hit = IocHit {
            kind: IocKind::Sha256,
            indicator: HASH.into(),
            feed: "abuse.ch".into(),
            feed_version: "v1".into(),
        };
        let message = hit.message("evil");
        assert!(message.contains(HASH) && message.contains("abuse.ch") && message.contains("(v1)"));
        assert!(message.starts_with("comm=evil "));
    }
}
