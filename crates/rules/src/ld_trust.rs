//! The dynamic linker's trust set, for `check_ld_preload_hijack` (T1574.006, #363).
//!
//! Two layers: a built-in baseline ([`LD_TRUST_PREFIXES`], the directories every
//! mainstream distro's linker searches), plus the directories the host's own
//! `/etc/ld.so.conf` declares, `include`s followed. The second layer is loaded once at
//! agent startup ([`crate::RuleState::seed_ld_trust_from_system`]); without it, a
//! vendor library directory legitimately registered with `ldconfig` (`/opt/<app>/lib`)
//! would look exactly like a planted preload.
//!
//! Parsing is pure, and the file walk takes injected `read`/`list` closures, so both are
//! unit-tested without touching the real `/etc`.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

/// Built-in trusted directories: the dynamic linker's default search path on every
/// mainstream distro, each also covering its multiarch subdirectories (e.g.
/// `/usr/lib/x86_64-linux-gnu/...` is nested under `/usr/lib/`). Always trusted, with
/// or without a readable `ld.so.conf`.
pub(crate) const LD_TRUST_PREFIXES: &[&str] = &[
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/lib/",
];

/// Directories never trusted even when `ld.so.conf` lists them: world-writable scratch
/// space, where any local user can plant a library. A root attacker can edit
/// `ld.so.conf` anyway; this guards against a careless configuration turning `/tmp`
/// into a blanket exemption.
const NEVER_TRUSTED: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// How deep `include` directives are followed. `ldconfig` has no documented limit;
/// real configurations nest one level (`ld.so.conf` → `ld.so.conf.d/*.conf`), so this
/// only bounds a pathological or cyclic setup.
const MAX_INCLUDE_DEPTH: usize = 8;

/// The system `ld.so.conf` root.
pub(crate) const LD_SO_CONF: &str = "/etc/ld.so.conf";

/// Whether every `:`-separated entry in an `LD_PRELOAD`/`LD_AUDIT` value is trusted:
/// either a bare filename (no `/`, resolved through the trusted search path itself), or
/// an absolute path under [`LD_TRUST_PREFIXES`] or one of `extra` (directories
/// normalized by [`collect_ld_dirs`], trailing `/` included).
pub(crate) fn all_paths_trusted(value: &str, extra: &[String]) -> bool {
    value.split(':').filter(|p| !p.is_empty()).all(|p| {
        !p.starts_with('/')
            || LD_TRUST_PREFIXES.iter().any(|prefix| p.starts_with(prefix))
            || extra.iter().any(|dir| p.starts_with(dir.as_str()))
    })
}

/// One meaningful line of an `ld.so.conf` file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LdConfEntry {
    /// A library directory.
    Dir(String),
    /// An `include` pattern (glob), possibly relative to the including file.
    Include(String),
}

/// Parses the text of one `ld.so.conf`-format file. Follows `ldconfig`'s grammar:
/// `#` starts a comment, directories may be separated by whitespace, `,` or `:`,
/// `include <pattern>...` pulls in other files, and `hwcap` lines are ignored. A
/// legacy `dir=TYPE` suffix (libc5 era) is stripped.
pub(crate) fn parse_ld_so_conf(text: &str) -> Vec<LdConfEntry> {
    let mut entries = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        match words.next() {
            Some("include") => {
                entries.extend(words.map(|w| LdConfEntry::Include(w.to_string())));
            }
            Some("hwcap") => {}
            _ => {
                for dir in line.split(|c: char| c.is_whitespace() || c == ',' || c == ':') {
                    let dir = dir.split('=').next().unwrap_or("").trim();
                    if !dir.is_empty() {
                        entries.push(LdConfEntry::Dir(dir.to_string()));
                    }
                }
            }
        }
    }
    entries
}

/// Walks `root` (an `ld.so.conf`) and every file it `include`s, returning the declared
/// directories as trust prefixes: absolute, `/`-terminated, deduplicated, with
/// [`NEVER_TRUSTED`] locations dropped. `read` returns a file's text (`None` if
/// unreadable); `list` returns a directory's entries (empty if unreadable). Best-effort
/// throughout: a missing or unreadable file contributes nothing and never fails.
pub(crate) fn collect_ld_dirs(
    root: &Path,
    read: &dyn Fn(&Path) -> Option<String>,
    list: &dyn Fn(&Path) -> Vec<PathBuf>,
) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut seen_dirs = HashSet::new();
    let mut seen_files = HashSet::new();
    walk(
        root,
        0,
        read,
        list,
        &mut seen_files,
        &mut seen_dirs,
        &mut dirs,
    );
    dirs
}

fn walk(
    file: &Path,
    depth: usize,
    read: &dyn Fn(&Path) -> Option<String>,
    list: &dyn Fn(&Path) -> Vec<PathBuf>,
    seen_files: &mut HashSet<PathBuf>,
    seen_dirs: &mut HashSet<String>,
    dirs: &mut Vec<String>,
) {
    if depth > MAX_INCLUDE_DEPTH || !seen_files.insert(file.to_path_buf()) {
        return;
    }
    let Some(text) = read(file) else {
        return;
    };
    let base = file.parent().unwrap_or_else(|| Path::new("/"));
    for entry in parse_ld_so_conf(&text) {
        match entry {
            LdConfEntry::Dir(dir) => {
                if let Some(prefix) = trust_prefix(&dir)
                    && seen_dirs.insert(prefix.clone())
                {
                    dirs.push(prefix);
                }
            }
            LdConfEntry::Include(pattern) => {
                let pattern = if pattern.starts_with('/') {
                    PathBuf::from(pattern)
                } else {
                    base.join(pattern)
                };
                let mut matches = expand_glob(&pattern, list);
                // `glob(3)` returns matches sorted; keep the same order.
                matches.sort();
                for included in matches {
                    walk(
                        &included,
                        depth + 1,
                        read,
                        list,
                        seen_files,
                        seen_dirs,
                        dirs,
                    );
                }
            }
        }
    }
}

/// Normalizes a declared directory into a trust prefix, or `None` if it is relative,
/// or sits under a [`NEVER_TRUSTED`] location.
fn trust_prefix(dir: &str) -> Option<String> {
    if !dir.starts_with('/') {
        return None;
    }
    let prefix = format!("{}/", dir.trim_end_matches('/'));
    if NEVER_TRUSTED.iter().any(|bad| prefix.starts_with(bad)) {
        return None;
    }
    Some(prefix)
}

/// Expands a pattern whose wildcards (`*`, `?`) sit in the final path component only,
/// which is how every real `ld.so.conf` writes it (`/etc/ld.so.conf.d/*.conf`). A
/// pattern without wildcards is returned as-is (the caller's `read` decides whether it
/// exists).
fn expand_glob(pattern: &Path, list: &dyn Fn(&Path) -> Vec<PathBuf>) -> Vec<PathBuf> {
    let Some(name) = pattern.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    if !name.contains(['*', '?']) {
        return vec![pattern.to_path_buf()];
    }
    let Some(dir) = pattern.parent() else {
        return Vec::new();
    };
    list(dir)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| wildcard_match(name.as_bytes(), n.as_bytes()))
        })
        .collect()
}

/// `*`/`?` matching over bytes, iterative with single-star backtracking (no
/// recursion, linear in practice for the short file names involved).
fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// The real-filesystem `read` for [`collect_ld_dirs`].
pub(crate) fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// The real-filesystem `list` for [`collect_ld_dirs`].
pub(crate) fn list_dir(path: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(path)
        .map(|entries| entries.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// An in-memory filesystem: file path → contents. Directory listings are derived
    /// from the file paths.
    fn fs(files: &[(&str, &str)]) -> HashMap<PathBuf, String> {
        files
            .iter()
            .map(|(p, c)| (PathBuf::from(p), (*c).to_string()))
            .collect()
    }

    fn collect(files: &HashMap<PathBuf, String>) -> Vec<String> {
        let read = |p: &Path| files.get(p).cloned();
        let list = |d: &Path| {
            files
                .keys()
                .filter(|p| p.parent() == Some(d))
                .cloned()
                .collect()
        };
        collect_ld_dirs(Path::new(LD_SO_CONF), &read, &list)
    }

    #[test]
    fn parses_dirs_includes_comments_and_separators() {
        let entries = parse_ld_so_conf(
            "# comment\ninclude /etc/ld.so.conf.d/*.conf\n\n/opt/a/lib, /opt/b/lib:/opt/c/lib # trailing\nhwcap 0 nosegneg\n/usr/X11R6/lib=libc6\n",
        );
        assert_eq!(
            entries,
            vec![
                LdConfEntry::Include("/etc/ld.so.conf.d/*.conf".into()),
                LdConfEntry::Dir("/opt/a/lib".into()),
                LdConfEntry::Dir("/opt/b/lib".into()),
                LdConfEntry::Dir("/opt/c/lib".into()),
                LdConfEntry::Dir("/usr/X11R6/lib".into()),
            ]
        );
    }

    #[test]
    fn debian_layout_follows_the_include_glob() {
        // Shape of a stock Debian/Ubuntu install plus one vendor drop-in.
        let files = fs(&[
            (LD_SO_CONF, "include /etc/ld.so.conf.d/*.conf\n"),
            (
                "/etc/ld.so.conf.d/x86_64-linux-gnu.conf",
                "# Multiarch support\n/usr/local/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n",
            ),
            ("/etc/ld.so.conf.d/libc.conf", "/usr/local/lib\n"),
            ("/etc/ld.so.conf.d/vendor.conf", "/opt/vendor/lib/\n"),
            ("/etc/ld.so.conf.d/README", "/opt/not-a-conf/lib\n"),
        ]);
        let dirs = collect(&files);
        assert!(dirs.contains(&"/opt/vendor/lib/".to_string()), "{dirs:?}");
        assert!(dirs.contains(&"/usr/lib/x86_64-linux-gnu/".to_string()));
        assert!(
            !dirs.iter().any(|d| d.contains("not-a-conf")),
            "only *.conf matches the glob: {dirs:?}"
        );
    }

    #[test]
    fn relative_include_resolves_against_the_including_file() {
        let files = fs(&[
            (LD_SO_CONF, "include ld.so.conf.d/*.conf\n"),
            ("/etc/ld.so.conf.d/app.conf", "/opt/app/lib\n"),
        ]);
        assert_eq!(collect(&files), vec!["/opt/app/lib/".to_string()]);
    }

    #[test]
    fn world_writable_and_relative_dirs_are_never_trusted() {
        let files = fs(&[(
            LD_SO_CONF,
            "/tmp/libs\n/var/tmp/x\n/dev/shm/y\nrelative/lib\n/opt/ok/lib\n",
        )]);
        assert_eq!(collect(&files), vec!["/opt/ok/lib/".to_string()]);
    }

    #[test]
    fn include_cycle_terminates_and_dedups() {
        let files = fs(&[
            (LD_SO_CONF, "include /etc/a.conf\n/opt/x/lib\n"),
            ("/etc/a.conf", "include /etc/ld.so.conf\n/opt/x/lib\n"),
        ]);
        assert_eq!(collect(&files), vec!["/opt/x/lib/".to_string()]);
    }

    #[test]
    fn missing_ld_so_conf_yields_nothing() {
        assert!(collect(&fs(&[])).is_empty());
    }

    #[test]
    fn extra_dirs_extend_the_builtin_trust_set() {
        let extra = vec!["/opt/vendor/lib/".to_string()];
        assert!(all_paths_trusted("/opt/vendor/lib/libv.so", &extra));
        assert!(!all_paths_trusted("/opt/vendor/lib/libv.so", &[]));
        // A sibling directory sharing the name prefix is not inside the trusted one.
        assert!(!all_paths_trusted("/opt/vendor/lib-evil/x.so", &extra));
        assert!(all_paths_trusted(
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            &[]
        ));
    }

    /// Reads the real host's `/etc/ld.so.conf`. Ignored by default (depends on the
    /// machine); run it in a lab VM with `cargo test -p rules -- --ignored --nocapture`
    /// to see what a given distro contributes.
    #[test]
    #[ignore = "reads the real /etc/ld.so.conf"]
    fn real_system_ld_so_conf() {
        let dirs = collect_ld_dirs(Path::new(LD_SO_CONF), &read_file, &list_dir);
        println!("ld.so.conf trust dirs: {dirs:?}");
        assert!(dirs.iter().all(|d| d.starts_with('/') && d.ends_with('/')));
        assert!(
            dirs.iter()
                .all(|d| !NEVER_TRUSTED.iter().any(|bad| d.starts_with(bad)))
        );
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match(b"*.conf", b"libc.conf"));
        assert!(!wildcard_match(b"*.conf", b"README"));
        assert!(wildcard_match(b"a?c*", b"abcdef"));
        assert!(!wildcard_match(b"*.conf", b"x.conf.bak"));
        assert!(wildcard_match(b"*", b""));
    }
}
