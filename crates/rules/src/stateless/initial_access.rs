//! Initial Access (TA0001): a database service writing outside its own directories.

use schema::{FileOpenEvent, detection::Severity};

use crate::{Alert, has_write_intent};

/// `mysqld`/`mariadbd`, exact-`comm` match — deliberately narrower than
/// [`SERVICE_COMMS`](crate::exclusions::SERVICE_COMMS) (T1059's broader web+DB
/// list): [`check_service_write_outside_datadir`] is MySQL/MariaDB-specific
/// (issue #478's own wording), not a generic "service wrote somewhere odd" rule.
const MYSQL_SERVICE_COMMS: &[&str] = &["mysqld", "mariadbd"];

/// Paths `mysqld`/`mariadbd` legitimately write under (T1190, issue #478): the
/// data directory, the log directory (package name varies: Debian ships
/// `mariadb-server` but keeps the `/var/log/mysql/` path for compatibility,
/// RHEL uses `/var/log/mariadb/`), the runtime socket/pid directory, and the
/// system temp directory — `mysqld`'s own `tmpdir` setting defaults to
/// `/tmp`, used for on-disk temp tables and sorts, a routine, high-volume
/// write path that would otherwise swamp the rule in false positives.
const MYSQL_WRITE_PATH_PREFIXES: &[&str] = &[
    "/var/lib/mysql/",
    "/var/lib/mariadb/",
    "/var/log/mysql/",
    "/var/log/mariadb/",
    "/run/mysqld/",
    "/var/run/mysqld/",
    "/tmp/",
];

/// T1190 — Exploit Public-Facing Application: `mysqld`/`mariadbd` writing a
/// file outside its normal footprint (issue #478, Level 1). A write anywhere
/// but [`MYSQL_WRITE_PATH_PREFIXES`] is the signature this rule targets:
/// `SELECT ... INTO OUTFILE` (SQL injection dropping a webshell under the web
/// root) or a malicious UDF `.so` planted outside the plugin directory —
/// MySQL/MariaDB has no legitimate reason to write anywhere else, which is
/// exactly why this is a "very low noise" signal per the issue's own framing.
///
/// Two properties learned from the live run on real `mariadbd` (#498 review),
/// both invisible to hand-written unit-test events:
/// - **The process name comes from the pid, not from `event.meta.comm`.** `comm`
///   is the *thread's* name: `SELECT ... INTO OUTFILE` runs on a connection
///   thread named `one_connection`, so a `comm` match never sees the attack.
///   `resolve_comm` is asked for the pid's own name (lazily — only once the path
///   and flags already say "candidate", so the common open never pays for a
///   `/proc` read) and is `RuleState`'s exec table, then `/proc/<pid>/comm`.
///   The sensor's `pid` is the tgid.
/// - **Only absolute paths alert.** The collector reports the raw `openat`
///   argument: startup opens `./ibdata1`, `plugin.MAI`, `#binlog_cache_files/`
///   (relative or dirfd-relative) and `/tmp` itself (`O_TMPFILE`, no trailing
///   slash), which no absolute-prefix allowlist can match — 284 false positives
///   on a bare start. A webshell drop needs an absolute path to reach the web
///   root, so skipping relative paths loses no attack shape.
#[must_use]
pub(crate) fn check_service_write_outside_datadir(
    event: &FileOpenEvent,
    resolve_comm: impl FnOnce(u32, Option<u64>) -> Option<String>,
) -> Option<Alert> {
    let path = &event.path;
    if !has_write_intent(event.flags)
        || !path.starts_with('/')
        || path == "/tmp"
        || MYSQL_WRITE_PATH_PREFIXES
            .iter()
            .any(|p| path.starts_with(p))
    {
        return None;
    }
    let comm = resolve_comm(event.meta.pid, event.meta.process_generation)?;
    if !MYSQL_SERVICE_COMMS.contains(&comm.as_str()) {
        return None;
    }
    Some(Alert {
        technique: "T1190",
        severity: Severity::High,
        message: format!(
            "pid={} comm={comm}: wrote outside its data/log/temp directories: {path} — \
             signature of SQL injection (SELECT ... INTO OUTFILE) or a malicious UDF",
            event.meta.pid,
        ),
    })
}
