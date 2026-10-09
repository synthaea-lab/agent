//! Stateless rules (base64, persistence writes) and the Linux stateful rules
//! (web-server→shell lineage, download-then-exec).

use super::*;

#[test]
fn base64_decode_matches() {
    let event = exec_event("bash -c $(echo ZWNobyBoZWxsbw== | base64 -d)");
    assert!(check_base64_decode(&event).is_some());
}

#[test]
fn base64_without_decode_flag_does_not_match() {
    let event = exec_event("base64 /etc/hosts");
    assert!(check_base64_decode(&event).is_none());
}

#[test]
fn benign_curl_does_not_match_base64() {
    let event = exec_event("curl -f http://backend:8000/api/health/");
    assert!(check_base64_decode(&event).is_none());
}

// ── T1059.001 PowerShell EncodedCommand (stateless, platform-neutral) ──────

#[test]
fn powershell_encoded_command_canonical_matches() {
    // Canonical shape: `powershell.exe -EncodedCommand <base64>` — the form
    // documented in every offensive-tradecraft resource.
    let event = exec_event("powershell.exe -EncodedCommand ZWNobyBoZWxsbw==");
    assert!(check_encoded_powershell(&event).is_some());
}

#[test]
fn powershell_enc_short_form_matches() {
    // Short truncation `-enc`, the other T1059.001 shape seen in the wild
    // (e.g. Empire, Cobalt Strike PowerShell payloads).
    let event = exec_event("powershell -enc ZWNobyBoZWxsbw==");
    assert!(check_encoded_powershell(&event).is_some());
}

#[test]
fn powershell_encoded_command_case_insensitive_matches() {
    // PowerShell parameter aliases are case-insensitive — attacker payload
    // may use mixed case to defeat naive lowercase-only matchers.
    let event = exec_event("PowerShell.exe -EnCoDeDcOmMaNd ZWNobyBoZWxsbw==");
    assert!(check_encoded_powershell(&event).is_some());
}

#[test]
fn pwsh_linux_variant_matches() {
    // T1059.001 is not Windows-only — `pwsh` is the PowerShell interpreter on
    // Linux/macOS (and PowerShell Core on Windows). The rule's anchor covers
    // both `powershell` and `pwsh` for exactly this case.
    let event = exec_event("pwsh -EncodedCommand ZWNobyBoZWxsbw==");
    assert!(check_encoded_powershell(&event).is_some());
}

#[test]
fn powershell_without_encoded_flag_does_not_match() {
    let event = exec_event("powershell.exe -Command Get-Process");
    assert!(check_encoded_powershell(&event).is_none());
}

#[test]
fn openssl_enc_without_powershell_does_not_match() {
    // `openssl enc` for legitimate encryption uses a `-enc` token but does not
    // mention powershell — the anchor filters it out.
    let event = exec_event("openssl enc -aes-256-cbc -in file.txt -out file.enc");
    assert!(check_encoded_powershell(&event).is_none());
}

#[test]
fn powershell_word_in_argument_but_no_encoded_flag_does_not_match() {
    // A shell that mentions "powershell" in a string argument but doesn't invoke
    // it with an encoded flag must not match (the word `enc` here is not a
    // standalone token starting with `-`).
    let event = exec_event("echo 'use powershell to enc your commands'");
    assert!(check_encoded_powershell(&event).is_none());
}

#[test]
fn powershell_intermediate_truncation_does_not_match_yet() {
    // Documented v1 limitation: PowerShell accepts `-Encoded`, `-Encod`, `-E`,
    // etc. as valid truncations of `-EncodedCommand`. v1 covers only the
    // canonical form and `-enc`; intermediate truncations are a follow-up
    // widening once telemetry justifies the trade-off against false positives
    // (any `-e` prefix token is very common on Unix cmdlines).
    let event = exec_event("powershell.exe -Encoded ZWNobyBoZWxsbw==");
    assert!(check_encoded_powershell(&event).is_none());
}

// ── T1574.006 dynamic linker hijacking (LD_PRELOAD family, issue #363) ─────

fn exec_with_env(env: &[(&str, &str)]) -> ExecEvent {
    let mut event = exec_event("irrelevant");
    event.env_security = env
        .iter()
        .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
        .collect();
    event
}

#[test]
fn ld_preload_outside_trust_set_alerts() {
    let event = exec_with_env(&[("LD_PRELOAD", "/tmp/evil.so")]);
    let alert = check_ld_preload_hijack(&event, &[]).expect("must alert");
    assert_eq!(alert.technique, "T1574.006");
    assert!(alert.message.contains("/tmp/evil.so"));
}

#[test]
fn ld_preload_inside_trust_set_does_not_alert() {
    assert!(
        check_ld_preload_hijack(
            &exec_with_env(&[("LD_PRELOAD", "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2")]),
            &[]
        )
        .is_none()
    );
}

#[test]
fn ld_preload_bare_filename_does_not_alert() {
    // No `/` — resolved via the trusted search path itself, not a planted path.
    assert!(
        check_ld_preload_hijack(&exec_with_env(&[("LD_PRELOAD", "libjemalloc.so.2")]), &[])
            .is_none()
    );
}

#[test]
fn ld_preload_mixed_trusted_and_untrusted_alerts() {
    // A colon-separated list where only one entry escapes the trust set still
    // counts as evidence of the attack (LD_PRELOAD loads every listed object).
    let event = exec_with_env(&[("LD_PRELOAD", "/usr/lib/libgood.so:/tmp/evil.so")]);
    assert!(check_ld_preload_hijack(&event, &[]).is_some());
}

#[test]
fn ld_audit_outside_trust_set_alerts() {
    let event = exec_with_env(&[("LD_AUDIT", "/tmp/audit-evil.so")]);
    assert_eq!(
        check_ld_preload_hijack(&event, &[])
            .expect("must alert")
            .technique,
        "T1574.006"
    );
}

#[test]
fn plain_exec_with_no_captured_env_does_not_alert() {
    assert!(check_ld_preload_hijack(&exec_event("ls -la"), &[]).is_none());
}

#[test]
fn other_captured_env_names_do_not_alert() {
    // GLIBC_TUNABLES/LD_DEBUG_OUTPUT are captured for hunting visibility but have
    // no trust-set shape to judge — only LD_PRELOAD/LD_AUDIT are rule-gated.
    let event = exec_with_env(&[("GLIBC_TUNABLES", "glibc.malloc.check=1")]);
    assert!(check_ld_preload_hijack(&event, &[]).is_none());
}

#[test]
fn ld_preload_fires_through_on_exec_not_evaluate_exec() {
    // The rule moved to the stateful path (it needs the seeded ld.so.conf trust set):
    // the agent's sink calls both dispatchers, so it must fire exactly once, from
    // `on_exec`.
    let event = exec_with_env(&[("LD_PRELOAD", "/tmp/evil.so")]);
    assert!(
        crate::evaluate_exec(&event)
            .iter()
            .all(|a| a.technique != "T1574.006")
    );
    let alerts = RuleState::new().on_exec(&event);
    assert_eq!(
        alerts.iter().filter(|a| a.technique == "T1574.006").count(),
        1
    );
}

#[test]
fn ld_preload_from_a_seeded_ld_so_conf_dir_does_not_alert() {
    // A vendor library directory registered with ldconfig (/etc/ld.so.conf.d/*.conf)
    // is part of the host's trust set once seeded — without the seed it alerts.
    let event = exec_with_env(&[("LD_PRELOAD", "/opt/vendor/lib/libhook.so")]);
    let fired = |state: &mut RuleState| {
        state
            .on_exec(&event)
            .iter()
            .any(|a| a.technique == "T1574.006")
    };
    assert!(fired(&mut RuleState::new()));
    let mut seeded = RuleState::new();
    seeded.seed_ld_trust_dirs(vec!["/opt/vendor/lib/".to_string()]);
    assert!(!fired(&mut seeded));
}

// ── persistence writes (T1546.004 / T1053.003 / T1543.002) ──────────────────

#[test]
fn write_to_bashrc_matches_persistence() {
    // O_WRONLY|O_CREAT|O_TRUNC, values observed in real conditions (touch(1)).
    let event = file_open_event("/home/app/.bashrc", 577);
    assert!(check_persistence_write(&event).is_some());
}

#[test]
fn linux_persistence_paths_are_tagged_with_their_own_technique() {
    // Regression (#495): every path was tagged T1037.004/T1053.003, and none of
    // them is an RC script (T1037.004).
    for (path, technique) in [
        ("/home/app/.bashrc", "T1546.004"),
        ("/home/app/.zshrc", "T1546.004"),
        ("/etc/profile.d/evil.sh", "T1546.004"),
        ("/etc/cron.d/evil", "T1053.003"),
        ("/etc/systemd/system/evil.service", "T1543.002"),
    ] {
        let alert = check_persistence_write(&file_open_event(path, O_WRONLY | O_CREAT))
            .expect("must alert");
        assert_eq!(alert.technique, technique, "{path}");
    }
}

#[test]
fn readonly_bashrc_does_not_alert() {
    // Every interactive shell reads ~/.bashrc on startup: alerting here would be
    // constant noise, not a detection.
    let event = file_open_event("/home/app/.bashrc", O_RDONLY);
    assert!(check_persistence_write(&event).is_none());
}

#[test]
fn write_outside_persistence_paths_does_not_alert() {
    let event = file_open_event("/tmp/test.txt", 577);
    assert!(check_persistence_write(&event).is_none());
}

#[test]
fn write_to_systemd_unit_matches_persistence() {
    let event = file_open_event("/etc/systemd/system/evil.service", O_WRONLY | O_CREAT);
    assert!(check_persistence_write(&event).is_some());
}

// ── T1190 mysqld/mariadbd write outside datadir (issue #478) ───────────────
// Driven through `RuleState`: the rule resolves the process name from the pid
// (#498 review), so a stateless call with a hand-written `comm` is exactly the
// shape the live run showed the sensor does not produce.

/// Every T1190 alert for one open, after the pid exec'd as `exec_comm` (`None` =
/// no exec seen for it). The open's own `comm` is the *thread* name, set by the
/// caller — it differs from the process name in the cases that matter.
fn mysql_open_alerts(exec_comm: Option<&str>, event: &FileOpenEvent) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    if let Some(comm) = exec_comm {
        state.on_exec(&exec_event_full(event.meta.pid, 1, comm, "", 0));
    }
    state
        .on_file_open(event)
        .into_iter()
        .filter(|a| a.technique == "T1190")
        .collect()
}

#[test]
fn mysqld_write_under_web_root_matches() {
    // SELECT ... INTO OUTFILE dropping a webshell.
    let event = file_open_event_full(
        200,
        "mysqld",
        "/var/www/html/shell.php",
        O_WRONLY | O_CREAT,
        0,
    );
    assert_eq!(mysql_open_alerts(Some("mysqld"), &event).len(), 1);
}

#[test]
fn outfile_from_a_connection_thread_matches_through_the_pids_process_name() {
    // Live on real mariadbd (#498 review): the open comes from a connection
    // *thread* whose comm is "one_connection", not "mariadbd". The process name
    // has to come from the pid.
    let event = file_open_event_full(
        202,
        "one_connection",
        "/var/www/html/x498.php",
        O_WRONLY | O_CREAT,
        0,
    );
    assert_eq!(mysql_open_alerts(Some("mariadbd"), &event).len(), 1);
}

#[test]
fn mariadbd_write_to_plugin_dir_matches() {
    // A malicious UDF .so: the plugin directory is delivered by the package
    // manager, never written to by mysqld/mariadbd itself in normal
    // operation, so it isn't in MYSQL_WRITE_PATH_PREFIXES — matches the
    // issue's own listing of "a .so in the plugin directory" as suspicious.
    let event = file_open_event_full(
        201,
        "mariadbd",
        "/usr/lib/mysql/plugin/evil.so",
        O_WRONLY | O_CREAT,
        0,
    );
    assert_eq!(mysql_open_alerts(Some("mariadbd"), &event).len(), 1);
}

#[test]
fn mysqld_write_under_datadir_does_not_alert() {
    let event = file_open_event_full(
        200,
        "mysqld",
        "/var/lib/mysql/mydb/table.ibd",
        O_WRONLY | O_CREAT,
        0,
    );
    assert!(mysql_open_alerts(Some("mysqld"), &event).is_empty());
}

#[test]
fn mysqld_write_to_tmpdir_does_not_alert() {
    // Routine on-disk temp table/sort spill — `mysqld`'s own `tmpdir` default.
    let event = file_open_event_full(200, "mysqld", "/tmp/#sql_1a2b_0.MYI", O_WRONLY | O_CREAT, 0);
    assert!(mysql_open_alerts(Some("mysqld"), &event).is_empty());
}

#[test]
fn mysqld_open_of_tmp_itself_does_not_alert() {
    // O_TMPFILE opens the directory itself: "/tmp" with no trailing slash, which
    // the "/tmp/" prefix never matched (#498 review, live).
    let event = file_open_event_full(200, "mariadbd", "/tmp", O_WRONLY, 0);
    assert!(mysql_open_alerts(Some("mariadbd"), &event).is_empty());
}

#[test]
fn mariadbd_startup_relative_and_dirfd_relative_opens_do_not_alert() {
    // The collector reports the raw openat argument. A bare `mariadbd` start
    // opened ~284 files like these and every one fired T1190 (#498 review, live):
    // no absolute-prefix allowlist can match them.
    for path in [
        "./ibdata1",
        "./mysql/db.frm",
        ".//undo001",
        "./ddl_recovery.log",
        "plugin.MAI",
        "#sql-temptable-49-1-3.MAI",
        "#binlog_cache_files/",
    ] {
        let event = file_open_event_full(200, "mariadbd", path, O_WRONLY | O_CREAT, 0);
        assert!(
            mysql_open_alerts(Some("mariadbd"), &event).is_empty(),
            "{path} must not alert: a web-root drop needs an absolute path"
        );
    }
}

#[test]
fn mysqld_readonly_open_outside_datadir_does_not_alert() {
    // No write intent — mysqld reading e.g. a config file elsewhere is routine.
    let event = file_open_event_full(200, "mysqld", "/etc/mysql/my.cnf", O_RDONLY, 0);
    assert!(mysql_open_alerts(Some("mysqld"), &event).is_empty());
}

#[test]
fn unrelated_process_write_under_web_root_does_not_match_mysql_rule() {
    // Not this rule's concern — a web server writing under its own web root is
    // routine (uploads, cache, generated assets).
    let event = file_open_event_full(
        200,
        "nginx",
        "/var/www/html/shell.php",
        O_WRONLY | O_CREAT,
        0,
    );
    assert!(mysql_open_alerts(Some("nginx"), &event).is_empty());
}

#[test]
fn write_outside_datadir_from_a_pid_whose_process_name_is_unknown_does_not_alert() {
    // No exec seen and no /proc entry for this pid: with no process name there is
    // nothing to say it is mysqld, whatever the thread's own comm claims.
    let event = file_open_event_full(
        4_000_000_000,
        "mysqld",
        "/var/www/html/shell.php",
        O_WRONLY | O_CREAT,
        0,
    );
    assert!(mysql_open_alerts(None, &event).is_empty());
}

#[test]
fn containerized_process_opening_proc_pid_root_matches_escape() {
    let event = file_open_event_containerized("/proc/1/root/etc/shadow", "abc123");
    assert!(check_proc_root_escape(&event).is_some());
}

#[test]
fn containerized_process_opening_proc_pid_root_bare_matches_escape() {
    // No subpath past `root` itself — still the same escape shape.
    let event = file_open_event_containerized("/proc/42/root", "abc123");
    assert!(check_proc_root_escape(&event).is_some());
}

#[test]
fn bare_metal_process_opening_proc_pid_root_does_not_alert() {
    // Same path, no container attribution: host tooling (nsenter, procfs walkers,
    // debuggers) does this constantly and legitimately.
    let event = file_open_event("/proc/1/root/etc/shadow", O_RDONLY);
    assert!(check_proc_root_escape(&event).is_none());
}

#[test]
fn containerized_process_opening_unrelated_proc_path_does_not_alert() {
    let event = file_open_event_containerized("/proc/1/cgroup", "abc123");
    assert!(check_proc_root_escape(&event).is_none());
}

#[test]
fn containerized_process_opening_proc_root_without_pid_does_not_alert() {
    // `/proc/root` isn't a thing — must not false-positive on a coincidental
    // substring match.
    let event = file_open_event_containerized("/proc/root", "abc123");
    assert!(check_proc_root_escape(&event).is_none());
}

#[test]
fn containerized_process_opening_proc_self_root_does_not_alert() {
    // `/proc/self/root` is a process reading its OWN root (harmless, extremely
    // common) — `self` isn't numeric, so this must not match.
    let event = file_open_event_containerized("/proc/self/root", "abc123");
    assert!(check_proc_root_escape(&event).is_none());
}

#[test]
fn nginx_spawning_shell_matches_lineage() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "nginx", "nginx -g daemon off;", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

// ── T1059 service-spawns-shell, extended to DB services (issue #478) ───────

#[test]
fn mysqld_spawning_shell_matches_lineage() {
    // mysqld spawning a shell = command execution through a UDF.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "mysqld", "/usr/sbin/mysqld", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn mariadbd_spawning_shell_matches_lineage() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(
        100,
        1,
        "mariadbd",
        "/usr/sbin/mariadbd",
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(101, 100, "bash", "bash -c id", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn postgres_spawning_shell_matches_lineage() {
    // The classic COPY PROGRAM / plpythonu escape.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "postgres", "postgres", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn php_fpm_versioned_spawning_shell_matches_lineage() {
    // Debian/Ubuntu suffix the pool binary's own comm with the PHP version
    // (php-fpm7.4, php-fpm8.1, ...) — a webshell's system()/exec() call spawns
    // a shell directly under this, not under nginx/Apache, so an exact-match
    // list alone would miss it entirely.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(
        100,
        1,
        "php-fpm7.4",
        "php-fpm: pool www",
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn php_fpm_bare_name_spawning_shell_matches_lineage() {
    // RHEL/Fedora ship a bare `php-fpm` (no version suffix) — same signal.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "php-fpm", "php-fpm: pool www", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn unrelated_service_named_process_spawning_shell_does_not_match() {
    // "phpstorm" starts with neither a SERVICE_COMMS entry nor "php-fpm" —
    // guards the prefix match against over-matching unrelated names.
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "phpstorm", "phpstorm", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert!(alerts.is_empty());
}

#[test]
#[cfg(target_os = "linux")]
fn resolve_comm_falls_back_to_live_proc_when_not_cached() {
    let state = RuleState::new();
    let own_pid = std::process::id();
    let expected_comm = std::fs::read_to_string("/proc/self/comm")
        .unwrap()
        .trim_end()
        .to_string();
    assert_eq!(state.resolve_comm(own_pid, None), Some(expected_comm));
}

#[test]
#[cfg(target_os = "linux")]
fn seed_from_proc_finds_own_pid_comm() {
    let mut state = RuleState::new();
    state.seed_from_proc();
    let own_pid = std::process::id();
    let expected_comm = std::fs::read_to_string("/proc/self/comm")
        .unwrap()
        .trim_end()
        .to_string();
    assert_eq!(
        state.pid_comm.peek(&own_pid).map(|f| f.value.as_str()),
        Some(expected_comm.as_str())
    );
}

#[test]
fn shell_spawned_by_unrelated_parent_does_not_match_lineage() {
    let mut state = RuleState::new();
    state.on_exec(&exec_event_full(100, 1, "bash", "bash", 0));
    let alerts = state.on_exec(&exec_event_full(101, 100, "sh", "sh -c id", 1));
    assert!(alerts.is_empty());
}

#[test]
fn download_then_direct_exec_matches() {
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    // Direct execution (e.g. ELF binary): comm == argv[0] == basename of the path.
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        5_000_000_000, // 5s later, within the 60s window
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1105");
}

#[test]
fn download_then_shebang_script_exec_matches() {
    // Regression from 2026-08-13: script with `#!/bin/sh`, so argv = ["/bin/sh",
    // "/tmp/edr-payload"] — argv[0] is not the downloaded path, only `comm` (derived by
    // the kernel from the script name) allows correlation. Case observed in real
    // conditions.
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/edr-payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        12327,
        "edr-payload",
        "/bin/sh /tmp/edr-payload",
        5_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1105");
}

#[test]
fn exec_outside_correlation_window_does_not_match() {
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        120_000_000_000, // 120s later, outside the 60s window
    ));
    assert!(alerts.is_empty());
}

#[test]
fn readonly_download_by_curl_does_not_match() {
    // `curl` without `-o`/`-O`: no local write (e.g. plain GET), nothing to correlate.
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_RDONLY,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "payload",
        "/tmp/payload",
        1_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn chmod_on_downloaded_path_does_not_match_download() {
    // Regression from 2026-08-13: `chmod +x /tmp/payload` wrongly matched (the path
    // appears as an argument, but `chmod` is not the downloaded payload).
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(
        51,
        1,
        "chmod",
        "chmod +x /tmp/payload",
        1_000_000_000,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn unrelated_exec_does_not_match_download() {
    let mut state = RuleState::new();
    state.on_file_open(&file_open_event_full(
        50,
        "curl",
        "/tmp/payload",
        O_WRONLY | O_CREAT,
        0,
    ));
    let alerts = state.on_exec(&exec_event_full(51, 1, "ls", "ls -la", 1_000_000_000));
    assert!(alerts.is_empty());
}

#[test]
fn beacon_ignores_the_unspecified_address_probe() {
    // Live on the lab VM (2026-09-29): sshd-session connects to 0.0.0.0:65535 and
    // :::65535 on every login, so three SSH logins in a minute raised T1071/T1041.
    let mut state = RuleState::new();
    for i in 0..5u64 {
        let v4 = connect_event_full(400, "sshd-session", [0, 0, 0, 0], 65535, i * 1_000_000_000);
        assert!(state.on_connect(&v4).is_empty());
        let mut v6 = v4.clone();
        v6.daddr = std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
        assert!(state.on_connect(&v6).is_empty());
    }
}

// ── BEACON via conntrack polling (issue #92, NetworkFlowEvent) ──────────────────

#[test]
fn beacon_flow_three_distinct_ports_triggers_alert() {
    // 3 distinct short-lived connections (3 distinct local ports) to the same
    // (comm, daddr, dport) — the real beaconing shape `lab/scenarios/beacon.sh`
    // exercises, observed here via conntrack polling instead of a discrete
    // ConnectEvent trace.
    let mut state = RuleState::new();
    state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50000,
        [127, 0, 0, 1],
        4444,
        0,
    ));
    state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50001,
        [127, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50002,
        [127, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1071/T1041");
}

#[test]
fn beacon_flow_same_local_port_repolled_does_not_alert() {
    // One single long-lived flow (same local_port every time) polled 5x within
    // the window must NOT count as 5 connections — the false-positive risk this
    // wiring exists to avoid (an ordinary long-lived SSH session still open on
    // its 3rd poll is not beaconing).
    let mut state = RuleState::new();
    for i in 0..5u64 {
        let alerts = state.on_network_flow(&network_flow_event_full(
            300,
            "sshd",
            50000,
            [127, 0, 0, 1],
            22222, // non-standard port, so STANDARD_PORTS doesn't mask this case
            i * 1_000_000_000,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn beacon_flow_ignores_the_unspecified_address_probe() {
    // Same sshd-session probe as `beacon_ignores_the_unspecified_address_probe`,
    // seen by conntrack polling: distinct local ports would otherwise count as
    // distinct connections (#525 review).
    let mut state = RuleState::new();
    for (i, port) in (50000..50005u16).enumerate() {
        let alerts = state.on_network_flow(&network_flow_event_full(
            400,
            "sshd-session",
            port,
            [0, 0, 0, 0],
            65535,
            i as u64 * 1_000_000_000,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn beacon_to_the_unspecified_address_on_another_port_still_alerts() {
    // #536: `0.0.0.0:<port>` reaches the local host like `127.0.0.1:<port>`, which is
    // counted. Only the sshd probe port is excluded, so a local-relay beacon cannot
    // hide behind the unspecified address.
    for (label, daddr) in [
        ("v4", std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        ("v6", std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
    ] {
        let mut state = RuleState::new();
        let mut alerts = Vec::new();
        for i in 0..5u64 {
            let mut event =
                connect_event_full(401, "implant", [0, 0, 0, 0], 4444, i * 1_000_000_000);
            event.daddr = daddr;
            alerts.extend(state.on_connect(&event));
        }
        assert_eq!(alerts.len(), 1, "{label}");
        assert_eq!(alerts[0].technique, "T1071/T1041", "{label}");
    }
}

#[test]
fn beacon_flow_to_the_unspecified_address_on_another_port_still_alerts() {
    // Same on the conntrack path (#536): distinct local ports count as distinct flows.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for (i, port) in (50000..50005u16).enumerate() {
        alerts.extend(state.on_network_flow(&network_flow_event_full(
            401,
            "implant",
            port,
            [0, 0, 0, 0],
            4444,
            i as u64 * 1_000_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1071/T1041");
}

#[test]
fn beacon_flow_standard_port_does_not_alert() {
    let mut state = RuleState::new();
    for (i, port) in (50000..50003u16).enumerate() {
        let alerts = state.on_network_flow(&network_flow_event_full(
            300,
            "app",
            port,
            [10, 0, 0, 1],
            443,
            i as u64 * 1_000_000_000,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn beacon_flow_and_connect_share_the_same_window_state() {
    // check_beacon and check_beacon_flow share the same underlying counter keyed
    // by (comm, daddr, dport) — a mixed source (2 discrete connects + 1 polled
    // flow, e.g. eBPF and netlink both active) must still cross the threshold,
    // not reset it.
    let mut state = RuleState::new();
    state.on_connect(&connect_event_full(300, "nc", [127, 0, 0, 1], 4444, 0));
    state.on_connect(&connect_event_full(
        300,
        "nc",
        [127, 0, 0, 1],
        4444,
        1_000_000_000,
    ));
    let alerts = state.on_network_flow(&network_flow_event_full(
        300,
        "nc",
        50002,
        [127, 0, 0, 1],
        4444,
        2_000_000_000,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1071/T1041");
}

// ── SCAN-SPREAD (T1046/T1210, issue #465) ───────────────────────────────────

#[test]
fn scan_spread_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    for i in 0..(SCAN_SPREAD_THRESHOLD - 1) {
        let alerts = state.on_connect(&connect_event_full(
            500,
            "bot",
            [10, 0, 0, i as u8],
            23,
            u64::from(i) * 10_000_000,
        ));
        assert!(alerts.is_empty());
    }
}

#[test]
fn scan_spread_distinct_destinations_triggers_alert() {
    // Shape of the live Mirai detonation that motivated #465: one pid, one
    // port (23), many distinct destinations, back to back.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..SCAN_SPREAD_THRESHOLD {
        alerts.extend(state.on_connect(&connect_event_full(
            500,
            "bot",
            [10, 0, 0, i as u8],
            23,
            u64::from(i) * 10_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1046/T1210");
}

#[test]
fn scan_spread_repeated_destination_does_not_count_twice() {
    // The BEACON mirror image: hammering the *same* destination repeatedly
    // must not cross *this* threshold, however many connections it takes —
    // that shape is check_beacon's job, not this one's (and check_beacon
    // does legitimately fire here on the same events — it's the
    // T1046/T1210 alert this test asserts against, not every alert).
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..(SCAN_SPREAD_THRESHOLD * 2) {
        alerts.extend(state.on_connect(&connect_event_full(
            500,
            "app",
            [10, 0, 0, 1],
            23,
            u64::from(i) * 10_000_000,
        )));
    }
    assert!(
        !alerts.iter().any(|a| a.technique == "T1046/T1210"),
        "repeating one destination is not a scan/spread burst"
    );
}

#[test]
fn scan_spread_outside_window_resets() {
    let mut state = RuleState::new();
    for i in 0..(SCAN_SPREAD_THRESHOLD - 1) {
        state.on_connect(&connect_event_full(500, "bot", [10, 0, 0, i as u8], 23, 0));
    }
    // Past the window relative to the first (SCAN_SPREAD_THRESHOLD - 1)
    // destinations — they must have expired, so one more distinct
    // destination here must not complete the threshold.
    let alerts = state.on_connect(&connect_event_full(
        500,
        "bot",
        [10, 0, 0, 200],
        23,
        SCAN_SPREAD_WINDOW_NS + 1,
    ));
    assert!(alerts.is_empty());
}

#[test]
fn scan_spread_correlates_only_its_own_pid_and_port() {
    let mut state = RuleState::new();
    for i in 0..(SCAN_SPREAD_THRESHOLD - 1) {
        state.on_connect(&connect_event_full(500, "bot", [10, 0, 0, i as u8], 23, 0));
    }
    // Different pid: must not inherit the other pid's near-threshold count.
    let alerts = state.on_connect(&connect_event_full(501, "bot", [10, 0, 0, 200], 23, 0));
    assert!(alerts.is_empty());
}

#[test]
fn scan_spread_standard_port_still_alerts() {
    // Unlike BEACON, STANDARD_PORTS must not exclude this rule — a spray
    // across many distinct hosts on a "standard" port (22, 23, 3389, ...) is
    // exactly the lateral-movement/credential-spray case #465 exists for.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..SCAN_SPREAD_THRESHOLD {
        alerts.extend(state.on_connect(&connect_event_full(
            500,
            "bot",
            [10, 0, 0, i as u8],
            443, // in STANDARD_PORTS
            u64::from(i) * 10_000_000,
        )));
    }
    assert_eq!(
        alerts.len(),
        1,
        "STANDARD_PORTS is a BEACON-only exclusion, not SCAN-SPREAD's"
    );
    assert_eq!(alerts[0].technique, "T1046/T1210");
}

#[test]
fn scan_spread_does_not_realert_within_window() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..(SCAN_SPREAD_THRESHOLD + 5) {
        alerts.extend(state.on_connect(&connect_event_full(
            500,
            "bot",
            [10, 0, 0, i as u8],
            23,
            u64::from(i) * 10_000_000,
        )));
    }
    assert_eq!(
        alerts.len(),
        1,
        "crossing the threshold again within the same window must not realert"
    );
}

// ── LISTENER-DRIFT via sock_diag polling (issue #92, ListenPortEvent) ───────────

#[test]
fn listen_port_not_in_baseline_alerts_once() {
    let mut state = RuleState::new();
    let alerts = state.on_listen_port(&listen_port_event_full(
        4242,
        "sshd-backdoor",
        [0, 0, 0, 0],
        31337,
        0,
    ));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1571");
}

#[test]
fn listen_port_seeded_at_startup_does_not_alert() {
    // The exact scenario seed_listen_ports exists for: a listener already up
    // before the agent attaches (sshd started by systemd at boot) must not look
    // like a freshly planted backdoor on the first poll.
    let mut state = RuleState::new();
    state.seed_listen_ports([(std::net::IpAddr::V4([0, 0, 0, 0].into()), 22)]);
    let alerts = state.on_listen_port(&listen_port_event_full(1, "sshd", [0, 0, 0, 0], 22, 0));
    assert!(alerts.is_empty());
}

#[test]
fn listen_port_repolled_does_not_realert() {
    // A poll-based source re-reports the same open listener every cycle — the
    // 2nd+ poll of the same (local_addr, local_port) is not a new finding.
    let mut state = RuleState::new();
    let first = state.on_listen_port(&listen_port_event_full(
        4242,
        "sshd-backdoor",
        [0, 0, 0, 0],
        31337,
        0,
    ));
    assert_eq!(first.len(), 1);
    let second = state.on_listen_port(&listen_port_event_full(
        4242,
        "sshd-backdoor",
        [0, 0, 0, 0],
        31337,
        10_000_000_000,
    ));
    assert!(second.is_empty());
}

#[test]
fn listen_port_two_distinct_new_ports_each_alert() {
    let mut state = RuleState::new();
    let first = state.on_listen_port(&listen_port_event_full(300, "nc", [0, 0, 0, 0], 4444, 0));
    let second = state.on_listen_port(&listen_port_event_full(
        301,
        "nc",
        [0, 0, 0, 0],
        4445,
        1_000_000_000,
    ));
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
}

#[test]
fn mass_rename_with_appended_suffix_triggers_at_threshold() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9000,
            "encryptor",
            &format!("/home/u/file{i}.docx"),
            &format!("/home/u/file{i}.docx.locked"),
            u64::from(i) * 100_000_000, // 100ms apart, well inside the 5s window
        )));
    }
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

/// The damage manifest of a ransomware detection (issue #82): what the rule state
/// remembers of the files a process renamed or deleted.
#[test]
fn touched_files_remembers_a_pids_renames_and_deletes_oldest_first() {
    let mut state = RuleState::new();
    state.on_file_rename(&file_rename_event_full(7, "enc", "/h/a", "/h/a.locked", 1));
    state.on_file_delete(&schema::FileDeleteEvent {
        meta: schema::EventMeta {
            pid: 7,
            timestamp_ns: 2,
            ..schema::fixtures::meta()
        },
        path: "/h/b".into(),
    });
    state.on_file_rename(&file_rename_event_full(8, "other", "/h/c", "/h/c.x", 3));

    let touched = state.touched_files(7, None);
    let kinds: Vec<&str> = touched
        .iter()
        .map(|e| match e {
            schema::Event::FileRename(_) => "rename",
            schema::Event::FileDelete(_) => "delete",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["rename", "delete"]);
    assert!(state.touched_files(99, None).is_empty());
}

#[test]
fn touched_files_keeps_only_the_newest_per_pid() {
    let mut state = RuleState::new();
    for i in 0..(TOUCHED_FILES_PER_PID as u64 + 25) {
        state.on_file_rename(&file_rename_event_full(
            7,
            "enc",
            &format!("/h/{i}"),
            &format!("/h/{i}.x"),
            i,
        ));
    }
    let touched = state.touched_files(7, None);
    assert_eq!(touched.len(), TOUCHED_FILES_PER_PID);
    assert_eq!(
        touched[0].meta().timestamp_ns,
        25,
        "the oldest 25 were dropped"
    );
    assert_eq!(
        touched.last().unwrap().meta().timestamp_ns,
        TOUCHED_FILES_PER_PID as u64 + 24
    );
}

#[test]
fn touched_files_bounds_the_pids_it_tracks() {
    let mut state = RuleState::new();
    let total = TOUCHED_FILES_PID_CAP as u32 + 10;
    for pid in 0..total {
        state.on_file_rename(&file_rename_event_full(
            1000 + pid,
            "enc",
            "/h/a",
            "/h/a.x",
            u64::from(pid),
        ));
    }
    // The map sheds in batches, so the exact count is its business; what matters is that
    // it never exceeds the cap and that the least recent pids go first.
    let tracked = (0..total)
        .filter(|pid| !state.touched_files(1000 + pid, None).is_empty())
        .count();
    assert!(tracked <= TOUCHED_FILES_PID_CAP, "tracked {tracked}");
    assert!(tracked > TOUCHED_FILES_PID_CAP / 2, "tracked {tracked}");
    assert!(
        state.touched_files(1000, None).is_empty(),
        "the oldest pid was shed"
    );
    assert!(
        !state.touched_files(1000 + total - 1, None).is_empty(),
        "the newest is kept"
    );
}

#[test]
fn touched_files_never_mixes_two_incarnations_of_a_recycled_pid() {
    let mut state = RuleState::new();
    let mut first = file_rename_event_full(7, "enc", "/h/old", "/h/old.x", 1);
    first.meta.process_generation = Some(1);
    let mut second = file_rename_event_full(7, "enc", "/h/new", "/h/new.x", 2);
    second.meta.process_generation = Some(2);
    state.on_file_rename(&first);
    state.on_file_rename(&second);

    let of_second = state.touched_files(7, Some(2));
    assert_eq!(of_second.len(), 1);
    assert_eq!(of_second[0].meta().process_generation, Some(2));
    assert_eq!(
        state.touched_files(7, None).len(),
        2,
        "no stamp: pid-only, as everywhere else"
    );
}

#[test]
fn mass_rename_below_threshold_does_not_alert() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD - 1 {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9001,
            "encryptor",
            &format!("/home/u/file{i}.docx"),
            &format!("/home/u/file{i}.docx.locked"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn mass_rename_does_not_realert_within_the_same_window() {
    let mut state = RuleState::new();
    let mut first_batch = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        first_batch.extend(state.on_file_rename(&file_rename_event_full(
            9002,
            "encryptor",
            &format!("/home/u/a{i}.docx"),
            &format!("/home/u/a{i}.docx.locked"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(first_batch.len(), 1);
    // One more rename immediately after, still inside the 5s window — the alert
    // already fired for this window, so no second one.
    let again = state.on_file_rename(&file_rename_event_full(
        9002,
        "encryptor",
        "/home/u/more.docx",
        "/home/u/more.docx.locked",
        RANSOMWARE_RENAME_WINDOW_NS - 1,
    ));
    assert!(again.is_empty());
}

#[test]
fn rename_without_a_preserved_prefix_is_never_counted() {
    // A normal `mv a b` — new_path bears no relation to old_path — must never
    // contribute to the ransomware counter, no matter how many happen in a burst.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9003,
            "mv",
            &format!("/home/u/src{i}.txt"),
            &format!("/home/u/dst{i}.txt"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn rename_outside_the_window_does_not_accumulate() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        // 2s apart: any 5s window holds at most 3 renames, far under threshold.
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9004,
            "encryptor",
            &format!("/home/u/b{i}.docx"),
            &format!("/home/u/b{i}.docx.locked"),
            u64::from(i) * 2_000_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn log_rotation_burst_does_not_alert() {
    // logrotate renames every log it handles within the same second, with a
    // numeric (`app.log.1`) or dateext (`app.log-20260924`) suffix — the exact
    // prefix-preserving shape, but no letter in the suffix.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        let suffix = if i % 2 == 0 { ".1" } else { "-20260924" };
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9005,
            "logrotate",
            &format!("/var/log/app{i}.log"),
            &format!("/var/log/app{i}.log{suffix}"),
            u64::from(i) * 10_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn mass_rename_with_random_hex_suffix_triggers() {
    // Families that append a per-victim id rather than a fixed word still match.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9006,
            "encryptor",
            &format!("/srv/share/r{i}.xlsx"),
            &format!("/srv/share/r{i}.xlsx.id-3fa9c1e0"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn shell_loop_rename_across_distinct_pids_triggers_via_ppid() {
    // `for f in *; do mv "$f" "$f.locked"; done`: each `mv` is its own short-lived
    // pid, so the per-pid counter never climbs — but every child shares the loop's
    // shell as ppid. The per-ppid counter catches it (issue #262 review, old-dov).
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        let mut ev = file_rename_event_full(
            20_000 + i, // a fresh mv pid each iteration
            "mv",
            &format!("/home/u/doc{i}.pdf"),
            &format!("/home/u/doc{i}.pdf.locked"),
            u64::from(i) * 100_000_000,
        );
        ev.meta.ppid = 4242; // the loop's shell
        alerts.extend(state.on_file_rename(&ev));
    }
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
    assert!(alerts[0].message.contains("ppid=4242"));
}

#[test]
fn distinct_pids_with_unknown_or_init_parent_do_not_alert_via_ppid() {
    // ppid 0 = "unknown" (a PROC_LINEAGE miss on the sensor) and ppid 1 = init are
    // shared buckets: unrelated single-rename processes must not be lumped into a
    // false shell-loop alert (#455 review, old-dov). Each rename is a distinct pid
    // (so the per-pid counter never climbs) sharing ppid 0, then ppid 1.
    for shared_ppid in [0u32, 1u32] {
        let mut state = RuleState::new();
        let mut alerts = Vec::new();
        for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
            let mut ev = file_rename_event_full(
                30_000 + i, // a distinct pid each time
                "daemon",
                &format!("/var/lib/app/x{i}.dat"),
                &format!("/var/lib/app/x{i}.dat.bak"),
                u64::from(i) * 100_000_000,
            );
            ev.meta.ppid = shared_ppid;
            alerts.extend(state.on_file_rename(&ev));
        }
        assert!(
            alerts.is_empty(),
            "ppid={shared_ppid} must not trigger a shell-loop alert"
        );
    }
}

#[test]
fn single_process_burst_yields_exactly_one_alert_not_two() {
    // Regression for the double-count seam: one encryptor pid's renames also land in
    // the shared per-ppid counter. Without the RANSOMWARE_LOOP_CHILD_MAX gate, a
    // rename after the per-pid alert would push the per-ppid counter over threshold
    // and fire a spurious second alert. Drive 2 * threshold renames from one pid and
    // assert exactly one alert total.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        let mut ev = file_rename_event_full(
            9100,
            "encryptor",
            &format!("/home/u/c{i}.docx"),
            &format!("/home/u/c{i}.docx.locked"),
            u64::from(i) * 100_000_000, // all inside one 5s window
        );
        ev.meta.ppid = 7000;
        alerts.extend(state.on_file_rename(&ev));
    }
    assert_eq!(alerts.len(), 1);
}

/// Runs the `sed -i.bak`-shaped rename burst (20+ files, one pid) through
/// `on_file_rename`, with `executable_path` set to `exe_path` on every event.
fn in_place_edit_burst(exe_path: Option<&str>) -> Vec<crate::Alert> {
    in_place_edit_burst_after_exec(None, exe_path)
}

/// Same burst, preceded by an `ExecEvent` for the pid with `exec_image`
/// (`None` = no exec seen), and `executable_path` = `exe_path` on every rename.
fn in_place_edit_burst_after_exec(
    exec_image: Option<&str>,
    exe_path: Option<&str>,
) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    if let Some(image) = exec_image {
        state.on_exec(&memfd_exec_event(9200, "sed", image, 0));
    }
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        let mut event = file_rename_event_full(
            9200,
            "sed",
            &format!("/etc/nginx/sites-enabled/s{i}.conf"),
            &format!("/etc/nginx/sites-enabled/s{i}.conf.bak"),
            u64::from(i) * 100_000_000,
        );
        event.executable_path = exe_path.map(str::to_string);
        alerts.extend(state.on_file_rename(&event));
    }
    alerts
}

#[test]
fn in_place_edit_backup_from_a_trusted_path_does_not_alert() {
    // Regression for #459 part 1: `sed -i.bak 's/old/new/' *.conf` across 20+
    // files rename(2)s each original to `f.conf.bak` from one pid — the exact
    // prefix-preserving, lettered-suffix shape check_mass_rename_pattern
    // otherwise flags. A real `/usr/bin/sed` must not alert.
    assert!(in_place_edit_burst(Some("/usr/bin/sed")).is_empty());
}

#[test]
fn in_place_edit_backup_with_a_trusted_exec_path_is_excluded_even_when_the_rename_time_path_raced()
{
    // Real `sed -i.bak` exits right after its renames, so the sensor's rename-time
    // /proc/<pid>/exe read is None (#513 review, live case C). The exec-time
    // image_path the kernel handed us is what proves it is /usr/bin/sed.
    assert!(in_place_edit_burst_after_exec(Some("/usr/bin/sed"), None).is_empty());
}

#[test]
fn in_place_edit_backup_from_an_untrusted_exec_path_alerts_even_when_the_rename_time_path_raced() {
    // #513 review, live case B: a binary under an attacker-chosen path sets
    // comm=sed, renames with a .bak suffix and exits promptly, so the rename-time
    // executable_path is None. The exec-time path is untrusted → must alert.
    let alerts = in_place_edit_burst_after_exec(Some("/root/fs513/A/sed"), None);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn in_place_edit_backup_exec_path_wins_over_a_rename_time_path() {
    // The exec-time path is authoritative: a trusted-looking rename-time value
    // must not launder an untrusted exec.
    let alerts = in_place_edit_burst_after_exec(Some("/home/attacker/sed"), Some("/usr/bin/sed"));
    assert_eq!(alerts.len(), 1);
}

#[test]
fn in_place_edit_backup_with_no_known_path_at_all_fails_closed() {
    // No exec seen for the pid (e.g. a forked child that only set comm=sed) and
    // no rename-time path: "unknown" is not evidence of /usr/bin/sed, and the
    // process controls it. Unlike the other name-keyed exclusions, this one alerts.
    let alerts = in_place_edit_burst(None);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn a_trusted_binary_that_renames_its_comm_to_sed_still_alerts() {
    // The system python3 (trusted path) calling prctl(PR_SET_NAME, "sed") passes the
    // path gate but is not a binary named sed, at exec time or via the rename-time path.
    for (exec_image, exe_path) in [
        (Some("/usr/bin/python3"), None),
        (None, Some("/usr/bin/python3")),
    ] {
        let alerts = in_place_edit_burst_after_exec(exec_image, exe_path);
        assert_eq!(alerts.len(), 1, "{exec_image:?} / {exe_path:?}");
        assert_eq!(alerts[0].technique, "T1486");
    }
}

// ── pid reuse (#519): the pid-keyed caches must not outlive their process ──────

/// A real `/usr/bin/sed` exec stamped `exec_generation`, then the `sed -i.bak`-shaped
/// burst from the same pid stamped `burst_generation`, with no rename-time path (the
/// process has already exited by the time the sensor would read it).
fn in_place_edit_burst_with_generations(
    exec_generation: Option<u64>,
    burst_generation: Option<u64>,
) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let mut exec = memfd_exec_event(9200, "sed", "/usr/bin/sed", 0);
    exec.meta.process_generation = exec_generation;
    state.on_exec(&exec);
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        let mut event = file_rename_event_full(
            9200,
            "sed",
            &format!("/etc/nginx/sites-enabled/s{i}.conf"),
            &format!("/etc/nginx/sites-enabled/s{i}.conf.bak"),
            u64::from(i) * 100_000_000,
        );
        event.executable_path = None;
        event.meta.process_generation = burst_generation;
        alerts.extend(state.on_file_rename(&event));
    }
    alerts
}

#[test]
fn a_recycled_pid_does_not_inherit_a_real_seds_exclusion() {
    // The reproduction from #519: a real `sed` exits, the kernel hands its pid to a
    // forked child that only sets `comm=sed` and renames 20+ files. Same pid, but a
    // different incarnation: the cached exec-time `/usr/bin/sed` is not its own.
    let alerts = in_place_edit_burst_with_generations(Some(1_000), Some(2_000));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn the_same_incarnation_keeps_the_in_place_edit_exclusion() {
    // The stamp must not break the legitimate case it sits next to.
    assert!(in_place_edit_burst_with_generations(Some(1_000), Some(1_000)).is_empty());
}

#[test]
fn a_missing_stamp_on_either_side_reads_as_the_same_process() {
    // Entries seeded at startup, and events from a platform with no stamp, behave as
    // they did before the stamp existed.
    assert!(in_place_edit_burst_with_generations(None, Some(2_000)).is_empty());
    assert!(in_place_edit_burst_with_generations(Some(1_000), None).is_empty());
    assert!(in_place_edit_burst_with_generations(None, None).is_empty());
}

/// An exec of `comm` at `pid` with its stamp, then a `sh` child of `pid` whose event
/// names `parent_generation` as its parent's incarnation.
fn shell_under_a_service(
    service_comm: &str,
    parent_pid: u32,
    parent_exec_generation: Option<u64>,
    parent_generation_seen_by_child: Option<u64>,
) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let mut parent = exec_event_full(parent_pid, 1, service_comm, "", 0);
    parent.meta.process_generation = parent_exec_generation;
    state.on_exec(&parent);
    let mut shell = exec_event_full(parent_pid + 1, parent_pid, "sh", "sh -c id", 1);
    shell.meta.parent_process_generation = parent_generation_seen_by_child;
    state.on_exec(&shell)
}

#[test]
fn a_shell_under_the_same_service_incarnation_still_matches() {
    // Pid far above any real `pid_max`, so the `/proc` fallback finds nothing and the
    // verdict comes from the cache alone.
    let alerts = shell_under_a_service("nginx", 4_000_000_000, Some(7), Some(7));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1059");
}

#[test]
fn a_recycled_parent_pid_is_not_credited_with_the_services_name() {
    // `nginx` exited, its pid was recycled by something else that then forked a
    // shell: the cache must not say the parent is nginx. (`/proc` has no such pid,
    // so with the stale entry rejected the parent is unknown, and nothing matches.)
    let alerts = shell_under_a_service("nginx", 4_000_000_000, Some(7), Some(8));
    assert!(alerts.is_empty(), "{alerts:?}");
}

/// The `sed -i.bak`-shaped burst for an arbitrary tool: `comm` and the exec-time image.
fn in_place_edit_burst_as(comm: &str, exec_image: &str, suffix: &str) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    state.on_exec(&memfd_exec_event(9210, comm, exec_image, 0));
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9210,
            comm,
            &format!("/home/u/docs/f{i}.docx"),
            &format!("/home/u/docs/f{i}.docx{suffix}"),
            u64::from(i) * 100_000_000,
        )));
    }
    alerts
}

#[test]
fn the_real_perl_interpreter_is_not_excluded() {
    // #528 review, live on Alpine: `/usr/bin/perl` at a trusted path, `comm=perl`,
    // renaming in bulk to `.locked`. perl runs any script, so the tool's name is no
    // evidence of what it is doing; sed's `-i` can only write a backup copy.
    let alerts = in_place_edit_burst_as("perl", "/usr/bin/perl", ".locked");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
    // The rename-to-`.bak` shape (perl older than 5.28) alerts too now: the accepted cost
    // of not trusting an interpreter. Current perl never produces it.
    assert_eq!(
        in_place_edit_burst_as("perl", "/usr/bin/perl", ".bak").len(),
        1
    );
}

#[test]
fn the_real_sed_stays_excluded_for_a_backup_suffix() {
    assert!(in_place_edit_burst_as("sed", "/usr/bin/sed", ".bak").is_empty());
}

#[test]
fn in_place_edit_backup_from_an_untrusted_path_still_alerts() {
    // The evidence gate's actual job: an encryptor can set comm="sed" for
    // free, but not make its own binary live under a trusted system prefix.
    let alerts = in_place_edit_burst(Some("/home/attacker/sed"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn maildir_flag_change_does_not_alert() {
    // Regression for #459 part 1: "mark all read" on a large Maildir folder —
    // one IMAP pid renaming every message's info marker (`:2,S` -> `:2,ST`),
    // prefix-preserving, lettered suffix. Deliberately not comm-gated (see
    // is_maildir_flag_change's doc) — an arbitrary comm here proves that.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9201,
            "imap-flags-tool",
            &format!("/home/u/Maildir/cur/171{i}.eml:2,S"),
            &format!("/home/u/Maildir/cur/171{i}.eml:2,ST"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn maildir_delivery_with_dovecot_keywords_does_not_alert() {
    // #526 review, live on Alpine: Dovecot keeps IMAP keywords as lowercase letters after
    // the standard flags (`:2,Sa`, `:2,RSab`); delivering or tagging 20+ messages must
    // not look like an encryptor, cross-directory or in place.
    for (from, to) in [
        ("new/{i}", "cur/{i}:2,Sa"),
        ("new/{i}", "cur/{i}:2,RSab"),
        ("cur/{i}:2,S", "cur/{i}:2,Sa"),
        ("cur/{i}:2,S", "cur/{i}:2,Sab"),
    ] {
        let mut state = RuleState::new();
        let mut alerts = Vec::new();
        for n in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
            let id = format!("171{n}.eml");
            alerts.extend(state.on_file_rename(&file_rename_event_full(
                9203,
                "imap",
                &format!("/home/u/Maildir/{}", from.replace("{i}", &id)),
                &format!("/home/u/Maildir/{}", to.replace("{i}", &id)),
                u64::from(n) * 100_000_000,
            )));
        }
        assert!(alerts.is_empty(), "{from} -> {to}");
    }
}

#[test]
fn a_maildir_shaped_suffix_outside_a_new_to_cur_move_still_alerts() {
    // #526 review: `:2,` plus lowercase letters is a free extension for an encryptor, so
    // the suffix alone must not exclude a rename; only a `new/` -> `cur/` move does.
    for (from, to) in [
        ("/home/u/docs/{i}.docx", "/home/u/docs/{i}.docx:2,locked"),
        ("/home/u/docs/{i}.docx", "/home/u/stash/{i}.docx:2,locked"),
        ("/home/u/Maildir/cur/{i}", "/home/u/Maildir/new/{i}:2,Sa"),
        ("/home/u/Maildir/new/{i}", "/home/u/Maildir/tmp/{i}:2,Sa"),
        ("/home/u/A/new/{i}", "/home/u/B/cur/{i}:2,Sa"),
    ] {
        let mut state = RuleState::new();
        let mut alerts = Vec::new();
        for n in 0..RANSOMWARE_RENAME_THRESHOLD {
            let id = format!("f{n}");
            alerts.extend(state.on_file_rename(&file_rename_event_full(
                9206,
                "evil",
                &from.replace("{i}", &id),
                &to.replace("{i}", &id),
                u64::from(n) * 100_000_000,
            )));
        }
        assert_eq!(alerts.len(), 1, "{from} -> {to}");
    }
}

#[test]
fn a_keyword_before_a_standard_flag_is_not_a_maildir_suffix() {
    // The order keeps the gate tight: keywords never precede a standard flag.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for n in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9204,
            "evil",
            &format!("/home/u/Maildir/new/171{n}.eml"),
            &format!("/home/u/Maildir/cur/171{n}.eml:2,aS"),
            u64::from(n) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
}

#[test]
fn a_same_directory_rename_with_mixed_separators_is_still_seen() {
    // Windows sensors can report one directory with `/` and `\` mixed (#526 review).
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for n in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9205,
            "enc.exe",
            &format!(r"C:\Users\u\Documents/f{n}.docx"),
            &format!(r"C:\Users\u\Documents\f{n}.docx.locked"),
            u64::from(n) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
}

#[test]
fn maildir_shaped_rename_with_an_invalid_flag_letter_still_alerts() {
    // The structural gate must be tight: "X" is not a Maildir flag letter, so
    // this must not be mistaken for the benign shape.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9202,
            "evil",
            &format!("/home/u/Maildir/cur/171{i}.eml:2,S"),
            &format!("/home/u/Maildir/cur/171{i}.eml:2,SX"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

// ── T1486 cross-directory moves (#512) ──

/// `RANSOMWARE_RENAME_THRESHOLD` renames from one pid, each `old_dir/f{i}<old_ext>` →
/// `new_dir/f{i}<old_ext><suffix>`, inside one window.
fn cross_dir_burst(
    comm: &str,
    old_dir: &str,
    new_dir: &str,
    old_ext: &str,
    suffix: &str,
) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9300,
            comm,
            &format!("{old_dir}/f{i}{old_ext}"),
            &format!("{new_dir}/f{i}{old_ext}{suffix}"),
            u64::from(i) * 100_000_000,
        )));
    }
    alerts
}

#[test]
fn cross_directory_move_with_an_appended_suffix_alerts() {
    // ~/docs/a.docx -> ~/.stash/a.docx.locked: the full-path prefix test can never
    // hold here, the file-name relation does.
    let alerts = cross_dir_burst(
        "encryptor",
        "/home/u/docs",
        "/home/u/.stash",
        ".docx",
        ".locked",
    );
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn cross_directory_move_between_relative_paths_alerts() {
    // Raw, unresolved paths (the sensor reports the syscall argument as given):
    // both sides are relative to the same cwd/dirfd, so the names still compare.
    let alerts = cross_dir_burst("encryptor", "docs", "stash", ".docx", ".locked");
    assert_eq!(alerts.len(), 1);
}

#[test]
fn cross_directory_move_from_a_bare_name_to_a_path_alerts() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9301,
            "encryptor",
            &format!("f{i}.docx"),
            &format!("/mnt/stash/f{i}.docx.locked"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
}

#[test]
fn cross_directory_move_with_windows_separators_alerts() {
    // Windows sensors feed this rule too: the file-name split must honour `\`.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9302,
            "encryptor",
            &format!(r"C:\Users\u\Documents\f{i}.docx"),
            &format!(r"C:\Users\u\AppData\stash\f{i}.docx.locked"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
}

#[test]
fn plain_cross_directory_move_without_a_suffix_does_not_alert() {
    // `mv *.docx /backup/`: same name, different directory, nothing appended.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9303,
            "mv",
            &format!("/home/u/docs/f{i}.docx"),
            &format!("/backup/f{i}.docx"),
            u64::from(i) * 50_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn cross_directory_move_to_a_different_name_does_not_alert() {
    // The file name is not preserved: no appended-suffix relation at all.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9304,
            "mv",
            &format!("/home/u/docs/f{i}.docx"),
            &format!("/backup/g{i}.pdf"),
            u64::from(i) * 50_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn cross_directory_log_rotation_does_not_alert() {
    // /var/log/app.log -> /var/log/archive/app.log.1: an all-digit suffix is the
    // one rotation shape a shape signal can settle, cross-directory or not.
    let alerts = cross_dir_burst("logrotate", "/var/log", "/var/log/archive", ".log", ".1");
    assert!(alerts.is_empty());
}

#[test]
fn maildir_delivery_from_new_to_cur_does_not_alert() {
    // new/<msg> -> cur/<msg>:2,S: a cross-directory rename appending exactly the
    // Maildir info marker, once per message a client opens. "Mark all read" on a
    // large folder is 20+ of them from one IMAP pid.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            9305,
            "dovecot-imapd",
            &format!("/home/u/Maildir/new/171{i}.host"),
            &format!("/home/u/Maildir/cur/171{i}.host:2,S"),
            u64::from(i) * 50_000_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn maildir_info_marker_with_an_invalid_flag_letter_still_alerts() {
    // The structural gate stays tight: "X" is not a Maildir flag letter.
    let alerts = cross_dir_burst(
        "evil",
        "/home/u/Maildir/new",
        "/home/u/Maildir/cur",
        "",
        ":2,SX",
    );
    assert_eq!(alerts.len(), 1);
}

// ── T1486 write-new-then-unlink (#512 part B) ──────────────────────────────

const O_NEW_FILE: u32 = O_WRONLY | O_CREAT;

/// One file of an encryptor-shaped pass: create `dir/f{i}.docx.locked`, then unlink
/// `dir/f{i}.docx`, both from `pid`. `unlink_first` feeds the unlink before the
/// creation, the arrival order the two independently drained ring buffers allow.
fn create_then_unlink(
    state: &mut RuleState,
    pid: u32,
    comm: &str,
    i: u32,
    unlink_first: bool,
) -> Vec<crate::Alert> {
    let ts = u64::from(i) * 100_000_000;
    let created = file_open_event_full(
        pid,
        comm,
        &format!("/home/u/docs/f{i}.docx.locked"),
        O_NEW_FILE,
        ts,
    );
    let deleted = file_delete_event_full(pid, comm, &format!("/home/u/docs/f{i}.docx"), ts + 1_000);
    let mut alerts = Vec::new();
    if unlink_first {
        alerts.extend(state.on_file_delete(&deleted));
        alerts.extend(state.on_file_open(&created));
    } else {
        alerts.extend(state.on_file_open(&created));
        alerts.extend(state.on_file_delete(&deleted));
    }
    alerts
}

fn write_new_then_unlink_burst(
    state: &mut RuleState,
    pid: u32,
    comm: &str,
    unlink_first: bool,
) -> Vec<crate::Alert> {
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(create_then_unlink(state, pid, comm, i, unlink_first));
    }
    alerts
}

#[test]
fn write_new_then_unlink_burst_alerts() {
    let mut state = RuleState::new();
    let alerts = write_new_then_unlink_burst(&mut state, 9400, "encryptor", false);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
    assert!(alerts[0].message.contains("write-new-then-unlink"));
}

#[test]
fn write_new_then_unlink_alerts_when_the_unlink_is_processed_first() {
    // The open and delete ring buffers are drained independently: the unlink can be
    // processed before the creation the kernel made first (the #503 ordering hazard).
    let mut state = RuleState::new();
    let alerts = write_new_then_unlink_burst(&mut state, 9401, "encryptor", true);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

/// A whole burst of one kind drained before the other, as the two ring buffers do live
/// (#512 part B, found on the Hyper-V lab: 30 unlinks were processed before their
/// creations, and a 16-entry history could never reach the threshold of 20).
fn batched_write_new_then_unlink(pid: u32, unlinks_first: bool) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    let n = RANSOMWARE_RENAME_THRESHOLD * 3 / 2;
    let mut alerts = Vec::new();
    let creates = |state: &mut RuleState, alerts: &mut Vec<crate::Alert>| {
        for i in 0..n {
            let ts = u64::from(i) * 100_000_000;
            let path = format!("/home/u/docs/f{i}.docx.locked");
            alerts.extend(state.on_file_open(&file_open_event_full(
                pid,
                "encryptor",
                &path,
                O_NEW_FILE,
                ts,
            )));
        }
    };
    let unlinks = |state: &mut RuleState, alerts: &mut Vec<crate::Alert>| {
        for i in 0..n {
            let ts = u64::from(i) * 100_000_000 + 1_000;
            let path = format!("/home/u/docs/f{i}.docx");
            alerts.extend(state.on_file_delete(&file_delete_event_full(
                pid,
                "encryptor",
                &path,
                ts,
            )));
        }
    };
    if unlinks_first {
        unlinks(&mut state, &mut alerts);
        creates(&mut state, &mut alerts);
    } else {
        creates(&mut state, &mut alerts);
        unlinks(&mut state, &mut alerts);
    }
    alerts
}

#[test]
fn a_batch_of_creations_then_a_batch_of_unlinks_alerts() {
    let alerts = batched_write_new_then_unlink(9410, false);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn a_batch_of_unlinks_then_a_batch_of_creations_alerts() {
    let alerts = batched_write_new_then_unlink(9411, true);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn a_long_burst_yields_exactly_one_alert() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        alerts.extend(create_then_unlink(&mut state, 9402, "encryptor", i, false));
    }
    assert_eq!(alerts.len(), 1);
}

#[test]
fn write_new_then_unlink_across_directories_alerts() {
    // create ~/.stash/f.docx.locked, unlink ~/docs/f.docx
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        let ts = u64::from(i) * 100_000_000;
        alerts.extend(state.on_file_open(&file_open_event_full(
            9403,
            "encryptor",
            &format!("/home/u/.stash/f{i}.docx.locked"),
            O_NEW_FILE,
            ts,
        )));
        alerts.extend(state.on_file_delete(&file_delete_event_full(
            9403,
            "encryptor",
            &format!("/home/u/docs/f{i}.docx"),
            ts + 1_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
}

/// Runs the burst as a compression tool would, after `exec_image` (`None` = no exec
/// seen for the pid).
fn compressor_burst(comm: &str, exec_image: Option<&str>) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    if let Some(image) = exec_image {
        state.on_exec(&memfd_exec_event(9410, comm, image, 0));
    }
    write_new_then_unlink_burst(&mut state, 9410, comm, false)
}

/// The same burst with a chosen output suffix, `.log.1` → `.log.1<suffix>`: what
/// `logrotate` with `compress` produces when it opens the output and unlinks the input
/// itself (both under `comm=logrotate`, #527 review).
fn logrotate_burst(image: Option<&str>, suffix: &str) -> Vec<crate::Alert> {
    let mut state = RuleState::new();
    if let Some(image) = image {
        state.on_exec(&memfd_exec_event(9420, "logrotate", image, 0));
    }
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        let ts = u64::from(i) * 100_000_000;
        alerts.extend(state.on_file_open(&file_open_event_full(
            9420,
            "logrotate",
            &format!("/var/log/app{i}.log.1{suffix}"),
            O_NEW_FILE,
            ts,
        )));
        alerts.extend(state.on_file_delete(&file_delete_event_full(
            9420,
            "logrotate",
            &format!("/var/log/app{i}.log.1"),
            ts + 1_000,
        )));
    }
    alerts
}

#[test]
fn logrotate_compressing_its_logs_does_not_alert() {
    for suffix in [".gz", ".xz", ".bz2", ".zst"] {
        assert!(
            logrotate_burst(Some("/usr/sbin/logrotate"), suffix).is_empty(),
            "{suffix}"
        );
    }
}

#[test]
fn logrotate_writing_a_non_compression_suffix_still_alerts() {
    // The suffix gate: a trusted logrotate does not make `.locked` benign.
    let alerts = logrotate_burst(Some("/usr/sbin/logrotate"), ".locked");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn a_logrotate_comm_from_an_untrusted_or_unknown_path_still_alerts() {
    for image in [Some("/tmp/logrotate"), Some("/usr/bin/python3"), None] {
        let alerts = logrotate_burst(image, ".gz");
        assert_eq!(alerts.len(), 1, "{image:?}");
    }
}

#[test]
fn a_real_compressor_does_not_alert() {
    // Measured live: gzip/xz/bzip2/zstd each did 30 create-X.ext-then-unlink-X in 5s.
    for (comm, image) in [
        ("gzip", "/usr/bin/gzip"),
        ("xz", "/usr/bin/xz"),
        ("bzip2", "/usr/bin/bzip2"),
        ("zstd", "/usr/bin/zstd"),
    ] {
        assert!(compressor_burst(comm, Some(image)).is_empty(), "{comm}");
    }
}

#[test]
fn a_compressor_comm_from_an_untrusted_path_still_alerts() {
    // The evidence gate's actual job: an encryptor can set comm="gzip" for free, but
    // not make its own binary live under a trusted system prefix.
    let alerts = compressor_burst("gzip", Some("/tmp/gzip"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn a_trusted_binary_that_renames_its_comm_to_a_compressor_still_alerts() {
    // A process running the system python3 can prctl(PR_SET_NAME) itself to "gzip":
    // the exec-time path is trusted, but it is not a binary *named* gzip.
    let alerts = compressor_burst("gzip", Some("/usr/bin/python3"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn a_compressor_comm_with_no_known_exec_path_fails_closed() {
    // No exec seen (a forked child that only set comm=gzip): unknown is not evidence
    // of /usr/bin/gzip, and the process controls it. Unlike most name-keyed exclusions
    // this one alerts, same reasoning as the sed/perl exclusion.
    let alerts = compressor_burst("gzip", None);
    assert_eq!(alerts.len(), 1);
}

#[test]
fn an_encryptor_that_names_its_output_dot_gz_still_alerts() {
    // A suffix allowlist would be free to copy: the exclusion is on the process, not
    // on the `.gz` shape.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        let ts = u64::from(i) * 100_000_000;
        alerts.extend(state.on_file_open(&file_open_event_full(
            9411,
            "encryptor",
            &format!("/home/u/docs/f{i}.docx.gz"),
            O_NEW_FILE,
            ts,
        )));
        alerts.extend(state.on_file_delete(&file_delete_event_full(
            9411,
            "encryptor",
            &format!("/home/u/docs/f{i}.docx"),
            ts + 1_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
}

#[test]
fn a_rotation_suffix_or_a_maildir_delivery_does_not_pair() {
    // (deleted path, created path): a rotation suffix anywhere, and a Maildir delivery,
    // which is a move from `new/` into the `cur/` beside it.
    for (dir_old, dir_new, suffix) in [
        ("/home/u", "/home/u", ".1"),
        ("/home/u", "/home/u", "-20260929"),
        ("/home/u/Maildir/new", "/home/u/Maildir/cur", ":2,S"),
        ("/home/u/Maildir/new", "/home/u/Maildir/cur", ":2,Sa"),
    ] {
        let mut state = RuleState::new();
        let mut alerts = Vec::new();
        for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
            let ts = u64::from(i) * 50_000_000;
            alerts.extend(state.on_file_open(&file_open_event_full(
                9420,
                "app",
                &format!("{dir_new}/f{i}.log{suffix}"),
                O_NEW_FILE,
                ts,
            )));
            alerts.extend(state.on_file_delete(&file_delete_event_full(
                9420,
                "app",
                &format!("{dir_old}/f{i}.log"),
                ts + 1_000,
            )));
        }
        assert!(alerts.is_empty(), "{dir_old} -> {dir_new} {suffix:?}");
    }
}

#[test]
fn a_maildir_shaped_suffix_outside_a_new_to_cur_move_still_pairs() {
    // #526 review, same hole on the create/unlink side: `:2,locked` is a free extension.
    for (dir_old, dir_new) in [
        ("/home/u/docs", "/home/u/docs"),
        ("/home/u/docs", "/home/u/stash"),
        ("/home/u/A/new", "/home/u/B/cur"),
    ] {
        let mut state = RuleState::new();
        let mut alerts = Vec::new();
        for i in 0..RANSOMWARE_RENAME_THRESHOLD {
            let ts = u64::from(i) * 50_000_000;
            alerts.extend(state.on_file_open(&file_open_event_full(
                9421,
                "evil",
                &format!("{dir_new}/f{i}.docx:2,locked"),
                O_NEW_FILE,
                ts,
            )));
            alerts.extend(state.on_file_delete(&file_delete_event_full(
                9421,
                "evil",
                &format!("{dir_old}/f{i}.docx"),
                ts + 1_000,
            )));
        }
        assert_eq!(alerts.len(), 1, "{dir_old} -> {dir_new}");
    }
}

#[test]
fn a_new_file_that_does_not_extend_the_deleted_name_does_not_pair() {
    // `cp new old-name-different && rm old`: nothing in the names relates them.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        let ts = u64::from(i) * 50_000_000;
        alerts.extend(state.on_file_open(&file_open_event_full(
            9421,
            "tool",
            &format!("/home/u/out/g{i}.dat"),
            O_NEW_FILE,
            ts,
        )));
        alerts.extend(state.on_file_delete(&file_delete_event_full(
            9421,
            "tool",
            &format!("/home/u/in/f{i}.docx"),
            ts + 1_000,
        )));
    }
    assert!(alerts.is_empty());
}

#[test]
fn a_creation_and_unlink_too_far_apart_do_not_pair() {
    let mut state = RuleState::new();
    let created = file_open_event_full(9422, "tool", "/home/u/f.docx.locked", O_NEW_FILE, 0);
    assert!(state.on_file_open(&created).is_empty());
    let late = file_delete_event_full(9422, "tool", "/home/u/f.docx", 61_000_000_000);
    assert!(state.on_file_delete(&late).is_empty());
    // ...and the unlink was parked, not counted: nothing pairs it afterwards either.
    let mut alerts = Vec::new();
    for i in 1..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(create_then_unlink(&mut state, 9422, "tool", i + 700, false));
    }
    assert!(alerts.is_empty());
}

#[test]
fn opens_that_are_not_new_files_are_not_creations() {
    // A read-only open, or a write open without O_CREAT (appending to an existing
    // file): not the "new file" half, so an unlink of the original pairs with nothing.
    for flags in [O_RDONLY, O_WRONLY] {
        let mut state = RuleState::new();
        let mut alerts = Vec::new();
        for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
            let ts = u64::from(i) * 50_000_000;
            alerts.extend(state.on_file_open(&file_open_event_full(
                9423,
                "tool",
                &format!("/home/u/f{i}.docx.locked"),
                flags,
                ts,
            )));
            alerts.extend(state.on_file_delete(&file_delete_event_full(
                9423,
                "tool",
                &format!("/home/u/f{i}.docx"),
                ts + 1_000,
            )));
        }
        assert!(alerts.is_empty(), "flags {flags:#o}");
    }
}

#[test]
fn non_unix_events_are_not_tracked() {
    // Windows/macOS producers of this shape were not measured: Unix events only.
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD * 2 {
        let ts = u64::from(i) * 50_000_000;
        let mut created = file_open_event_full(
            9424,
            "tool.exe",
            &format!(r"C:\docs\f{i}.docx.locked"),
            O_NEW_FILE,
            ts,
        );
        created.meta.user = schema::User::Windows {
            sid: "S-1-5-21-0-0-0-1000".to_string(),
            integrity_level: Some(0x2000),
        };
        let mut deleted =
            file_delete_event_full(9424, "tool.exe", &format!(r"C:\docs\f{i}.docx"), ts + 1_000);
        deleted.meta.user = created.meta.user.clone();
        alerts.extend(state.on_file_open(&created));
        alerts.extend(state.on_file_delete(&deleted));
    }
    assert!(alerts.is_empty());
}

// ── T1486 write-volume corroboration (issue #82) ───────────────────────────
// Second, independent signal alongside check_mass_rename_pattern: heavy write
// volume + a rename burst, regardless of rename shape — catches a
// write-new-then-unlink encryptor that doesn't preserve the original name as a
// prefix (check_mass_rename_pattern's shape requirement). Renames below use an
// unrelated old/new path pair so check_mass_rename_pattern's own shape check never
// fires, isolating the volume signal under test.

#[test]
fn burst_write_and_rename_fires_without_matching_rename_shape() {
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(7100, "evil", 60 * 1024 * 1024, 0));
    state.on_file_write(&file_write_event_full(
        7100,
        "evil",
        60 * 1024 * 1024,
        1_000_000_000,
    ));

    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7100,
            "evil",
            &format!("/home/u/src{i}.docx"),
            &format!("/home/u/dst{i}.docx"),
            2_000_000_000 + u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn burst_write_alone_does_not_alert_without_mass_rename() {
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(
        7101,
        "evil",
        BURST_WRITE_BYTES_THRESHOLD * 2,
        0,
    ));
    let alerts = state.on_file_rename(&file_rename_event_full(
        7101,
        "evil",
        "/home/u/one_src.docx",
        "/home/u/one_dst.docx",
        1_000_000_000,
    ));
    assert!(
        alerts.is_empty(),
        "one rename is not a burst, even with heavy write volume"
    );
}

#[test]
fn mass_rename_without_write_volume_does_not_trigger_volume_signal() {
    let mut state = RuleState::new();
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7102,
            "evil",
            &format!("/home/u/src{i}.docx"),
            &format!("/home/u/dst{i}.docx"),
            u64::from(i) * 100_000_000,
        )));
    }
    assert!(
        alerts.is_empty(),
        "a rename burst with no write volume, and no rename-shape match, must not alert"
    );
}

#[test]
fn burst_write_and_rename_excludes_tmp_path() {
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(7103, "tar", 200 * 1024 * 1024, 0));
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7103,
            "tar",
            &format!("/tmp/src{i}.docx"),
            &format!("/tmp/dst{i}.docx"),
            1_000_000_000 + u64::from(i) * 100_000_000,
        )));
    }
    assert!(
        alerts.is_empty(),
        "/tmp is excluded (compression temp files)"
    );
}

#[test]
fn burst_write_and_rename_fires_with_realistic_small_writes() {
    // Regression for #496: the old SlidingSum pushed one entry per
    // FileWriteEvent, so its 256-entry cap capped the tracked total at
    // 256 * (bytes per call) — ~16-32MB at real buffered-I/O sizes, never
    // reaching BURST_WRITE_BYTES_THRESHOLD (100MB) outside a test that (like
    // the ones above) feeds two unrealistic 60MB single writes. 1700 writes
    // of 64KB, 1ms apart, is the shape a real bulk-encrypting write loop
    // actually produces — should still cross the threshold once coalesced.
    let mut state = RuleState::new();
    let write_size: u64 = 64 * 1024;
    let write_count: u32 = 1700; // 1700 * 64KB ~= 106MB, safely over the 100MB threshold
    for i in 0..write_count {
        state.on_file_write(&file_write_event_full(
            7105,
            "evil",
            write_size,
            u64::from(i) * 1_000_000, // 1ms apart
        ));
    }
    let writes_end_ns = u64::from(write_count) * 1_000_000;
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7105,
            "evil",
            &format!("/home/u/src{i}.docx"),
            &format!("/home/u/dst{i}.docx"),
            writes_end_ns + u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(
        alerts.len(),
        1,
        "realistic small writes should still cross the byte threshold"
    );
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn burst_write_and_rename_excludes_package_manager_temp_rename() {
    // Regression for #496: a package upgrade staging heavy writes under
    // `foo.dpkg-new` then renaming each one onto `foo` cleared both of this
    // rule's gates (rename count, byte volume) with no ransomware behavior at
    // all — confirmed live (30 files, 120MB).
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(7106, "dpkg", 200 * 1024 * 1024, 0));
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7106,
            "dpkg",
            &format!("/usr/lib/libfoo{i}.so.dpkg-new"),
            &format!("/usr/lib/libfoo{i}.so"),
            1_000_000_000 + u64::from(i) * 100_000_000,
        )));
    }
    assert!(
        alerts.is_empty(),
        "package-manager stage-then-rename-over-original is not ransomware"
    );
}

#[test]
fn burst_write_and_rename_still_fires_for_the_dpkg_new_shape_under_a_non_package_manager_comm() {
    // Regression for #500 (Nikolas's review): the filename convention alone
    // used to be a free pass — an encryptor naming its own staging files
    // `<target>.dpkg-new` and renaming onto `<target>` cleared this rule
    // exactly like a real package manager would. `comm` must also actually
    // be a package manager now.
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(7107, "evil", 200 * 1024 * 1024, 0));
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7107,
            "evil",
            &format!("/home/u/doc{i}.docx.dpkg-new"),
            &format!("/home/u/doc{i}.docx"),
            1_000_000_000 + u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(
        alerts.len(),
        1,
        "the .dpkg-new naming convention alone must not suppress the alert \
         when comm isn't a real package manager"
    );
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn burst_write_and_rename_excludes_the_real_apk_staging_shape() {
    // Regression for #500 review (Jihair, real `apk fix` reinstall on
    // Alpine): apk doesn't use the `.apk-new` suffix — it stages each file as
    // a hidden `.apk.<hex>` name in the *same directory* as the final path
    // and renames that onto it. Paths are relative (renameat against a
    // directory fd), not absolute.
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(7108, "apk", 200 * 1024 * 1024, 0));
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7108,
            "apk",
            &format!("usr/bin/.apk.e9a41015f8b7e04a3f02df6f500e89f18738758051d637{i:02}"),
            &format!("usr/bin/bin{i}"),
            1_000_000_000 + u64::from(i) * 100_000_000,
        )));
    }
    assert!(
        alerts.is_empty(),
        "apk's real staging-file shape is not ransomware"
    );
}

#[test]
fn burst_write_and_rename_still_fires_for_the_apk_staging_shape_under_a_non_package_manager_comm() {
    // Same shape, arbitrary comm: the directory+prefix convention alone must
    // not be a free pass, same reasoning as the dpkg-new test above.
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(7109, "evil", 200 * 1024 * 1024, 0));
    let mut alerts = Vec::new();
    for i in 0..RANSOMWARE_RENAME_THRESHOLD {
        alerts.extend(state.on_file_rename(&file_rename_event_full(
            7109,
            "evil",
            &format!("home/u/.apk.e9a41015f8b7e04a3f02df6f500e89f18738758051d637{i:02}"),
            &format!("home/u/doc{i}"),
            1_000_000_000 + u64::from(i) * 100_000_000,
        )));
    }
    assert_eq!(
        alerts.len(),
        1,
        "the .apk.<hex> staging convention alone must not suppress the alert \
         when comm isn't a real package manager"
    );
    assert_eq!(alerts[0].technique, "T1486");
}

#[test]
fn burst_write_and_rename_does_not_realert_within_window() {
    let mut state = RuleState::new();
    state.on_file_write(&file_write_event_full(7104, "evil", 60 * 1024 * 1024, 0));
    state.on_file_write(&file_write_event_full(
        7104,
        "evil",
        60 * 1024 * 1024,
        1_000_000_000,
    ));
    let mut fired = 0;
    for i in 0..RANSOMWARE_RENAME_THRESHOLD + 10 {
        let alerts = state.on_file_rename(&file_rename_event_full(
            7104,
            "evil",
            &format!("/home/u/src{i}.docx"),
            &format!("/home/u/dst{i}.docx"),
            2_000_000_000 + u64::from(i) * 100_000_000,
        ));
        fired += alerts.len();
    }
    assert_eq!(
        fired, 1,
        "one alert per window, not one per rename past threshold"
    );
}

// ── T1620 memfd fileless exec (stateful since #497, issue #85) ─────────────
// Strings below are what the kernel actually emits (traced on Alpine 6.18.50
// against a live memfd exec, #85 review) — NOT `/memfd:<name> (deleted)`, which is
// only what `readlink /proc/<pid>/exe` shows and the sensor never reads.

fn memfd_exec_event(pid: u32, comm: &str, image_path: &str, timestamp_ns: u64) -> ExecEvent {
    let mut event = exec_event_full(pid, 1, comm, "", timestamp_ns);
    event.image_path = image_path.to_string();
    event
}

#[test]
fn memfd_exec_matches_dev_fd_path_with_memfd_comm() {
    // execveat(fd, "", AT_EMPTY_PATH): bprm->filename is /dev/fd/<n>, and the
    // kernel names the task after the memfd dentry.
    let event = memfd_exec_event(100, "memfd:payload", "/dev/fd/3", 0);
    let alerts = RuleState::new().on_exec(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1620");
}

#[test]
fn dev_fd_path_without_memfd_comm_does_not_alert() {
    // Regression (#497): the first cut treated /dev/fd/<n> alone as
    // sufficient — a real on-disk binary exec'd via
    // open()+execveat(fd,"",AT_EMPTY_PATH) produces this exact path shape
    // too, with an ordinary comm, and isn't fileless.
    let event = memfd_exec_event(100, "busybox", "/dev/fd/3", 0);
    assert!(RuleState::new().on_exec(&event).is_empty());
}

#[test]
fn proc_self_fd_exec_with_prior_memfd_create_matches() {
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_full(100, 0));
    let event = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000); // 10ms later
    let alerts = state.on_exec(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1620");
}

#[test]
fn proc_pid_fd_exec_with_prior_memfd_create_matches() {
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_full(100, 0));
    let event = memfd_exec_event(100, "4", "/proc/100/fd/3", 10_000_000);
    let alerts = state.on_exec(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1620");
}

#[test]
fn runc_style_proc_self_fd_reexec_without_memfd_create_does_not_alert() {
    // Regression (#497, live on the lab VM): runc's own CVE-2019-5736
    // self-protection re-execs "runc init" via /proc/self/fd/<n> on every
    // container start — comm truncated to the fd number, parent_comm=runc,
    // no memfd_create anywhere in the picture. `docker run --rm alpine true`
    // x3 gave 3 false T1620 alerts before this fix.
    let event = memfd_exec_event(200, "6", "/proc/self/fd/6", 0);
    assert!(RuleState::new().on_exec(&event).is_empty());
}

#[test]
fn proc_fd_exec_past_the_correlation_window_does_not_alert() {
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_full(100, 0));
    let event = memfd_exec_event(100, "4", "/proc/self/fd/3", MEMFD_EXEC_WINDOW_NS + 1);
    assert!(state.on_exec(&event).is_empty());
}

#[test]
fn proc_fd_exec_correlates_only_its_own_pid() {
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_full(999, 0)); // a different pid
    let event = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    assert!(state.on_exec(&event).is_empty());
}

#[test]
fn normal_exec_does_not_match_memfd() {
    let event = exec_event("/usr/bin/ls -la");
    assert!(RuleState::new().on_exec(&event).is_empty());
}

#[test]
fn path_with_fd_in_an_unrelated_location_does_not_false_positive() {
    // Contains "/fd/" but isn't rooted at /dev or /proc — a real user path.
    let event = memfd_exec_event(100, "notes", "/home/user/documents/fd/notes.txt", 0);
    assert!(RuleState::new().on_exec(&event).is_empty());
}

#[test]
fn proc_fd_path_with_non_numeric_pid_does_not_false_positive() {
    let event = memfd_exec_event(100, "x", "/proc/self/fd/notanumber", 0);
    assert!(RuleState::new().on_exec(&event).is_empty());
}

#[test]
fn memfd_create_arriving_after_a_pending_proc_fd_exec_alerts_retroactively() {
    // Regression (#503 review, Nikolas): the kernel always creates the memfd
    // before executing it, but userspace drains the two ring buffers
    // independently, so the exec event can be processed here first. The exec
    // must not be silently dropped just because its evidence hasn't arrived
    // yet.
    let mut state = RuleState::new();
    let exec = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    assert!(
        state.on_exec(&exec).is_empty(),
        "no corroborating evidence yet — held, not alerted, and not dropped"
    );
    let alerts = state.on_memfd_create(&memfd_create_event_full(100, 0)); // "before" the exec, kernel-time
    assert_eq!(
        alerts.len(),
        1,
        "the held exec must alert once its evidence arrives, even though \
         the exec was processed first"
    );
    assert_eq!(alerts[0].technique, "T1620");
}

#[test]
fn memfd_create_outside_the_window_does_not_retroactively_alert() {
    let mut state = RuleState::new();
    let exec = memfd_exec_event(100, "4", "/proc/self/fd/3", MEMFD_EXEC_WINDOW_NS + 1);
    assert!(state.on_exec(&exec).is_empty());
    let alerts = state.on_memfd_create(&memfd_create_event_full(100, 0));
    assert!(
        alerts.is_empty(),
        "a creation more than MEMFD_EXEC_WINDOW_NS before the held exec \
         must not retroactively alert"
    );
}

#[test]
fn pending_proc_fd_exec_is_consumed_and_does_not_double_alert() {
    let mut state = RuleState::new();
    let exec = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    assert!(state.on_exec(&exec).is_empty());
    let first = state.on_memfd_create(&memfd_create_event_full(100, 0));
    assert_eq!(first.len(), 1);
    // A second creation for the same pid must not re-match the same
    // already-consumed pending exec.
    let second = state.on_memfd_create(&memfd_create_event_full(100, 5_000_000));
    assert!(second.is_empty());
}

#[test]
fn a_memfd_created_after_the_exec_does_not_corroborate_it_via_the_retroactive_path() {
    // Regression (#503 review, Jihair, caught live on the lab VM): the kernel
    // always creates the memfd before the exec, so a memfd_create timestamped
    // *after* the held exec is a different, unrelated call — not late
    // evidence for it. `saturating_sub` alone can't distinguish "arrived
    // late but really was earlier" from "really did happen later": both
    // directions produce a small delta once one timestamp exceeds the other,
    // so the ordering itself must be checked, not just the window.
    let mut state = RuleState::new();
    let exec = memfd_exec_event(100, "3", "/proc/self/fd/3", 0);
    assert!(state.on_exec(&exec).is_empty());
    // This memfd_create is stamped 8s *after* the held exec — same shape as
    // the live false positive (an unrelated memfd_create long after an
    // on-disk /proc/self/fd re-exec, e.g. a payload using memfd for IPC).
    let alerts = state.on_memfd_create(&memfd_create_event_full(100, 8_000_000_000));
    assert!(
        alerts.is_empty(),
        "a memfd created after the held exec must not retroactively corroborate it"
    );
}

#[test]
fn a_memfd_created_after_the_exec_does_not_corroborate_it_via_the_forward_path() {
    // Same bug, other delivery order: the memfd_create is seen first (and
    // recorded), then an unrelated /proc/fd exec for the same pid arrives
    // stamped *before* that creation. The creation cannot be evidence for an
    // exec that (by wall-clock/kernel time) happened first.
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_full(100, 8_000_000_000));
    let event = memfd_exec_event(100, "3", "/proc/self/fd/3", 0);
    assert!(
        state.on_exec(&event).is_empty(),
        "a memfd created after this exec must not corroborate it"
    );
}

#[test]
fn proc_fd_alert_names_the_descriptor_that_matched() {
    // #510: the alert can now say the executed fd *is* the created memfd, and
    // names it, instead of the pid+time hedge #503 had to settle for.
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_full(100, 0));
    let event = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    let alerts = state.on_exec(&event);
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0].message.contains("file descriptor 3"),
        "the alert must name the matched descriptor: {}",
        alerts[0].message
    );
}

#[test]
fn proc_fd_exec_through_a_different_fd_than_the_memfd_does_not_alert() {
    // #510, the gap #503 left open: the process created a memfd (fd 5) for its own
    // reasons and then exec'd an ordinary on-disk binary through an unrelated
    // descriptor (fd 3) inside the window. Pid+time matched; the fd does not.
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_with_fd(100, 0, 5));
    let event = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    assert!(state.on_exec(&event).is_empty());
}

#[test]
fn proc_fd_exec_matches_any_of_the_processs_recent_memfds() {
    // A process can hold several memfds; the exec names one of them, not
    // necessarily the latest.
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_with_fd(100, 0, 3));
    state.on_memfd_create(&memfd_create_event_with_fd(100, 1_000_000, 4));
    let event = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    let alerts = state.on_exec(&event);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].technique, "T1620");
}

#[test]
fn proc_fd_exec_through_another_pids_descriptor_does_not_corroborate() {
    // /proc/<other>/fd/3 is a descriptor in a different process's table: this pid's
    // own memfd 3 says nothing about it.
    let mut state = RuleState::new();
    state.on_memfd_create(&memfd_create_event_full(100, 0));
    let event = memfd_exec_event(100, "4", "/proc/999/fd/3", 10_000_000);
    assert!(state.on_exec(&event).is_empty());
}

#[test]
fn memfds_beyond_the_per_pid_cap_forget_the_oldest() {
    // Bounded per-pid history: the 9th creation pushes the 1st (fd 3) out, so an
    // exec through fd 3 no longer corroborates. Newer ones still do.
    let mut state = RuleState::new();
    for (i, fd) in (3..12).enumerate() {
        state.on_memfd_create(&memfd_create_event_with_fd(100, i as u64, fd));
    }
    let evicted = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    assert!(state.on_exec(&evicted).is_empty());
    let kept = memfd_exec_event(100, "4", "/proc/self/fd/11", 10_000_000);
    assert_eq!(state.on_exec(&kept).len(), 1);
}

#[test]
fn late_memfd_create_with_a_different_fd_does_not_retroactively_alert() {
    // Same #510 rule on the other delivery order (the exec is processed first and
    // held): a creation that arrives afterwards must carry the same fd.
    let mut state = RuleState::new();
    let exec = memfd_exec_event(100, "4", "/proc/self/fd/3", 10_000_000);
    assert!(state.on_exec(&exec).is_empty());
    let alerts = state.on_memfd_create(&memfd_create_event_with_fd(100, 0, 5));
    assert!(alerts.is_empty());
    // ...and the matching one still fires afterwards: the pending exec was kept.
    let alerts = state.on_memfd_create(&memfd_create_event_with_fd(100, 1_000_000, 3));
    assert_eq!(alerts.len(), 1);
}

// ── T1071 unusual outbound from a web/DB service (issue #478) ──────────────

#[test]
fn nginx_unusual_outbound_port_matches() {
    let event = connect_event_full(300, "nginx", [93, 184, 216, 34], 4444, 0);
    let alert = check_service_unusual_outbound(&event).unwrap();
    assert_eq!(alert.technique, "T1071");
}

#[test]
fn mysqld_any_outbound_to_unusual_port_matches() {
    // mysqld almost never has a legitimate reason to connect out at all.
    let event = connect_event_full(301, "mysqld", [93, 184, 216, 34], 1337, 0);
    assert!(check_service_unusual_outbound(&event).is_some());
}

#[test]
fn php_fpm_versioned_unusual_outbound_matches() {
    let event = connect_event_full(302, "php-fpm7.4", [93, 184, 216, 34], 4444, 0);
    assert!(check_service_unusual_outbound(&event).is_some());
}

#[test]
fn nginx_outbound_to_https_does_not_alert() {
    // A web app calling out to an HTTPS API/update endpoint — routine.
    let event = connect_event_full(300, "nginx", [93, 184, 216, 34], 443, 0);
    assert!(check_service_unusual_outbound(&event).is_none());
}

#[test]
fn php_fpm_outbound_to_redis_port_does_not_alert() {
    // Common multi-tier shape: php-fpm dialing a backend cache/DB on a
    // "non-standard" port that is nonetheless completely routine.
    let event = connect_event_full(302, "php-fpm7.4", [10, 0, 0, 5], 6379, 0);
    assert!(check_service_unusual_outbound(&event).is_none());
}

#[test]
fn nginx_outbound_to_loopback_unusual_port_does_not_alert() {
    // Same-host backend (a local API, Postgres, ...) — the overwhelming
    // majority of "unusual port" traffic from these processes in practice,
    // and never the real exfil/C2 path (loopback can't leave the host).
    let event = connect_event_full(300, "nginx", [127, 0, 0, 1], 9999, 0);
    assert!(check_service_unusual_outbound(&event).is_none());
}

#[test]
fn postgres_startup_connect_to_unspecified_address_does_not_alert() {
    // postgres's startup connect() to 0.0.0.0:65535 and :::65535 fired T1071 on a
    // bare container start (#498 review, live). Unspecified means "this host" on
    // Linux, same as loopback — not a destination that leaves the box.
    let v4 = connect_event_full(304, "postgres", [0, 0, 0, 0], 65535, 0);
    assert!(check_service_unusual_outbound(&v4).is_none());
    let mut v6 = connect_event_full(304, "postgres", [0, 0, 0, 0], 65535, 0);
    v6.daddr = std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
    assert!(check_service_unusual_outbound(&v6).is_none());
}

#[test]
fn unrelated_process_unusual_outbound_does_not_match_service_rule() {
    let event = connect_event_full(303, "curl", [93, 184, 216, 34], 4444, 0);
    assert!(check_service_unusual_outbound(&event).is_none());
}
