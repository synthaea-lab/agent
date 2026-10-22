//! CREDENTIAL-READ (#377): T1003.008 for the shadow files, T1552.004 / T1552.001 for the
//! credential files of a home directory.

use super::*;

const SECOND_NS: u64 = 1_000_000_000;

/// A state in which `pid` was exec'd from `image` as `comm`, child of `ppid`.
fn state_with(execs: &[(u32, u32, &str, &str)]) -> RuleState {
    let mut state = RuleState::new();
    for &(pid, ppid, comm, image) in execs {
        let event = ExecEvent {
            image_path: image.to_string(),
            ..exec_event_full(pid, ppid, comm, "", 0)
        };
        state.on_exec(&event);
    }
    state
}

fn open(
    state: &mut RuleState,
    pid: u32,
    ppid: u32,
    comm: &str,
    path: &str,
    flags: u32,
    at_s: u64,
) -> Vec<crate::Alert> {
    let mut event = file_open_event_full(pid, comm, path, flags, at_s * SECOND_NS);
    event.meta.ppid = ppid;
    state.on_file_open(&event)
}

fn read(state: &mut RuleState, pid: u32, comm: &str, path: &str) -> Vec<crate::Alert> {
    open(state, pid, 1, comm, path, O_RDONLY, 0)
}

fn techniques(alerts: &[crate::Alert]) -> Vec<&'static str> {
    alerts.iter().map(|a| a.technique).collect()
}

// ── T1003.008: the shadow files ────────────────────────────────────────────

#[test]
fn cat_reading_etc_shadow_alerts() {
    let mut state = state_with(&[(200, 1, "cat", "/usr/bin/cat")]);
    let alerts = read(&mut state, 200, "cat", "/etc/shadow");
    assert_eq!(techniques(&alerts), ["T1003.008"]);
    assert!(alerts[0].message.contains("/etc/shadow"));
}

#[test]
fn a_shadow_alias_alerts_as_the_shadow_path_does() {
    for path in [
        "/etc/gshadow",
        "/etc/shadow-",
        "/etc//shadow",
        "/etc/./shadow",
        "/proc/1/root/etc/shadow",
    ] {
        let mut state = state_with(&[(200, 1, "cat", "/usr/bin/cat")]);
        assert_eq!(
            techniques(&read(&mut state, 200, "cat", path)),
            ["T1003.008"],
            "{path}"
        );
    }
}

#[test]
fn the_authentication_stack_reading_etc_shadow_does_not_alert() {
    for (comm, image) in [
        ("sshd", "/usr/sbin/sshd"),
        ("sshd-session", "/usr/libexec/openssh/sshd-session"),
        ("sudo", "/usr/bin/sudo"),
        ("su", "/usr/bin/su"),
        ("login", "/usr/bin/login"),
        ("passwd", "/usr/bin/passwd"),
        ("useradd", "/usr/sbin/useradd"),
        ("unix_chkpwd", "/usr/sbin/unix_chkpwd"),
        ("crond", "/usr/sbin/crond"),
        // The kernel keeps 15 bytes of the name.
        ("polkit-agent-he", "/usr/lib/polkit-1/polkit-agent-helper-1"),
        // systemd's PAM-session child keeps the `systemd` image under another name.
        ("(sd-pam)", "/usr/lib/systemd/systemd"),
    ] {
        let mut state = state_with(&[(200, 1, comm, image)]);
        assert!(
            read(&mut state, 200, comm, "/etc/shadow").is_empty(),
            "{comm}"
        );
    }
}

#[test]
fn a_forked_child_of_the_authentication_stack_does_not_alert() {
    // An older `sshd` forks its privilege-separated child without an exec: the child is in no
    // exec table of its own, its parent is.
    let mut state = state_with(&[(100, 1, "sshd", "/usr/sbin/sshd")]);
    assert!(open(&mut state, 300, 100, "sshd", "/etc/shadow", O_RDONLY, 0).is_empty());
}

#[test]
fn an_sshd_copied_outside_the_system_directories_alerts() {
    // The name-keyed exclusion is gated on the image (CLAUDE.md): a rename in /tmp inherits
    // nothing.
    let mut state = state_with(&[(200, 1, "sshd", "/tmp/sshd")]);
    assert_eq!(
        techniques(&read(&mut state, 200, "sshd", "/etc/shadow")),
        ["T1003.008"]
    );
}

#[test]
fn an_interpreter_that_renamed_itself_after_the_stack_alerts() {
    // `prctl(PR_SET_NAME, "sshd")` changes `comm`, not the image the kernel recorded at exec.
    let mut state = state_with(&[(200, 1, "python3", "/usr/bin/python3")]);
    assert_eq!(
        techniques(&read(&mut state, 200, "sshd", "/etc/shadow")),
        ["T1003.008"]
    );
}

#[test]
fn a_process_with_no_known_image_is_excluded_by_name_only() {
    // A sensor gap is not evidence of masquerade: the stack's names still count...
    let mut state = RuleState::new();
    assert!(read(&mut state, 200, "sshd", "/etc/shadow").is_empty());
    // ...and any other name still alerts.
    assert_eq!(
        techniques(&read(&mut state, 201, "cat", "/etc/shadow")),
        ["T1003.008"]
    );
}

#[test]
fn a_write_only_open_of_etc_shadow_is_not_a_read() {
    let mut state = state_with(&[(200, 1, "vim", "/usr/bin/vim")]);
    assert!(open(&mut state, 200, 1, "vim", "/etc/shadow", O_WRONLY, 0).is_empty());
    assert_eq!(
        techniques(&open(&mut state, 200, 1, "vim", "/etc/shadow", 0o2, 1)),
        ["T1003.008"]
    );
}

#[test]
fn paths_that_are_not_the_shadow_files_do_not_alert() {
    let mut state = state_with(&[(200, 1, "cat", "/usr/bin/cat")]);
    for path in [
        "/etc/passwd",
        "/etc/shadow.bak",
        "/etc/shadowfoo",
        "shadow",
        "/tmp/shadow",
    ] {
        assert!(read(&mut state, 200, "cat", path).is_empty(), "{path}");
    }
}

#[test]
fn repeated_reads_of_the_shadow_file_alert_once_per_window() {
    let mut state = state_with(&[(200, 1, "cat", "/usr/bin/cat")]);
    assert_eq!(
        open(&mut state, 200, 1, "cat", "/etc/shadow", O_RDONLY, 0).len(),
        1
    );
    assert!(open(&mut state, 200, 1, "cat", "/etc/shadow", O_RDONLY, 10).is_empty());
    assert!(open(&mut state, 200, 1, "cat", "/etc/gshadow", O_RDONLY, 20).is_empty());
    // Past the window the same pid alerts again.
    assert_eq!(
        open(&mut state, 200, 1, "cat", "/etc/shadow", O_RDONLY, 400).len(),
        1
    );
}

#[test]
fn two_pids_reading_the_shadow_file_alert_separately() {
    let mut state = state_with(&[
        (200, 1, "cat", "/usr/bin/cat"),
        (201, 1, "grep", "/usr/bin/grep"),
    ]);
    assert_eq!(read(&mut state, 200, "cat", "/etc/shadow").len(), 1);
    assert_eq!(read(&mut state, 201, "grep", "/etc/shadow").len(), 1);
}

// ── T1552: credentials in a home directory ─────────────────────────────────

#[test]
fn a_web_service_reading_a_private_key_alerts() {
    let mut state = state_with(&[(200, 1, "nginx", "/usr/sbin/nginx")]);
    let alerts = read(&mut state, 200, "nginx", "/home/alice/.ssh/id_rsa");
    assert_eq!(techniques(&alerts), ["T1552.004"]);
}

#[test]
fn a_php_fpm_worker_reading_a_credentials_file_alerts() {
    let mut state = state_with(&[(200, 1, "php-fpm8.1", "/usr/sbin/php-fpm8.1")]);
    let alerts = read(
        &mut state,
        200,
        "php-fpm8.1",
        "/home/alice/.aws/credentials",
    );
    assert_eq!(techniques(&alerts), ["T1552.001"]);
}

#[test]
fn a_database_worker_thread_is_recognised_by_its_process_name() {
    // The event's `comm` is the thread's (`one_connection`), the exec table's the process's.
    let mut state = state_with(&[(200, 1, "mysqld", "/usr/sbin/mysqld")]);
    let alerts = read(&mut state, 200, "one_connection", "/root/.ssh/id_ed25519");
    assert_eq!(techniques(&alerts), ["T1552.004"]);
}

#[test]
fn a_child_of_a_web_service_reading_a_credentials_file_alerts() {
    // `cat` is a system binary, so only its parent gives it away.
    let mut state = state_with(&[
        (100, 1, "nginx", "/usr/sbin/nginx"),
        (200, 100, "cat", "/usr/bin/cat"),
    ]);
    let alerts = open(
        &mut state,
        200,
        100,
        "cat",
        "/home/alice/.git-credentials",
        O_RDONLY,
        0,
    );
    assert_eq!(techniques(&alerts), ["T1552.001"]);
}

#[test]
fn a_binary_run_from_tmp_reading_a_credentials_file_alerts() {
    let mut state = state_with(&[(200, 1, "x", "/tmp/x")]);
    assert_eq!(
        techniques(&read(&mut state, 200, "x", "/home/alice/.aws/credentials")),
        ["T1552.001"]
    );
    assert_eq!(
        techniques(&read(&mut state, 200, "x", "/home/alice/.ssh/id_rsa")),
        ["T1552.004"]
    );
}

#[test]
fn the_tools_that_own_the_credentials_do_not_alert() {
    // Each runs from the system directories, as the package installed it.
    for (comm, image, path) in [
        (
            "aws",
            "/usr/local/aws-cli/v2/current/bin/aws",
            "/home/alice/.aws/credentials",
        ),
        (
            "python3",
            "/usr/bin/python3",
            "/home/alice/.aws/credentials",
        ),
        ("ssh", "/usr/bin/ssh", "/home/alice/.ssh/id_ed25519"),
        ("ssh-add", "/usr/bin/ssh-add", "/home/alice/.ssh/id_rsa"),
        ("kubectl", "/usr/bin/kubectl", "/home/alice/.kube/config"),
        (
            "git-credential",
            "/usr/libexec/git-core/git-credential-store",
            "/home/alice/.git-credentials",
        ),
    ] {
        let mut state = state_with(&[(200, 1, comm, image)]);
        assert!(read(&mut state, 200, comm, path).is_empty(), "{comm}");
    }
}

#[test]
fn a_reader_with_no_known_image_and_no_service_parent_does_not_alert() {
    // No evidence either way, so no alert: the rule never alerts on a sensor gap.
    let mut state = RuleState::new();
    assert!(read(&mut state, 200, "x", "/home/alice/.ssh/id_rsa").is_empty());
}

#[test]
fn the_public_half_and_the_neighbours_of_a_credential_file_do_not_alert() {
    let mut state = state_with(&[(200, 1, "nginx", "/usr/sbin/nginx")]);
    for path in [
        "/home/alice/.ssh/id_rsa.pub",
        "/home/alice/.ssh/known_hosts",
        "/home/alice/.aws/config",
        "/var/www/html/index.php",
    ] {
        assert!(read(&mut state, 200, "nginx", path).is_empty(), "{path}");
    }
}

#[test]
fn writing_a_credential_file_is_not_reading_it() {
    let mut state = state_with(&[(200, 1, "x", "/tmp/x")]);
    assert!(
        open(
            &mut state,
            200,
            1,
            "x",
            "/home/alice/.ssh/id_rsa",
            O_WRONLY | O_CREAT,
            0
        )
        .is_empty()
    );
}

#[test]
fn the_kind_of_credential_file_is_alerted_separately_for_one_pid() {
    let mut state = state_with(&[(200, 1, "x", "/tmp/x")]);
    assert_eq!(
        read(&mut state, 200, "x", "/home/alice/.ssh/id_rsa").len(),
        1
    );
    assert_eq!(
        read(&mut state, 200, "x", "/home/alice/.aws/credentials").len(),
        1
    );
    assert!(read(&mut state, 200, "x", "/home/alice/.ssh/id_ed25519").is_empty());
}

#[test]
fn a_macos_home_credential_file_is_classified_too() {
    let mut state = state_with(&[(200, 1, "x", "/private/tmp/x")]);
    assert_eq!(
        techniques(&read(&mut state, 200, "x", "/Users/bob/.aws/credentials")),
        ["T1552.001"]
    );
}

// ── macOS: keychains and browser stores (T1555) ─────────────────────────────

#[test]
fn a_binary_outside_the_system_directories_reading_a_keychain_alerts() {
    // One state each: a pid alerts once per kind of file per window.
    for path in [
        "/Users/bob/Library/Keychains/login.keychain-db",
        "/Library/Keychains/System.keychain",
    ] {
        let mut state = state_with(&[(200, 1, "dump", "/private/tmp/dump")]);
        assert_eq!(
            techniques(&read(&mut state, 200, "dump", path)),
            ["T1555.001"],
            "{path}"
        );
    }
}

#[test]
fn the_apple_daemon_reading_a_keychain_does_not_alert() {
    let mut state = state_with(&[(200, 1, "securityd", "/usr/libexec/securityd")]);
    let path = "/Users/bob/Library/Keychains/login.keychain-db";
    assert!(read(&mut state, 200, "securityd", path).is_empty());
}

#[test]
fn a_binary_outside_the_system_directories_reading_a_browser_store_alerts() {
    for path in [
        "/Users/bob/Library/Application Support/Google/Chrome/Default/Login Data",
        "/Users/bob/Library/Application Support/Firefox/Profiles/ab12.default/key4.db",
    ] {
        let mut state = state_with(&[(200, 1, "stealer", "/Users/bob/Downloads/stealer")]);
        assert_eq!(
            techniques(&read(&mut state, 200, "stealer", path)),
            ["T1555.003"],
            "{path}"
        );
    }
}

#[test]
fn the_browser_reading_its_own_store_from_applications_does_not_alert() {
    let mut state = state_with(&[(
        200,
        1,
        "Google Chrome",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    )]);
    let path = "/Users/bob/Library/Application Support/Google/Chrome/Default/Login Data";
    assert!(read(&mut state, 200, "Google Chrome", path).is_empty());
}

#[test]
fn a_browser_history_or_bookmarks_read_does_not_alert() {
    let mut state = state_with(&[(200, 1, "tool", "/private/tmp/tool")]);
    for path in [
        "/Users/bob/Library/Application Support/Google/Chrome/Default/History",
        "/Users/bob/Library/Application Support/Google/Chrome/Default/Bookmarks",
        "/Users/bob/Library/Keychains/login.keychain-db.bak",
    ] {
        assert!(read(&mut state, 200, "tool", path).is_empty(), "{path}");
    }
}

#[test]
fn opening_a_keychain_write_only_is_not_a_read() {
    let mut state = state_with(&[(200, 1, "dump", "/private/tmp/dump")]);
    let path = "/Users/bob/Library/Keychains/login.keychain-db";
    assert!(open(&mut state, 200, 1, "dump", path, O_WRONLY, 0).is_empty());
}

// ── bounded state ──────────────────────────────────────────────────────────

#[test]
fn the_alert_history_is_bounded_and_an_evicted_pid_alerts_again() {
    let mut state = RuleState::new();
    for pid in 0..=(COUNTER_CAP as u32) {
        let mut e = file_open_event_full(10_000 + pid, "cat", "/etc/shadow", O_RDONLY, 0);
        e.meta.ppid = 1;
        // No known image, comm outside the stack: every pid alerts once.
        assert_eq!(state.on_file_open(&e).len(), 1);
    }
    // The oldest entries were shed, never the whole history: the newest pid stays quiet,
    // the first alerts again.
    let mut newest = file_open_event_full(
        10_000 + COUNTER_CAP as u32,
        "cat",
        "/etc/shadow",
        O_RDONLY,
        SECOND_NS,
    );
    newest.meta.ppid = 1;
    assert!(state.on_file_open(&newest).is_empty());
    let mut oldest = file_open_event_full(10_000, "cat", "/etc/shadow", O_RDONLY, SECOND_NS);
    oldest.meta.ppid = 1;
    assert_eq!(state.on_file_open(&oldest).len(), 1);
}
