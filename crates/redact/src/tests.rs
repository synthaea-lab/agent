use proptest::prelude::*;

use super::*;

#[test]
fn redacts_supported_command_line_shapes_and_keeps_near_misses() {
    for (image, input, expected) in [
        (
            "curl.exe",
            "curl https://u:p@example.com/a?id=1&token=abc",
            "curl https://REDACTED@example.com/a?id=1&token=REDACTED",
        ),
        (
            "curl",
            "curl -u user:pass https://h",
            "curl -u REDACTED https://h",
        ),
        ("curl", "curl -u admin https://h", "curl -u admin https://h"),
        (
            "wget",
            "wget --user='u:p' https://h",
            "wget --user='REDACTED' https://h",
        ),
        (
            "curl",
            "curl --user u:secret https://h",
            "curl --user REDACTED https://h",
        ),
        (
            "mysql",
            "mysql --password=\"two words\"",
            "mysql --password=\"REDACTED\"",
        ),
        (
            "mysql",
            "mysql --password hunter2",
            "mysql --password hunter2",
        ),
        ("tool", "tool --passwd=x", "tool --passwd=REDACTED"),
        ("tool", "tool --pass x", "tool --pass REDACTED"),
        ("tool", "tool --token=x", "tool --token=REDACTED"),
        ("tool", "tool --secret x", "tool --secret REDACTED"),
        ("tool", "tool --api-key=x", "tool --api-key=REDACTED"),
        ("tool", "tool --password-file=/x", "tool --password-file=/x"),
        (
            "tool",
            r"tool --password=one\ two",
            "tool --password=REDACTED",
        ),
        ("mysql", "mysql -pS3cret", "mysql -pREDACTED"),
        (
            "mysql",
            "mysql -p 'S3cret value'",
            "mysql -p 'S3cret value'",
        ),
        ("mysql", "mysql -p prod_db", "mysql -p prod_db"),
        ("mariadb", "mariadb -p prod_db", "mariadb -p prod_db"),
        (
            "mysql",
            "mysql --password prod_db",
            "mysql --password prod_db",
        ),
        (
            "mariadb",
            "mariadb --password prod_db",
            "mariadb --password prod_db",
        ),
        (
            "mysqldump",
            "mysqldump -p --all-databases",
            "mysqldump -p --all-databases",
        ),
        ("psexec", "psexec -p S3cret", "psexec -p REDACTED"),
        (
            "sshpass",
            "sshpass -p S3cret ssh host",
            "sshpass -p REDACTED ssh host",
        ),
        (
            "psexec.exe",
            "psexec C:\\Program Files\\x\\ -p S3cret",
            "psexec C:\\Program Files\\x\\ -p REDACTED",
        ),
        (
            "psexec.exe",
            r#"psexec "C:\Program Files\x" -p S3cret"#,
            r#"psexec "C:\Program Files\x" -p REDACTED"#,
        ),
        (
            "psexec",
            r#"psexec 'C:\Program Files\x' -p S3cret"#,
            r#"psexec 'C:\Program Files\x' -p REDACTED"#,
        ),
        (
            "net.exe",
            r"net use \\fs\share\ S3cret /user:corp\adm",
            r"net use \\fs\share\ REDACTED /user:corp\adm",
        ),
        ("ssh", "ssh -p 2222 host", "ssh -p 2222 host"),
        ("mkdir", "mkdir -p x", "mkdir -p x"),
        ("cp", "cp -p a b", "cp -p a b"),
        ("tar", "tar -cpf archive file", "tar -cpf archive file"),
        ("grep", "grep -p pattern file", "grep -p pattern file"),
        ("scp", "scp -P 22 file host:", "scp -P 22 file host:"),
        ("sqlcmd", "sqlcmd -P 'Secret'", "sqlcmd -P 'REDACTED'"),
        (
            "schtasks.exe",
            "schtasks /p:secret /rp next",
            "schtasks /p:REDACTED /rp REDACTED",
        ),
        ("cmd", "cmd /p secret", "cmd /p secret"),
        ("cmd", "cmd /passive", "cmd /passive"),
        (
            "curl",
            "curl -H \"X-Api-Key: secret\"",
            "curl -H \"X-Api-Key: REDACTED\"",
        ),
        (
            "curl",
            "curl -H \"X-Trace: keep\"",
            "curl -H \"X-Trace: keep\"",
        ),
        (
            "curl",
            "curl -H \"Authorization: Bearer abc\"",
            "curl -H \"Authorization: Bearer REDACTED\"",
        ),
        (
            "tool",
            "Authorization: Basic dXNlcjpwYXNz",
            "Authorization: Basic REDACTED",
        ),
        ("tool", "Authorization: Basic", "Authorization: Basic"),
        (
            "tool",
            "Authorization: secret-value",
            "Authorization: REDACTED",
        ),
        (
            "curl",
            "curl -H Authorization:\u{3000}Bearer abc",
            "curl -H Authorization:\u{3000}Bearer REDACTED",
        ),
        (
            "tool",
            "Authorization: Unknown scheme-secret",
            "Authorization: Unknown REDACTED",
        ),
        (
            "tool",
            "echo the bearer of bad news",
            "echo the bearer of bad news",
        ),
        (
            "tool",
            "Authorization: Bearer token-value",
            "Authorization: Bearer REDACTED",
        ),
        (
            "net.exe",
            "net use \\\\host\\share hunter2",
            "net use \\\\host\\share REDACTED",
        ),
        ("net.exe", "net user bob hunter2", "net user bob REDACTED"),
        ("net.exe", "net user bob *", "net user bob *"),
        ("net.exe", "net user bob /delete", "net user bob /delete"),
    ] {
        assert_eq!(redact_command_line(image, input), expected, "{input}");
    }
}

#[test]
fn argv_redaction_preserves_argument_count_and_matches_flat_line() {
    let mut mysql = vec!["mysql".into(), "-p".into(), "prod_db".into()];
    redact_argv("/usr/bin/mysql", &mut mysql);
    assert_eq!(mysql, ["mysql", "-p", "prod_db"]);
    assert_eq!(mysql.len(), 3);
    let mut psexec = vec!["psexec".into(), "-p".into(), "hunter2".into()];
    redact_argv("psexec.exe", &mut psexec);
    assert_eq!(psexec, ["psexec", "-p", "REDACTED"]);
    let mut attached = vec!["mysql".into(), "-pS3cret".into()];
    redact_argv("mysql", &mut attached);
    assert_eq!(attached, ["mysql", "-pREDACTED"]);
}

#[test]
fn argv_wrappers_skip_options_and_redact_the_wrapped_command() {
    for (image, argv) in [
        (
            "sudo",
            vec!["sudo", "-u", "alice", "curl", "-u", "a:S3cret", "h"],
        ),
        ("doas", vec!["doas", "curl", "-u", "a:S3cret", "h"]),
        ("nohup", vec!["nohup", "curl", "-u", "a:S3cret", "h"]),
        (
            "env",
            vec![
                "env",
                "-u",
                "OLD_TOKEN",
                "TOKEN=abc",
                "curl",
                "-u",
                "a:S3cret",
                "h",
            ],
        ),
        (
            "timeout",
            vec![
                "timeout", "-s", "TERM", "-k", "2", "5", "curl", "-u", "a:S3cret", "h",
            ],
        ),
        (
            "nice",
            vec!["nice", "-n", "3", "curl", "-u", "a:S3cret", "h"],
        ),
        ("cmd.exe", vec!["cmd.exe", "/c", "curl -u a:S3cret h"]),
        ("bash", vec!["bash", "-c", "curl -u a:S3cret h"]),
        ("pwsh", vec!["pwsh", "-Command", "curl -u a:S3cret h"]),
    ] {
        let arg_count = argv.len();
        let mut argv = argv.into_iter().map(str::to_owned).collect::<Vec<_>>();
        redact_argv(image, &mut argv);
        assert_eq!(argv.len(), arg_count, "{image}: {argv:?}");
        assert!(
            argv.iter().all(|arg| !arg.contains("S3cret")),
            "{image}: {argv:?}"
        );
    }

    let mut negative = vec!["sudo", "-u", "alice", "ls"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    redact_argv("sudo", &mut negative);
    assert_eq!(negative, ["sudo", "-u", "alice", "ls"]);
}

#[test]
fn combined_flags_wrappers_tool_passwords_headers_and_form_data_are_redacted() {
    for line in [
        "curl -su admin:S3cret h",
        "curl -Lu admin:S3cret h",
        "curl -sLu admin:S3cret h",
        "curl -sLuadmin:S3cret h",
        "sudo curl -u a:S3cret h",
        "sudo -u alice curl -u a:S3cret h",
        "doas curl -u a:S3cret h",
        "nohup curl -u a:S3cret h",
        "env TOKEN=abc mysql -pS3cret",
        "env -u OLD_TOKEN TOKEN=abc curl -u a:S3cret h",
        "timeout 5 mysql -pS3cret",
        "timeout -s TERM -k 2 5 curl -u a:S3cret h",
        "nice -n 3 mysql -pS3cret",
        "cmd /c \"net user bob S3cret /add\"",
        "cmd.exe /k \"net1 user bob S3cret /add\"",
        "cmd.exe /c net user bob S3cret /add",
        "cmd /c \"net user bob S3cret /add\" && echo done",
        "sh -c \"curl -u a:S3cret h\"",
        "bash -c \"curl -u a:S3cret h\"",
        "zsh -c \"curl -u a:S3cret h\"",
        "dash -c \"curl -u a:S3cret h\"",
        "sh -c curl -u a:S3cret h",
        "sh -c \"curl -u a:S3cret h\" && echo done",
        "powershell -Command \"curl -u a:S3cret h\"",
        "pwsh -Command \"curl -u a:S3cret h\"",
        "net1 user bob S3cret /add",
        "net1 use \\\\h\\c$ S3cret /user:a",
        "net use \\\\h\\c$ /user:a S3cret",
        "net use \\\\h\\c$ S3cret /user:a",
        "curl --access-token=abc --client-secret=x --passphrase=pp --api_key=kk --apikey=aa --auth-token=at --secret-key=sk h",
        "curl -H\"Authorization: Bearer abc\" h",
        "curl -H'Cookie: sid=abc' h",
        "curl --header='X-Auth-Token: abc' h",
        "curl -H 'Private-Token: abc' h",
        "mysqladmin -pS3cret",
        "mysqlimport -pS3cret",
        "docker login -pS3cret",
        "docker login -p S3cret",
        "docker login --password S3cret",
        "redis-cli -a S3cret",
        "ldapsearch -wS3cret",
        "ldapmodify -w S3cret",
        "ldapadd -w S3cret",
        "smbclient -U user%S3cret",
        "7z a -pS3cret archive",
        "zip -P S3cret archive file",
        "cmdkey /pass:S3cret",
        "openssl enc -pass pass:S3cret",
        "curl --proxy-user a:S3cret h",
        "curl -U a:S3cret h",
        "wget --http-password=S3cret h",
        "wget --ftp-password=S3cret h",
        "wget --password=S3cret h",
        "curl -d 'username=bob&password=S3cret&token=abc' h",
        "curl --data='username=bob&password=S3cret' h",
        "curl --data-urlencode 'password=S3cret' h",
        "curl -dpassword=S3cret h",
    ] {
        let image = line.split_ascii_whitespace().next().unwrap_or("");
        let output = redact_command_line(image, line);
        assert!(!output.contains("S3cret"), "{line} => {output}");
        if line.contains("username=bob") {
            assert!(
                output.contains("username=bob"),
                "non-secret form field lost: {output}"
            );
        }
    }
    for line in [
        "curl -sL h",
        "curl -o out.txt h",
        "ssh -p 2222 h",
        "mysql -P 3306",
        "mysql -p",
        "zip -p",
        "ssh -p2222 host",
        "ssh -w0:0 host",
        "curl -aS3cret h",
        "curl -pass value h",
        "docker run -p 8080:80 img",
        "redis-cli -h host",
        "openssl -in f -out g",
        "curl -d name=bob h",
        "curl --data name=bob h",
        "ssh -PS3cret host",
        "mysql -sLuadmin:S3cret",
        "sqlcmd -Sserver",
        "bcp -Sserver",
        "net user bob /active:no",
        "sudo -u alice ls",
        "foo --password --verbose S3cret",
    ] {
        let output = redact_command_line(line.split_ascii_whitespace().next().unwrap_or(""), line);
        assert!(
            !output.contains("--verbose") || output.contains("--verbose S3cret"),
            "ambiguous flag must be retained: {output}"
        );
        if line == "foo --password --verbose S3cret" {
            assert!(output.contains("--verbose S3cret"), "{output}");
        } else {
            assert_eq!(output, line, "negative: {line}");
        }
    }
    assert_eq!(
        redact_command_line("net", "net use \\\\h\\c$ /persistent:yes /user:a S3cret"),
        "net use \\\\h\\c$ /persistent:yes /user:a REDACTED"
    );
    assert_eq!(
        redact_command_line("net", "net use \\\\h\\c$ S3cret extra"),
        "net use \\\\h\\c$ REDACTED extra"
    );
    assert_eq!(
        redact_command_line("openssl", "openssl enc -pass pass:S3cret"),
        "openssl enc -pass pass:REDACTED"
    );
    for (image, input, expected) in [
        ("cmdkey", "cmdkey /pass:S3cret", "cmdkey /pass:REDACTED"),
        (
            "smbclient",
            "smbclient //h/share -U user%S3cret",
            "smbclient //h/share -U user%REDACTED",
        ),
        (
            "smbclient",
            "smbclient //h/share -Uuser%S3cret",
            "smbclient //h/share -Uuser%REDACTED",
        ),
        (
            "curl",
            "curl --proxy-user=a:S3cret h",
            "curl --proxy-user=REDACTED h",
        ),
        ("curl", "curl -U a:S3cret h", "curl -U REDACTED h"),
        (
            "wget",
            "wget --http-password=S3cret h",
            "wget --http-password=REDACTED h",
        ),
        (
            "wget",
            "wget --ftp-password=S3cret h",
            "wget --ftp-password=REDACTED h",
        ),
        (
            "wget",
            "wget --password=S3cret h",
            "wget --password=REDACTED h",
        ),
        (
            "curl",
            "curl --data='username=bob&password=S3cret' h",
            "curl --data='username=bob&password=REDACTED' h",
        ),
        (
            "curl",
            "curl -dpassword=S3cret h",
            "curl -dpassword=REDACTED h",
        ),
        ("curl", "curl -sLuadmin:S3cret h", "curl -sLuREDACTED h"),
        ("curl", "curl -Luadmin:S3cret h", "curl -LuREDACTED h"),
        ("curl", "curl -suadmin:S3cret h", "curl -suREDACTED h"),
        ("curl", "curl -uadmin:S3cret h", "curl -uREDACTED h"),
        ("curl", "curl '-uadmin:S3cret' h", "curl '-uREDACTED' h"),
        ("curl", "curl -sLu admin:S3cret h", "curl -sLu REDACTED h"),
        ("mysql", "mysql -pS3cret", "mysql -pREDACTED"),
        (
            "zip",
            "zip -PS3cret archive file",
            "zip -PREDACTED archive file",
        ),
        ("redis-cli", "redis-cli -aS3cret", "redis-cli -aREDACTED"),
        ("sqlcmd", "sqlcmd -PS3cret", "sqlcmd -PREDACTED"),
        ("bcp", "bcp -PS3cret", "bcp -PREDACTED"),
        ("mysqladmin", "mysqladmin -pS3cret", "mysqladmin -pREDACTED"),
        (
            "mysqlimport",
            "mysqlimport -pS3cret",
            "mysqlimport -pREDACTED",
        ),
        ("docker", "docker login -pS3cret", "docker login -pREDACTED"),
        (
            "docker",
            "docker login -p S3cret",
            "docker login -p REDACTED",
        ),
        (
            "docker",
            "docker login --password=S3cret",
            "docker login --password=REDACTED",
        ),
        (
            "docker",
            "docker login --password S3cret",
            "docker login --password REDACTED",
        ),
        ("redis-cli", "redis-cli -aS3cret", "redis-cli -aREDACTED"),
        ("ldapsearch", "ldapsearch -wS3cret", "ldapsearch -wREDACTED"),
        ("7z", "7z a -pS3cret archive", "7z a -pREDACTED archive"),
        (
            "zip",
            "zip -P S3cret archive file",
            "zip -P REDACTED archive file",
        ),
        (
            "zip",
            "zip -PS3cret archive file",
            "zip -PREDACTED archive file",
        ),
        (
            "wget",
            "wget --http-password=S3cret h",
            "wget --http-password=REDACTED h",
        ),
    ] {
        assert_eq!(redact_command_line(image, input), expected, "{input}");
    }
    assert_eq!(
        redact_command_line("robocopy", "robocopy src dst /pass:literal"),
        "robocopy src dst /pass:literal"
    );
}

#[test]
fn unbalanced_quote_or_trailing_escape_does_not_hide_later_secrets() {
    for line in [
        "curl -u a:S3cret 'unterminated",
        "curl -u a:S3cret \"unterminated",
        "curl -u a:S3cret trailing\\",
    ] {
        let output = redact_command_line("curl", line);
        assert!(!output.contains("S3cret"), "{line} => {output}");
    }
    let windows = redact_command_line("C:\\curl.exe", "curl -u a:S3cret \"unterminated");
    assert!(!windows.contains("S3cret"), "{windows}");
}

#[test]
fn argv_url_arguments_are_redacted_without_retokenizing_them() {
    let mut argv = vec![
        "curl".into(),
        "--url=https://user:pass@example.test/path?token=secret".into(),
    ];
    redact_argv("curl", &mut argv);
    assert_eq!(
        argv[1],
        "--url=https://REDACTED@example.test/path?token=REDACTED"
    );
    assert_eq!(argv.len(), 2);
}

#[test]
fn a_bare_curl_data_flag_redacts_the_next_argv_element() {
    // #843 CI (SherlockOmss, 2026-10-21): a bare `--data`/`--data-raw`/
    // `--data-binary`/`--data-urlencode` with the value as the *next* argv
    // element (not attached with `=`) fell through both arms and leaked —
    // the string path (`redact_command_line`) already handled this shape,
    // but Linux events arrive as argv, which real detections use.
    for flag in [
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
    ] {
        let mut argv: Vec<String> = ["curl", flag, "password=S3cret", "h"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        redact_argv("curl", &mut argv);
        assert_eq!(argv[2], "password=REDACTED", "flag {flag}");
    }
    let mut attached: Vec<String> = ["curl", "--data=password=S3cret", "h"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    redact_argv("curl", &mut attached);
    assert_eq!(attached[1], "--data=password=REDACTED");
}

#[test]
fn an_attached_curl_header_flag_keeps_its_name_and_only_redacts_the_value() {
    // #843 CI (SherlockOmss, 2026-10-21): the curl `-u user:pass` clustered
    // short-flag scan matched the literal `u` inside "Authorization" (and
    // any other header name containing `u`) on a `-H<header>` argv element,
    // mangling the header name instead of just redacting the secret value.
    let mut argv: Vec<String> = ["curl", "-HAuthorization: Bearer S3cret", "h"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    redact_argv("curl", &mut argv);
    assert_eq!(argv[1], "-HAuthorization: Bearer REDACTED");

    let mut argv2: Vec<String> = ["curl", "-HX-Auth-Token: S3cret", "h"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    redact_argv("curl", &mut argv2);
    assert_eq!(argv2[1], "-HX-Auth-Token: REDACTED");
}

#[test]
fn argv_header_redaction_matches_the_command_line_path_for_any_header_argument() {
    let cases = [
        (
            "curl",
            vec![
                "curl",
                "--proxy-header",
                "Proxy-Authorization: Basic S3cret",
                "h",
            ],
            "curl --proxy-header Proxy-Authorization: Basic S3cret h",
        ),
        (
            "http",
            vec!["http", "h", "Authorization:Bearer S3cret"],
            "http h Authorization:Bearer S3cret",
        ),
        (
            "python3",
            vec!["python3", "x.py", "Authorization: Bearer S3cret"],
            "python3 x.py Authorization: Bearer S3cret",
        ),
    ];

    for (image, raw_argv, raw_cmdline) in cases {
        let expected = redact_command_line(image, raw_cmdline).into_owned();
        let mut argv = raw_argv.into_iter().map(str::to_owned).collect::<Vec<_>>();
        redact_argv(image, &mut argv);

        assert!(!expected.contains("S3cret"), "{image}: {expected}");
        assert_eq!(
            argv.join(" "),
            expected,
            "argv/command-line mismatch for {image}"
        );
        assert!(argv.join(" ").contains("REDACTED"), "{image}: {argv:?}");
    }
}

#[test]
fn a_quoted_query_value_keeps_its_quotes_so_redaction_stays_idempotent() {
    // #843 CI: `token="A"` lost its opening quote, which changed the line's quote
    // parity and made a second pass redact differently.
    let line = "net use \"A\"	 https://u:p@example.test/?token=\"A\"	 -p\"A\"";
    let once = redact_command_line("tool.exe", line).into_owned();
    assert!(once.contains("token=\"REDACTED\""), "{once}");
    assert_eq!(redact_command_line("tool.exe", &once), once);
    assert_eq!(
        redact_url_secrets("https://h/?token='abc'"),
        "https://h/?token='REDACTED'"
    );
    assert_eq!(
        redact_url_secrets("https://h/?token=\"\""),
        "https://h/?token=\"\""
    );
}

proptest! {
    #[test]
    fn trigger_words_mixed_with_arbitrary_unicode_are_safe(
        noise in prop::collection::vec(
            prop_oneof![
                any::<char>().prop_filter("arbitrary Unicode except backslash and single quote", |ch| {
                    !matches!(*ch, '\\' | '\'')
                }),
                Just('\u{00a0}'),
                Just('\u{2003}'),
                Just('\u{3000}'),
                Just('\u{0301}'),
            ],
            0..40,
        ),
    ) {
        let noise: String = noise.into_iter().collect();
        let input = format!(
            "{noise} authorization:{noise}Bearer{noise}x-api-key:{noise} --password={noise} -p{noise} /password:{noise} net use {noise} https://user:pass@example.test/?token={noise}",
        );
        let once = redact_command_line("tool.exe", &input).into_owned();
        let twice = redact_command_line("tool.exe", &once).into_owned();
        prop_assert_eq!(&once, &twice);
        prop_assert!(once.len() <= input.len().saturating_add(32 * REDACTED.len()));
        let mut argv = vec![input];
        redact_argv("tool.exe", &mut argv);
        prop_assert_eq!(argv.len(), 1);
        let once_argv = argv.clone();
        redact_argv("tool.exe", &mut argv);
        prop_assert_eq!(argv, once_argv);
    }

    #[test]
    fn arbitrary_utf8_redaction_is_panic_free_idempotent_and_bounded(input in any::<String>()) {
        let once = redact_command_line("mysql", &input).into_owned();
        let twice = redact_command_line("mysql", &once).into_owned();
        prop_assert_eq!(once.clone(), twice);
        let sites = input.matches(['=', ':']).count()
            .saturating_add(input.split_ascii_whitespace().count())
            .saturating_add(1);
        prop_assert!(once.len() <= input.len().saturating_add(sites * REDACTED.len()));
        let mut argv = vec![input.clone()];
        redact_argv("mysql", &mut argv);
        prop_assert_eq!(argv.len(), 1);
    }

    #[test]
    fn argv_and_joined_cmdline_agree_for_plain_generated_arguments(
        tail in prop::collection::vec("[A-Za-z0-9_-]{0,12}", 0..8),
        secret in "secret[0-9]{1,8}"
    ) {
        let mut raw_argv = vec!["curl".to_owned(), "-u".to_owned(), format!("user:{secret}")];
        raw_argv.extend(tail);
        let mut argv = raw_argv.clone();
        redact_argv("curl", &mut argv);
        let joined = raw_argv.join(" ");
        let from_line = redact_command_line("curl", &joined).into_owned();
        prop_assert_eq!(argv.join(" ").contains(&secret), from_line.contains(&secret));
        prop_assert!(!from_line.contains(&secret));
    }
}

#[test]
fn malformed_quote_context_does_not_make_redaction_non_idempotent() {
    let noise = "\"";
    let input = format!(
        "{noise} authorization:{noise}Bearer{noise}x-api-key:{noise} --password={noise} -p{noise} /password:{noise} net use {noise} https://user:pass@example.test/?token={noise}",
    );
    let once = redact_command_line("tool.exe", &input).into_owned();
    let twice = redact_command_line("tool.exe", &once).into_owned();
    assert_eq!(once, twice);
}

#[test]
fn unicode_authorization_whitespace_never_panics_in_line_or_argv() {
    for input in [
        "curl -H \"Authorization: Bearer\u{00a0}abc\" https://h",
        "curl -H \"Authorization:\u{3000}Basic\u{2003}abc\" https://h",
    ] {
        let output = redact_command_line("curl", input);
        assert!(output.contains("REDACTED"), "{output}");
        assert!(!output.contains("abc"), "{output}");
        let header = input.split_once("-H ").map_or(input, |(_, value)| value);
        let mut argv = vec!["curl".into(), "-H".into(), header.into()];
        redact_argv("curl", &mut argv);
        assert!(argv[2].contains("REDACTED"), "{argv:?}");
        assert!(!argv[2].contains("abc"), "{argv:?}");
    }
}

#[test]
fn no_change_borrows_the_original_command_line() {
    let input = "ssh -p 2222 host";
    assert!(matches!(
        redact_command_line("ssh", input),
        std::borrow::Cow::Borrowed(_)
    ));
}

#[test]
fn a_presigned_s3_url_keeps_its_shape_and_loses_its_credentials() {
    let url = "https://bucket.s3.amazonaws.com/kit/payload.exe?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                   &X-Amz-Credential=AKIAEXAMPLE%2F20260930%2Fus-east-1%2Fs3%2Faws4_request\
                   &X-Amz-Date=20260930T101500Z&X-Amz-Expires=300\
                   &X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLE\
                   &X-Amz-SignedHeaders=host&X-Amz-Signature=0123abcd&utm_campaign=q3-invoice";
    assert_eq!(
        redact_url_secrets(url),
        "https://bucket.s3.amazonaws.com/kit/payload.exe?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=REDACTED&X-Amz-Date=20260930T101500Z&X-Amz-Expires=300\
             &X-Amz-Security-Token=REDACTED&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=REDACTED&utm_campaign=q3-invoice"
    );
}

#[test]
fn gcs_azure_and_legacy_s3_signatures_are_redacted() {
    for (url, expected) in [
        (
            "https://storage.googleapis.com/b/x.msi?X-Goog-Credential=svc%40p.iam&X-Goog-Signature=beef",
            "https://storage.googleapis.com/b/x.msi?X-Goog-Credential=REDACTED&X-Goog-Signature=REDACTED",
        ),
        (
            "https://acct.blob.core.windows.net/c/x.zip?sv=2022-11-02&se=2026-10-01&sp=r&sig=abc%3D",
            "https://acct.blob.core.windows.net/c/x.zip?sv=2022-11-02&se=2026-10-01&sp=r&sig=REDACTED",
        ),
        (
            "https://b.s3.amazonaws.com/x.exe?AWSAccessKeyId=AKIA&Expires=1&Signature=zz",
            "https://b.s3.amazonaws.com/x.exe?AWSAccessKeyId=REDACTED&Expires=1&Signature=REDACTED",
        ),
    ] {
        assert_eq!(redact_url_secrets(url), expected, "{url}");
    }
}

#[test]
fn oauth_and_session_parameters_are_redacted_case_insensitively() {
    assert_eq!(
        redact_url_secrets(
            "https://h/cb?Access_Token=a&CODE=b&client_secret=c&PHPSESSID=d&api_key=e&x-api-key=f&state=keep"
        ),
        "https://h/cb?Access_Token=REDACTED&CODE=REDACTED&client_secret=REDACTED\
             &PHPSESSID=REDACTED&api_key=REDACTED&x-api-key=REDACTED&state=keep"
    );
}

#[test]
fn a_sharepoint_tempauth_link_loses_its_bearer_token() {
    // #550 review: the most common download source on a managed fleet.
    assert_eq!(
        redact_url_secrets(
            "https://contoso.sharepoint.com/sites/x/_layouts/15/download.aspx\
                 ?UniqueId=0a1b2c3d&Translate=false&tempauth=eyJ0eXAiOiJKV1Qi.v1&ApiVersion=2.0"
        ),
        "https://contoso.sharepoint.com/sites/x/_layouts/15/download.aspx\
             ?UniqueId=0a1b2c3d&Translate=false&tempauth=REDACTED&ApiVersion=2.0"
    );
    assert_eq!(
        redact_url_secrets("https://h/x?auth=a&OAuth=b&author=keep"),
        "https://h/x?auth=REDACTED&OAuth=REDACTED&author=keep"
    );
}

#[test]
fn userinfo_and_fragment_are_always_redacted() {
    assert_eq!(
        redact_url_secrets("https://user:hunter2@host:8443/x.exe#access_token=abc"),
        "https://REDACTED@host:8443/x.exe#REDACTED"
    );
    // The last `@` in the authority ends the userinfo; one in the path is not userinfo.
    assert_eq!(
        redact_url_secrets("ftp://a@b@host/p@th"),
        "ftp://REDACTED@host/p@th"
    );
}

#[test]
fn a_question_mark_inside_the_fragment_is_not_a_query() {
    assert_eq!(
        redact_url_secrets("https://h/x.exe#frag?token=abc"),
        "https://h/x.exe#REDACTED"
    );
}

#[test]
fn urls_without_secrets_are_unchanged() {
    for url in [
        "https://example.test/invoice.exe",
        "https://example.test/dl?id=42&utm_source=mail",
        "about:internet",
        "C:\\Users\\Public\\x.exe",
        "https://h/x?flag&=v&k=&&",
        "https://h/x#",
        "",
    ] {
        assert_eq!(redact_url_secrets(url), url, "{url}");
    }
}

#[test]
fn redaction_is_idempotent() {
    let url = "https://u:p@h/x?sig=1&keep=2&token=3#f";
    let once = redact_url_secrets(url);
    assert_eq!(redact_url_secrets(&once), once);
}

#[test]
fn never_panics_on_any_truncation_or_odd_input() {
    // The URL comes from an attacker-writable ADS or xattr: every prefix of
    // a dense URL (multi-byte chars included), plus separator soup.
    let dense = "https://ü:p@h\u{e9}ll\u{f6}/\u{1f600}?sig=\u{e9}&a=b=c&&token#x?y@z";
    for (end, _) in dense.char_indices() {
        let _ = redact_url_secrets(&dense[..end]);
    }
    for odd in [
        "://",
        "://@",
        "?",
        "#",
        "?#",
        "@",
        "a://b@",
        "?=",
        "?&=&",
        "#?@://",
        "\u{0}?\u{0}=\u{0}",
    ] {
        let _ = redact_url_secrets(odd);
    }
}
