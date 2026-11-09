//! Event-boundary redaction wrappers for the agent.
//!
//! `FileQuarantine`'s `origin_url`/`referrer_url`, a `BitsJob`'s `url` (#284), and an
//! `HttpRequest`'s evidence value (#478, ADR-0022 §4) are redacted here before any
//! consumer sees the event — see [`redact_event`]'s doc for exactly what each path
//! covers. `Exec` command lines/argv (#705, ADR-0034) and the command text of `ReadlineInput`,
//! `ScriptBlock`, `AmsiContent` and `WmiActivity` (#895) go through the same boundary,
//! via the pure functions in `crates/redact`; [`RedactingSink::redact_commands`] controls
//! whether a given sink sees them raw (live detection pipelines) or redacted
//! (capture/output paths).

// The shared sink wrapper is used by all platform run and capture commands.

use std::sync::Arc;

pub(crate) use redact::{
    CommandDialect, REDACTED, is_secret_key, redact_argv, redact_command_line, redact_command_text,
    redact_url_secrets,
};
use schema::{Event, sensor::EventSink};

/// Redacts output copies while allowing live detection pipelines to inspect raw command
/// events ([`carries_command_text`]).
pub(crate) struct RedactingSink<S> {
    pub(crate) inner: S,
    pub(crate) redact_commands: bool,
}

impl<S: EventSink> EventSink for RedactingSink<S> {
    fn on_event(&self, mut event: Event) {
        // Command text must remain raw until rules, Sigma and correlation have
        // consumed it. Output copies are scrubbed at their own sink boundary.
        if self.redact_commands || !carries_command_text(&event) {
            redact_event(&mut event);
        }
        self.inner.on_event(event);
    }
}

/// Events whose command text detection reads raw (ADR-0034): a live pipeline must not
/// redact them before the rules run, only the copies that leave the process.
fn carries_command_text(event: &Event) -> bool {
    matches!(
        event,
        Event::Exec(_)
            | Event::ReadlineInput(_)
            | Event::ScriptBlock(_)
            | Event::AmsiContent(_)
            | Event::WmiActivity(_)
    )
}

/// Puts a [`RedactingSink`] in front of a sensor sink used by run or capture commands.
/// Capture callers set `redact_commands`; live detection pipelines leave command events raw.
pub(crate) fn redacting(sink: Box<dyn EventSink>, redact_commands: bool) -> Arc<dyn EventSink> {
    Arc::new(RedactingSink {
        inner: Arc::<dyn EventSink>::from(sink),
        redact_commands,
    })
}

#[cfg(target_os = "linux")]
pub(crate) struct SharedSink(pub(crate) Arc<dyn EventSink>);

#[cfg(target_os = "linux")]
impl EventSink for SharedSink {
    fn on_event(&self, event: Event) {
        self.0.on_event(event);
    }
}

/// Redacts sensitive fields on an event copy immediately before output. Run-mode
/// sensor wrappers preserve Exec until detection; capture-mode wrappers redact it
/// at their output boundary. `log_sources::deliver` also uses this for Linux HTTP
/// evidence (ADR-0018/0022).
///
/// An `HttpRequest`'s evidence is the one query parameter a signature matched on,
/// and its value is what leaves the host (ADR-0022 §4). When that parameter's *name*
/// marks it as a secret (`?token=…`, `?password=…`), the whole value is replaced by
/// [`REDACTED`], the name is kept so the finding still reads. A parameter that is not
/// named like a secret (`?id=1 union select 1`) keeps its value: it is the evidence.
pub(crate) fn redact_event(event: &mut Event) {
    match event {
        Event::FileQuarantine(quarantine) => {
            for url in [&mut quarantine.origin_url, &mut quarantine.referrer_url]
                .into_iter()
                .flatten()
            {
                *url = redact_url_secrets(url);
            }
        }
        Event::BitsJob(job) => job.url = redact_url_secrets(&job.url),
        Event::HttpRequest(request) => {
            if let Some(evidence) = &mut request.evidence
                && is_secret_key(&evidence.param)
            {
                evidence.value = REDACTED.to_owned();
            }
        }
        Event::Exec(exec) => {
            if exec.argv.is_empty() {
                exec.cmdline = redact_command_line(&exec.image_path, &exec.cmdline).into_owned();
            } else {
                redact_argv(&exec.image_path, &mut exec.argv);
                exec.cmdline = exec.argv.join(" ");
            }
        }
        Event::ReadlineInput(readline) => {
            readline.input =
                redact_command_text(&readline.input, CommandDialect::Posix).into_owned();
        }
        Event::ScriptBlock(block) => {
            block.text = redact_command_text(&block.text, CommandDialect::PowerShell).into_owned();
        }
        Event::AmsiContent(amsi) => {
            if let Some(text) = &mut amsi.text {
                *text = redact_command_text(text, amsi_dialect(&amsi.app_name)).into_owned();
            }
            if let Some(name) = &mut amsi.content_name
                && name.contains("://")
            {
                *name = redact_url_secrets(name);
            }
        }
        Event::WmiActivity(wmi) => {
            if let Some(query) = &mut wmi.query {
                *query = redact_command_text(query, CommandDialect::Opaque).into_owned();
            }
        }
        _ => {}
    }
}

/// The language of an AMSI buffer, from the runtime that asked for the scan:
/// `PowerShell_C:\…\powershell.exe_10.0…` is `PowerShell`; `VBScript`, `JScript`, VBA and
/// .NET content is not parsed ([`CommandDialect::Opaque`]).
fn amsi_dialect(app_name: &str) -> CommandDialect {
    if app_name
        .get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("powershell"))
    {
        CommandDialect::PowerShell
    } else {
        CommandDialect::Opaque
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records what reaches the inner sink.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<Event>>);

    impl EventSink for Recorder {
        fn on_event(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    struct SharedRecorder(Arc<Mutex<Vec<Event>>>);

    impl EventSink for SharedRecorder {
        fn on_event(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn the_sink_redacts_both_quarantine_urls_before_forwarding() {
        let sink = RedactingSink {
            inner: Recorder::default(),
            redact_commands: true,
        };
        sink.on_event(Event::FileQuarantine(schema::FileQuarantineEvent {
            origin_url: Some("https://h/x.exe?token=abc".into()),
            referrer_url: Some("https://u:p@h/page".into()),
            ..schema::fixtures::file_quarantine()
        }));
        let events = sink.inner.0.lock().unwrap();
        let [Event::FileQuarantine(q)] = events.as_slice() else {
            panic!("expected one FileQuarantine, got {events:?}");
        };
        assert_eq!(
            q.origin_url.as_deref(),
            Some("https://h/x.exe?token=REDACTED")
        );
        assert_eq!(q.referrer_url.as_deref(), Some("https://REDACTED@h/page"));
    }

    #[test]
    fn the_sink_redacts_a_bits_job_url_and_keeps_the_rest_of_the_job() {
        let job = schema::BitsJobEvent {
            job_id: "{c40080ab-6fe4-418a-8ba6-c271c5298f18}".into(),
            url: "https://u:p@cdn.example/f.exe?X-Amz-Signature=abc&v=2#frag".into(),
            local_path: r"C:\Users\a\f.exe".into(),
            ..schema::fixtures::bits_job()
        };
        let sink = RedactingSink {
            inner: Recorder::default(),
            redact_commands: true,
        };
        sink.on_event(Event::BitsJob(job.clone()));
        let events = sink.inner.0.lock().unwrap();
        let [Event::BitsJob(redacted)] = events.as_slice() else {
            panic!("expected one BitsJob, got {events:?}");
        };
        assert_eq!(
            redacted.url,
            "https://REDACTED@cdn.example/f.exe?X-Amz-Signature=REDACTED&v=2#REDACTED"
        );
        assert_eq!(
            *redacted,
            schema::BitsJobEvent {
                url: redacted.url.clone(),
                ..job
            }
        );
    }

    #[test]
    fn the_sink_leaves_other_events_untouched() {
        let sink = RedactingSink {
            inner: Recorder::default(),
            redact_commands: true,
        };
        // Connect events carry no command-line field, so this boundary leaves them intact.
        let connect = Event::Connect(schema::fixtures::connect());
        sink.on_event(connect.clone());
        assert_eq!(*sink.inner.0.lock().unwrap(), [connect]);
    }

    #[test]
    fn the_real_output_wrapper_redacts_joined_linux_argv_and_raw_windows_lines() {
        let records = Arc::new(Mutex::new(Vec::new()));
        let sink = redacting(Box::new(SharedRecorder(Arc::clone(&records))), true);
        let mut exec = schema::fixtures::exec();
        exec.image_path = "/usr/bin/curl".into();
        exec.argv = vec![
            "curl".into(),
            "-A".into(),
            "it's".into(),
            "-u".into(),
            "a:S3cret".into(),
            "h".into(),
        ];
        exec.cmdline = exec.argv.join(" ");
        sink.on_event(Event::Exec(exec));
        let mut raw = schema::fixtures::exec();
        raw.image_path = "C:\\curl.exe".into();
        raw.cmdline = "curl -A it's -u a:S3cret h".into();
        sink.on_event(Event::Exec(raw));
        {
            let events = records.lock().unwrap();
            let [Event::Exec(argv_exec), Event::Exec(raw_exec)] = events.as_slice() else {
                panic!("{events:?}");
            };
            assert_eq!(argv_exec.cmdline, argv_exec.argv.join(" "));
            for exec in [argv_exec, raw_exec] {
                assert!(!exec.cmdline.contains("S3cret"), "{}", exec.cmdline);
                assert!(
                    exec.argv.iter().all(|arg| !arg.contains("S3cret")),
                    "{:?}",
                    exec.argv
                );
            }
        }
        let mut mysql = schema::fixtures::exec();
        mysql.image_path = "/usr/bin/mysql".into();
        mysql.argv = vec!["mysql".into(), "-pS3 cret".into()];
        mysql.cmdline = mysql.argv.join(" ");
        sink.on_event(Event::Exec(mysql));
        {
            let events = records.lock().unwrap();
            let Event::Exec(mysql) = events.last().unwrap() else {
                unreachable!()
            };
            assert_eq!(mysql.argv[1], "-pREDACTED");
            assert!(!mysql.cmdline.contains("S3") && !mysql.cmdline.contains("cret"));
        }
        let mut wrapped = schema::fixtures::exec();
        wrapped.image_path = "/usr/bin/sudo".into();
        wrapped.argv = vec![
            "sudo".into(),
            "curl".into(),
            "-u".into(),
            "a:S3cret".into(),
            "h".into(),
        ];
        wrapped.cmdline = wrapped.argv.join(" ");
        sink.on_event(Event::Exec(wrapped));
        {
            let events = records.lock().unwrap();
            let Event::Exec(wrapped) = events.last().unwrap() else {
                unreachable!()
            };
            assert!(!wrapped.cmdline.contains("S3cret"), "{}", wrapped.cmdline);
        }
        let mut header = schema::fixtures::exec();
        header.image_path = "/usr/bin/curl".into();
        header.argv = vec![
            "curl".into(),
            "-H".into(),
            "Cookie: sid=S3cret".into(),
            "h".into(),
        ];
        header.cmdline = header.argv.join(" ");
        sink.on_event(Event::Exec(header));
        {
            let events = records.lock().unwrap();
            let Event::Exec(header) = events.last().unwrap() else {
                unreachable!()
            };
            assert!(!header.cmdline.contains("S3cret"), "{}", header.cmdline);
        }
    }

    /// The four command-text events (#895), each holding `S3cret` in its command text.
    fn command_text_events() -> Vec<Event> {
        vec![
            Event::ReadlineInput(schema::ReadlineInputEvent {
                input: "export DB_PASSWORD=S3cret; mysql -pS3cret prod".into(),
                ..schema::fixtures::readline_input()
            }),
            Event::ScriptBlock(schema::ScriptBlockEvent {
                script_block_id: "{6f1d}".into(),
                path: Some(r"C:\ops\deploy.ps1".into()),
                text: "$pw = ConvertTo-SecureString 'S3cret' -AsPlainText -Force\nnet use \\\\fs\\c$ S3cret /user:ops".into(),
                message_number: 1,
                message_total: 1,
                ..schema::fixtures::script_block()
            }),
            Event::AmsiContent(schema::AmsiContentEvent {
                app_name: r"PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0".into(),
                content_name: Some("https://u:S3cret@h/s.ps1?token=S3cret".into()),
                text: Some("New-LocalUser -Name svc -Password 'S3cret'".into()),
                content_hash: "ab".repeat(32),
                ..schema::fixtures::amsi_content()
            }),
            Event::WmiActivity(schema::WmiActivityEvent {
                namespace: r"ROOT\CIMv2".into(),
                query: Some("SELECT * FROM X WHERE Url = 'https://u:S3cret@h/'".into()),
                ..schema::fixtures::wmi_activity()
            }),
        ]
    }

    /// Everything but the command text, so a test can check nothing else moved.
    fn without_command_text(event: &Event) -> Event {
        let mut event = event.clone();
        match &mut event {
            Event::ReadlineInput(e) => e.input.clear(),
            Event::ScriptBlock(e) => e.text.clear(),
            Event::AmsiContent(e) => {
                e.text = None;
                e.content_name = None;
            }
            Event::WmiActivity(e) => e.query = None,
            _ => {}
        }
        event
    }

    #[test]
    fn the_output_wrapper_redacts_command_text_and_keeps_the_rest_of_the_evidence() {
        let records = Arc::new(Mutex::new(Vec::new()));
        let sink = redacting(Box::new(SharedRecorder(Arc::clone(&records))), true);
        let raw = command_text_events();
        for event in raw.clone() {
            sink.on_event(event);
        }
        let written = records.lock().unwrap();
        assert_eq!(written.len(), raw.len());
        for (raw, written) in raw.iter().zip(written.iter()) {
            let json = serde_json::to_string(written).unwrap();
            assert!(!json.contains("S3cret"), "{json}");
            assert!(json.contains(REDACTED), "{json}");
            assert_eq!(without_command_text(written), without_command_text(raw));
        }
        let [
            Event::ReadlineInput(readline),
            Event::ScriptBlock(block),
            Event::AmsiContent(amsi),
            _,
        ] = written.as_slice()
        else {
            panic!("{written:?}");
        };
        assert_eq!(
            readline.input,
            "export DB_PASSWORD=REDACTED; mysql -pREDACTED prod"
        );
        assert!(
            block.text.contains("net use \\\\fs\\c$ REDACTED /user:ops"),
            "{}",
            block.text
        );
        assert_eq!(
            amsi.text.as_deref(),
            Some("New-LocalUser -Name svc -Password 'REDACTED'")
        );
    }

    #[test]
    fn a_live_pipeline_hands_command_text_to_detection_raw() {
        let records = Arc::new(Mutex::new(Vec::new()));
        let sink = redacting(Box::new(SharedRecorder(Arc::clone(&records))), false);
        let raw = command_text_events();
        for event in raw.clone() {
            sink.on_event(event);
        }
        assert_eq!(*records.lock().unwrap(), raw);
    }

    #[test]
    fn non_powershell_amsi_content_only_loses_tool_independent_secrets() {
        let mut event = Event::AmsiContent(schema::AmsiContentEvent {
            app_name: "JScript".into(),
            text: Some("x.open('GET', 'https://u:S3cret@h/'); var Password = 'kept'".into()),
            ..schema::fixtures::amsi_content()
        });
        redact_event(&mut event);
        let Event::AmsiContent(amsi) = event else {
            unreachable!()
        };
        assert_eq!(
            amsi.text.as_deref(),
            Some("x.open('GET', 'https://REDACTED@h/'); var Password = 'kept'")
        );
    }

    fn http_request_with(param: &str, value: &str) -> Event {
        Event::HttpRequest(schema::HttpRequestEvent {
            path: "/a.php".into(),
            param_names: vec![param.into()],
            signature: schema::HttpSignature::SqlInjection,
            evidence: Some(schema::HttpEvidence {
                param: param.into(),
                value: value.into(),
            }),
            ..schema::fixtures::http_request()
        })
    }

    fn evidence_of(event: &Event) -> &schema::HttpEvidence {
        let Event::HttpRequest(request) = event else {
            panic!("expected an HttpRequest, got {event:?}");
        };
        request.evidence.as_ref().expect("evidence")
    }

    #[test]
    fn an_http_evidence_value_on_a_secret_named_parameter_is_redacted_and_its_name_kept() {
        for param in ["token", "password", "access_token", "api_key", "PHPSESSID"] {
            let mut event = http_request_with(param, "s3cr3t' union select 1");
            redact_event(&mut event);
            let evidence = evidence_of(&event);
            assert_eq!(evidence.param, param, "the name stays: it is the finding");
            assert_eq!(evidence.value, REDACTED, "{param}");
        }
    }

    #[test]
    fn a_percent_encoded_secret_name_is_still_a_secret_name() {
        for param in ["pass%77ord", "%74oken", "pass%2577ord", "Access%5FToken"] {
            let mut event = http_request_with(param, "hunter2 union select 1");
            redact_event(&mut event);
            let evidence = evidence_of(&event);
            assert_eq!(evidence.param, param, "the name stays as written");
            assert_eq!(evidence.value, REDACTED, "{param}");
        }
        assert_eq!(
            redact_url_secrets("https://h/x?pass%77ord=hunter2&id=7"),
            "https://h/x?pass%77ord=REDACTED&id=7"
        );
    }

    #[test]
    fn an_http_evidence_value_on_an_ordinary_parameter_is_the_evidence_and_is_kept() {
        for param in ["id", "cmd", "file", "q"] {
            let mut event = http_request_with(param, "1 union select 1");
            redact_event(&mut event);
            assert_eq!(evidence_of(&event).value, "1 union select 1", "{param}");
        }
    }

    #[test]
    fn redacting_an_http_request_twice_changes_nothing_and_only_touches_the_value() {
        let original = http_request_with("token", "s3cr3t");
        let mut once = original.clone();
        redact_event(&mut once);
        let mut twice = once.clone();
        redact_event(&mut twice);
        assert_eq!(once, twice);

        let (Event::HttpRequest(before), Event::HttpRequest(after)) = (&original, &once) else {
            unreachable!()
        };
        assert_eq!(
            schema::HttpRequestEvent {
                evidence: None,
                ..before.clone()
            },
            schema::HttpRequestEvent {
                evidence: None,
                ..after.clone()
            },
            "nothing but the evidence value changes"
        );
    }

    #[test]
    fn an_http_request_without_evidence_is_left_alone() {
        let mut event = Event::HttpRequest(schema::HttpRequestEvent {
            signature: schema::HttpSignature::ScannerUserAgent,
            scanner: Some("sqlmap".into()),
            ..schema::fixtures::http_request()
        });
        let before = event.clone();
        redact_event(&mut event);
        assert_eq!(event, before);
    }
}
