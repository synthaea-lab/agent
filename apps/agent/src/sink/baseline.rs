//! `BaselineSink`: the ML baseline capture sink.

use std::{
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use schema::{Event, sensor::EventSink};
use sinks::JsonlWriter;

use crate::sync::LockExt as _;

/// Minimal sink for ML baseline capture: records the exec events that trigger NO
/// deterministic rule — the "known benign under current rules" corpus consumed by
/// `synthaea_ml` training. Migrated from the old agent's `BaselineSink`, now
/// platform-neutral (any sensor speaking the contract feeds it).
pub(crate) struct BaselineSink {
    rule_state: Mutex<rules::RuleState>,
    out: JsonlWriter,
    count: AtomicU64,
}

/// One baseline record — the format `synthaea_ml` training consumes.
///
/// `argv` is the canonical form: the training side joins it with NUL exactly as
/// [`schema::ExecEvent::ml_cmdline`] does, so the model trains on the vectors the
/// agent will score. `cmdline` is kept alongside it for human inspection of the
/// capture and as the documented fallback when `argv` is empty (Windows/ETW).
#[derive(serde::Serialize)]
struct BaselineRecord<'a> {
    argv: &'a [String],
    cmdline: &'a str,
}

impl BaselineSink {
    pub(crate) fn new(rule_state: rules::RuleState, output: &Path) -> std::io::Result<Self> {
        Ok(Self {
            rule_state: Mutex::new(rule_state),
            out: JsonlWriter::open(output)?,
            count: AtomicU64::new(0),
        })
    }
}

impl EventSink for BaselineSink {
    fn on_event(&self, event: Event) {
        match &event {
            Event::Exec(e) => {
                // Evaluate the deterministic rules — alerting cmdlines are excluded
                // from the baseline (they are exactly what the model must not learn
                // as normal).
                let det_alerts = rules::evaluate_exec(e);
                let mut rule_state = self.rule_state.lock_recovering();
                // Conservative: a gated finding excludes the cmdline whatever the
                // signature would have said.
                let gated = rule_state.on_exec_signature_gated(e);
                let state_alerts = rule_state.on_exec(e);
                drop(rule_state);
                if !det_alerts.is_empty() || !state_alerts.is_empty() || gated.is_some() {
                    return;
                }
                // Baselines leave the process and are used as a training corpus;
                // store the same redacted canonical argv that inference can derive.
                let mut safe = e.clone();
                crate::redact::redact_exec(&mut safe);
                self.out.write(&BaselineRecord {
                    argv: &safe.argv,
                    cmdline: &safe.cmdline,
                });
                let n = self.count.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_multiple_of(10) {
                    eprintln!("[baseline] {n} cmdlines captured...");
                }
            }
            // File events feed the stateful rules' history (download tracking) so
            // exclusion decisions stay accurate; connects are irrelevant here.
            Event::FileOpen(e) => {
                self.rule_state.lock_recovering().on_file_open(e);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use schema::{Event, sensor::EventSink as _};

    use super::BaselineSink;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("baseline-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mysql_exec() -> schema::ExecEvent {
        let mut exec = schema::fixtures::exec();
        exec.image_path = "/usr/bin/mysql".into();
        exec.cmdline = "mysql --password=S3cret".into();
        exec.argv = vec!["mysql".into(), "--password=S3cret".into()];
        exec
    }

    #[test]
    fn baseline_corpus_stores_redacted_command_line_and_argv() {
        let dir = tmp("cmdline-redaction");
        let path = dir.join("baseline.jsonl");
        let sink = BaselineSink::new(rules::RuleState::new(), &path).unwrap();
        sink.on_event(Event::Exec(mysql_exec()));

        let record = std::fs::read_to_string(path).unwrap();
        assert!(record.contains("--password=REDACTED"), "{record}");
        assert!(!record.contains("S3cret"), "{record}");
    }

    #[test]
    fn baseline_corpus_redacts_the_raw_command_line_when_there_is_no_argv() {
        let dir = tmp("raw-cmdline-redaction");
        let path = dir.join("baseline.jsonl");
        let sink = BaselineSink::new(rules::RuleState::new(), &path).unwrap();
        let exec = schema::ExecEvent {
            argv: Vec::new(),
            ..mysql_exec()
        };
        sink.on_event(Event::Exec(exec));

        let record: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        assert_eq!(record["argv"], serde_json::json!([]));
        assert_eq!(record["cmdline"], "mysql --password=REDACTED");
    }
}
