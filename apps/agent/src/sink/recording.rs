//! Recording a finding: redaction, verdict fusion, the alert log, escalation and the durable
//! detection spool. One pipeline for every engine, on the capture thread
//! ([`DetectionSink::record`]) and on the enrichment worker (the free functions). See
//! `docs/lifecycle.md`, "Recording a finding".

use std::sync::Mutex;

use schema::Event;

use super::{DetectionSink, entity_key, escalate_if_warranted, techniques_from};
use crate::{alerts::AlertLog, sync::LockExt as _};

/// One engine's finding, as [`record_detection`] takes it.
pub(super) struct Finding<'a> {
    pub(super) entity: &'a verdict::EntityKey,
    pub(super) technique: &'a str,
    pub(super) message: &'a str,
    pub(super) source: schema::detection::DetectionSource,
    pub(super) severity: schema::detection::Severity,
}

impl<'a> Finding<'a> {
    /// A plain `rules::Alert`: its technique doubles as the rule id.
    pub(super) fn rule(entity: &'a verdict::EntityKey, alert: &'a rules::Alert) -> Self {
        Self {
            entity,
            technique: alert.technique,
            message: &alert.message,
            source: schema::detection::DetectionSource::Rule {
                rule_id: alert.technique.to_string(),
            },
            severity: alert.severity,
        }
    }

    /// A canary touch the deception gate did not excuse (#81).
    pub(super) fn canary(entity: &'a verdict::EntityKey, message: &'a str) -> Self {
        Self {
            entity,
            technique: super::canary::CANARY_TECHNIQUE,
            message,
            source: schema::detection::DetectionSource::Rule {
                rule_id: super::canary::CANARY_RULE_ID.to_string(),
            },
            severity: schema::detection::Severity::High,
        }
    }

    /// An IOC match (#60); `message` is `hit.message(comm)`.
    pub(super) fn ioc(
        entity: &'a verdict::EntityKey,
        message: &'a str,
        hit: crate::ioc::IocHit,
    ) -> Self {
        Self {
            entity,
            technique: crate::ioc::IOC_TECHNIQUE,
            message,
            severity: hit.severity(),
            source: schema::detection::DetectionSource::Ioc {
                kind: hit.kind,
                indicator: hit.indicator,
                feed: hit.feed,
                feed_version: hit.feed_version,
                reference: None,
            },
        }
    }
}

impl DetectionSink {
    /// Records one finding from the capture thread, with `evidence` events after the
    /// triggering one. The alert log gets a line even when fusion absorbs the finding as a
    /// duplicate. The returned verdict is the entity's composed state, **not** for
    /// kill-gating: `correlate` gates on this event's own severity (PR #502 review).
    pub(super) fn record(
        &self,
        finding: Finding<'_>,
        event: &Event,
        evidence: Vec<Event>,
    ) -> Option<verdict::Verdict> {
        let persist = |detection| self.spool_detection(detection);
        let persist = self
            .detection_spool
            .as_ref()
            .map(|_| &persist as &dyn Fn(_));
        record_detection(
            &self.verdict,
            &self.alert_log,
            finding,
            event,
            evidence,
            persist,
        )
    }

    /// Hands a finding to the worker for the durable detection spool.
    fn spool_detection(&self, detection: schema::detection::Detection) {
        if let Err(detection) = self.enrich_queue.enqueue_detection(detection) {
            // The queue is full, so the capture thread does this file append
            // itself, which the #126 design otherwise keeps off it. Under sustained
            // overload every finding takes this path; accepted on purpose (a finding
            // is never lost), and only reached once the queue is already shedding.
            tracing::warn!("detection queue full; persisting on capture thread");
            if let Some(spool) = &self.detection_spool
                && let Err(e) = crate::upload::persist_detection(spool, *detection)
            {
                tracing::error!(error = %e, "detection spool append failed on fallback");
            }
        }
    }
}

/// Records one finding: redacted, fused into the verdict, written to the alert log,
/// escalated when warranted, then handed to `persist` (the durable detection spool, when
/// one is configured). A free function so the enrichment worker, which has no
/// `DetectionSink`, records the signature-gated findings the same way (#441).
fn record_detection(
    verdict: &Mutex<verdict::VerdictEngine>,
    alert_log: &AlertLog,
    finding: Finding<'_>,
    event: &Event,
    evidence: Vec<Event>,
    persist: Option<&dyn Fn(schema::detection::Detection)>,
) -> Option<verdict::Verdict> {
    let now_ns = event.meta().timestamp_ns;
    // Rules and Sigma have already evaluated the raw event/message. Redact only
    // the copy that enters the verdict, alert log, and durable detection spool.
    let safe_message = safe_detection_message(event, &evidence, finding.message);
    let mut safe_events: Vec<Event> = std::iter::once(event.clone()).chain(evidence).collect();
    for event in &mut safe_events {
        crate::redact::redact_event(event);
    }
    let detection = schema::detection::Detection {
        timestamp_ns: now_ns,
        severity: finding.severity,
        title: safe_message.clone(),
        source: finding.source,
        score: None,
        attributions: Vec::new(),
        techniques: techniques_from(finding.technique),
        events: safe_events,
    };
    let spooled = persist.map(|_| detection.clone());
    let result = verdict.lock_recovering().record(
        finding.entity.clone(),
        finding.technique,
        detection,
        now_ns,
    );
    alert_log.record(finding.technique, safe_message);
    if let Some(fused) = &result {
        escalate_if_warranted(alert_log, fused);
    }
    if let (Some(persist), Some(detection)) = (persist, spooled) {
        persist(detection);
    }
    result
}

/// A detection's message as it may leave the process: the command text a rule quoted from
/// the event (an Exec command line, an AMSI excerpt, #895) swapped for its redacted copy.
fn safe_detection_message(event: &Event, evidence: &[Event], message: &str) -> String {
    let mut related = std::iter::once(event).chain(evidence.iter());
    let Some(source) = related.find(|e| matches!(e, Event::Exec(_) | Event::AmsiContent(_))) else {
        return message.to_owned();
    };
    let mut safe = source.clone();
    crate::redact::redact_event(&mut safe);
    match (source, &safe) {
        (Event::Exec(raw), Event::Exec(safe)) => {
            redact_detection_message(&raw.cmdline, &safe.cmdline, message)
        }
        (Event::AmsiContent(raw), Event::AmsiContent(safe)) => redact_detection_message(
            &rules::amsi_excerpt(raw.text.as_deref()),
            &rules::amsi_excerpt(safe.text.as_deref()),
            message,
        ),
        _ => message.to_owned(),
    }
}

pub(super) fn redact_detection_message(
    raw_cmdline: &str,
    safe_cmdline: &str,
    message: &str,
) -> String {
    if raw_cmdline.is_empty() {
        message.to_owned()
    } else {
        message.replace(raw_cmdline, safe_cmdline)
    }
}

/// [`record_detection`] on the worker for one `rules::Alert`.
pub(super) fn record_rule_alert(
    verdict: &Mutex<verdict::VerdictEngine>,
    alert_log: &AlertLog,
    event: &Event,
    alert: &rules::Alert,
    persist: Option<&dyn Fn(schema::detection::Detection)>,
) {
    let entity = entity_key(event.meta());
    let finding = Finding::rule(&entity, alert);
    record_detection(verdict, alert_log, finding, event, Vec::new(), persist);
}

/// [`record_detection`] on the worker for one IOC match on an exec image. The capture
/// thread records a connect's match through [`DetectionSink::record_ioc`].
pub(super) fn record_ioc_hit(
    verdict: &Mutex<verdict::VerdictEngine>,
    alert_log: &AlertLog,
    event: &Event,
    hit: crate::ioc::IocHit,
    persist: Option<&dyn Fn(schema::detection::Detection)>,
) {
    let message = hit.message(&event.meta().comm);
    let entity = entity_key(event.meta());
    let finding = Finding::ioc(&entity, &message, hit);
    record_detection(verdict, alert_log, finding, event, Vec::new(), persist);
}

/// The enrichment worker's append to the durable detection spool. A failure
/// loses only the upload copy: the finding is already in the alert log.
pub(super) fn spool_on_worker(
    spool: Option<&Mutex<store::EventSpool>>,
    detection: schema::detection::Detection,
) {
    if let Some(spool) = spool
        && let Err(e) = crate::upload::persist_detection(spool, detection)
    {
        tracing::warn!(error = %e, "detection spool append failed");
    }
}
