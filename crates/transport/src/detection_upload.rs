//! Store-and-forward upload of structured detections.

use std::time::Duration;

use schema::detection::Detection;
use serde::{Deserialize, Serialize};

use crate::{
    TransportClient, TransportConfig,
    error::{Result, TransportError},
    upload::UploadStep,
};

/// The largest detection body the control plane accepts: `client_max_body_size 8m` on the
/// agent ingest locations of `server/nginx.conf`. A larger body is answered `413`, which is
/// permanent, so the agent shortens a detection to fit before it sends it ([`fit_detection_to_limit`]):
/// dropping it would let a process that pads its own command line erase its detection on the
/// host it controls. A mirror of that setting, not a negotiated value: if the server limit
/// changes, change it here (a smaller server limit is still caught by the per-record `413`
/// handling below, a larger one only shortens detections more than needed).
pub const MAX_DETECTION_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The `error` the detection route answers with a `400` when the payload (or the idempotency
/// key) fails validation: `server/app/api/ingest/detection/route.ts`, the `ZodError` branch.
/// Any other `400` (`Invalid certificate subject`, a proxy's HTML page for a client certificate
/// that does not verify) is about the whole agent: the segment stays spooled and the loop backs off.
const SERVER_INVALID_PAYLOAD: &str = "Invalid payload";

/// The retry identity is persisted in the same spool record as its detection.
/// Reopening an in-flight segment therefore reuses the exact same key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueuedDetection {
    pub key: String,
    pub detection: Detection,
}

/// Two-phase drain of detection records. Implementations retain a drained
/// segment until `ack` or `skip`, including across process restarts.
pub trait DetectionDrain: Send {
    /// Returns the oldest segment, or an empty vector if the spool is empty.
    ///
    /// # Errors
    /// Returns an I/O error when the segment cannot be read.
    fn drain(&mut self) -> std::io::Result<Vec<QueuedDetection>>;

    /// Removes the segment after every detection was accepted by the server.
    ///
    /// # Errors
    /// Returns an I/O error when acknowledgement cannot be persisted.
    fn ack(&mut self) -> std::io::Result<()>;

    /// Discards a permanently rejected segment and counts its lost records.
    ///
    /// # Errors
    /// Returns an I/O error when discard cannot be persisted.
    fn skip(&mut self) -> std::io::Result<()>;

    /// Removes the segment like [`ack`](Self::ack) and counts `dropped` of its records that the
    /// server refused for good (#1119): they were left out one by one, the rest was accepted.
    /// Required, with no default: a drain that forgot it would lose the count silently.
    ///
    /// # Errors
    /// Returns an I/O error when acknowledgement cannot be persisted.
    fn ack_dropping(&mut self, dropped: u64) -> std::io::Result<()>;
}

/// Whether `error` says something about this one record, not about the agent or the server:
/// `400` with the route's `Invalid payload` (it fails validation), `409` (its idempotency key
/// was already used for a different detection), `413` (it is over the body limit), `422` (it
/// cannot be processed), or a record that cannot be serialized. Retrying the record gives the
/// same answer, and the other records of its segment are not affected. Every other permanent
/// error says something that holds for the whole upload, so the segment stays spooled and the loop backs off:
/// `401`, `403`, `404`, `429`, a `400` that is not `Invalid payload` (a certificate or subject
/// failure), a TLS or configuration error.
///
/// A validation `400` after a rolling upgrade (a newer agent field an older server refuses)
/// lands here too and clears when the server is upgraded: those detections are lost either way,
/// as the old whole-segment skip lost them, and each one is logged with its key (the server's own
/// error does not say which field a newer agent added, so the two cannot be told apart here).
fn refuses_this_record(error: &TransportError) -> bool {
    match error {
        TransportError::ServerError { status, message } => match status {
            400 => message == SERVER_INVALID_PAYLOAD,
            409 | 413 | 422 => true,
            _ => false,
        },
        TransportError::Serialization(_) => true,
        _ => false,
    }
}

/// The longest title the control plane keeps: `MAX_TITLE_BYTES` in
/// `server/lib/detection-payload.ts`, which cuts the **end** of a longer title. A mirror, like
/// [`MAX_DETECTION_BODY_BYTES`].
const TITLE_MAX_BYTES: usize = 64 * 1024;

/// Keys of an event that identify it and that a process does not pad: they are never cut when an
/// oversize detection is shortened, so the alert keeps who ran what (the image hash and paths feed
/// the control plane's SHA-256 check and its image prevalence, which a cut value would break).
const PROTECTED_KEYS: &[&str] = &[
    "type",
    "meta",
    "sha256",
    "signature",
    "image_path",
    "parent_image_path",
    "path",
    "old_path",
    "new_path",
    "comm",
    "pcomm",
    "parent_comm",
    "target_user",
];

/// How hard the process-controlled fields of the events are cut, one step after the other until the
/// body fits: (longest string in bytes, longest array in items). The command line and its `argv`
/// are what a process pads, so they go first.
const SHORTEN_STEPS: [(usize, usize); 5] =
    [(8192, 1024), (2048, 256), (512, 64), (128, 16), (32, 4)];

/// Cuts a string to at most `cap` bytes, the `…` that marks the cut included, on a character
/// boundary.
fn cut_string(text: &mut String, cap: usize) {
    if text.len() <= cap {
        return;
    }
    let mut end = cap.saturating_sub('…'.len_utf8());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push('…');
}

/// Cuts the strings longer than `string_cap` bytes and the arrays longer than `array_cap` items of
/// `value`, recursively, except under [`PROTECTED_KEYS`]. Keys of objects are left alone.
fn shorten_events(value: &mut serde_json::Value, string_cap: usize, array_cap: usize) {
    match value {
        serde_json::Value::String(text) => cut_string(text, string_cap),
        serde_json::Value::Array(items) => {
            items.truncate(array_cap);
            for item in items {
                shorten_events(item, string_cap, array_cap);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                if !PROTECTED_KEYS.contains(&key.as_str()) {
                    shorten_events(field, string_cap, array_cap);
                }
            }
        }
        _ => {}
    }
}

/// An event reduced to its identity: only its [`PROTECTED_KEYS`], each string cut to 256 bytes.
fn identity_of(event: &serde_json::Value) -> serde_json::Value {
    let mut stub = serde_json::Map::new();
    if let Some(fields) = event.as_object() {
        for (key, field) in fields {
            if PROTECTED_KEYS.contains(&key.as_str()) {
                let mut field = field.clone();
                if let serde_json::Value::String(text) = &mut field {
                    cut_string(text, 256);
                }
                stub.insert(key.clone(), field);
            }
        }
    }
    serde_json::Value::Object(stub)
}

/// Bounds the parts of a detection other than its events, so that the body they leave is small
/// whatever a process did: at most 64 techniques and attributions, short strings in each.
fn bound_small_parts(value: &mut serde_json::Value) {
    for (key, item_cap, string_cap) in [("techniques", 64, 64), ("attributions", 64, 128)] {
        if let Some(serde_json::Value::Array(items)) = value.get_mut(key) {
            items.truncate(item_cap);
            for item in items {
                shorten_events(item, string_cap, item_cap);
            }
        }
    }
    if let Some(source) = value.get_mut("source") {
        shorten_events(source, 2048, 64);
    }
}

/// The length of `value` serialized.
fn json_len(value: &serde_json::Value) -> std::result::Result<usize, serde_json::Error> {
    Ok(serde_json::to_vec(value)?.len())
}

/// The detection serialized, shortened to [`MAX_DETECTION_BODY_BYTES`] when it is over. **The result
/// is never over the limit.**
///
/// A process controls fields of the events a detection carries (an argv it padded to megabytes),
/// and a field a process controls is bounded by truncation, never by rejection: the detection is
/// still sent. The steps, each only if the body is still too big:
/// 1. the strings and arrays of the events are cut, by [`SHORTEN_STEPS`] down to 32 bytes and 4
///    items, never under [`PROTECTED_KEYS`] (image hash and paths, pid, user);
/// 2. events are dropped from the end, the first kept, each measured once;
/// 3. the first event is replaced by its identity (the protected keys only);
/// 4. the events are removed.
///
/// Title, source, techniques, severity, score and the key are kept (the title is cut to the
/// server's own limit, and starts with a note of how many bytes the events had, so the note
/// survives a title that is long; source, techniques and attributions are bounded, which is
/// what makes step 4 enough). The result is a pure function of the detection, so a retry of the
/// same record sends the same bytes (the server hashes the body against the key).
///
/// # Errors
/// Returns the serialization error of the detection.
pub fn fit_detection_to_limit(
    detection: &Detection,
) -> std::result::Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(detection)?;
    if body.len() <= MAX_DETECTION_BODY_BYTES {
        return Ok(body);
    }
    let original = body.len();
    drop(body);
    let mut value = serde_json::to_value(detection)?;

    let note = format!("[events shortened from {original} bytes] ");
    if let Some(title) = value.get_mut("title")
        && let Some(text) = title.as_str()
    {
        let mut text = text.to_owned();
        cut_string(&mut text, TITLE_MAX_BYTES.saturating_sub(note.len()));
        *title = serde_json::Value::String(format!("{note}{text}"));
    }
    bound_small_parts(&mut value);

    let mut events = match value.get_mut("events").map(serde_json::Value::take) {
        Some(serde_json::Value::Array(events)) => events,
        _ => Vec::new(),
    };
    let finish = |value: &mut serde_json::Value,
                  events: Vec<serde_json::Value>|
     -> std::result::Result<Vec<u8>, serde_json::Error> {
        value["events"] = serde_json::Value::Array(events);
        serde_json::to_vec(value)
    };

    // 1. Cut what a process pads.
    for (string_cap, array_cap) in SHORTEN_STEPS {
        for event in &mut events {
            shorten_events(event, string_cap, array_cap);
        }
        let body = finish(&mut value, events.clone())?;
        if body.len() <= MAX_DETECTION_BODY_BYTES {
            return Ok(body);
        }
    }

    // 2. Drop events from the end, the first kept: measure every event once and keep the longest
    // prefix that fits.
    value["events"] = serde_json::Value::Array(Vec::new());
    let fixed = json_len(&value)?;
    let mut total = fixed;
    let mut keep = 0usize;
    for event in &events {
        let size = json_len(event)? + usize::from(keep > 0);
        if total + size > MAX_DETECTION_BODY_BYTES {
            break;
        }
        total += size;
        keep += 1;
    }
    if keep > 0 {
        events.truncate(keep);
        return finish(&mut value, events);
    }

    // 3. Not even one event fits: the first one, reduced to its identity.
    if let Some(first) = events.first() {
        let stub = vec![identity_of(first)];
        let body = finish(&mut value, stub)?;
        if body.len() <= MAX_DETECTION_BODY_BYTES {
            return Ok(body);
        }
    }

    // 4. Without events: bounded by construction (title, source, techniques, attributions). Checked
    // all the same: an oversize body is never returned, it is a serialization error the caller
    // drops and counts like any record that cannot be sent.
    let body = finish(&mut value, Vec::new())?;
    if body.len() > MAX_DETECTION_BODY_BYTES {
        return Err(serde::ser::Error::custom(
            "detection over the body limit even without its events",
        ));
    }
    Ok(body)
}

/// Uploads detections one at a time, preserving each record's retry key.
pub struct DetectionUploader<D: DetectionDrain> {
    client: TransportClient,
    drain: D,
    config: TransportConfig,
    consecutive_failures: u32,
}

impl<D: DetectionDrain> DetectionUploader<D> {
    /// Creates an uploader for a durable detection drain.
    pub fn new(client: TransportClient, drain: D) -> Self {
        let config = client.config().clone();
        Self {
            client,
            drain,
            config,
            consecutive_failures: 0,
        }
    }

    /// Uploads the oldest segment. A lost response leaves it in flight; retry
    /// reuses the same keys, so the server acknowledges already-stored records.
    /// Network failures never discard a segment.
    ///
    /// A detection over the server's body limit is shortened to fit, not dropped
    /// ([`fit_detection_to_limit`]). A record the server refuses for good (see [`refuses_this_record`]) is
    /// dropped on its own, logged with its key, and the rest of the segment is uploaded: one bad
    /// record must not take with it the unrelated detections spooled in the same segment
    /// (#1119). The drops are counted once, when the segment is acknowledged, so a retry of the
    /// segment does not count them again. Any other error leaves the segment spooled and the loop
    /// backs off: a failure that is not about this record (a certificate or authentication
    /// error, a route or TLS problem) does not erase the detection.
    ///
    /// Returns the number of records handled: accepted by the server, or dropped one by one. It is `0`
    /// only for an empty spool.
    ///
    /// # Errors
    /// Returns an upload or spool error.
    pub fn upload_once(&mut self) -> Result<usize> {
        let records = self.drain.drain()?;
        if records.is_empty() {
            // A malformed segment can deserialize to zero records while still
            // becoming in-flight. `skip` is a no-op for a truly empty spool.
            self.drain.skip()?;
            return Ok(0);
        }
        let mut uploaded = 0usize;
        let mut dropped = 0u64;
        for record in &records {
            let body = match fit_detection_to_limit(&record.detection) {
                Ok(body) => body,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        key = %record.key,
                        "detection cannot be serialized; dropped, the rest of its segment goes on"
                    );
                    dropped += 1;
                    continue;
                }
            };
            match self.client.upload_detection_bytes(&body, &record.key) {
                Ok(()) => uploaded += 1,
                Err(error) if refuses_this_record(&error) => {
                    tracing::warn!(
                        error = %error,
                        key = %record.key,
                        "server refused a detection for good; dropped, the rest of its segment goes on"
                    );
                    dropped += 1;
                }
                Err(error) => {
                    // Nothing here says the record is bad: either the failure is transient, or it
                    // is about the whole agent (a certificate that does not verify, a rotated CA,
                    // a `401`/`403`, a route or TLS problem). Skipping would erase the detection,
                    // and every one behind it in turn, in seconds during a certificate rotation:
                    // the segment stays spooled and the loop backs off. The spool's byte cap sheds
                    // the oldest if this lasts.
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                    if error.is_retryable() {
                        tracing::warn!(error = %error, "detection upload failed; segment remains spooled");
                    } else {
                        tracing::warn!(error = %error, "server refused the upload for a reason that is not about this detection (certificate, authentication, route); segment remains spooled, retrying with backoff");
                    }
                    return Err(error);
                }
            }
        }
        self.drain.ack_dropping(dropped)?;
        self.consecutive_failures = 0;
        // Records handled, the dropped ones included: `0` means an empty spool to the upload loop,
        // which sleeps a poll interval, so a segment of refused records must not return it.
        Ok(uploaded + usize::try_from(dropped).unwrap_or(usize::MAX))
    }

    /// Exponential retry delay, capped by the transport configuration.
    #[must_use]
    pub fn backoff_duration(&self) -> Duration {
        if self.consecutive_failures == 0 {
            return Duration::ZERO;
        }
        let base = self.config.retry_base.as_millis() as u64;
        let cap = self.config.retry_max.as_millis() as u64;
        Duration::from_millis(
            base.saturating_mul(1 << (self.consecutive_failures - 1).min(10))
                .min(cap),
        )
    }
}

impl<D: DetectionDrain> UploadStep for DetectionUploader<D> {
    fn upload_once(&mut self) -> Result<usize> {
        DetectionUploader::upload_once(self)
    }

    fn backoff_duration(&self) -> Duration {
        DetectionUploader::backoff_duration(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(status: u16, message: &str) -> TransportError {
        TransportError::ServerError {
            status,
            message: message.to_owned(),
        }
    }

    #[test]
    fn a_serialization_error_is_about_the_record() {
        let error = serde_json::from_str::<u8>("x").unwrap_err();
        assert!(refuses_this_record(&TransportError::Serialization(error)));
    }

    #[test]
    fn only_record_level_statuses_are_per_record() {
        for (code, message, expected) in [
            (400, "Invalid payload", true),
            (400, "Invalid certificate subject", false),
            (409, "", true),
            (413, "", true),
            (422, "", true),
            (401, "", false),
            (403, "", false),
            (404, "", false),
            (429, "", false),
        ] {
            assert_eq!(
                refuses_this_record(&status(code, message)),
                expected,
                "{code} {message}"
            );
        }
    }
}
