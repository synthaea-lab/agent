//! Keeps an event upload under the control plane's body limit (#1131).
//!
//! A process controls fields of the events the agent records about it (an argv padded to
//! megabytes, #1060). The events route answers a body over its limit with a permanent `413`, and
//! dropping the segment would let a process erase the record of its own exec. So an oversized
//! event is shortened, never dropped: the fields a process pads are cut, the ones that identify
//! the event are kept, the same approach as `fit_detection_to_limit` for detections (#1122).

use schema::Event;

/// The largest body the events route reads: `MAX_BODY_BYTES` of
/// `server/app/api/ingest/events/route.ts` (4 MiB; nginx allows 8 MiB, so the handler is the
/// binding limit). A mirror, not a negotiated value: change it here when the route changes.
pub(crate) const MAX_EVENT_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Room kept in a batch body for the envelope (`agent_id`, the array brackets).
const ENVELOPE_SLACK_BYTES: usize = 1024;

/// The largest single event kept as is. Larger events are shortened, so any batch of at least
/// one event fits the limit whatever a process padded: the segment cap of the spool is 1 MiB,
/// and this is the same size.
pub(crate) const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// Keys that identify an event and that a process does not pad: never cut (the image hash
/// and paths feed the server's SHA-256 check and its image prevalence).
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

/// How hard the process-controlled fields are cut, one step after the other until the event fits:
/// (longest string in bytes, longest array in items).
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

/// Cuts the strings over `string_cap` bytes and the arrays over `array_cap` items of `value`,
/// recursively, except under [`PROTECTED_KEYS`].
fn shorten(value: &mut serde_json::Value, string_cap: usize, array_cap: usize) {
    match value {
        serde_json::Value::String(text) => cut_string(text, string_cap),
        serde_json::Value::Array(items) => {
            items.truncate(array_cap);
            for item in items {
                shorten(item, string_cap, array_cap);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                if !PROTECTED_KEYS.contains(&key.as_str()) {
                    shorten(field, string_cap, array_cap);
                }
            }
        }
        _ => {}
    }
}

/// `event` shortened to at most `limit` bytes serialized, and its size before. `None` when it
/// cannot be shortened that far (or not serialized): the caller drops and counts it. The result
/// is a pure function of the event.
fn shorten_event(event: &Event, limit: usize) -> Option<Event> {
    let mut value = serde_json::to_value(event).ok()?;
    for (string_cap, array_cap) in SHORTEN_STEPS {
        shorten(&mut value, string_cap, array_cap);
        if serde_json::to_vec(&value).ok()?.len() <= limit {
            return serde_json::from_value(value).ok();
        }
    }
    None
}

/// The batches to send for `events`: at most `batch_size` events each, and each body under
/// [`MAX_EVENT_BODY_BYTES`]. An event over [`MAX_EVENT_BYTES`] is shortened first and logged
/// with its original size; one that cannot be shortened enough is dropped and counted in the
/// second value. Order is kept.
pub(crate) fn fit_batches(events: Vec<Event>, batch_size: usize) -> (Vec<Vec<Event>>, usize) {
    let batch_size = batch_size.max(1);
    let budget = MAX_EVENT_BODY_BYTES - ENVELOPE_SLACK_BYTES;
    let mut batches: Vec<Vec<Event>> = Vec::new();
    let mut current: Vec<Event> = Vec::new();
    let mut current_bytes = 0usize;
    let mut dropped = 0usize;
    for event in events {
        let Ok(mut size) = serde_json::to_vec(&event).map(|body| body.len()) else {
            dropped += 1;
            continue;
        };
        let mut event = event;
        if size > MAX_EVENT_BYTES {
            let original = size;
            match shorten_event(&event, MAX_EVENT_BYTES) {
                Some(short) => {
                    size = serde_json::to_vec(&short).map_or(MAX_EVENT_BYTES, |body| body.len());
                    tracing::warn!(
                        original_bytes = original,
                        sent_bytes = size,
                        "event over the body limit; shortened before sending"
                    );
                    event = short;
                }
                None => {
                    tracing::warn!(
                        original_bytes = original,
                        "event cannot be shortened to the body limit; dropped"
                    );
                    dropped += 1;
                    continue;
                }
            }
        }
        // +1 for the comma between events.
        if !current.is_empty() && (current.len() >= batch_size || current_bytes + size + 1 > budget)
        {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes += size + 1;
        current.push(event);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    (batches, dropped)
}

#[cfg(test)]
mod tests {
    use schema::ExecEvent;

    use super::*;

    fn padded_exec(argv_tokens: usize, token_bytes: usize) -> Event {
        Event::Exec(ExecEvent {
            argv: vec!["\u{1}".repeat(token_bytes); argv_tokens],
            cmdline: "\u{1}".repeat(token_bytes * argv_tokens),
            image_path: "/tmp/padder".into(),
            ..schema::fixtures::exec()
        })
    }

    #[test]
    fn an_event_padded_past_the_body_limit_is_shortened_and_keeps_who_ran_what() {
        // The #1060 padded exec: 12 arguments of 100,000 bytes, serialized well past 1 MiB.
        let event = padded_exec(12, 100_000);
        let (batches, dropped) = fit_batches(vec![event], 100);
        assert_eq!(dropped, 0);
        assert_eq!(batches.len(), 1);
        let body = serde_json::to_vec(&batches[0]).unwrap();
        assert!(body.len() <= MAX_EVENT_BODY_BYTES, "{}", body.len());
        let Event::Exec(exec) = &batches[0][0] else {
            panic!("still an exec");
        };
        assert_eq!(exec.image_path, "/tmp/padder");
        assert!(!exec.argv.is_empty() && exec.cmdline.ends_with('…'));
    }

    #[test]
    fn an_event_under_the_limit_is_sent_untouched() {
        let event = padded_exec(2, 100);
        let (batches, dropped) = fit_batches(vec![event.clone()], 100);
        assert_eq!(dropped, 0);
        assert_eq!(batches, vec![vec![event]]);
    }

    #[test]
    fn a_batch_is_split_by_bytes_and_by_count_and_keeps_order() {
        // 5 events of about 1 MiB cannot share a 4 MiB body.
        let events: Vec<Event> = (0..5)
            .map(|i| {
                Event::Exec(ExecEvent {
                    cmdline: format!("{i}{}", "a".repeat(MAX_EVENT_BYTES - 2048)),
                    ..schema::fixtures::exec()
                })
            })
            .collect();
        let (batches, dropped) = fit_batches(events, 100);
        assert_eq!(dropped, 0);
        assert!(batches.len() >= 2);
        for batch in &batches {
            assert!(serde_json::to_vec(batch).unwrap().len() <= MAX_EVENT_BODY_BYTES);
        }
        let order: Vec<char> = batches
            .iter()
            .flatten()
            .map(|e| match e {
                Event::Exec(x) => x.cmdline.chars().next().unwrap(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(order, vec!['0', '1', '2', '3', '4']);

        let small: Vec<Event> = (0..5).map(|_| padded_exec(1, 10)).collect();
        let (batches, _) = fit_batches(small, 2);
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [2, 2, 1]);
    }

    #[test]
    fn cut_string_stays_on_a_character_boundary() {
        let mut text = "é".repeat(10);
        cut_string(&mut text, 8);
        assert!(text.len() <= 8 && text.ends_with('…'));
    }
}
