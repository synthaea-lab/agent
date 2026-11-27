//! Secrets in form-encoded request bodies.

use super::{secrets::is_secret_key, url::redacted_keeping_quotes};

pub(super) fn add_form_edits(
    input: &str,
    start: usize,
    end: usize,
    edits: &mut Vec<(usize, usize)>,
) {
    if end > input.len() || start > end {
        return;
    }
    let body = &input[start..end];
    let mut base = start;
    for pair in body.split('&') {
        if let Some((key, value)) = pair.split_once('=')
            && is_secret_key(key)
            && !value.is_empty()
        {
            let value_start = base + key.len() + 1;
            edits.push((value_start, value_start + value.len()));
        }
        base += pair.len() + 1;
    }
}

pub(super) fn redact_form_data(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for (i, pair) in body.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        if let Some((key, value)) = pair.split_once('=') {
            out.push_str(key);
            out.push('=');
            if is_secret_key(key) && !value.is_empty() {
                out.push_str(&redacted_keeping_quotes(value));
            } else {
                out.push_str(value);
            }
        } else {
            out.push_str(pair);
        }
    }
    out
}
