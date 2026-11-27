//! Splitting a command line into tokens the way its shell would, and naming the program it runs.

pub(super) fn image_name(image: &str) -> String {
    let name = image.rsplit(['/', '\\']).next().unwrap_or(image);
    let name = if name.to_ascii_lowercase().ends_with(".exe") {
        &name[..name.len() - 4]
    } else {
        name
    };
    name.to_ascii_lowercase()
}

pub(super) fn uses_windows_quotes(image: &str) -> bool {
    image.contains('\\') || image.to_ascii_lowercase().ends_with(".exe")
}

pub(super) fn token_ranges(input: &str, windows: bool) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let mut ranges = Vec::new();
    let (mut i, mut start, mut quote) = (0, None, None);
    let mut unbalanced_start = None;
    while i < bytes.len() {
        let byte = bytes[i];
        if start.is_none() && byte.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        start.get_or_insert(i);
        if windows {
            if byte == b'\\' {
                let run_start = i;
                while i < bytes.len() && bytes[i] == b'\\' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'"' {
                    if (i - run_start) % 2 == 0 {
                        if quote.is_some() {
                            quote = None;
                        } else {
                            quote = Some(b'"');
                            unbalanced_start = start;
                        }
                    }
                    i += 1;
                }
                continue;
            }
            if byte == b'"' {
                if quote.is_some() {
                    quote = None;
                } else {
                    quote = Some(b'"');
                    unbalanced_start = start;
                }
            } else if byte.is_ascii_whitespace()
                && quote.is_none()
                && let Some(token_start) = start.take()
            {
                ranges.push((token_start, i));
            }
            i += 1;
            continue;
        }
        if byte == b'\\' {
            i += 1;
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if let Some(active_quote) = quote {
            if byte == active_quote {
                quote = None;
            }
        } else if byte == b'\'' || byte == b'"' {
            if quote.is_none() {
                unbalanced_start = start;
            }
            quote = Some(byte);
        } else if byte.is_ascii_whitespace()
            && let Some(token_start) = start.take()
        {
            ranges.push((token_start, i));
        }
        i += 1;
    }
    if let Some(token_start) = start
        && quote.is_none()
    {
        ranges.push((token_start, bytes.len()));
    }
    if let (Some(_), Some(fallback_start)) = (quote, unbalanced_start) {
        ranges.retain(|(token_start, _)| *token_start < fallback_start);
        let mut pos = fallback_start;
        while pos < bytes.len() {
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos == bytes.len() {
                break;
            }
            let token_start = pos;
            while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            ranges.push((token_start, pos));
        }
    }
    ranges
}

pub(super) fn trim_quotes(input: &str, start: usize, end: usize) -> (usize, usize) {
    if end > start + 1 {
        let bytes = input.as_bytes();
        if matches!(bytes[start], b'\'' | b'"') && bytes[end - 1] == bytes[start] {
            return (start + 1, end - 1);
        }
    }
    (start, end)
}
