//! Secrets in HTTP headers given on a command line.

use super::options::push_value_edit;
use super::secrets::is_secret_key;
use super::tokens::{token_ranges, trim_quotes};

pub(super) fn header_secret_value(token: &str, offset: usize) -> Option<(usize, usize)> {
    let (base, end) = trim_quotes(token, 0, token.len());
    let token = &token[base..end];
    let offset = offset + base;
    let colon = token.find(':')?;
    let key = token[..colon]
        .trim_matches(['\'', '"', ' '])
        .to_ascii_lowercase();
    if !matches!(
        key.as_str(),
        "authorization" | "proxy-authorization" | "cookie"
    ) && !is_secret_key(&key.replace('-', "_"))
    {
        return None;
    }
    let mut start = colon + 1;
    while let Some(ch) = token[start..].chars().next() {
        if !ch.is_whitespace() {
            break;
        }
        start += ch.len_utf8();
    }
    let value_start = if key.ends_with("authorization") {
        let rest = &token[start..];
        if is_authorization_scheme(rest) {
            return None;
        }
        if let Some((relative, whitespace)) = rest.char_indices().find(|(_, ch)| ch.is_whitespace())
        {
            let mut after_scheme = start + relative + whitespace.len_utf8();
            while let Some(ch) = token[after_scheme..].chars().next() {
                if !ch.is_whitespace() {
                    break;
                }
                after_scheme += ch.len_utf8();
            }
            after_scheme
        } else {
            start
        }
    } else {
        start
    };
    if value_start < token.len() {
        Some((offset + value_start, offset + token.len()))
    } else {
        None
    }
}

pub(super) fn is_authorization_scheme(value: &str) -> bool {
    ["basic", "bearer", "digest", "negotiate", "ntlm"]
        .iter()
        .any(|scheme| value.eq_ignore_ascii_case(scheme))
}

pub(super) fn add_header_edits(input: &str, windows: bool, edits: &mut Vec<(usize, usize)>) {
    let tokens = token_ranges(input, windows);
    for (index, &(start, end)) in tokens.iter().enumerate() {
        let token = &input[start..end];
        let (base, token_end) = trim_quotes(token, 0, token.len());
        let mut header = &token[base..token_end];
        let mut header_offset = start + base;
        if let Some(rest) = header.strip_prefix("--header=") {
            header_offset += header.len() - rest.len();
            header = rest;
        } else if let Some(rest) = header.strip_prefix("-H") {
            header_offset += header.len() - rest.len();
            header = rest;
        } else if header.eq_ignore_ascii_case("-H") || header.eq_ignore_ascii_case("--header") {
            let Some(&(next_start, next_end)) = tokens.get(index + 1) else {
                continue;
            };
            header = &input[next_start..next_end];
            header_offset = next_start;
        }
        if let Some((value_start, value_end)) = header_secret_value(header, header_offset) {
            push_value_edit(input, value_start, value_end, edits);
        }
        let Some(colon) = header.find(':') else {
            continue;
        };
        let key = header[..colon]
            .trim_matches(['\'', '"', ' '])
            .to_ascii_lowercase();
        if !matches!(
            key.as_str(),
            "authorization" | "proxy-authorization" | "cookie"
        ) && !is_secret_key(&key.replace('-', "_"))
        {
            continue;
        }
        let mut rest_start = colon + 1;
        while let Some(ch) = header[rest_start..].chars().next() {
            if !ch.is_whitespace() {
                break;
            }
            rest_start += ch.len_utf8();
        }
        let rest = &header[rest_start..];
        let next_secret = if key.ends_with("authorization") {
            if rest.is_empty() {
                let Some(next) = index.checked_add(1) else {
                    continue;
                };
                match tokens.get(next) {
                    Some(&(next_start, next_end))
                        if is_authorization_scheme(&input[next_start..next_end]) =>
                    {
                        next.checked_add(1).filter(|&secret| secret < tokens.len())
                    }
                    Some(_)
                        if next
                            .checked_add(1)
                            .is_some_and(|secret| secret < tokens.len()) =>
                    {
                        next.checked_add(1)
                    }
                    Some(_) => Some(next),
                    None => None,
                }
            } else if is_authorization_scheme(rest) {
                index.checked_add(1)
            } else {
                None
            }
        } else if rest.is_empty() {
            index.checked_add(1)
        } else {
            None
        };
        if let Some((secret_start, secret_end)) =
            next_secret.and_then(|next| tokens.get(next).copied())
        {
            push_value_edit(input, secret_start, secret_end, edits);
        }
    }
}
