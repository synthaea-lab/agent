//! Redacting a command line held as one string.

use std::borrow::Cow;

use super::{
    REDACTED,
    form::add_form_edits,
    headers::{add_header_edits, header_secret_value},
    net::{NetMode, net_password_index, net_subcommand},
    options::{credential_option, push_value_edit, should_redact_next},
    tokens::{image_name, token_ranges, trim_quotes, uses_windows_quotes},
    url::{redact_url_secrets, redacted_keeping_quotes, url_range},
};

/// Redacts well-known command-line credential forms without reformatting the line.
/// Detection must consume the original event; call this only on copies at output
/// boundaries. Unsupported positional/encoded forms are documented there.
#[must_use]
pub fn redact_command_line<'a>(image: &str, cmdline: &'a str) -> Cow<'a, str> {
    redact_command_line_inner(image, cmdline, 0, 0, redacted_keeping_quotes)
}

/// [`redact_command_line`] with the function that writes a redacted value: free command
/// text (`text`) also keeps escape characters, whose dialect a command line does not have.
pub(super) fn redact_command_line_with<'a>(
    image: &str,
    cmdline: &'a str,
    redacted: fn(&str) -> String,
) -> Cow<'a, str> {
    redact_command_line_inner(image, cmdline, 0, 0, redacted)
}

pub(super) fn redact_command_line_inner<'a>(
    image: &str,
    cmdline: &'a str,
    shell_depth: u8,
    wrapper_depth: u8,
    redacted: fn(&str) -> String,
) -> Cow<'a, str> {
    let tool = image_name(image);
    let tokens = token_ranges(cmdline, uses_windows_quotes(image));
    if wrapper_depth < 8
        && let Some((start, end)) = wrapped_command_range(cmdline, &tokens)
    {
        let first = tokens
            .first()
            .map(|&(s, e)| cmdline[s..e].trim_matches(['"', '\'']).to_ascii_lowercase())
            .unwrap_or_default();
        let is_shell = matches!(
            first.as_str(),
            "sh" | "bash" | "zsh" | "dash" | "powershell" | "pwsh" | "powershell.exe" | "pwsh.exe"
        );
        let (inner_start, inner_end) = trim_quotes(cmdline, start, end);
        let inner = &cmdline[inner_start..inner_end];
        let inner_tokens = token_ranges(inner, false);
        let inner_image = inner_tokens
            .first()
            .map(|&(s, e)| &inner[s..e])
            .unwrap_or("");
        if is_shell && shell_depth >= 1 {
            // One shell-string layer is parsed; deeper command languages are opaque.
        } else {
            let safe = redact_command_line_inner(
                inner_image,
                inner,
                shell_depth + u8::from(is_shell),
                wrapper_depth + 1,
                redacted,
            )
            .into_owned();
            if safe != inner {
                let mut out =
                    String::with_capacity(cmdline.len() + safe.len().saturating_sub(inner.len()));
                out.push_str(&cmdline[..inner_start]);
                out.push_str(&safe);
                out.push_str(&cmdline[inner_end..]);
                return Cow::Owned(out);
            }
        }
    }
    let mut edits = Vec::<(usize, usize)>::new();
    let mut redact_next = false;
    let mut positional_net = net_subcommand(&tool, &tokens, cmdline);

    for (index, &(start, end)) in tokens.iter().enumerate() {
        let token = &cmdline[start..end];
        let effective_tool = if tool == "docker"
            && tokens
                .get(1)
                .is_some_and(|&(s, e)| cmdline[s..e].eq_ignore_ascii_case("login"))
        {
            "docker-login"
        } else {
            &tool
        };
        if redact_next {
            let previous = index
                .checked_sub(1)
                .and_then(|i| tokens.get(i))
                .map(|&(s, e)| &cmdline[s..e]);
            if tool == "openssl"
                && previous.is_some_and(|flag| matches!(flag, "-pass" | "-passin" | "-passout"))
                && cmdline[start..end].starts_with("pass:")
            {
                push_value_edit(cmdline, start + 5, end, &mut edits);
            } else if tool == "smbclient"
                && previous.is_some_and(|flag| flag.eq_ignore_ascii_case("-u"))
                && let Some(percent) = cmdline[start..end].find('%')
            {
                push_value_edit(cmdline, start + percent + 1, end, &mut edits);
            } else {
                push_value_edit(cmdline, start, end, &mut edits);
            }
            redact_next = false;
            continue;
        }

        if let Some(attached) = credential_option(effective_tool, token) {
            if let Some((value_start, value_end)) = attached {
                push_value_edit(cmdline, start + value_start, start + value_end, &mut edits);
            } else if index + 1 < tokens.len()
                && should_redact_next(
                    effective_tool,
                    token,
                    &cmdline[tokens[index + 1].0..tokens[index + 1].1],
                )
            {
                redact_next = true;
            }
        }

        if effective_tool == "curl" {
            if token == "-d" {
                if let Some(&(ds, de)) = tokens.get(index + 1) {
                    add_form_edits(cmdline, ds, de, &mut edits);
                }
            } else if token.starts_with("--data") {
                if let Some(equal) = token.find('=') {
                    add_form_edits(cmdline, start + equal + 1, end, &mut edits);
                } else if let Some(&(ds, de)) = tokens.get(index + 1) {
                    add_form_edits(cmdline, ds, de, &mut edits);
                }
            } else if token.starts_with("-d") && token.len() > 2 {
                add_form_edits(cmdline, start + 2, end, &mut edits);
            }
        }

        if let Some((value_start, value_end)) = header_secret_value(token, start) {
            push_value_edit(cmdline, value_start, value_end, &mut edits);
        }
        if token.contains("://")
            && let Some((url_start, url_end)) = url_range(token, start)
        {
            let url = &cmdline[url_start..url_end];
            let redacted = redact_url_secrets(url);
            if redacted != url {
                // Record the complete URL and apply the existing URL scrubber below.
                edits.push((url_start, url_end));
            }
        }

        if let Some(mode) = positional_net
            && let Some(next) = net_password_index(mode, index, &tokens, cmdline)
        {
            let (ps, pe) = tokens[next];
            push_value_edit(cmdline, ps, pe, &mut edits);
            positional_net = Some(NetMode::Done);
        }
    }
    add_header_edits(cmdline, uses_windows_quotes(image), &mut edits);

    let mut out = String::with_capacity(cmdline.len().saturating_add(edits.len() * REDACTED.len()));
    let mut cursor = 0;
    edits.sort_unstable();
    edits.dedup();
    for (start, end) in edits {
        if start < cursor || start >= end || end > cmdline.len() {
            continue;
        }
        out.push_str(&cmdline[cursor..start]);
        // URL edits are replaced by the existing URL scrubber; all other edits
        // replace only the value, retaining quote characters around it.
        let original = &cmdline[start..end];
        if original.contains("://") {
            out.push_str(&redact_url_secrets(original));
        } else {
            out.push_str(&redacted(original));
        }
        cursor = end;
    }
    if cursor == 0 {
        return Cow::Borrowed(cmdline);
    }
    out.push_str(&cmdline[cursor..]);
    Cow::Owned(out)
}

pub(super) fn wrapped_command_range(
    line: &str,
    tokens: &[(usize, usize)],
) -> Option<(usize, usize)> {
    let arg = |i: usize| tokens.get(i).map(|&(s, e)| &line[s..e]);
    if tokens.is_empty() {
        return None;
    }
    let first = arg(0)?.trim_matches(['"', '\'']).to_ascii_lowercase();
    let mut i = 1;
    match first.as_str() {
        "sudo" | "doas" | "nohup" => {
            while let Some(option) = arg(i) {
                if !option.starts_with('-') {
                    break;
                }
                if matches!(
                    option,
                    "-u" | "-g"
                        | "-h"
                        | "-p"
                        | "-C"
                        | "-T"
                        | "--user"
                        | "--group"
                        | "--host"
                        | "--prompt"
                        | "--chdir"
                        | "--close-from"
                        | "--command-timeout"
                ) {
                    i += 1;
                }
                i += 1;
            }
        }
        "env" => {
            while let Some(option) = arg(i) {
                if option.starts_with('-') {
                    if matches!(option, "-u" | "--unset") {
                        i += 1;
                    }
                    i += 1;
                } else if option.contains('=') {
                    i += 1;
                } else {
                    break;
                }
            }
        }
        "timeout" => {
            while let Some(option) = arg(i).filter(|s| s.starts_with('-')) {
                if matches!(option, "-k" | "--kill-after" | "-s" | "--signal") {
                    i += 1;
                }
                i += 1;
            }
            if arg(i).is_some() {
                i += 1;
            }
        }
        "nice" => {
            if matches!(arg(i), Some("-n" | "--adjustment")) {
                i += 2;
            }
        }
        "cmd" | "cmd.exe" => {
            if matches!(
                arg(i).map(str::to_ascii_lowercase).as_deref(),
                Some("/c" | "/k")
            ) {
                i += 1;
            } else {
                return None;
            }
        }
        "sh" | "bash" | "zsh" | "dash" => {
            if arg(i) == Some("-c") {
                i += 1;
            } else {
                return None;
            }
        }
        "powershell" | "pwsh" | "powershell.exe" | "pwsh.exe"
            if arg(i).is_some_and(|s| {
                s.eq_ignore_ascii_case("-command") || s.eq_ignore_ascii_case("-c")
            }) =>
        {
            i += 1;
        }
        "powershell" | "pwsh" | "powershell.exe" | "pwsh.exe" => return None,
        _ => return None,
    }
    let &(start, end) = tokens.get(i)?;
    // A quoted wrapped command (`cmd /c "net user bob S3cret /add" && echo
    // done`) is already one token with its own matching closing quote;
    // spanning to the end of the line would swallow `&& echo done` too and
    // leave `trim_quotes` looking for a closing quote at the very end of the
    // line, which isn't there, so nothing downstream gets redacted (#843
    // review). Only an unquoted wrapped command, where the rest of the line
    // really is the command, needs the wider span.
    if matches!(line.as_bytes()[start], b'"' | b'\'') {
        Some((start, end))
    } else {
        Some((start, line.len()))
    }
}
