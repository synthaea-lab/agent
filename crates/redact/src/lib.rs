//! Pure credential-redaction helpers shared by the agent and runnable without platform runtimes.

use std::borrow::Cow;

/// Replacement marker used for every recognized secret value.
pub const REDACTED: &str = "REDACTED";

/// Parameter names that are secrets whole. Matched case-insensitively.
const SECRET_KEYS: &[&str] = &["sig", "code", "pwd", "pass", "sid", "jwt"];

/// Substrings that mark a parameter name as a secret: `X-Amz-Signature`,
/// `X-Goog-Credential`, `X-Amz-Security-Token`, `access_token`,
/// `client_secret`, `password`, `sessionid`, `PHPSESSID`, …
const SECRET_KEY_PARTS: &[&str] = &[
    "signature",
    "token",
    "secret",
    "passw",
    "credential",
    "session",
    "sessid",
    "authoriz",
    "cookie",
    "passphrase",
];

/// Suffixes that mark a parameter name as a secret: `api_key`, `apikey`,
/// `x-api-key`, `oauth_consumer_key`, `AWSAccessKeyId`, `auth`, `oauth`, and
/// SharePoint/OneDrive's `tempauth` bearer token on `download.aspx` links, the
/// most common download source on a managed Windows fleet (#550 review).
const SECRET_KEY_SUFFIXES: &[&str] = &["key", "keyid", "auth"];

/// Redacts well-known command-line credential forms without reformatting the line.
/// Detection must consume the original event; call this only on copies at output
/// boundaries (ADR-0034). Unsupported positional/encoded forms are documented there.
#[must_use]
pub fn redact_command_line<'a>(image: &str, cmdline: &'a str) -> Cow<'a, str> {
    redact_command_line_inner(image, cmdline, 0, 0)
}

fn redact_command_line_inner<'a>(
    image: &str,
    cmdline: &'a str,
    shell_depth: u8,
    wrapper_depth: u8,
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
            out.push_str(&redacted_keeping_quotes(original));
        }
        cursor = end;
    }
    if cursor == 0 {
        return Cow::Borrowed(cmdline);
    }
    out.push_str(&cmdline[cursor..]);
    Cow::Owned(out)
}

fn wrapped_command_range(line: &str, tokens: &[(usize, usize)]) -> Option<(usize, usize)> {
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
                return tokens.get(i).copied();
            }
            return None;
        }
        "sh" | "bash" | "zsh" | "dash" => {
            if arg(i) == Some("-c") {
                i += 1;
                return tokens.get(i).copied();
            }
            return None;
        }
        "powershell" | "pwsh" | "powershell.exe" | "pwsh.exe" => {
            if arg(i)
                .is_some_and(|s| s.eq_ignore_ascii_case("-command") || s.eq_ignore_ascii_case("-c"))
            {
                i += 1;
                return tokens.get(i).copied();
            }
            return None;
        }
        _ => return None,
    }
    tokens.get(i).map(|&(start, _)| (start, line.len()))
}

/// Redacts recognized secrets in argv in place while retaining its number and order
/// of arguments.
pub fn redact_argv(image: &str, argv: &mut [String]) {
    redact_argv_inner(image, argv, 0);
}

fn redact_argv_inner(image: &str, argv: &mut [String], wrapper_depth: u8) {
    if wrapper_depth < 8
        && let Some(target) = wrapped_command_argv_index(argv)
    {
        let wrapper = argv.first().map(|s| image_name(s)).unwrap_or_default();
        if matches!(
            wrapper.as_str(),
            "sh" | "bash" | "zsh" | "dash" | "powershell" | "pwsh" | "cmd" | "cmd.exe"
        ) {
            if target + 1 == argv.len() && argv[target].contains(char::is_whitespace) {
                let command = argv[target].clone();
                let nested = token_ranges(&command, false);
                let inner_image = nested.first().map(|&(s, e)| &command[s..e]).unwrap_or("");
                argv[target] = redact_command_line(inner_image, &command).into_owned();
            } else {
                let command_image = argv[target].clone();
                redact_argv_inner(&command_image, &mut argv[target..], wrapper_depth + 1);
            }
        } else {
            let command_image = argv[target].clone();
            redact_argv_inner(&command_image, &mut argv[target..], wrapper_depth + 1);
        }
        return;
    }
    let tool = image_name(image);
    let mut redact_next = false;
    let mut net_mode = None;
    for index in 0..argv.len() {
        if redact_next {
            let previous = index.checked_sub(1).map(|i| argv[i].as_str());
            if tool == "openssl"
                && previous.is_some_and(|flag| matches!(flag, "-pass" | "-passin" | "-passout"))
                && argv[index].starts_with("pass:")
            {
                argv[index].replace_range(5.., REDACTED);
            } else if tool == "smbclient"
                && previous.is_some_and(|flag| flag.eq_ignore_ascii_case("-u"))
                && let Some(percent) = argv[index].find('%')
            {
                argv[index].replace_range(percent + 1.., REDACTED);
            } else if argv[index] != REDACTED {
                argv[index] = REDACTED.to_owned();
            }
            redact_next = false;
            continue;
        }
        let effective_tool = if tool == "docker"
            && argv
                .get(1)
                .is_some_and(|arg| arg.eq_ignore_ascii_case("login"))
        {
            "docker-login"
        } else {
            &tool
        };
        let token = argv[index].clone();
        if let Some(attached) = credential_option(effective_tool, &token) {
            if let Some((start, end)) = attached {
                argv[index].replace_range(start..end, REDACTED);
            } else if index + 1 < argv.len()
                && should_redact_next(effective_tool, &token, &argv[index + 1])
            {
                redact_next = true;
            }
        }
        if effective_tool == "curl" {
            if token == "-d" || token.starts_with("--data") {
                if token == "-d" {
                    if let Some(next) = argv.get_mut(index + 1) {
                        *next = redact_form_data(next);
                    }
                } else if let Some(eq) = token.find('=') {
                    argv[index].replace_range(eq + 1.., &redact_form_data(&token[eq + 1..]));
                }
            } else if token.starts_with("-d") && token.len() > 2 {
                argv[index].replace_range(2.., &redact_form_data(&token[2..]));
            }
        }
        if let Some((start, end)) = header_secret_value(&argv[index], 0) {
            argv[index].replace_range(start..end, REDACTED);
        }
        let attached_header = token
            .strip_prefix("--header=")
            .map(|header| (index, token.len() - header.len()))
            .or_else(|| {
                token
                    .strip_prefix("-H")
                    .filter(|header| !header.is_empty())
                    .map(|header| (index, token.len() - header.len()))
            });
        let separate_header =
            if matches!(token.as_str(), "-H" | "--header") && index + 1 < argv.len() {
                Some(index + 1)
            } else {
                None
            };
        if let Some((header_index, prefix)) = attached_header {
            let header = argv[header_index][prefix..].to_owned();
            if let Some((start, end)) = header_secret_value(&header, 0) {
                argv[header_index].replace_range(prefix + start..prefix + end, REDACTED);
            }
        } else if let Some(header_index) = separate_header {
            let header = argv[header_index].clone();
            if let Some((start, end)) = header_secret_value(&header, 0) {
                argv[header_index].replace_range(start..end, REDACTED);
            }
        }
        if argv[index].contains("://")
            && let Some((start, end)) = url_range(&argv[index], 0)
        {
            let url = &argv[index][start..end];
            let redacted = redact_url_secrets(url);
            if redacted != url {
                argv[index].replace_range(start..end, &redacted);
            }
        }
        if net_mode.is_none() {
            net_mode = net_subcommand_argv(&tool, argv);
        }
        let is_net_password = net_mode
            .and_then(|mode| net_password_argv_index(mode, argv))
            .is_some_and(|password_index| index == password_index);
        if is_net_password && !argv[index].starts_with('/') && argv[index] != "*" {
            argv[index] = REDACTED.to_owned();
            net_mode = Some(NetMode::Done);
        }
    }
}

fn net_password_argv_index(mode: NetMode, argv: &[String]) -> Option<usize> {
    match mode {
        NetMode::User if argv.len() > 3 => Some(3),
        NetMode::Use => {
            let unc_index = (2..argv.len()).find(|&i| argv[i].starts_with("\\\\"))?;
            ((unc_index + 1)..argv.len()).find(|&i| !argv[i].starts_with('/') && argv[i] != "*")
        }
        _ => None,
    }
}

fn wrapped_command_argv_index(argv: &[String]) -> Option<usize> {
    let first = image_name(argv.first()?);
    let mut i = 1;
    match first.as_str() {
        "sudo" | "doas" | "nohup" => {
            while let Some(option) = argv.get(i) {
                if !option.starts_with('-') {
                    break;
                }
                if matches!(
                    option.as_str(),
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
            while let Some(option) = argv.get(i) {
                if option.starts_with('-') {
                    if matches!(option.as_str(), "-u" | "--unset") {
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
            while argv.get(i).is_some_and(|s| s.starts_with('-')) {
                if matches!(argv[i].as_str(), "-k" | "--kill-after" | "-s" | "--signal") {
                    i += 1;
                }
                i += 1;
            }
            if argv.get(i).is_some() {
                i += 1;
            }
        }
        "nice" => {
            if argv
                .get(i)
                .is_some_and(|s| s == "-n" || s == "--adjustment")
            {
                i += 2;
            }
        }
        "cmd" | "cmd.exe" => {
            if argv
                .get(i)
                .is_some_and(|s| s.eq_ignore_ascii_case("/c") || s.eq_ignore_ascii_case("/k"))
            {
                i += 1;
            }
        }
        "sh" | "bash" | "zsh" | "dash" => {
            if argv.get(i).is_some_and(|s| s == "-c") {
                i += 1;
            } else {
                return None;
            }
        }
        "powershell" | "pwsh" | "powershell.exe" | "pwsh.exe" => {
            if argv
                .get(i)
                .is_some_and(|s| s.eq_ignore_ascii_case("-command") || s.eq_ignore_ascii_case("-c"))
            {
                i += 1;
            } else {
                return None;
            }
        }
        _ => return None,
    }
    (i < argv.len()).then_some(i)
}

fn add_form_edits(input: &str, start: usize, end: usize, edits: &mut Vec<(usize, usize)>) {
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

fn redact_form_data(body: &str) -> String {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum NetMode {
    Use,
    User,
    Done,
}

fn image_name(image: &str) -> String {
    let name = image.rsplit(['/', '\\']).next().unwrap_or(image);
    let name = if name.to_ascii_lowercase().ends_with(".exe") {
        &name[..name.len() - 4]
    } else {
        name
    };
    name.to_ascii_lowercase()
}

fn uses_windows_quotes(image: &str) -> bool {
    image.contains('\\') || image.to_ascii_lowercase().ends_with(".exe")
}

fn token_ranges(input: &str, windows: bool) -> Vec<(usize, usize)> {
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

fn trim_quotes(input: &str, start: usize, end: usize) -> (usize, usize) {
    if end > start + 1 {
        let bytes = input.as_bytes();
        if matches!(bytes[start], b'\'' | b'"') && bytes[end - 1] == bytes[start] {
            return (start + 1, end - 1);
        }
    }
    (start, end)
}

fn push_value_edit(input: &str, start: usize, end: usize, edits: &mut Vec<(usize, usize)>) {
    let (start, end) = trim_quotes(input, start, end);
    if start < end && &input[start..end] != REDACTED {
        edits.push((start, end));
    }
}

fn credential_option(tool: &str, token: &str) -> Option<Option<(usize, usize)>> {
    let (base, end) = trim_quotes(token, 0, token.len());
    let value = &token[base..end];
    if !value.starts_with(['-', '/']) {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("--") {
        let name_end = lower.find('=').unwrap_or(lower.len());
        let key = lower[2..name_end].replace('-', "_");
        if !key.ends_with("_file") && is_secret_key(&key) {
            if name_end < lower.len() {
                return Some(Some((base + name_end + 1, end)));
            }
            if matches!(
                tool,
                "mysql" | "mariadb" | "mysqldump" | "mysqladmin" | "mysqlimport"
            ) && matches!(key.as_str(), "password" | "passwd")
            {
                return None;
            }
            return Some(None);
        }
    }
    if tool == "cmdkey" && lower.starts_with("/pass:") {
        return Some(Some((base + 6, end)));
    }
    if tool == "openssl" && matches!(lower.as_str(), "-pass" | "-passin" | "-passout") {
        return Some(None);
    }
    if tool == "smbclient" && lower == "-u" {
        return Some(None);
    }
    if tool == "smbclient"
        && value.starts_with("-U")
        && let Some(percent) = value.find('%')
    {
        return Some(Some((base + percent + 1, end)));
    }
    if tool == "curl" && matches!(lower.as_str(), "--proxy-user" | "-u") {
        return Some(None);
    }
    if tool == "curl" && lower.starts_with("--proxy-user=") {
        return Some(Some((base + 13, end)));
    }
    if tool == "curl" && (lower == "-d" || lower.starts_with("--data")) {
        return Some(None);
    }
    if tool == "zip" && value == "-p" {
        return None;
    }
    let short_p = matches!(
        tool,
        "psexec"
            | "psexec64"
            | "sshpass"
            | "docker"
            | "docker-login"
            | "ldapsearch"
            | "ldapmodify"
            | "ldapadd"
            | "redis-cli"
            | "zip"
    );
    let attached_password = matches!(
        tool,
        "mysql"
            | "mariadb"
            | "mysqldump"
            | "mysqladmin"
            | "mysqlimport"
            | "psexec"
            | "psexec64"
            | "sshpass"
            | "7z"
    );
    if short_p
        && matches!(
            (tool, lower.as_str()),
            ("psexec", "-p")
                | ("psexec64", "-p")
                | ("sshpass", "-p")
                | ("docker-login", "-p")
                | ("redis-cli", "-a")
                | ("ldapsearch", "-w")
                | ("ldapmodify", "-w")
                | ("ldapadd", "-w")
        )
    {
        return Some(None);
    }
    if tool == "zip" && value == "-P" {
        return Some(None);
    }
    if tool == "zip" && value.starts_with("-P") && value.len() > 2 {
        return Some(Some((base + 2, end)));
    }
    if tool == "docker-login" && lower.starts_with("--password=") {
        return Some(Some((base + 11, end)));
    }
    if tool == "docker-login" && lower == "--password" {
        return Some(None);
    }
    if tool == "docker-login" && value.starts_with("-p") && value.len() > 2 {
        return Some(Some((base + 2, end)));
    }
    if tool == "smbclient"
        && lower.starts_with("-u")
        && let Some(percent) = value.find('%')
    {
        return Some(Some((base + percent + 1, end)));
    }
    if tool == "openssl" && matches!(lower.as_str(), "-pass" | "-passin" | "-passout") {
        return Some(None);
    }
    if attached_password && value.starts_with("-p") && value.len() > 2 {
        return Some(Some((base + 2, end)));
    }
    if tool == "redis-cli" && value.starts_with("-a") && value.len() > 2 {
        return Some(Some((base + 2, end)));
    }
    if matches!(tool, "ldapsearch" | "ldapmodify" | "ldapadd")
        && value.starts_with("-w")
        && value.len() > 2
    {
        return Some(Some((base + 2, end)));
    }
    if tool == "smbclient"
        && value.starts_with("-U")
        && let Some(percent) = value.find('%')
    {
        return Some(Some((base + percent + 1, end)));
    }
    if tool == "curl" || tool == "wget" {
        if lower == "-u" || lower == "--user" {
            return Some(None);
        }
        if lower.starts_with("--user=") {
            return Some(Some((base + 7, end)));
        }
        if let Some(v) = lower.strip_prefix("-u")
            && !v.is_empty()
            && v.contains(':')
        {
            let offset = token.len() - value.len() + 2;
            return Some(Some((offset, end)));
        }
        if tool == "curl" && value.starts_with('-') && !value.starts_with("--") {
            let cluster = &lower[1..];
            if let Some(u) = cluster.find('u') {
                let rest = &cluster[u + 1..];
                if !rest.is_empty() {
                    return Some(Some((base + 2 + u, end)));
                }
                if u + 1 == cluster.len() {
                    return Some(None);
                }
            }
        }
        if tool == "wget"
            && ["--http-password=", "--ftp-password=", "--password="]
                .iter()
                .any(|flag| lower.starts_with(flag))
        {
            let equal = value.find('=')?;
            return Some(Some((base + equal + 1, end)));
        }
    }
    if matches!(tool, "sqlcmd" | "bcp") {
        if value == "-P" {
            return Some(None);
        }
        if value.starts_with("-P") && value.len() > 2 {
            return Some(Some((base + 2, end)));
        }
    }
    if matches!(tool, "schtasks" | "wmic") {
        for flag in ["/password:", "/pass:", "/p:", "/rp:"] {
            if lower.starts_with(flag) {
                return Some(Some((base + flag.len(), end)));
            }
        }
        if ["/password", "/pass", "/p", "/rp"].contains(&lower.as_str()) {
            return Some(None);
        }
    }
    None
}

fn should_redact_next(tool: &str, flag: &str, value: &str) -> bool {
    if tool == "curl"
        && flag.starts_with('-')
        && !flag.starts_with("--")
        && flag[1..].ends_with('u')
    {
        return value.contains(':');
    }
    if matches!(tool, "curl" | "wget") && matches!(flag, "-u" | "--user" | "--proxy-user") {
        return value.contains(':');
    }
    if tool == "curl" && (flag == "-d" || flag.starts_with("--data")) {
        return false;
    }
    if tool == "docker" && flag == "-p" {
        return false;
    }
    if value.starts_with("--") {
        return false;
    }
    true
}

fn header_secret_value(token: &str, offset: usize) -> Option<(usize, usize)> {
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

fn is_authorization_scheme(value: &str) -> bool {
    ["basic", "bearer", "digest", "negotiate", "ntlm"]
        .iter()
        .any(|scheme| value.eq_ignore_ascii_case(scheme))
}

fn add_header_edits(input: &str, windows: bool, edits: &mut Vec<(usize, usize)>) {
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

fn url_range(token: &str, offset: usize) -> Option<(usize, usize)> {
    let scheme = token.find("://")?;
    let start = token[..scheme]
        .rfind(['=', '\'', '"', ' ', '\t'])
        .map_or(0, |i| i + 1);
    let mut end = token.len();
    while end > scheme + 3 && matches!(token.as_bytes()[end - 1], b'\'' | b'"' | b',' | b')' | b']')
    {
        end -= 1;
    }
    Some((offset + start, offset + end))
}

fn net_subcommand(tool: &str, tokens: &[(usize, usize)], line: &str) -> Option<NetMode> {
    if !matches!(tool, "net" | "net1") || tokens.len() < 2 {
        return None;
    }
    net_mode_from(&line[tokens[1].0..tokens[1].1])
}
fn net_subcommand_argv(tool: &str, argv: &[String]) -> Option<NetMode> {
    if matches!(tool, "net" | "net1") && argv.len() > 1 {
        net_mode_from(&argv[1])
    } else {
        None
    }
}
fn net_mode_from(command: &str) -> Option<NetMode> {
    if command.eq_ignore_ascii_case("use") {
        Some(NetMode::Use)
    } else if command.eq_ignore_ascii_case("user") {
        Some(NetMode::User)
    } else {
        None
    }
}
fn net_password_index(
    mode: NetMode,
    index: usize,
    tokens: &[(usize, usize)],
    line: &str,
) -> Option<usize> {
    let len = tokens.len();
    let token = &line[tokens[index].0..tokens[index].1];
    if mode == NetMode::Done || index < 2 || token.starts_with('/') || token == "*" {
        return None;
    }
    match mode {
        NetMode::User => (index == 3 && len > 3).then_some(index),
        NetMode::Use => {
            let unc_index =
                (2..len).find(|&i| line[tokens[i].0..tokens[i].1].starts_with("\\\\"))?;
            ((unc_index + 1)..len)
                .find(|&i| {
                    let candidate = &line[tokens[i].0..tokens[i].1];
                    !candidate.starts_with('/') && candidate != "*"
                })
                .filter(|&password| password == index)
        }
        _ => None,
    }
}

/// Returns `url` with its userinfo, fragment, and secret query values replaced
/// by [`REDACTED`]. Anything that isn't a hierarchical URL (`about:internet`,
/// a bare path) keeps everything but a query or fragment it happens to carry.
/// Idempotent, and never panics on arbitrary input.
/// Redacts credentials in URL userinfo, fragments, and secret-named query values.
#[must_use]
pub fn redact_url_secrets(url: &str) -> String {
    // RFC 3986: the fragment starts at the first `#`, the query at the first
    // `?` before it — a `?` inside the fragment is fragment data.
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment)),
        None => (url, None),
    };
    let (base, query) = match before_fragment.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (before_fragment, None),
    };

    let mut out = String::with_capacity(url.len());
    push_without_userinfo(&mut out, base);
    if let Some(query) = query {
        out.push('?');
        push_redacted_query(&mut out, query);
    }
    if let Some(fragment) = fragment {
        out.push('#');
        if !fragment.is_empty() {
            out.push_str(&redacted_keeping_quotes(fragment));
        }
    }
    out
}

/// Pushes `base` (scheme, authority, path) with any `userinfo@` in the
/// authority replaced by [`REDACTED`]. The last `@` ends the userinfo, as in
/// browsers: `https://a@b@host/` has userinfo `a@b`.
fn push_without_userinfo(out: &mut String, base: &str) {
    let Some(scheme_end) = base.find("://") else {
        out.push_str(base);
        return;
    };
    let authority_start = scheme_end + "://".len();
    let authority_end = base[authority_start..]
        .find('/')
        .map_or(base.len(), |i| authority_start + i);
    match base[authority_start..authority_end].rfind('@') {
        Some(at) => {
            out.push_str(&base[..authority_start]);
            out.push_str(&redacted_keeping_quotes(
                &base[authority_start..authority_start + at],
            ));
            out.push_str(&base[authority_start + at..]);
        }
        None => out.push_str(base),
    }
}

/// Pushes `query` with the value of every secret-named parameter replaced by
/// [`REDACTED`]. Separators, order, valueless and empty parameters are kept
/// as they were.
/// [`REDACTED`] in place of `value`, keeping every quote character the value held:
/// the leading ones before the token, the rest after it. On a command line those
/// quotes belong to the shell's quoting; dropping one (`token="A"` →
/// `token=REDACTED"`) flips the line's quote parity, so a second pass tokenises
/// differently and redaction stops being idempotent (#843, found by the proptest
/// on CI). A value made only of quotes holds no secret and is kept as is.
fn redacted_keeping_quotes(value: &str) -> String {
    let is_quote = |c: char| c == '"' || c == '\'';
    if value.chars().all(is_quote) {
        return value.to_owned();
    }
    let rest = value.trim_start_matches(is_quote);
    let mut out = String::with_capacity(REDACTED.len() + value.len() - rest.len() + 2);
    out.push_str(&value[..value.len() - rest.len()]);
    out.push_str(REDACTED);
    out.extend(rest.chars().filter(|&c| is_quote(c)));
    out
}

fn push_redacted_query(out: &mut String, query: &str) {
    for (i, param) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match param.split_once('=') {
            Some((key, value)) if !value.is_empty() && is_secret_key(key) => {
                out.push_str(key);
                out.push('=');
                out.push_str(&redacted_keeping_quotes(value));
            }
            _ => out.push_str(param),
        }
    }
}

/// Whether a query parameter name marks its value as a credential. The name is read
/// as written and percent-decoded twice (the web-log matcher's own normalisation), so
/// `pass%77ord` and `%74oken` do not slip past.
/// Returns whether a URL query key identifies a credential.
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    is_secret_name(key) || is_secret_name(&percent_decode(&percent_decode(key)))
}

fn is_secret_name(key: &str) -> bool {
    let key = key.trim_end_matches("[]").to_ascii_lowercase();
    SECRET_KEYS.contains(&key.as_str())
        || SECRET_KEY_PARTS.iter().any(|part| key.contains(part))
        || SECRET_KEY_SUFFIXES
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

/// Percent-decodes `s` (`+` is a space); invalid escapes are kept as written.
fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        char::from(b).to_digit(16).map(|d| d as u8)
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
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
            "sh -c \"curl -u a:S3cret h\"",
            "bash -c \"curl -u a:S3cret h\"",
            "zsh -c \"curl -u a:S3cret h\"",
            "dash -c \"curl -u a:S3cret h\"",
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
            "docker run -p 8080:80 img",
            "redis-cli -h host",
            "openssl -in f -out g",
            "curl -d name=bob h",
            "curl --data name=bob h",
            "sudo -u alice ls",
            "foo --password --verbose S3cret",
        ] {
            let output =
                redact_command_line(line.split_ascii_whitespace().next().unwrap_or(""), line);
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
                "curl",
                "curl --proxy-user=a:S3cret h",
                "curl --proxy-user=REDACTED h",
            ),
            ("curl", "curl -U a:S3cret h", "curl -U REDACTED h"),
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
}
