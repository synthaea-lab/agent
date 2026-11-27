//! Redacting a command line held as an argument vector.

use super::{
    REDACTED,
    cmdline::redact_command_line,
    form::redact_form_data,
    headers::header_secret_value,
    net::{NetMode, net_password_argv_index, net_subcommand_argv},
    options::{credential_option, should_redact_next},
    tokens::{image_name, token_ranges},
    url::{redact_url_secrets, url_range},
};

/// Redacts recognized secrets in argv in place while retaining its number and order
/// of arguments.
pub fn redact_argv(image: &str, argv: &mut [String]) {
    redact_argv_inner(image, argv, 0);
}

pub(super) fn redact_argv_inner(image: &str, argv: &mut [String], wrapper_depth: u8) {
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
                if let Some(eq) = token.find('=') {
                    argv[index].replace_range(eq + 1.., &redact_form_data(&token[eq + 1..]));
                } else if let Some(next) = argv.get_mut(index + 1) {
                    // Bare `-d`/`--data`/`--data-raw`/`--data-binary`/`--data-urlencode`:
                    // the value is the next argv element, not attached with `=`.
                    *next = redact_form_data(next);
                }
            } else if token.starts_with("-d") && token.len() > 2 {
                argv[index].replace_range(2.., &redact_form_data(&token[2..]));
            }
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
        // Header-shaped argv elements can arrive through options other than
        // curl's `-H`/`--header` (for example `--proxy-header`), or as ordinary
        // arguments to tools such as httpie. Match the command-line path's
        // generic header scan so these values cannot bypass redaction.
        if let Some((start, end)) = header_secret_value(&argv[index], 0) {
            argv[index].replace_range(start..end, REDACTED);
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

pub(super) fn wrapped_command_argv_index(argv: &[String]) -> Option<usize> {
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
        "powershell" | "pwsh" | "powershell.exe" | "pwsh.exe"
            if argv.get(i).is_some_and(|s| {
                s.eq_ignore_ascii_case("-command") || s.eq_ignore_ascii_case("-c")
            }) =>
        {
            i += 1;
        }
        "powershell" | "pwsh" | "powershell.exe" | "pwsh.exe" => return None,
        _ => return None,
    }
    (i < argv.len()).then_some(i)
}
