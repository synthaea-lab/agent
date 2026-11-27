//! The Windows `net` command, whose password is a positional argument.

pub(super) fn net_password_argv_index(mode: NetMode, argv: &[String]) -> Option<usize> {
    match mode {
        NetMode::User if argv.len() > 3 => Some(3),
        NetMode::Use => {
            let unc_index = (2..argv.len()).find(|&i| argv[i].starts_with("\\\\"))?;
            ((unc_index + 1)..argv.len()).find(|&i| !argv[i].starts_with('/') && argv[i] != "*")
        }
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NetMode {
    Use,
    User,
    Done,
}

pub(super) fn net_subcommand(tool: &str, tokens: &[(usize, usize)], line: &str) -> Option<NetMode> {
    if !matches!(tool, "net" | "net1") || tokens.len() < 2 {
        return None;
    }
    net_mode_from(&line[tokens[1].0..tokens[1].1])
}
pub(super) fn net_subcommand_argv(tool: &str, argv: &[String]) -> Option<NetMode> {
    if matches!(tool, "net" | "net1") && argv.len() > 1 {
        net_mode_from(&argv[1])
    } else {
        None
    }
}
pub(super) fn net_mode_from(command: &str) -> Option<NetMode> {
    if command.eq_ignore_ascii_case("use") {
        Some(NetMode::Use)
    } else if command.eq_ignore_ascii_case("user") {
        Some(NetMode::User)
    } else {
        None
    }
}
pub(super) fn net_password_index(
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
