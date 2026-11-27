//! Command-line options that take a credential, per tool.

use super::REDACTED;
use super::secrets::is_secret_key;
use super::tokens::trim_quotes;

pub(super) fn push_value_edit(
    input: &str,
    start: usize,
    end: usize,
    edits: &mut Vec<(usize, usize)>,
) {
    let (start, end) = trim_quotes(input, start, end);
    if start < end && &input[start..end] != REDACTED {
        edits.push((start, end));
    }
}

pub(super) fn credential_option(tool: &str, token: &str) -> Option<Option<(usize, usize)>> {
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
        && lower.starts_with("-u")
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
    if tool == "docker-login" && value.starts_with("-p") && value.len() > 2 {
        return Some(Some((base + 2, end)));
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
            let offset = base + 2;
            return Some(Some((offset, end)));
        }
        if tool == "curl"
            && value.starts_with('-')
            && !value.starts_with("--")
            && !value.starts_with("-H")
        {
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

pub(super) fn should_redact_next(tool: &str, flag: &str, value: &str) -> bool {
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
