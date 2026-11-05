//! Credential redaction for free command text: a typed shell line, a `PowerShell` script
//! block, an AMSI buffer, a WQL query (#895, ADR-0034 "Command text outside `Exec`").
//!
//! [`crate::redact_command_line`] reads one process's command line, whose first word is the
//! image. Free text holds many commands, so it is cut into statements first (unquoted
//! separators and grouping characters) and each statement is redacted as a command line of
//! its own first word. The cut never happens inside quotes and a redacted value keeps its
//! quotes and holds no separator, so a second pass cuts at the same places: idempotence
//! carries over from the command-line redaction.

use std::borrow::Cow;

use crate::{
    REDACTED, is_secret_key, push_value_edit, redact_command_line_with, token_ranges, trim_quotes,
};

/// The language a block of command text is written in, which decides how it is cut into
/// statements and which credential shapes are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandDialect {
    /// `sh`/`bash`/`zsh` input: statements, leading `NAME=value` assignments and
    /// `export`-style declarations, then each command's own options.
    Posix,
    /// `PowerShell`: statements, the native commands they call, secret-named
    /// `-Parameter` values and the literal handed to `ConvertTo-SecureString`.
    PowerShell,
    /// Text whose grammar is not parsed (`VBScript`, `JScript`, WQL): only the
    /// tool-independent shapes, URL credentials, secret headers and secret-named
    /// `--option=value` pairs.
    Opaque,
}

/// Redacts recognized credential shapes in `text` without reformatting it. Detection must
/// consume the original event; call this only on copies at output boundaries (ADR-0034).
#[must_use]
pub fn redact_command_text(text: &str, dialect: CommandDialect) -> Cow<'_, str> {
    let Cow::Owned(mut current) = redact_pass(text, dialect) else {
        return Cow::Borrowed(text);
    };
    if current == text {
        return Cow::Borrowed(text);
    }
    for _ in 1..MAX_PASSES {
        match redact_pass(&current, dialect) {
            Cow::Owned(next) if next != current => current = next,
            _ => break,
        }
    }
    Cow::Owned(current)
}

/// Passes [`redact_command_text`] runs at most. A pass rewrites values with quote and
/// escape characters kept, but on hostile quoting the statement cut and the command-line
/// tokenizer can still disagree, so a pass may leave a value the next one finds. Text
/// without a secret costs one pass and ordinary text two; four were not enough for the
/// escape-and-quote noise the proptest generates (100,000 cases pass at sixteen).
const MAX_PASSES: usize = 16;

fn redact_pass(text: &str, dialect: CommandDialect) -> Cow<'_, str> {
    if dialect == CommandDialect::Opaque {
        return redact_command_line_with("", text, redacted_keeping_syntax);
    }
    let mut out = String::new();
    let mut cursor = 0;
    for (start, end) in statement_ranges(text, dialect) {
        let statement = &text[start..end];
        let safe = match dialect {
            CommandDialect::Posix => redact_posix_statement(statement),
            CommandDialect::PowerShell => redact_powershell_statement(statement),
            CommandDialect::Opaque => Cow::Borrowed(statement),
        };
        if let Cow::Owned(safe) = safe {
            out.push_str(&text[cursor..start]);
            out.push_str(&safe);
            cursor = end;
        }
    }
    if cursor == 0 {
        return Cow::Borrowed(text);
    }
    out.push_str(&text[cursor..]);
    Cow::Owned(out)
}

/// The byte ranges of `text`'s statements: cut at unquoted newlines, `;`, `|`, grouping
/// characters, and `&` (`PowerShell`: only `&&`, a single `&` is its call operator). A
/// quote left open runs to the end of the text.
fn statement_ranges(text: &str, dialect: CommandDialect) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let escape = if dialect == CommandDialect::PowerShell {
        b'`'
    } else {
        b'\\'
    };
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if let Some(active) = quote {
            if byte == escape && active == b'"' {
                i += 2;
                continue;
            }
            if byte == active {
                quote = None;
            }
            i += 1;
            continue;
        }
        if byte == escape {
            i += 2;
            continue;
        }
        let separator = match byte {
            b'\'' | b'"' => {
                quote = Some(byte);
                false
            }
            b'\n' | b'\r' | b';' | b'|' | b'(' | b')' | b'{' | b'}' => true,
            b'`' => dialect == CommandDialect::Posix,
            b'&' => dialect == CommandDialect::Posix || bytes.get(i + 1) == Some(&b'&'),
            _ => false,
        };
        if separator {
            ranges.push((start, i));
            start = i + 1;
        }
        i += 1;
    }
    ranges.push((start.min(bytes.len()), bytes.len()));
    ranges.retain(|&(s, e)| s < e);
    ranges
}

/// Shell words that declare variables: `export TOKEN=x` is an assignment, not a command.
const DECLARATION_WORDS: &[&str] = &["export", "declare", "local", "readonly", "typeset"];

/// One shell statement: secret-named assignments ahead of the command (`TOKEN=x cmd`,
/// `export TOKEN=x`), then the command as a command line of its own first word.
fn redact_posix_statement(statement: &str) -> Cow<'_, str> {
    let tokens = token_ranges(statement, false);
    let mut edits = Vec::new();
    let mut command_start = None;
    for (index, &(start, end)) in tokens.iter().enumerate() {
        let token = &statement[start..end];
        if index == 0 && DECLARATION_WORDS.contains(&token) {
            continue;
        }
        if let Some((name, _)) = token.split_once('=')
            && is_variable_name(name)
        {
            if !name.to_ascii_lowercase().ends_with("_file") && is_secret_key(name) {
                push_value_edit(statement, start + name.len() + 1, end, &mut edits);
            }
            continue;
        }
        command_start = Some(start);
        break;
    }
    let split = command_start.unwrap_or(statement.len());
    let (prefix, command) = statement.split_at(split);
    let image = first_word(command);
    match (
        apply_edits(prefix, &edits),
        redact_command_line_with(image, command, redacted_keeping_syntax),
    ) {
        (Cow::Borrowed(_), Cow::Borrowed(_)) => Cow::Borrowed(statement),
        (prefix, command) => Cow::Owned(format!("{prefix}{command}")),
    }
}

fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One `PowerShell` statement: the native command it may call (`net user`, `cmdkey`, a URL
/// with credentials), then the cmdlet shapes.
fn redact_powershell_statement(statement: &str) -> Cow<'_, str> {
    let native = redact_native_command(statement);
    let safe = redact_powershell_parameters(&native);
    match safe {
        Cow::Owned(safe) => Cow::Owned(safe),
        Cow::Borrowed(_) => native,
    }
}

/// The statement as a native command line. A leading call operator (`& 'C:\x\mysql.exe'`,
/// `. .\setup.ps1`) is skipped, so the program it calls is the one read. A statement that
/// starts with a variable or a type (`$c = …`, `[pscredential]::new`) is an expression, not
/// a command: read as one, `[pscredential]::new` looks like a secret header.
fn redact_native_command(statement: &str) -> Cow<'_, str> {
    let tokens = token_ranges(statement, false);
    let start = match tokens.as_slice() {
        [(s, _), ..] if statement[*s..].starts_with(['$', '[']) => {
            return Cow::Borrowed(statement);
        }
        [(s, e), (next, _), ..] if matches!(&statement[*s..*e], "&" | ".") => *next,
        _ => 0,
    };
    let (prefix, command) = statement.split_at(start);
    match redact_command_line_with(first_word(command), command, redacted_keeping_syntax) {
        Cow::Borrowed(_) => Cow::Borrowed(statement),
        Cow::Owned(safe) => Cow::Owned(format!("{prefix}{safe}")),
    }
}

/// Secret-named parameters (`-Password x`, `-ApiKey:x`, `-Token 'x'`) and the plain-text
/// literal of `ConvertTo-SecureString`. A value that is a variable, a subexpression or a
/// splat (`$pw`, `(Read-Host)`, `@args`) holds no literal secret and is kept: it is what
/// tells an analyst where the secret came from.
fn redact_powershell_parameters(statement: &str) -> Cow<'_, str> {
    let tokens = token_ranges(statement, false);
    let mut edits = Vec::new();
    if let Some(value_start) = secret_assignment_value(statement)
        && let Some(&(start, end)) = tokens
            .iter()
            .find(|&&(s, e)| s <= value_start && value_start < e)
        // Only a quoted value is a literal here: `$password = Read-Host` calls a command.
        && statement[value_start..end].starts_with(['\'', '"'])
    {
        push_value_edit(statement, value_start.max(start), end, &mut edits);
    }
    // `ConvertTo-SecureString` anywhere in the statement (`$pw = ConvertTo-SecureString …`):
    // its first literal after it is the plain text.
    let securestring_at = tokens
        .iter()
        .position(|&(s, e)| statement[s..e].eq_ignore_ascii_case("ConvertTo-SecureString"));
    let securestring = securestring_at.is_some();
    let mut securestring_literal_seen = false;
    let mut index = 0;
    while index < tokens.len() {
        let (start, end) = tokens[index];
        let token = &statement[start..end];
        let next = tokens.get(index + 1).copied();
        if let Some(parameter) = token.strip_prefix('-')
            && !parameter.starts_with('-')
        {
            let (name, attached) = match parameter.split_once(':') {
                Some((name, value)) => (name, Some(value)),
                None => (parameter, None),
            };
            let lower = name.to_ascii_lowercase();
            let is_secret = !lower.ends_with("file")
                && !lower.ends_with("path")
                && (is_secret_key(name) || (securestring && lower == "string"));
            if is_secret {
                if let Some(value) = attached {
                    if is_literal(value) {
                        push_value_edit(statement, end - value.len(), end, &mut edits);
                    }
                } else if let Some((value_start, value_end)) = next
                    && is_literal(&statement[value_start..value_end])
                {
                    push_value_edit(statement, value_start, value_end, &mut edits);
                    securestring_literal_seen |= securestring;
                    index += 2;
                    continue;
                }
            }
        } else if securestring_at.is_some_and(|at| index > at)
            && !securestring_literal_seen
            && is_literal(token)
        {
            push_value_edit(statement, start, end, &mut edits);
            securestring_literal_seen = true;
        }
        index += 1;
    }
    apply_edits(statement, &edits)
}

/// Where the value starts in `$name = value` when `name` (scope such as `env:` or
/// `script:` dropped) is secret-named: `$env:API_TOKEN = 'x'`, `$password="x"`.
fn secret_assignment_value(statement: &str) -> Option<usize> {
    let offset = statement.len() - statement.trim_start().len();
    let rest = statement[offset..].strip_prefix('$')?;
    let name_len = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .unwrap_or(rest.len());
    let name = &rest[..name_len];
    let name = name.rsplit(':').next().unwrap_or(name);
    let after = &rest[name_len..];
    let value = after.trim_start().strip_prefix('=')?;
    if value.starts_with('=') || name.to_ascii_lowercase().ends_with("file") || !is_secret_key(name)
    {
        return None;
    }
    let value_offset = statement.len() - value.trim_start().len();
    (value_offset < statement.len()).then_some(value_offset)
}

/// A parameter value written out in the text, as opposed to one computed at run time.
fn is_literal(value: &str) -> bool {
    !value.is_empty() && !value.starts_with(['-', '$', '(', '@', '['])
}

/// The first word of `command` without its quotes: the image a command line is read for.
fn first_word(command: &str) -> &str {
    token_ranges(command, false).first().map_or("", |&(s, e)| {
        let (s, e) = trim_quotes(command, s, e);
        &command[s..e]
    })
}

/// [`REDACTED`] in place of `value`, keeping what decides how the rest of the text is read:
/// the leading quotes, then every later quote and escape (`` ` `` or `\`) in order. An
/// escape keeps the character it consumes when that is a quote or an escape, and an `R` in
/// place of any other one, so a quote it neutralised stays neutralised. Without that, a
/// value such as ``a`'b`` would become `REDACTED'` and the next pass would cut the text
/// at different places (#895, found by the proptest).
fn redacted_keeping_syntax(value: &str) -> String {
    let is_quote = |c: char| c == '"' || c == '\'';
    let is_escape = |c: char| c == '`' || c == '\\';
    if value.chars().all(is_quote) {
        return value.to_owned();
    }
    let rest = value.trim_start_matches(is_quote);
    let mut out = String::with_capacity(REDACTED.len() + value.len() - rest.len() + 2);
    out.push_str(&value[..value.len() - rest.len()]);
    out.push_str(REDACTED);
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        if is_escape(c) {
            out.push(c);
            match chars.next() {
                Some(next) if is_quote(next) || is_escape(next) => out.push(next),
                Some(_) => out.push('R'),
                None => {}
            }
        } else if is_quote(c) {
            out.push(c);
        }
    }
    out
}

/// `input` with every edit range replaced by [`REDACTED`], see [`redacted_keeping_syntax`].
fn apply_edits<'a>(input: &'a str, edits: &[(usize, usize)]) -> Cow<'a, str> {
    let mut edits = edits.to_vec();
    edits.sort_unstable();
    edits.dedup();
    let mut out = String::new();
    let mut cursor = 0;
    for (start, end) in edits {
        if start < cursor || start >= end || end > input.len() {
            continue;
        }
        out.push_str(&input[cursor..start]);
        out.push_str(&redacted_keeping_syntax(&input[start..end]));
        cursor = end;
    }
    if cursor == 0 {
        return Cow::Borrowed(input);
    }
    out.push_str(&input[cursor..]);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn posix(text: &str) -> String {
        redact_command_text(text, CommandDialect::Posix).into_owned()
    }

    fn powershell(text: &str) -> String {
        redact_command_text(text, CommandDialect::PowerShell).into_owned()
    }

    #[test]
    fn every_command_of_a_typed_shell_line_is_read_for_its_own_tool() {
        assert_eq!(
            posix("cd /srv && mysql -pS3cret db | tee out; curl -u a:S3cret https://h"),
            "cd /srv && mysql -pREDACTED db | tee out; curl -u REDACTED https://h"
        );
        assert_eq!(
            posix("x=$(curl -u a:S3cret https://h)"),
            "x=$(curl -u REDACTED https://h)"
        );
        assert_eq!(
            posix("sudo mysql --password=S3cret"),
            "sudo mysql --password=REDACTED"
        );
    }

    #[test]
    fn secret_named_shell_assignments_lose_their_value_and_others_are_kept() {
        assert_eq!(
            posix("export AWS_SECRET_ACCESS_KEY=abc123 REGION=eu-west-3"),
            "export AWS_SECRET_ACCESS_KEY=REDACTED REGION=eu-west-3"
        );
        assert_eq!(
            posix("GITHUB_TOKEN='ghp_x' gh pr list"),
            "GITHUB_TOKEN='REDACTED' gh pr list"
        );
        assert_eq!(
            posix("PASSWORD_FILE=/run/secrets/db app"),
            "PASSWORD_FILE=/run/secrets/db app"
        );
        assert_eq!(
            posix("PATH=/opt/bin:$PATH make"),
            "PATH=/opt/bin:$PATH make"
        );
    }

    #[test]
    fn a_separator_inside_quotes_does_not_cut_the_statement() {
        assert_eq!(
            posix("echo 'curl -u a:b h'"),
            "echo 'curl -u a:b h'",
            "quoted text handed to echo is data, not a command"
        );
    }

    #[test]
    fn powershell_secret_parameters_and_securestring_literals_are_redacted() {
        assert_eq!(
            powershell("New-LocalUser -Name bob -Password 'S3cret!' -FullName Bob"),
            "New-LocalUser -Name bob -Password 'REDACTED' -FullName Bob"
        );
        assert_eq!(
            powershell("Connect-Service -ApiKey:abc123 -Verbose"),
            "Connect-Service -ApiKey:REDACTED -Verbose"
        );
        assert_eq!(
            powershell(
                "$c = [pscredential]::new('bob', (ConvertTo-SecureString 'S3cret!' -AsPlainText -Force))"
            ),
            "$c = [pscredential]::new('bob', (ConvertTo-SecureString 'REDACTED' -AsPlainText -Force))"
        );
        assert_eq!(
            powershell("ConvertTo-SecureString -String \"S3cret\" -AsPlainText -Force"),
            "ConvertTo-SecureString -String \"REDACTED\" -AsPlainText -Force"
        );
        assert_eq!(
            powershell("$env:API_TOKEN = 'abc123'; $password=\"S3cret\"; $user = 'bob'"),
            "$env:API_TOKEN = 'REDACTED'; $password=\"REDACTED\"; $user = 'bob'"
        );
        assert_eq!(
            powershell("$pw = ConvertTo-SecureString 'S3cret' -AsPlainText -Force"),
            "$pw = ConvertTo-SecureString 'REDACTED' -AsPlainText -Force"
        );
        for kept in [
            "$token = $env:TOKEN; if ($token -eq $null) { exit }",
            "$password = Read-Host -AsSecureString",
        ] {
            assert_eq!(powershell(kept), kept);
        }
    }

    #[test]
    fn powershell_values_computed_at_run_time_are_kept() {
        for text in [
            "Enter-PSSession -ComputerName h -Credential $cred",
            "Set-Secret -Name db -Secret (Read-Host -AsSecureString)",
            "Invoke-Thing -Token @splat",
            "Import-Thing -PasswordFile C:\\keys\\p.txt",
        ] {
            assert_eq!(powershell(text), text);
        }
    }

    #[test]
    fn native_commands_inside_a_script_block_are_read_too() {
        assert_eq!(
            powershell(
                "Invoke-Command { net user bob S3cret! /add }\ncmdkey /add:h /user:u /pass:S3cret"
            ),
            "Invoke-Command { net user bob REDACTED /add }\ncmdkey /add:h /user:u /pass:REDACTED"
        );
        assert_eq!(
            powershell("iwr https://u:p@h/x?token=abc -OutFile x"),
            "iwr https://REDACTED@h/x?token=REDACTED -OutFile x"
        );
        // A single `&` is the call operator, not a separator: the program it calls is read.
        assert_eq!(
            powershell("& 'C:\\tools\\mysql.exe' -pS3cret"),
            "& 'C:\\tools\\mysql.exe' -pREDACTED"
        );
    }

    #[test]
    fn opaque_text_only_loses_tool_independent_shapes() {
        let text = "Set x = CreateObject(\"MSXML2.XMLHTTP\"): x.Open \"GET\", \"https://u:p@h/?token=abc\"";
        assert_eq!(
            redact_command_text(text, CommandDialect::Opaque),
            "Set x = CreateObject(\"MSXML2.XMLHTTP\"): x.Open \"GET\", \"https://REDACTED@h/?token=REDACTED\""
        );
        let wql = "SELECT * FROM Win32_Process WHERE Name = 'mysql.exe'";
        assert!(matches!(
            redact_command_text(wql, CommandDialect::Opaque),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn text_without_a_secret_is_borrowed() {
        for dialect in [CommandDialect::Posix, CommandDialect::PowerShell] {
            assert!(matches!(
                redact_command_text("ls -la | grep x; Get-Process", dialect),
                Cow::Borrowed(_)
            ));
        }
    }

    proptest! {
        #[test]
        fn arbitrary_text_redaction_is_panic_free_and_idempotent(
            input in any::<String>(),
            dialect in prop_oneof![
                Just(CommandDialect::Posix),
                Just(CommandDialect::PowerShell),
                Just(CommandDialect::Opaque),
            ],
        ) {
            let once = redact_command_text(&input, dialect).into_owned();
            let twice = redact_command_text(&once, dialect).into_owned();
            prop_assert_eq!(once, twice);
        }

        #[test]
        fn trigger_words_in_arbitrary_text_are_idempotent(
            noise in prop::collection::vec(
                prop_oneof![
                    any::<char>(),
                    Just(';'), Just('|'), Just('&'), Just('`'), Just('('), Just(')'),
                    Just('\''), Just('"'), Just('\n'), Just('$'), Just('='),
                ],
                0..40,
            ),
            dialect in prop_oneof![Just(CommandDialect::Posix), Just(CommandDialect::PowerShell)],
        ) {
            let noise: String = noise.into_iter().collect();
            let input = format!(
                "{noise}export TOKEN={noise} -Password {noise}(ConvertTo-SecureString {noise}mysql -p{noise}; net user a {noise}",
            );
            let once = redact_command_text(&input, dialect).into_owned();
            let twice = redact_command_text(&once, dialect).into_owned();
            prop_assert_eq!(&once, &twice);
            prop_assert!(once.len() <= input.len().saturating_add(64 * REDACTED.len()));
        }
    }
}
