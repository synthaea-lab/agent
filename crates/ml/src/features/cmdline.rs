//! Command-line features for the T0 cmdline scorer — the Rust mirror of
//! `ml/synthaea_ml/features/cmdline.py`.
//!
//! This is a parity seam: a model trained on the Python vectors only scores
//! consistently here if both sides produce the identical vector for the same command
//! line (same string, argv `\0` separators included — see [`schema::ExecEvent::cmdline`]).
//! The pairing is locked by `ml/tests/fixtures/features_golden.jsonl`, checked from
//! Rust ([`super`]'s golden test) and Python (`ml/tests/test_features_golden.py`).
//!
//! The token/path lists are a known generalization weakness (an attacker who reads
//! them evades them like a static rule); replacing them with hashed n-grams is issue
//! #48's territory. Until then they are migrated verbatim — changing them here without
//! changing Python and retraining is a silent model lobotomy.

/// See `cmdline.py::SUSPICIOUS_TOKENS` — keep in sync.
const SUSPICIOUS_TOKENS: &[&str] = &[
    "base64", "-d", "-D", "--decode", "chmod +x", "/dev/tcp", "nc ", "| sh", "| bash", "|sh",
    "|bash",
];

/// See `cmdline.py::SHELL_METACHARS` — keep in sync.
const SHELL_METACHARS: &str = "|;&$`()<>";

/// See `cmdline.py::SUSPICIOUS_WIN_PATHS` — keep in sync.
const SUSPICIOUS_WIN_PATHS: &[&str] = &[
    "\\AppData\\",
    "\\Temp\\",
    "\\tmp\\",
    "\\Public\\",
    "\\Downloads\\",
    "\\Desktop\\",
    "%temp%",
    "%appdata%",
];

/// See `cmdline.py::LEGIT_WIN_PATHS` — keep in sync.
const LEGIT_WIN_PATHS: &[&str] = &[
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\SystemApps\\",
    "\\Windows\\UUS\\",
    "\\Program Files\\",
    "\\Program Files (x86)\\",
    "\\ProgramData\\Microsoft\\",
];

/// Feature names in output order — must match `cmdline.py::FEATURE_NAMES` and the ONNX
/// model's input column order. Public so a detection can name the attributed features.
pub const FEATURE_NAMES: [&str; 9] = [
    "length",
    "entropy",
    "suspicious_token_count",
    "token_count",
    "max_token_length",
    "shell_metachar_count",
    "digit_ratio",
    "is_suspicious_win_path",
    "is_legit_win_path",
];

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.chars().count() as f32;
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    -counts
        .values()
        .map(|&c| {
            let p = c as f32 / len;
            p * p.log2()
        })
        .sum::<f32>()
}

fn suspicious_token_count(cmdline: &str) -> f32 {
    SUSPICIOUS_TOKENS
        .iter()
        .filter(|t| cmdline.contains(*t))
        .count() as f32
}

fn token_count(cmdline: &str) -> f32 {
    cmdline.split('\0').filter(|t| !t.is_empty()).count() as f32
}

fn max_token_length(cmdline: &str) -> f32 {
    cmdline
        .split('\0')
        .filter(|t| !t.is_empty())
        .map(|t| t.chars().count())
        .max()
        .unwrap_or(0) as f32
}

fn shell_metachar_count(cmdline: &str) -> f32 {
    cmdline
        .chars()
        .filter(|c| SHELL_METACHARS.contains(*c))
        .count() as f32
}

fn digit_ratio(cmdline: &str) -> f32 {
    // ASCII digits only (mirror of the Python `"0" <= c <= "9"`, NOT str.isdigit()):
    // `char::is_ascii_digit` and the Python range both reject Unicode digits like "²".
    if cmdline.is_empty() {
        return 0.0;
    }
    let len = cmdline.chars().count() as f32;
    cmdline.chars().filter(|c| c.is_ascii_digit()).count() as f32 / len
}

fn contains_any_ci(cmdline_lower: &str, needles: &[&str]) -> f32 {
    if needles
        .iter()
        .any(|p| cmdline_lower.contains(&p.to_lowercase()))
    {
        1.0
    } else {
        0.0
    }
}

/// The 9-feature cmdline vector, in [`FEATURE_NAMES`] order.
///
/// `length` counts Unicode scalar values, not bytes: the Python side counts characters
/// (`len(cmdline)`), so `str::len` (UTF-8 bytes) would diverge on any non-ASCII input.
#[must_use]
pub fn extract_features(cmdline: &str) -> [f32; 9] {
    let lower = cmdline.to_lowercase();
    [
        cmdline.chars().count() as f32,
        shannon_entropy(cmdline),
        suspicious_token_count(cmdline),
        token_count(cmdline),
        max_token_length(cmdline),
        shell_metachar_count(cmdline),
        digit_ratio(cmdline),
        contains_any_ci(&lower, SUSPICIOUS_WIN_PATHS),
        contains_any_ci(&lower, LEGIT_WIN_PATHS),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_has_high_suspicious_count() {
        let cmdline = "bash\0-c\0$(echo ZWNobyBoZWxsbw== | base64 -d)\0";
        assert_eq!(suspicious_token_count(cmdline), 2.0); // "base64" + "-d"
    }

    #[test]
    fn empty_cmdline_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn benign_curl_has_no_suspicious_tokens() {
        let cmdline = "curl\0-f\0http://backend:8000/api/health/\0";
        assert_eq!(suspicious_token_count(cmdline), 0.0);
    }

    #[test]
    fn win_path_matching_is_case_insensitive() {
        assert_eq!(
            extract_features("c:\\users\\bob\\appdata\\local\\temp\\x.exe\0")[7],
            1.0
        );
        assert_eq!(extract_features("C:\\WINDOWS\\SYSTEM32\\cmd.exe\0")[8], 1.0);
    }

    #[test]
    fn digit_ratio_ignores_unicode_digits() {
        // "²" is a Unicode digit but not ASCII — must not count (parity with Python).
        let feats = extract_features("echo\0x²\0");
        assert_eq!(feats[6], 0.0);
    }
}
