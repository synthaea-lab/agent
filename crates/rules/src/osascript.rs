//! OSASCRIPT-PASSWORD-PROMPT (T1056.002 / T1059.002, #1032): an `osascript` command line that
//! raises a password dialog, or runs a shell command with administrator privileges.
//!
//! A fake "System Preferences needs your password" dialog is `display dialog ... hidden
//! answer`: the `AppleScript` option `hidden answer` makes a password field, and the answer is
//! then typically fed to `do shell script ... with administrator privileges`.
//!
//! | Command line (lowercased) | Technique | Severity |
//! | --- | --- | --- |
//! | `display dialog` + `hidden answer` + `with administrator privileges` | T1056.002/T1059.002 | High |
//! | `display dialog` + `hidden answer` | T1056.002/T1059.002 | Medium |
//! | `do shell script` + `with administrator privileges` | T1059.002 | Low |
//!
//! The last row is the system's own authentication prompt, not a fake one: it is MDM, update
//! and installer noise, so it is a hunting-grade Low and not a phishing claim.
//!
//! **Installers.** Packages that ask for a password from a postinstall script run `osascript`
//! under the installer's own processes ([`INSTALLER_PARENTS`]). That is how a benign
//! installer is told apart: by the parent process, nothing else, because the dialog text of a
//! legitimate prompt and a fake one are the same kind of string. Under an installer parent
//! the hidden-answer case drops to **Low** (not silent: a malicious package's postinstall is
//! the same shape) and the admin-only case is silent.
//!
//! **Provisional.** The Low/Medium split and the parent list were not measured on a fleet or
//! on a Mac (macOS VM not run). Not covered: a script run from a file (`osascript x.scpt`),
//! where the command line carries no script text; JavaScript for Automation (`-l
//! JavaScript`), which spells the same calls differently; and a prompt raised through other
//! tools (`swift`, `python` with `pyobjc`, `dscl . -authonly` against a harvested password).

use schema::{ExecEvent, detection::Severity};

use crate::Alert;

/// Parents under which a package's own scripts run. Names as `comm` gives them; **not checked
/// on a Mac**: a wrong name only keeps an installer's prompt at Low instead of silencing the
/// admin-only case.
const INSTALLER_PARENTS: &[&str] = &[
    "Installer",
    "installd",
    "package_script_service",
    "PackageKit",
    "system_installd",
];

const TECHNIQUE_PROMPT: &str = "T1056.002/T1059.002";
const TECHNIQUE_ADMIN_ONLY: &str = "T1059.002";

fn is_osascript(event: &ExecEvent) -> bool {
    let image = event.image_path.rsplit('/').next().unwrap_or("");
    image == "osascript"
}

/// See the module doc.
#[must_use]
pub(crate) fn check_osascript_password_prompt(event: &ExecEvent) -> Option<Alert> {
    if !is_osascript(event) {
        return None;
    }
    let script = event.cmdline.to_ascii_lowercase();
    let hidden_dialog = script.contains("display dialog") && script.contains("hidden answer");
    let admin_shell =
        script.contains("do shell script") && script.contains("with administrator privileges");
    let from_installer = event
        .parent_comm
        .as_deref()
        .is_some_and(|parent| INSTALLER_PARENTS.contains(&parent));

    let (technique, severity, what) = match (hidden_dialog, admin_shell, from_installer) {
        (false, false, _) | (false, true, true) => return None,
        (true, true, false) => (
            TECHNIQUE_PROMPT,
            Severity::High,
            "password dialog whose answer feeds a shell command run with administrator privileges",
        ),
        (true, _, false) => (
            TECHNIQUE_PROMPT,
            Severity::Medium,
            "password dialog (display dialog with hidden answer)",
        ),
        (true, _, true) => (
            TECHNIQUE_PROMPT,
            Severity::Low,
            "password dialog under an installer process",
        ),
        (false, true, false) => (
            TECHNIQUE_ADMIN_ONLY,
            Severity::Low,
            "shell command run with administrator privileges",
        ),
    };
    Some(Alert {
        technique,
        severity,
        message: format!(
            "pid={} comm={} parent={}: osascript {what}: {}",
            event.meta.pid,
            event.meta.comm,
            event.parent_comm.as_deref().unwrap_or("unknown"),
            event.cmdline,
        ),
    })
}
