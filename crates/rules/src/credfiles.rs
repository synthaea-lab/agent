//! Credential-file reads (#377): which paths hold credentials, and which readers have a
//! reason to open them. The decision that needs process history (the pid's exec-time image,
//! its parent's name) lives in `RuleState::check_credential_file_read`; this module is the
//! part that needs none.
//!
//! The sensor reports the raw `openat` argument, so only an **absolute** path is classified:
//! `cd /etc && cat shadow` opens the relative `shadow` and is not seen, and neither is a read
//! through a symlink (`/tmp/x` → `/etc/shadow`). Both are gaps of the telemetry, not of the
//! rule. Absolute paths are normalised lexically (`//`, `/./`, `/../`, a `/proc/<pid>/root`
//! alias) so the cheap evasions of the exact string do not work.

/// A kind of credential file, which decides the technique and the question asked of the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CredFile {
    /// `/etc/shadow` and `/etc/gshadow` (and their `-` backups): T1003.008.
    Shadow,
    /// An SSH private key in a home directory: T1552.004.
    PrivateKey,
    /// Cloud, registry, VCS and database credentials kept in a home directory: T1552.001.
    HomeCredentials,
    /// A macOS keychain database: T1555.001.
    Keychain,
    /// A macOS browser's saved logins, cookies or autofill store: T1555.003.
    BrowserStore,
}

/// Named constants, not literals inside a `match`: `tools/attack-coverage.py` reads a
/// technique from a `technique` field or from a string constant of this shape.
const SHADOW_TECHNIQUE: &str = "T1003.008";
const PRIVATE_KEY_TECHNIQUE: &str = "T1552.004";
const HOME_CREDENTIALS_TECHNIQUE: &str = "T1552.001";
const KEYCHAIN_TECHNIQUE: &str = "T1555.001";
const BROWSER_STORE_TECHNIQUE: &str = "T1555.003";

impl CredFile {
    pub(crate) fn technique(self) -> &'static str {
        match self {
            Self::Shadow => SHADOW_TECHNIQUE,
            Self::PrivateKey => PRIVATE_KEY_TECHNIQUE,
            Self::HomeCredentials => HOME_CREDENTIALS_TECHNIQUE,
            Self::Keychain => KEYCHAIN_TECHNIQUE,
            Self::BrowserStore => BROWSER_STORE_TECHNIQUE,
        }
    }
}

/// Key file names under `~/.ssh` (the `.pub` halves are public and not listed).
const PRIVATE_KEY_NAMES: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
];

/// Credential files below a home directory, as path segments. Each is a file a tool keeps a
/// secret in, readable by the user that owns it.
const HOME_CREDENTIAL_FILES: &[&[&str]] = &[
    &[".aws", "credentials"],
    &[".git-credentials"],
    &[".netrc"],
    &[".pgpass"],
    &[".docker", "config.json"],
    &[".kube", "config"],
    &[".azure", "accessTokens.json"],
    &[".config", "gcloud", "credentials.db"],
    &[".config", "gcloud", "application_default_credentials.json"],
];

/// A macOS keychain database, below `/Users/<user>` as segments (`*` is any one segment):
/// the login keychain in both of its formats, and the data-protection keychain, which lives in
/// a per-device directory.
const MACOS_KEYCHAIN_FILES: &[&[&str]] = &[
    &["Library", "Keychains", "login.keychain-db"],
    &["Library", "Keychains", "login.keychain"],
    &["Library", "Keychains", "*", "keychain-2.db"],
];

/// A macOS browser's store of saved logins, cookies and autofill data, below `/Users/<user>`
/// (`*` is any one segment: the profile). The Chromium family shares the file names; Firefox
/// keeps the logins and the key that decrypts them apart.
const MACOS_BROWSER_STORES: &[&[&str]] = &[
    &[
        "Library",
        "Application Support",
        "Google",
        "Chrome",
        "*",
        "Login Data",
    ],
    &[
        "Library",
        "Application Support",
        "Google",
        "Chrome",
        "*",
        "Login Data For Account",
    ],
    &[
        "Library",
        "Application Support",
        "Google",
        "Chrome",
        "*",
        "Cookies",
    ],
    &[
        "Library",
        "Application Support",
        "Google",
        "Chrome",
        "*",
        "Network",
        "Cookies",
    ],
    &[
        "Library",
        "Application Support",
        "Google",
        "Chrome",
        "*",
        "Web Data",
    ],
    &[
        "Library",
        "Application Support",
        "Microsoft Edge",
        "*",
        "Login Data",
    ],
    &[
        "Library",
        "Application Support",
        "Microsoft Edge",
        "*",
        "Cookies",
    ],
    &[
        "Library",
        "Application Support",
        "Microsoft Edge",
        "*",
        "Network",
        "Cookies",
    ],
    &[
        "Library",
        "Application Support",
        "BraveSoftware",
        "Brave-Browser",
        "*",
        "Login Data",
    ],
    &[
        "Library",
        "Application Support",
        "BraveSoftware",
        "Brave-Browser",
        "*",
        "Cookies",
    ],
    &[
        "Library",
        "Application Support",
        "BraveSoftware",
        "Brave-Browser",
        "*",
        "Network",
        "Cookies",
    ],
    &[
        "Library",
        "Application Support",
        "Chromium",
        "*",
        "Login Data",
    ],
    &["Library", "Application Support", "Chromium", "*", "Cookies"],
    &[
        "Library",
        "Application Support",
        "Firefox",
        "Profiles",
        "*",
        "logins.json",
    ],
    &[
        "Library",
        "Application Support",
        "Firefox",
        "Profiles",
        "*",
        "key4.db",
    ],
    &[
        "Library",
        "Application Support",
        "Firefox",
        "Profiles",
        "*",
        "cookies.sqlite",
    ],
];

/// Whether `rest` is one of `patterns`, where a `*` pattern segment matches any one segment.
fn matches_any(patterns: &[&[&str]], rest: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        pattern.len() == rest.len()
            && pattern
                .iter()
                .zip(rest)
                .all(|(p, segment)| *p == "*" || p == segment)
    })
}

/// The path as the kernel resolves it for the cheap aliases, or `None` for a relative one.
fn normalize(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') {
        return None;
    }
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    // `/proc/<pid>/root/<path>` and `/proc/self/root/<path>` are `<path>`.
    if let [first, pid, "root", rest @ ..] = segments.as_slice()
        && *first == "proc"
        && (*pid == "self" || (!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())))
    {
        return Some(rest.to_vec());
    }
    Some(segments)
}

/// The credential file `path` names, when it names one.
pub(crate) fn classify(path: &str) -> Option<CredFile> {
    let segments = normalize(path)?;
    match segments.as_slice() {
        ["etc", "shadow" | "gshadow" | "shadow-" | "gshadow-"] => Some(CredFile::Shadow),
        ["Library", "Keychains", "System.keychain"] => Some(CredFile::Keychain),
        ["root", rest @ ..] => classify_in_home(rest),
        ["home" | "Users", user, rest @ ..] if !user.is_empty() => classify_in_home(rest),
        _ => None,
    }
}

fn classify_in_home(rest: &[&str]) -> Option<CredFile> {
    if let [".ssh", name] = rest
        && PRIVATE_KEY_NAMES.contains(name)
    {
        return Some(CredFile::PrivateKey);
    }
    if matches_any(MACOS_KEYCHAIN_FILES, rest) {
        return Some(CredFile::Keychain);
    }
    if matches_any(MACOS_BROWSER_STORES, rest) {
        return Some(CredFile::BrowserStore);
    }
    HOME_CREDENTIAL_FILES
        .contains(&rest)
        .then_some(CredFile::HomeCredentials)
}

/// Whether an open with these `open(2)` flags can read the file: anything but write-only.
pub(crate) fn can_read(flags: u32) -> bool {
    const O_ACCMODE: u32 = 0o3;
    const O_WRONLY: u32 = 0o1;
    flags & O_ACCMODE != O_WRONLY
}

/// The kernel keeps 15 bytes of a process name (`TASK_COMM_LEN` is 16, with the NUL).
const COMM_LEN: usize = 15;

/// Whether `comm` is the (possibly truncated) name `name`.
fn comm_is(comm: &str, name: &str) -> bool {
    comm == name || name.get(..COMM_LEN) == Some(comm)
}

/// Programs that read the shadow files as part of authenticating, changing or listing an
/// account: the `shadow-utils` tools, the PAM helpers and the logon front ends (sshd, login,
/// sudo, su, cron's PAM account check, the display managers' session workers). Not complete:
/// a site's own PAM service (an FTP or mail daemon, `saslauthd`) is not here and alerts once
/// per window, which is where an operator tunes it.
///
/// Matched against the **basename of the exec-time image** at a trusted system path (a name
/// alone is a rename away from being excluded, CLAUDE.md), and only against `comm` when the
/// sensor gave no image for the process (see [`is_auth_stack`]).
const AUTH_STACK: &[&str] = &[
    "login",
    "sshd",
    "sshd-session",
    "sshd-auth",
    "sudo",
    "su",
    "runuser",
    "sulogin",
    "passwd",
    "chpasswd",
    "chage",
    "chfn",
    "chsh",
    "gpasswd",
    "newgrp",
    "sg",
    "newusers",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "groupmems",
    "vipw",
    "vigr",
    "pwck",
    "grpck",
    "pwconv",
    "pwunconv",
    "grpconv",
    "grpunconv",
    "unix_chkpwd",
    "unix_update",
    "polkit-agent-helper-1",
    "cron",
    "crond",
    "atd",
    "systemd-sysusers",
    "cockpit-session",
    "gdm-session-worker",
    "lightdm",
    "sddm-helper",
];

/// `systemd` holds a user's PAM session open in a child it names `(sd-pam)` (its image stays
/// the `systemd` binary), and that child runs the account check. `systemd` itself is not in
/// [`AUTH_STACK`], so the exception is this one `comm`.
const SD_PAM_COMM: &str = "(sd-pam)";
const SD_PAM_IMAGE: &str = "systemd";

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether a reader of the shadow files is part of the authentication stack.
///
/// `image` is the pid's exec-time image path when known. A known image must sit at a trusted
/// system path **and** be one of [`AUTH_STACK`]: the process's own `comm` is then irrelevant,
/// so `prctl(PR_SET_NAME, "sshd")` in a script interpreter buys nothing, and an `sshd` copied
/// to `/tmp` is not excluded. With no known image the name is all there is, and the exclusion
/// applies on it (`policy::name_exclusion_applies`: a sensor limitation is not evidence of
/// masquerade).
pub(crate) fn is_auth_stack(comm: &str, image: Option<&str>) -> bool {
    match image {
        Some(path) if !path.is_empty() => {
            if !policy::name_exclusion_applies(Some(path)) {
                return false;
            }
            let name = basename(path);
            AUTH_STACK.contains(&name) || (name == SD_PAM_IMAGE && comm == SD_PAM_COMM)
        }
        _ => AUTH_STACK.iter().any(|name| comm_is(comm, name)) || comm == SD_PAM_COMM,
    }
}

/// Whether an image path the sensor reported lies outside the system directories, where only
/// a privileged installer writes: a home directory, `/tmp`, `/var/tmp`, `/dev/shm`. An unknown
/// path is not "outside": the absence of evidence is not evidence.
pub(crate) fn image_outside_system_dirs(image: Option<&str>) -> bool {
    image.is_some_and(|p| !p.is_empty() && !policy::name_exclusion_applies(Some(p)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_of_the_shadow_path_classify_as_the_shadow_path() {
        for path in [
            "/etc/shadow",
            "/etc//shadow",
            "/etc/./shadow",
            "/etc/../etc/shadow",
            "/proc/1/root/etc/shadow",
            "/proc/self/root/etc/shadow",
            "/etc/gshadow",
            "/etc/shadow-",
            "/etc/gshadow-",
        ] {
            assert_eq!(classify(path), Some(CredFile::Shadow), "{path}");
        }
    }

    #[test]
    fn near_misses_of_the_shadow_path_do_not_classify() {
        for path in [
            "shadow",
            "etc/shadow",
            "/etc/passwd",
            "/etc/shadowfoo",
            "/etc/shadow.bak",
            "/etc/shadow/x",
            "/usr/etc/shadow",
            "/proc/x/root/etc/shadow",
            "/proc/root/etc/shadow",
            "",
        ] {
            assert_eq!(classify(path), None, "{path}");
        }
    }

    #[test]
    fn home_credential_files_classify_by_kind() {
        assert_eq!(
            classify("/home/alice/.ssh/id_ed25519"),
            Some(CredFile::PrivateKey)
        );
        assert_eq!(classify("/root/.ssh/id_rsa"), Some(CredFile::PrivateKey));
        assert_eq!(
            classify("/home/alice/.aws/credentials"),
            Some(CredFile::HomeCredentials)
        );
        assert_eq!(
            classify("/Users/bob/.config/gcloud/credentials.db"),
            Some(CredFile::HomeCredentials)
        );
        assert_eq!(
            classify("/home/alice//.aws/./credentials"),
            Some(CredFile::HomeCredentials)
        );
    }

    #[test]
    fn macos_keychains_and_browser_stores_classify_by_kind() {
        for path in [
            "/Users/bob/Library/Keychains/login.keychain-db",
            "/Users/bob/Library/Keychains/login.keychain",
            "/Users/bob/Library/Keychains/6F1B2C3D-0000-4000-8000-000000000001/keychain-2.db",
            "/Library/Keychains/System.keychain",
        ] {
            assert_eq!(classify(path), Some(CredFile::Keychain), "{path}");
        }
        for path in [
            "/Users/bob/Library/Application Support/Google/Chrome/Default/Login Data",
            "/Users/bob/Library/Application Support/Google/Chrome/Profile 2/Network/Cookies",
            "/Users/bob/Library/Application Support/Microsoft Edge/Default/Login Data",
            "/Users/bob/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
            "/Users/bob/Library/Application Support/Firefox/Profiles/ab12.default/key4.db",
            "/Users/bob/Library/Application Support/Firefox/Profiles/ab12.default/logins.json",
        ] {
            assert_eq!(classify(path), Some(CredFile::BrowserStore), "{path}");
        }
    }

    #[test]
    fn macos_neighbours_of_the_keychain_and_browser_stores_do_not_classify() {
        for path in [
            "/Users/bob/Library/Keychains/login.keychain-db.bak",
            "/Users/bob/Library/Keychains",
            "/Users/bob/Library/Keychains/x/y/keychain-2.db",
            "/Users/bob/Library/Application Support/Google/Chrome/Default/Bookmarks",
            "/Users/bob/Library/Application Support/Google/Chrome/Default/History",
            "/Users/bob/Library/Application Support/Firefox/Profiles/ab12.default/places.sqlite",
            "/Users/bob/Library/Application Support/Google/Chrome/Login Data",
        ] {
            assert_eq!(classify(path), None, "{path}");
        }
    }

    #[test]
    fn public_halves_and_neighbours_of_credential_files_do_not_classify() {
        for path in [
            "/home/alice/.ssh/id_rsa.pub",
            "/home/alice/.ssh/known_hosts",
            "/home/alice/.ssh/config",
            "/home/alice/.aws/config",
            "/home/alice/.kube/cache/x",
            "/home/.aws/credentials",
            "/home/alice/projects/.aws/credentials",
            "/var/lib/app/.ssh/id_rsa",
        ] {
            assert_eq!(classify(path), None, "{path}");
        }
    }

    #[test]
    fn only_a_write_only_open_cannot_read() {
        assert!(can_read(0));
        assert!(can_read(0o2));
        assert!(can_read(0o2 | 0o100));
        assert!(!can_read(0o1));
        assert!(!can_read(0o1 | 0o100 | 0o1000));
    }

    #[test]
    fn a_truncated_comm_is_the_same_name() {
        assert!(comm_is("polkit-agent-he", "polkit-agent-helper-1"));
        assert!(comm_is("sshd", "sshd"));
        assert!(!comm_is("polkit", "polkit-agent-helper-1"));
        assert!(!comm_is("sshdx", "sshd"));
    }
}
