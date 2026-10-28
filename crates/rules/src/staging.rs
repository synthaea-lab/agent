//! STAGING-DIR (T1074.001, #380): path classification and the per-pid state of the rule.
//!
//! The rule itself is [`crate::RuleState::check_staging_dir`]; this module holds what it
//! reads paths with: which opens count as a read of user data, which directory a created file
//! is staged in, and the bounded per-pid history.

use crate::{
    exclusions::{STAGING_EXCLUDED_DIR_NAMES, STAGING_PROFILE_TEMP_ROOTS, STAGING_TEMP_ROOTS},
    sliding::SlidingDistinct,
};

/// Distinct user-data files a pid has opened for reading (newest window only).
pub(crate) struct StagingReads {
    pub(crate) generation: Option<u64>,
    pub(crate) files: SlidingDistinct<String>,
}

/// Distinct files a pid created in one staging directory.
pub(crate) struct StagingDir {
    pub(crate) generation: Option<u64>,
    pub(crate) files: SlidingDistinct<String>,
}

/// The path as `/`-separated, lowercase-insensitive segments, `.` and `..` resolved, or
/// `None` for a relative path (the Linux `dfd` limitation: a relative path proves nothing
/// either way). Accepts a Windows `C:\...` path; a `/proc/<pid>/root` prefix is not
/// unwrapped here, a missed alias only costs the rule a read or a create.
fn segments(path: &str) -> Option<Vec<String>> {
    let bytes = path.as_bytes();
    let absolute = path.starts_with('/')
        || path.starts_with('\\')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/'));
    if !absolute {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for segment in path.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other.to_string()),
        }
    }
    Some(out)
}

fn is_hidden(segment: &str) -> bool {
    segment.len() > 1 && segment.starts_with('.') && segment != ".."
}

/// The segments after the profile directory of a user (`/home/<u>/`, `/Users/<u>/`,
/// `/root/`, `C:\Users\<u>\`), or `None` when `segs` is not inside one.
fn under_home(segs: &[String]) -> Option<&[String]> {
    let lower = |i: usize| segs.get(i).map(|s| s.to_ascii_lowercase());
    match lower(0).as_deref() {
        Some("home" | "users") if segs.len() > 2 => Some(&segs[2..]),
        Some("root") => Some(&segs[1..]),
        // `C:\Users\<u>\...`: the drive is the first segment.
        Some(drive)
            if drive.len() == 2
                && drive.ends_with(':')
                && lower(1).as_deref() == Some("users")
                && segs.len() > 3 =>
        {
            Some(&segs[3..])
        }
        _ => None,
    }
}

/// A file a collection reads: inside a user's profile, not in a hidden directory
/// (`~/.config`, `~/.local`, a dotfile: configuration and caches, read by everything) and not
/// under `AppData` (the Windows equivalent). Returns the file's normalized path and its parent
/// directory.
pub(crate) fn user_data_file(path: &str) -> Option<(String, String)> {
    let segs = segments(path)?;
    let rest = under_home(&segs)?;
    if rest.is_empty()
        || rest
            .iter()
            .any(|s| is_hidden(s) || s.eq_ignore_ascii_case("appdata"))
    {
        return None;
    }
    let (_, parent) = segs.split_last()?;
    Some((segs.join("/"), parent.join("/")))
}

/// Whether `dir` (lowercase segments) is strictly below `root`, matched from its start.
fn strictly_below(dir: &[String], root: &str) -> bool {
    let root: Vec<&str> = root.split('/').collect();
    dir.len() > root.len() && dir.iter().zip(&root).all(|(d, r)| d == r)
}

/// The directory a created file is staged in, when that directory is a staging place: a
/// subdirectory of a temp root (`/tmp/x/`, `%TEMP%\x\`), or a hidden directory anywhere
/// (`/tmp/.x/`, `~/.hidden/`), except the build and cache directories of
/// [`STAGING_EXCLUDED_DIR_NAMES`]. A file created straight in `/tmp` is not staged in
/// "one directory": every program does that. The temp roots are anchored at the filesystem
/// root (after a Windows drive) or at the profile: a `tmp/` inside a project is that
/// project's own build directory.
pub(crate) fn staging_dir(path: &str) -> Option<String> {
    let segs = segments(path)?;
    let (_, parent) = segs.split_last()?;
    if parent.is_empty()
        || parent.iter().any(|s| {
            STAGING_EXCLUDED_DIR_NAMES
                .iter()
                .any(|excluded| s.eq_ignore_ascii_case(excluded))
        })
    {
        return None;
    }
    let lower: Vec<String> = parent.iter().map(|s| s.to_ascii_lowercase()).collect();
    // A Windows path starts with its drive, which is not part of the root's name.
    let from_root = match lower.first() {
        Some(drive) if drive.len() == 2 && drive.ends_with(':') => &lower[1..],
        _ => &lower[..],
    };
    let profile = under_home(&segs).map(|rest| {
        rest[..rest.len() - 1]
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<Vec<_>>()
    });
    let in_temp = STAGING_TEMP_ROOTS
        .iter()
        .any(|root| strictly_below(from_root, root))
        || profile.as_ref().is_some_and(|rest| {
            STAGING_PROFILE_TEMP_ROOTS
                .iter()
                .any(|root| strictly_below(rest, root))
        });
    // A hidden directory below the profile, or at any depth outside one.
    let scope = under_home(&segs).unwrap_or(&segs[..]);
    let hidden = scope[..scope.len() - 1].iter().any(|s| is_hidden(s));
    (in_temp || hidden).then(|| parent.join("/"))
}

#[cfg(test)]
mod tests {
    use super::{staging_dir, user_data_file};

    #[test]
    fn user_data_files_are_visible_files_in_a_profile() {
        let (file, dir) = user_data_file("/home/alice/Documents/q3/plan.xlsx").expect("user data");
        assert_eq!(file, "home/alice/Documents/q3/plan.xlsx");
        assert_eq!(dir, "home/alice/Documents/q3");
        assert!(user_data_file("/Users/bob/Desktop/notes.txt").is_some());
        assert!(user_data_file("/root/work/report.pdf").is_some());
        assert!(user_data_file("C:\\Users\\carol\\Documents\\a.docx").is_some());
    }

    #[test]
    fn configuration_caches_and_system_paths_are_not_user_data() {
        assert!(user_data_file("/home/alice/.config/app/settings.json").is_none());
        assert!(user_data_file("/home/alice/.bashrc").is_none());
        assert!(user_data_file("/home/alice/work/.git/config").is_none());
        assert!(user_data_file("C:\\Users\\carol\\AppData\\Roaming\\x\\y.dat").is_none());
        assert!(user_data_file("/etc/hosts").is_none());
        assert!(user_data_file("/usr/lib/x.so").is_none());
        assert!(user_data_file("Documents/a.txt").is_none(), "relative");
        assert!(
            user_data_file("/home/alice").is_none(),
            "a profile is not a file in it"
        );
    }

    #[test]
    fn dotdot_cannot_walk_out_of_a_profile_or_into_one() {
        assert!(user_data_file("/home/alice/Documents/../../bob/a.txt").is_some());
        assert!(user_data_file("/home/alice/../../etc/passwd").is_none());
    }

    #[test]
    fn a_subdirectory_of_a_temp_root_or_a_hidden_directory_is_a_staging_dir() {
        assert_eq!(staging_dir("/tmp/x/a.bin").as_deref(), Some("tmp/x"));
        assert_eq!(
            staging_dir("/var/tmp/x/y/a.bin").as_deref(),
            Some("var/tmp/x/y")
        );
        assert_eq!(staging_dir("/dev/shm/x/a").as_deref(), Some("dev/shm/x"));
        assert_eq!(staging_dir("/tmp/.x/a").as_deref(), Some("tmp/.x"));
        assert_eq!(
            staging_dir("/home/alice/.stash/a").as_deref(),
            Some("home/alice/.stash")
        );
        assert!(staging_dir("C:\\Users\\carol\\AppData\\Local\\Temp\\x\\a.zip").is_some());
        assert!(staging_dir("C:\\Windows\\Temp\\x\\a.zip").is_some());
    }

    #[test]
    fn a_file_straight_in_a_temp_root_or_an_ordinary_directory_is_not() {
        assert!(staging_dir("/tmp/a.bin").is_none());
        assert!(staging_dir("/var/tmp/a.bin").is_none());
        assert!(staging_dir("/home/alice/Documents/a.bin").is_none());
        assert!(staging_dir("/var/lib/x/a.bin").is_none());
        assert!(staging_dir("C:\\Users\\carol\\Documents\\a.zip").is_none());
        assert!(staging_dir("a.bin").is_none(), "relative");
    }

    #[test]
    fn build_and_cache_directories_are_not_staging_dirs() {
        assert!(staging_dir("/home/alice/.cache/app/a").is_none());
        assert!(staging_dir("/home/alice/proj/.git/objects/ab/cd").is_none());
        assert!(staging_dir("/tmp/.git/x/a").is_none());
    }
}
