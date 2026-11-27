//! A path read the way the kernel resolves it for the cheap aliases a sensor reports verbatim:
//! empty and `.` segments dropped (`//sys/fs//cgroup/./x`), `..` popping the segment before it
//! (`/sys/fs/../fs/cgroup/x`), and `/proc/<pid>/root/<path>` read as `<path>`. Lexical only: a
//! symlink is not followed, so a path through one is read as written.

/// The segments of `path`, absolute or relative, with `.`, `..` and empty segments resolved.
pub(crate) fn lexical_segments(path: &str) -> Vec<&str> {
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
    segments
}

/// The segments of the absolute path `path` names, with the `/proc/<pid>/root/` and
/// `/proc/self/root/` aliases removed, or `None` for a relative path.
pub(crate) fn absolute_segments(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') {
        return None;
    }
    let segments = lexical_segments(path);
    if let [first, pid, "root", rest @ ..] = segments.as_slice()
        && *first == "proc"
        && (*pid == "self" || (!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())))
    {
        return Some(rest.to_vec());
    }
    Some(segments)
}

#[cfg(test)]
mod tests {
    use super::{absolute_segments, lexical_segments};

    #[test]
    fn dot_dot_and_empty_segments_resolve_as_the_kernel_resolves_them() {
        assert_eq!(
            lexical_segments("//sys/fs/../fs//cgroup/./x"),
            ["sys", "fs", "cgroup", "x"]
        );
    }

    #[test]
    fn a_relative_path_keeps_its_segments_but_has_no_absolute_form() {
        assert_eq!(
            lexical_segments("x.service/memory.max"),
            ["x.service", "memory.max"]
        );
        assert_eq!(absolute_segments("x.service/memory.max"), None);
    }

    #[test]
    fn a_proc_root_alias_reads_as_the_path_it_reaches() {
        for path in ["/proc/self/root/etc/shadow", "/proc/42/root/etc/shadow"] {
            assert_eq!(
                absolute_segments(path),
                Some(vec!["etc", "shadow"]),
                "{path}"
            );
        }
        assert_eq!(
            absolute_segments("/proc/abc/root/etc/shadow"),
            Some(vec!["proc", "abc", "root", "etc", "shadow"])
        );
    }
}
