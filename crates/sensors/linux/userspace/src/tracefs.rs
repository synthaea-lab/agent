//! Tracepoint record layouts read from tracefs at load time (issue #415).
//!
//! `sched_process_fork`'s record layout differs across kernels: `parent_comm` is an
//! inline `char[16]` on 5.15/6.1/6.8 and a `__data_loc` field on newer kernels
//! (Alpine 6.18), which shifts every field after it. Compile-time offsets are wrong on
//! one family or the other, so the probe's offsets are `aya_ebpf::Global`s that
//! [`crate::load_ebpf`] overrides from the running kernel's `format` file. Parsing is
//! pure ([`parse_fork_format`]) and unit-tested against real captures of both layouts.

use std::path::Path;

/// Where tracefs is usually mounted: its own mount point first (4.1+), then the
/// legacy location under debugfs.
const TRACEFS_ROOTS: &[&str] = &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// A tracepoint record is at most a few hundred bytes; anything past this is a
/// parse error, not a real offset (keeps a corrupted format file from steering the
/// probe's reads somewhere absurd).
const MAX_FIELD_OFFSET: u32 = 4096;

/// The `sched_process_fork` field offsets the probe needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForkLayout {
    /// Offset of `parent_comm` — the inline `char[16]`, or its `u32` data-locator.
    pub parent_comm_offset: u32,
    /// Whether `parent_comm` is a `__data_loc` field (true) or inline (false).
    pub parent_comm_data_loc: bool,
    /// Offset of `pid_t parent_pid`.
    pub parent_pid_offset: u32,
    /// Offset of `pid_t child_pid`.
    pub child_pid_offset: u32,
}

/// Parses the text of `events/sched/sched_process_fork/format`. Returns `None` when
/// any of the three fields is missing, has an unexpected type/size, or sits at an
/// implausible offset — the caller then leaves the probe disabled rather than guess.
pub(crate) fn parse_fork_format(format: &str) -> Option<ForkLayout> {
    let mut parent_comm = None;
    let mut parent_pid = None;
    let mut child_pid = None;
    for line in format.lines() {
        let Some(field) = parse_field_line(line) else {
            continue;
        };
        match field.name {
            "parent_comm" => {
                let data_loc = field.decl.starts_with("__data_loc");
                // Inline: `char parent_comm[16]` (size 16). Data-loc: a u32 locator.
                let size_ok = if data_loc {
                    field.size == 4
                } else {
                    field.size == 16
                };
                if size_ok && field.decl.contains("char") {
                    parent_comm = Some((field.offset, data_loc));
                }
            }
            "parent_pid" if field.size == 4 => parent_pid = Some(field.offset),
            "child_pid" if field.size == 4 => child_pid = Some(field.offset),
            _ => {}
        }
    }
    let (parent_comm_offset, parent_comm_data_loc) = parent_comm?;
    let layout = ForkLayout {
        parent_comm_offset,
        parent_comm_data_loc,
        parent_pid_offset: parent_pid?,
        child_pid_offset: child_pid?,
    };
    [
        layout.parent_comm_offset,
        layout.parent_pid_offset,
        layout.child_pid_offset,
    ]
    .iter()
    .all(|&o| o < MAX_FIELD_OFFSET)
    .then_some(layout)
}

/// Reads and parses the running kernel's `sched_process_fork` format. `None` when
/// tracefs is not mounted/readable or the format is not recognised.
pub(crate) fn read_fork_layout() -> Option<ForkLayout> {
    TRACEFS_ROOTS.iter().find_map(|root| {
        let path = Path::new(root).join("events/sched/sched_process_fork/format");
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| parse_fork_format(&text))
    })
}

struct Field<'a> {
    /// Declaration without the name, e.g. `char` or `__data_loc char[]`.
    decl: &'a str,
    name: &'a str,
    offset: u32,
    size: u32,
}

/// Parses one `field:<decl> <name>[N];\toffset:O;\tsize:S;\tsigned:X;` line.
fn parse_field_line(line: &str) -> Option<Field<'_>> {
    let mut parts = line.trim().split(';').map(str::trim);
    let decl_and_name = parts.next()?.strip_prefix("field:")?;
    let offset = parts.next()?.strip_prefix("offset:")?.parse().ok()?;
    let size = parts.next()?.strip_prefix("size:")?.parse().ok()?;
    let (decl, name) = decl_and_name.rsplit_once(' ')?;
    // `parent_comm[16]` → `parent_comm`.
    let name = name.split('[').next()?;
    Some(Field {
        decl: decl.trim(),
        name,
        offset,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured verbatim on Ubuntu 24.04, `6.8.0-142-generic` (Hyper-V lab, #415).
    /// 5.15 and 6.1 emit the same layout.
    const FORK_FORMAT_INLINE_6_8: &str = "name: sched_process_fork
ID: 324
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;

print fmt: \"comm=%s pid=%d child_comm=%s child_pid=%d\", REC->parent_comm, REC->parent_pid, REC->child_comm, REC->child_pid
";

    /// The `__data_loc` layout Alpine `6.18.50-0-virt` emits, as recorded in #205.
    const FORK_FORMAT_DATA_LOC_6_18: &str = "name: sched_process_fork
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;
\tfield:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;
";

    #[test]
    fn inline_comm_layout_from_6_8() {
        assert_eq!(
            parse_fork_format(FORK_FORMAT_INLINE_6_8),
            Some(ForkLayout {
                parent_comm_offset: 8,
                parent_comm_data_loc: false,
                parent_pid_offset: 24,
                child_pid_offset: 44,
            })
        );
    }

    #[test]
    fn data_loc_comm_layout_from_6_18() {
        assert_eq!(
            parse_fork_format(FORK_FORMAT_DATA_LOC_6_18),
            Some(ForkLayout {
                parent_comm_offset: 8,
                parent_comm_data_loc: true,
                parent_pid_offset: 12,
                child_pid_offset: 20,
            })
        );
    }

    #[test]
    fn missing_field_is_unrecognised() {
        let without_child: String = FORK_FORMAT_INLINE_6_8
            .lines()
            .filter(|l| !l.contains("child_pid;"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_fork_format(&without_child), None);
    }

    #[test]
    fn unexpected_field_size_is_unrecognised() {
        let odd = FORK_FORMAT_INLINE_6_8.replace(
            "pid_t parent_pid;\toffset:24;\tsize:4;",
            "pid_t parent_pid;\toffset:24;\tsize:8;",
        );
        assert_eq!(parse_fork_format(&odd), None);
    }

    #[test]
    fn absurd_offset_is_unrecognised() {
        let odd = FORK_FORMAT_INLINE_6_8.replace("offset:44;", "offset:99999;");
        assert_eq!(parse_fork_format(&odd), None);
    }

    #[test]
    fn empty_or_garbage_input_is_unrecognised() {
        assert_eq!(parse_fork_format(""), None);
        assert_eq!(parse_fork_format("not a format file\n"), None);
    }
}
