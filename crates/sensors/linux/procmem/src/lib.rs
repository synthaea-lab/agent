//! # sensor-linux-procmem
//!
//! The mechanism behind process-memory scanning (issue #85, ADR-0023): list a process's
//! mappings from `/proc/<pid>/maps` and read bytes from `/proc/<pid>/mem`. No policy lives
//! here (which regions to read, how much, how often is `yara`'s `memory` module); the
//! agent adapts the two.
//!
//! Reading another process's memory is gated by `ptrace_may_access`: the same uid and
//! dumpable, or `CAP_SYS_PTRACE`. When the right is missing the open fails with
//! `PermissionDenied`, and that is a normal, expected outcome the caller counts.
//!
//! Everything a mapping line says is attacker-influenced (the pathname is whatever the
//! process named its file), so the parser never panics and never trusts a length: a
//! malformed line is an error the caller can count, and a read is capped by the caller's
//! `len` and by what the kernel returns.

use std::io;

/// One line of `/proc/<pid>/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapsEntry {
    pub start: u64,
    /// Exclusive end.
    pub end: u64,
    /// The `rwxp` column, as the kernel writes it.
    pub perms: String,
    /// The pathname column: a file path, `/memfd:name`, `[heap]`, `[stack]`, ... or `None`
    /// for an anonymous mapping. A deleted file keeps its path with a ` (deleted)` suffix.
    pub pathname: Option<String>,
}

/// Why a maps line was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MapsError {
    #[error("maps line has no address range")]
    NoRange,
    #[error("maps address range `{0}` is not `start-end` in hex")]
    BadRange(String),
    #[error("maps line has no permissions column")]
    NoPerms,
}

/// Parses one `/proc/<pid>/maps` line:
/// `7f2c1a000000-7f2c1a021000 rwxp 00000000 00:00 0   /memfd:payload (deleted)`.
///
/// # Errors
///
/// A line without a hex `start-end` range or a permissions column.
pub fn parse_maps_line(line: &str) -> Result<MapsEntry, MapsError> {
    let mut parts = line.split_whitespace();
    let range = parts.next().ok_or(MapsError::NoRange)?;
    let perms = parts.next().ok_or(MapsError::NoPerms)?;
    let bad = || MapsError::BadRange(range.chars().take(40).collect());
    let (start, end) = range.split_once('-').ok_or_else(bad)?;
    let start = u64::from_str_radix(start, 16).map_err(|_| bad())?;
    let end = u64::from_str_radix(end, 16).map_err(|_| bad())?;
    // offset, dev, inode, then the pathname, which may itself contain spaces.
    let pathname = line
        .splitn(6, char::is_whitespace)
        .nth(5)
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    Ok(MapsEntry {
        start,
        end,
        perms: perms.to_string(),
        pathname,
    })
}

/// Parses a whole `maps` file, skipping and counting lines it cannot read.
#[must_use]
pub fn parse_maps(text: &str) -> (Vec<MapsEntry>, usize) {
    let mut entries = Vec::new();
    let mut malformed = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match parse_maps_line(line) {
            Ok(entry) => entries.push(entry),
            Err(_) => malformed += 1,
        }
    }
    (entries, malformed)
}

/// The mappings of `pid`, and how many lines could not be parsed.
///
/// The file is read as bytes and decoded lossily: the pathname column is raw bytes, and
/// `memfd_create` accepts any name, so a process can name its memfd with bytes that are
/// not UTF-8. Strict decoding would fail the whole file and let exactly the process this
/// scan targets opt out of it; lossy decoding costs that one name its invalid bytes
/// (they become U+FFFD) and nothing else.
///
/// # Errors
///
/// When `/proc/<pid>/maps` cannot be read (the process exited, or access is denied).
pub fn read_maps(pid: u32) -> io::Result<(Vec<MapsEntry>, usize)> {
    let bytes = std::fs::read(format!("/proc/{pid}/maps"))?;
    Ok(parse_maps(&String::from_utf8_lossy(&bytes)))
}

/// Up to `len` bytes of `pid`'s memory at `start`: fewer if the read comes up short, and
/// an empty vector if the very first byte is unreadable.
///
/// # Errors
///
/// When `/proc/<pid>/mem` cannot be opened (`PermissionDenied` without the ptrace right),
/// or reading the first bytes fails (the region was unmapped since the maps were read).
#[cfg(unix)]
pub fn read_memory(pid: u32, start: u64, len: usize) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt as _;

    let file = std::fs::File::open(format!("/proc/{pid}/mem"))?;
    let mut buf = vec![0_u8; len];
    let mut filled = 0;
    while filled < len {
        match file.read_at(&mut buf[filled..], start + filled as u64) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // A hole partway through (a guard page): keep what was read.
            Err(_) if filled > 0 => break,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Process memory is read through `/proc`, which only exists on Unix.
///
/// # Errors
///
/// Always: unsupported on this platform.
#[cfg(not(unix))]
pub fn read_memory(_pid: u32, _start: u64, _len: usize) -> io::Result<Vec<u8>> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_anonymous_mapping_has_no_pathname() {
        let e = parse_maps_line("7f2c1a000000-7f2c1a021000 rwxp 00000000 00:00 0").unwrap();
        assert_eq!((e.start, e.end), (0x7f2c_1a00_0000, 0x7f2c_1a02_1000));
        assert_eq!(e.perms, "rwxp");
        assert_eq!(e.pathname, None);
    }

    #[test]
    fn a_file_mapping_keeps_its_path_and_a_memfd_its_name() {
        let lib = parse_maps_line(
            "7f2c1b000000-7f2c1b1c0000 r-xp 00000000 08:01 131 /usr/lib/x86_64-linux-gnu/libc.so.6",
        )
        .unwrap();
        assert_eq!(
            lib.pathname.as_deref(),
            Some("/usr/lib/x86_64-linux-gnu/libc.so.6")
        );
        let memfd = parse_maps_line(
            "7f2c1c000000-7f2c1c001000 r-xp 00000000 00:01 9 /memfd:payload (deleted)",
        )
        .unwrap();
        assert_eq!(memfd.pathname.as_deref(), Some("/memfd:payload (deleted)"));
    }

    #[test]
    fn a_pathname_with_spaces_is_kept_whole() {
        let e = parse_maps_line("1000-2000 r-xp 00000000 08:01 5     /opt/my app/bin x (deleted)")
            .unwrap();
        assert_eq!(e.pathname.as_deref(), Some("/opt/my app/bin x (deleted)"));
    }

    #[test]
    fn pseudo_paths_are_returned_as_written() {
        let e = parse_maps_line("7ffd3c000000-7ffd3c021000 rw-p 00000000 00:00 0 [stack]").unwrap();
        assert_eq!(e.pathname.as_deref(), Some("[stack]"));
    }

    #[test]
    fn malformed_lines_are_errors_and_counted_never_a_panic() {
        assert_eq!(parse_maps_line(""), Err(MapsError::NoRange));
        assert_eq!(parse_maps_line("7f00-7f10"), Err(MapsError::NoPerms));
        assert!(matches!(
            parse_maps_line("zz-qq rwxp 0 0 0"),
            Err(MapsError::BadRange(_))
        ));
        assert!(matches!(
            parse_maps_line("nodash rwxp 0 0 0"),
            Err(MapsError::BadRange(_))
        ));
        let (entries, bad) =
            parse_maps("1000-2000 r-xp 0 0 0 /a\ngarbage\n\n3000-4000 rw-p 0 0 0\n");
        assert_eq!((entries.len(), bad), (2, 1));
        // An enormous range column cannot make the error message huge.
        let long = format!("{}-1 rwxp 0 0 0", "f".repeat(10_000));
        let Err(MapsError::BadRange(shown)) = parse_maps_line(&long) else {
            panic!("expected BadRange")
        };
        assert!(shown.len() <= 40);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_own_process_maps_and_memory_can_be_read() {
        let marker = b"PROCMEM-SELF-TEST-MARKER".to_vec();
        let pid = std::process::id();
        let (entries, _) = read_maps(pid).unwrap();
        let addr = marker.as_ptr() as u64;
        let region = entries
            .iter()
            .find(|e| e.start <= addr && addr < e.end)
            .expect("the marker lives in some mapping");
        assert!(region.perms.starts_with('r'));
        let got = read_memory(pid, addr, marker.len()).unwrap();
        assert_eq!(got, marker);
    }

    /// A memfd named with bytes that are not UTF-8 must not cost the scan the rest of the
    /// process's mappings: it used to fail the whole file with `InvalidData`, which let a
    /// memfd-exec implant opt out of the scan by how it named its memfd.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_memfd_with_a_non_utf8_name_does_not_hide_the_other_mappings() {
        let marker = b"PROCMEM-NON-UTF8-MARKER".to_vec();
        // SAFETY: a NUL-terminated name, and the fd returned is checked before use.
        let fd = unsafe { libc::memfd_create(c"\xff x".as_ptr(), 0) };
        assert!(
            fd >= 0,
            "memfd_create failed: {}",
            io::Error::last_os_error()
        );
        // SAFETY: `fd` is the memfd just created and owned here; resizing it to one page
        // and mapping that page read-only is bounded, and MAP_FAILED is checked.
        let page = unsafe {
            assert_eq!(libc::ftruncate(fd, 4096), 0);
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED, "{}", io::Error::last_os_error());

        let result = read_maps(std::process::id());

        // SAFETY: the mapping and fd created above, released exactly once.
        unsafe {
            libc::munmap(page, 4096);
            libc::close(fd);
        }
        let (entries, _) = result.expect("one hostile name must not fail the whole file");
        let hostile = entries
            .iter()
            .find(|e| e.pathname.as_deref().is_some_and(|p| p.contains("memfd:")))
            .expect("the hostile memfd mapping is still listed");
        assert!(
            hostile.pathname.as_deref().unwrap().contains('\u{FFFD}'),
            "the invalid byte is replaced, not dropped with the line: {hostile:?}"
        );
        let addr = marker.as_ptr() as u64;
        assert!(
            entries.iter().any(|e| e.start <= addr && addr < e.end),
            "the mapping holding another region's marker is still found"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_read_at_an_unmapped_address_is_an_error_not_garbage() {
        assert!(read_memory(std::process::id(), 8, 16).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_that_does_not_exist_is_an_error() {
        assert!(read_maps(u32::MAX).is_err());
        assert!(read_memory(u32::MAX, 0x1000, 8).is_err());
    }
}
