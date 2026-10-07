//! The Linux side of process-memory scanning (issue #85, ADR-0023): adapts
//! `sensor-linux-procmem` (the `/proc` mechanism) to `yara::MemorySource` (the budget
//! and trigger policy). Linux-only; the sink starts no memory scanner elsewhere.

use std::io;

use sensor_linux_procmem::{MapsEntry, read_maps, read_memory};
use yara::{MemoryRegion, MemorySource, RegionKind, RegionPerms};

/// Reads processes through `/proc/<pid>/maps` and `/proc/<pid>/mem`. A process the agent
/// may not ptrace (another uid without `CAP_SYS_PTRACE`) fails with `PermissionDenied`,
/// which the scan queue counts as `unreadable`.
pub(crate) struct ProcMemSource;

impl MemorySource for ProcMemSource {
    fn regions(&self, pid: u32) -> io::Result<Vec<MemoryRegion>> {
        let (entries, malformed) = read_maps(pid)?;
        if malformed > 0 {
            tracing::debug!(pid, malformed, "memscan: unparsable maps lines skipped");
        }
        Ok(entries.iter().map(to_region).collect())
    }

    fn read(&self, pid: u32, start: u64, len: usize) -> io::Result<Vec<u8>> {
        read_memory(pid, start, len)
    }
}

fn to_region(entry: &MapsEntry) -> MemoryRegion {
    MemoryRegion {
        start: entry.start,
        end: entry.end,
        perms: RegionPerms::parse(&entry.perms),
        kind: classify(entry.pathname.as_deref()),
    }
}

/// What backs a mapping, from the `maps` pathname column.
fn classify(pathname: Option<&str>) -> RegionKind {
    let Some(path) = pathname else {
        return RegionKind::Anonymous;
    };
    if path.starts_with("/memfd:") {
        RegionKind::Memfd
    } else if path.ends_with(" (deleted)") {
        RegionKind::Deleted
    } else if path.starts_with("[anon:") {
        // A named anonymous mapping (`prctl(PR_SET_VMA_ANON_NAME)`): still no file.
        RegionKind::Anonymous
    } else if path.starts_with('[') {
        RegionKind::Special
    } else {
        RegionKind::FileBacked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_are_classified_by_what_backs_them() {
        assert_eq!(classify(None), RegionKind::Anonymous);
        assert_eq!(classify(Some("/memfd:payload")), RegionKind::Memfd);
        assert_eq!(
            classify(Some("/memfd:payload (deleted)")),
            RegionKind::Memfd
        );
        assert_eq!(
            classify(Some("/tmp/dropped (deleted)")),
            RegionKind::Deleted
        );
        assert_eq!(
            classify(Some("[anon:scudo:primary]")),
            RegionKind::Anonymous
        );
        assert_eq!(classify(Some("[stack]")), RegionKind::Special);
        assert_eq!(classify(Some("[vdso]")), RegionKind::Special);
        assert_eq!(classify(Some("/usr/lib/libc.so.6")), RegionKind::FileBacked);
    }

    #[test]
    fn an_own_process_scan_sees_its_executable_anonymous_regions_only_as_candidates() {
        let regions = ProcMemSource.regions(std::process::id()).unwrap();
        assert!(!regions.is_empty());
        // The test binary itself is file-backed: never a candidate.
        assert!(regions.iter().any(|r| r.kind == RegionKind::FileBacked));
        assert!(
            regions
                .iter()
                .filter(|r| r.is_candidate())
                .all(|r| r.perms.exec && r.perms.read && r.kind != RegionKind::FileBacked)
        );
    }

    #[test]
    fn a_process_that_is_gone_is_an_io_error() {
        assert!(ProcMemSource.regions(u32::MAX).is_err());
    }
}
