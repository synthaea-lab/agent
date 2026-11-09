//! Kernel paths into the one form every event carries: the NT device prefix
//! mapped to its drive letter (F-5), then 8.3 short components expanded (#489).

use std::{collections::HashMap, sync::Mutex};

use crate::{
    long_path::{self, LongPathCache},
    normalize,
    sync::LockExt,
};

/// NT device prefix (`\Device\HarddiskVolume3`) → drive (`C:`).
pub(crate) type VolumeMap = HashMap<String, String>;

/// Owns the volume map and the long-path cache, and the two lookups that fill
/// them (`QueryDosDeviceW` and `GetLongPathNameW` on Windows).
pub(crate) struct PathNormalizer {
    volumes: Mutex<VolumeMap>,
    long_paths: Mutex<LongPathCache>,
    read_volume_map: fn() -> VolumeMap,
    long_path_name: fn(&str) -> Option<String>,
}

impl PathNormalizer {
    /// Reads the volume map once, up front.
    pub(crate) fn new(
        read_volume_map: fn() -> VolumeMap,
        long_path_name: fn(&str) -> Option<String>,
        long_path_cache_cap: usize,
    ) -> Self {
        Self {
            volumes: Mutex::new(read_volume_map()),
            long_paths: Mutex::new(LongPathCache::new(long_path_cache_cap)),
            read_volume_map,
            long_path_name,
        }
    }

    pub(crate) fn normalize(&self, raw: &str) -> String {
        let dos = self.to_dos_path(raw);
        long_path::expand(&dos, &self.long_paths, self.long_path_name)
    }

    fn to_dos_path(&self, raw: &str) -> String {
        let normalized = normalize::normalize_nt_path(raw, &self.volumes.lock_or_recover());
        if normalized.starts_with(r"\Device\") {
            // Unknown device: refresh the map once (a newly mounted volume) and retry.
            let fresh = (self.read_volume_map)();
            let mut volumes = self.volumes.lock_or_recover();
            *volumes = fresh;
            return normalize::normalize_nt_path(raw, &volumes);
        }
        normalized
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    thread_local! {
        static VOLUME_MAP_READS: Cell<u32> = const { Cell::new(0) };
        static SECOND_VOLUME_MOUNTED: Cell<bool> = const { Cell::new(false) };
        static LONG_PATH_LOOKUPS: Cell<u32> = const { Cell::new(0) };
    }

    fn volume_map() -> VolumeMap {
        VOLUME_MAP_READS.with(|reads| reads.set(reads.get() + 1));
        let mut map = VolumeMap::from([(r"\Device\HarddiskVolume3".to_owned(), "C:".to_owned())]);
        if SECOND_VOLUME_MOUNTED.with(Cell::get) {
            map.insert(r"\Device\HarddiskVolume7".to_owned(), "E:".to_owned());
        }
        map
    }

    fn long_path_name(path: &str) -> Option<String> {
        LONG_PATH_LOOKUPS.with(|lookups| lookups.set(lookups.get() + 1));
        match path {
            r"C:\Users\JIHAIR~1" => Some(r"C:\Users\Ji Hair".to_owned()),
            r"C:\Users\Ji Hair\PAYLOA~1.EXE" => Some(r"C:\Users\Ji Hair\payload.exe".to_owned()),
            _ => None,
        }
    }

    fn volume_map_reads() -> u32 {
        VOLUME_MAP_READS.with(Cell::get)
    }

    /// Resets the fakes too: with `--test-threads=1` every test runs on one thread.
    fn normalizer() -> PathNormalizer {
        VOLUME_MAP_READS.with(|reads| reads.set(0));
        SECOND_VOLUME_MOUNTED.with(|mounted| mounted.set(false));
        LONG_PATH_LOOKUPS.with(|lookups| lookups.set(0));
        PathNormalizer::new(volume_map, long_path_name, 16)
    }

    #[test]
    fn the_volume_map_is_read_once_at_construction() {
        let _normalizer = normalizer();
        assert_eq!(volume_map_reads(), 1);
    }

    #[test]
    fn a_known_device_maps_to_its_drive_without_rereading_the_map() {
        let normalizer = normalizer();
        assert_eq!(
            normalizer.normalize(r"\Device\HarddiskVolume3\Windows\notepad.exe"),
            r"C:\Windows\notepad.exe"
        );
        assert_eq!(volume_map_reads(), 1);
    }

    #[test]
    fn an_unknown_device_rereads_the_map_and_finds_a_newly_mounted_volume() {
        let normalizer = normalizer();
        SECOND_VOLUME_MOUNTED.with(|mounted| mounted.set(true));
        assert_eq!(
            normalizer.normalize(r"\Device\HarddiskVolume7\stage\x.exe"),
            r"E:\stage\x.exe"
        );
        assert_eq!(volume_map_reads(), 2);
    }

    #[test]
    fn the_reread_map_is_kept_for_later_paths() {
        let normalizer = normalizer();
        SECOND_VOLUME_MOUNTED.with(|mounted| mounted.set(true));
        normalizer.normalize(r"\Device\HarddiskVolume7\a");
        assert_eq!(normalizer.normalize(r"\Device\HarddiskVolume7\b"), r"E:\b");
        assert_eq!(volume_map_reads(), 2);
    }

    #[test]
    fn a_device_still_unknown_after_the_reread_keeps_its_raw_path() {
        let normalizer = normalizer();
        assert_eq!(
            normalizer.normalize(r"\Device\Mup\server\share\x.exe"),
            r"\Device\Mup\server\share\x.exe"
        );
        assert_eq!(volume_map_reads(), 2);
    }

    #[test]
    fn short_components_are_expanded_after_the_drive_is_mapped() {
        let normalizer = normalizer();
        assert_eq!(
            normalizer.normalize(r"\Device\HarddiskVolume3\Users\JIHAIR~1\PAYLOA~1.EXE"),
            r"C:\Users\Ji Hair\payload.exe"
        );
    }

    #[test]
    fn an_expanded_short_directory_is_cached() {
        let normalizer = normalizer();
        normalizer.normalize(r"C:\Users\JIHAIR~1\a.txt");
        normalizer.normalize(r"C:\Users\JIHAIR~1\b.txt");
        assert_eq!(LONG_PATH_LOOKUPS.with(Cell::get), 1);
    }

    #[test]
    fn a_path_without_short_components_is_not_looked_up() {
        let normalizer = normalizer();
        assert_eq!(
            normalizer.normalize(r"\Device\HarddiskVolume3\Windows\x.exe"),
            r"C:\Windows\x.exe"
        );
        assert_eq!(LONG_PATH_LOOKUPS.with(Cell::get), 0);
    }
}
