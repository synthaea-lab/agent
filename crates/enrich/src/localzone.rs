//! The host's own time zone, as the platform's conversion gives it (#1088): the offset from UTC
//! at a given instant, daylight saving included, so ODD-HOUR-LOGON judges a logon by the hour
//! the host's clock showed.
//!
//! **No zone database is bundled.** The platform already has one and keeps it current, and a
//! copy in the agent would go stale on its own schedule. The cost is that this module is three
//! small platform calls instead of one portable one, and that the answer is only as right as the
//! host's own zone configuration:
//! - Unix (Linux, macOS): `tzset` + `localtime_r`, which read `TZ` or `/etc/localtime` and the
//!   zoneinfo file, and give `tm_gmtoff` for any instant (past or future, either side of a
//!   change). `tzset` is called on every conversion so a zone the administrator changes while
//!   the agent runs is followed; a logon is rare, so the call is cheap enough.
//! - Windows: `GetDynamicTimeZoneInformation` + `SystemTimeToTzSpecificLocalTimeEx`, the
//!   year-aware conversion (the older call applies the rules of the current year to every
//!   instant).
//!
//! [`configured`] says whether the host names a zone at all. On Unix a host with no `TZ` and no
//! `/etc/localtime` (a minimal container) is silently UTC to the C library, and that is not a
//! zone anyone chose: the rule would then judge in UTC on a host whose people are not. Such a
//! host stays off until the operator sets `[detection] utc_offset_minutes`.

/// Whether the host names a time zone: `TZ` is set, or `/etc/localtime` exists (Unix); always
/// true on Windows, which has a zone setting whether or not anyone changed it.
#[must_use]
pub fn configured() -> bool {
    #[cfg(unix)]
    {
        std::env::var_os("TZ").is_some() || std::path::Path::new("/etc/localtime").exists()
    }
    #[cfg(windows)]
    {
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Minutes east of UTC that the host's zone is at `utc_secs` (seconds since the Unix epoch), or
/// `None` when the platform cannot convert that instant. Sub-minute offsets (historic local mean
/// time) are truncated to the minute.
#[must_use]
pub fn utc_offset_minutes_at(utc_secs: i64) -> Option<i32> {
    imp::utc_offset_seconds_at(utc_secs).map(|s| i32::try_from(s / 60).ok())?
}

#[cfg(unix)]
mod imp {
    unsafe extern "C" {
        /// POSIX; the `libc` crate does not bind it.
        fn tzset();
    }

    pub(super) fn utc_offset_seconds_at(utc_secs: i64) -> Option<i64> {
        let time = libc::time_t::try_from(utc_secs).ok()?;
        // SAFETY: `tm` is plain data the call fills in; `localtime_r` writes only into it and
        // reads `time` by pointer for the duration of the call. `tzset` takes no arguments.
        unsafe {
            tzset();
            let mut tm: libc::tm = std::mem::zeroed();
            if libc::localtime_r(&time, &mut tm).is_null() {
                return None;
            }
            // `c_long`: `i64` here, `i32` on a 32-bit target, so the widening is not always useless.
            #[allow(clippy::useless_conversion)]
            Some(i64::from(tm.tm_gmtoff))
        }
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::{
        Foundation::{FILETIME, SYSTEMTIME},
        System::Time::{
            DYNAMIC_TIME_ZONE_INFORMATION, FileTimeToSystemTime, GetDynamicTimeZoneInformation,
            SystemTimeToFileTime, SystemTimeToTzSpecificLocalTimeEx, TIME_ZONE_ID_INVALID,
        },
    };

    /// Seconds from 1601-01-01 (the `FILETIME` epoch) to 1970-01-01.
    const UNIX_TO_FILETIME_SECS: i64 = 11_644_473_600;
    const TICKS_PER_SEC: i64 = 10_000_000;

    fn filetime_secs(ft: &FILETIME) -> i64 {
        let ticks = (i64::from(ft.dwHighDateTime) << 32) | i64::from(ft.dwLowDateTime);
        ticks / TICKS_PER_SEC - UNIX_TO_FILETIME_SECS
    }

    pub(super) fn utc_offset_seconds_at(utc_secs: i64) -> Option<i64> {
        let ticks = utc_secs
            .checked_add(UNIX_TO_FILETIME_SECS)?
            .checked_mul(TICKS_PER_SEC)?;
        let ticks = u64::try_from(ticks).ok()?;
        let ft = FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        // SAFETY: every struct is plain data the call fills in or reads, alive for the call.
        unsafe {
            let mut utc: SYSTEMTIME = std::mem::zeroed();
            if FileTimeToSystemTime(&ft, &mut utc) == 0 {
                return None;
            }
            let mut zone: DYNAMIC_TIME_ZONE_INFORMATION = std::mem::zeroed();
            if GetDynamicTimeZoneInformation(&mut zone) == TIME_ZONE_ID_INVALID {
                return None;
            }
            let mut local: SYSTEMTIME = std::mem::zeroed();
            if SystemTimeToTzSpecificLocalTimeEx(&zone, &utc, &mut local) == 0 {
                return None;
            }
            let mut local_ft: FILETIME = std::mem::zeroed();
            if SystemTimeToFileTime(&local, &mut local_ft) == 0 {
                return None;
            }
            Some(filetime_secs(&local_ft) - utc_secs)
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn utc_offset_seconds_at(_utc_secs: i64) -> Option<i64> {
        None
    }
}
