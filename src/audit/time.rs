//! Minimal RFC3339 (UTC, second precision) formatter.
//!
//! Lifted out of `chrono` / `time` to keep the dependency footprint
//! small. The implementation handles dates from the Unix epoch onward —
//! ptuf never emits a timestamp earlier than that, and all sinks use
//! [`std::time::SystemTime::now`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Format the supplied [`SystemTime`] as an RFC3339 string in UTC with
/// second precision (e.g. `2026-05-04T12:00:00Z`). Times before the
/// Unix epoch are clamped to the epoch — they never occur in practice
/// but a panic-free fallback keeps the audit pipeline lossless.
pub fn rfc3339_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let (year, month, day, hour, min, sec) = decompose(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert a Unix timestamp (seconds since epoch, UTC) into
/// `(year, month, day, hour, minute, second)` components. Pure
/// computation, no allocations beyond the return tuple.
fn decompose(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let day_seconds = 86_400u64;
    let mut days = (secs / day_seconds) as i64;
    let mut rem = (secs % day_seconds) as u32;
    let hour = rem / 3_600;
    rem %= 3_600;
    let min = rem / 60;
    let sec = rem % 60;

    let mut year: i32 = 1970;
    loop {
        let dy = days_in_year(year);
        if days >= dy as i64 {
            days -= dy as i64;
            year += 1;
        } else {
            break;
        }
    }
    let leap = is_leap(year);
    let mut month = 1u32;
    while month <= 12 {
        let dim = days_in_month(month, leap) as i64;
        if days >= dim {
            days -= dim;
            month += 1;
        } else {
            break;
        }
    }
    let day = days as u32 + 1;
    (year, month, day, hour, min, sec)
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_year(year: i32) -> u32 {
    if is_leap(year) { 366 } else { 365 }
}

fn days_in_month(month: u32, leap: bool) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_secs(s: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(s)
    }

    #[test]
    fn formats_unix_epoch() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn formats_known_timestamps() {
        // 2024-01-01T00:00:00Z = 1_704_067_200
        assert_eq!(
            rfc3339_utc(from_secs(1_704_067_200)),
            "2024-01-01T00:00:00Z"
        );
        // 2026-05-04T12:00:00Z = 1_777_896_000
        assert_eq!(
            rfc3339_utc(from_secs(1_777_896_000)),
            "2026-05-04T12:00:00Z"
        );
        // 2000-02-29T00:00:00Z (leap-year boundary)
        assert_eq!(rfc3339_utc(from_secs(951_782_400)), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn pre_epoch_clamps_to_epoch_string() {
        // SystemTime can represent times before UNIX_EPOCH on some
        // platforms; we treat those as the epoch rather than panic.
        let t = UNIX_EPOCH - Duration::from_secs(60);
        assert_eq!(rfc3339_utc(t), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn leap_year_predicate_matches_gregorian_rule() {
        assert!(is_leap(2000));
        assert!(!is_leap(1900));
        assert!(is_leap(2024));
        assert!(!is_leap(2023));
    }

    #[test]
    fn days_in_month_handles_february_leap_and_non_leap() {
        assert_eq!(days_in_month(2, true), 29);
        assert_eq!(days_in_month(2, false), 28);
        assert_eq!(days_in_month(4, false), 30);
        assert_eq!(days_in_month(7, false), 31);
        assert_eq!(days_in_month(13, false), 0);
    }
}
