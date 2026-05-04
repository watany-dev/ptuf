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

/// Parse a minimal RFC3339 timestamp (`YYYY-MM-DDTHH:MM:SS` followed by
/// `Z` or `±HH:MM`) into seconds since the Unix epoch. Fractional
/// seconds, lowercase `t`, and offsets without a colon are rejected;
/// allowlist authors are expected to write timestamps in canonical
/// form. Returns `None` on any parse failure.
pub fn parse_rfc3339_to_secs(s: &str) -> Option<u64> {
    // YYYY-MM-DDTHH:MM:SS = 19 chars, plus zone (`Z` or `±HH:MM`).
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    if bytes[4] != b'-' {
        return None;
    }
    let month: u32 = s.get(5..7)?.parse().ok()?;
    if bytes[7] != b'-' {
        return None;
    }
    let day: u32 = s.get(8..10)?.parse().ok()?;
    if bytes[10] != b'T' {
        return None;
    }
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    if bytes[13] != b':' {
        return None;
    }
    let minute: u32 = s.get(14..16)?.parse().ok()?;
    if bytes[16] != b':' {
        return None;
    }
    let second: u32 = s.get(17..19)?.parse().ok()?;

    let (zone_sign, zone_hours, zone_minutes) = match bytes[19] {
        b'Z' => {
            if bytes.len() != 20 {
                return None;
            }
            (1i64, 0u32, 0u32)
        }
        sign @ (b'+' | b'-') => {
            if bytes.len() != 25 || bytes[22] != b':' {
                return None;
            }
            let zh: u32 = s.get(20..22)?.parse().ok()?;
            let zm: u32 = s.get(23..25)?.parse().ok()?;
            let mul: i64 = if sign == b'+' { 1 } else { -1 };
            (mul, zh, zm)
        }
        _ => return None,
    };

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
        || zone_hours > 23
        || zone_minutes > 59
    {
        return None;
    }

    let local = ymdhms_to_secs((year, month, day, hour, minute, second))?;
    let offset = (zone_hours as i64) * 3600 + (zone_minutes as i64) * 60;
    let utc = local.checked_sub(zone_sign * offset)?;
    if utc < 0 { None } else { Some(utc as u64) }
}

/// Convert a UTC date-time tuple into seconds since 1970-01-01T00:00:00Z.
/// Returns `None` for years before 1970 (the project never emits or
/// accepts pre-epoch timestamps).
fn ymdhms_to_secs(parts: (i32, u32, u32, u32, u32, u32)) -> Option<i64> {
    let (year, month, day, hour, minute, second) = parts;
    if year < 1970 {
        return None;
    }
    let mut days: i64 = 0;
    for y in 1970..year {
        days += days_in_year(y) as i64;
    }
    let leap = is_leap(year);
    for m in 1..month {
        days += days_in_month(m, leap) as i64;
    }
    if day == 0 || day > days_in_month(month, leap) {
        return None;
    }
    days += (day - 1) as i64;
    let secs = days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64;
    Some(secs)
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

    #[test]
    fn parses_canonical_utc_timestamp() {
        assert_eq!(
            parse_rfc3339_to_secs("2024-01-01T00:00:00Z"),
            Some(1_704_067_200)
        );
        assert_eq!(parse_rfc3339_to_secs("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parses_positive_and_negative_offsets() {
        // 09:00 +09:00 == 00:00 UTC
        assert_eq!(
            parse_rfc3339_to_secs("2024-01-01T09:00:00+09:00"),
            Some(1_704_067_200)
        );
        // 23:00 prior day -01:00 == 00:00 UTC
        assert_eq!(
            parse_rfc3339_to_secs("2023-12-31T23:00:00-01:00"),
            Some(1_704_067_200)
        );
    }

    #[test]
    fn rejects_malformed_timestamps() {
        assert!(parse_rfc3339_to_secs("").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01t00:00:00Z").is_none()); // lowercase t
        assert!(parse_rfc3339_to_secs("2024-13-01T00:00:00Z").is_none()); // month 13
        assert!(parse_rfc3339_to_secs("2024-01-32T00:00:00Z").is_none()); // day 32
        assert!(parse_rfc3339_to_secs("2024-01-01T24:00:00Z").is_none()); // hour 24
        assert!(parse_rfc3339_to_secs("2024-01-01T00:60:00Z").is_none()); // minute 60
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00+0900").is_none()); // missing colon
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00Z00").is_none()); // trailing data
        assert!(parse_rfc3339_to_secs("2024-02-30T00:00:00Z").is_none()); // invalid day for Feb
        assert!(parse_rfc3339_to_secs("1969-12-31T23:59:59Z").is_none()); // pre-epoch
    }

    #[test]
    fn parses_leap_day() {
        // 2024-02-29 is a valid leap-year date.
        assert_eq!(
            parse_rfc3339_to_secs("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
        // 2023 was not a leap year.
        assert!(parse_rfc3339_to_secs("2023-02-29T00:00:00Z").is_none());
    }

    #[test]
    fn rejects_wrong_separator_after_year() {
        // bytes[4] must be '-'.
        assert!(parse_rfc3339_to_secs("2024.01-01T00:00:00Z").is_none());
    }

    #[test]
    fn rejects_wrong_separator_after_month() {
        // bytes[7] must be '-'.
        assert!(parse_rfc3339_to_secs("2024-01.01T00:00:00Z").is_none());
    }

    #[test]
    fn rejects_wrong_separator_after_hour() {
        // bytes[13] must be ':'.
        assert!(parse_rfc3339_to_secs("2024-01-01T00.00:00Z").is_none());
    }

    #[test]
    fn rejects_wrong_separator_after_minute() {
        // bytes[16] must be ':'.
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00.00Z").is_none());
    }

    #[test]
    fn rejects_unrecognised_zone_marker() {
        // bytes[19] must be 'Z', '+', or '-'.
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00X").is_none());
    }
}
