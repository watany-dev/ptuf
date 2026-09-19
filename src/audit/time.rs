//! RFC3339 UTC timestamp helpers for audit records and allowlist expiry.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format the supplied [`SystemTime`] as an RFC3339 string in UTC with
/// second precision (e.g. `2026-05-04T12:00:00Z`). Times before the
/// Unix epoch are clamped to the epoch; they never occur in practice
/// but a panic-free fallback keeps the audit pipeline lossless.
pub fn rfc3339_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parse a canonical RFC3339 timestamp (`YYYY-MM-DDTHH:MM:SS` followed
/// by `Z` or `±HH:MM`) into seconds since the Unix epoch. Fractional
/// seconds, lowercase `t`, and offsets without a colon are rejected;
/// allowlist authors are expected to write timestamps in canonical
/// form. Returns `None` on any parse failure.
pub fn parse_rfc3339_to_secs(s: &str) -> Option<u64> {
    if !has_canonical_shape(s) {
        return None;
    }
    let bytes = s.as_bytes();
    let year = i32::try_from(parse_digits(bytes, 0, 4)?).ok()?;
    let month = parse_digits(bytes, 5, 2)?;
    let day = parse_digits(bytes, 8, 2)?;
    let hour = parse_digits(bytes, 11, 2)?;
    let minute = parse_digits(bytes, 14, 2)?;
    let second = parse_digits(bytes, 17, 2)?;
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let max_day = days_in_month(year, month)?;
    if day < 1 || day > max_day {
        return None;
    }
    let mut unix = days_from_civil(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(i64::from(hour * 3_600 + minute * 60 + second))?;
    if bytes.len() == 25 {
        let sign: i64 = if bytes[19] == b'+' { 1 } else { -1 };
        let off_h = parse_digits(bytes, 20, 2)?;
        let off_m = parse_digits(bytes, 23, 2)?;
        if off_h > 23 || off_m > 59 {
            return None;
        }
        let offset = i64::from(off_h * 3_600 + off_m * 60) * sign;
        unix = unix.checked_sub(offset)?;
    }
    u64::try_from(unix).ok()
}

fn parse_digits(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let slice = bytes.get(start..start + len)?;
    let mut n = 0u32;
    for b in slice {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(n)
}

fn is_leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        },
        _ => return None,
    })
}

/// Howard Hinnant `days_from_civil`: days since 1970-01-01.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);
    if m <= 2 {
        y -= 1;
    }
    let era = if y >= 0 { y } else { y - 399 }.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Howard Hinnant `civil_from_days`: inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = u32::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i32::try_from(yoe).unwrap_or(i32::MAX) + i32::try_from(era).unwrap_or(0) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn has_canonical_shape(s: &str) -> bool {
    let bytes = s.as_bytes();
    match bytes.len() {
        20 => {
            bytes[4] == b'-'
                && bytes[7] == b'-'
                && bytes[10] == b'T'
                && bytes[13] == b':'
                && bytes[16] == b':'
                && bytes[19] == b'Z'
        },
        25 => {
            bytes[4] == b'-'
                && bytes[7] == b'-'
                && bytes[10] == b'T'
                && bytes[13] == b':'
                && bytes[16] == b':'
                && matches!(bytes[19], b'+' | b'-')
                && bytes[22] == b':'
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
    fn drops_subsecond_precision() {
        let t = UNIX_EPOCH + Duration::new(1_704_067_200, 123_456_789);
        assert_eq!(rfc3339_utc(t), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn pre_epoch_clamps_to_epoch_string() {
        // SystemTime can represent times before UNIX_EPOCH on some
        // platforms; we treat those as the epoch rather than panic.
        let t = UNIX_EPOCH - Duration::from_mins(1);
        assert_eq!(rfc3339_utc(t), "1970-01-01T00:00:00Z");
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

    // `+00:00` / `-00:00` must parse to the same instant as `Z` so
    // future authors don't accidentally restrict the parser to `Z`.
    #[test]
    fn parses_explicit_zero_offset_as_utc() {
        assert_eq!(
            parse_rfc3339_to_secs("2024-01-01T00:00:00+00:00"),
            parse_rfc3339_to_secs("2024-01-01T00:00:00Z"),
        );
        assert_eq!(
            parse_rfc3339_to_secs("2024-01-01T00:00:00-00:00"),
            parse_rfc3339_to_secs("2024-01-01T00:00:00Z"),
        );
    }

    // Extreme IANA offsets (+14:00, -12:00) must parse so allowlist
    // authors anywhere can express expiry without converting to UTC.
    #[test]
    fn parses_extreme_iana_offsets() {
        // 14:00 +14:00 == 00:00 UTC
        assert_eq!(
            parse_rfc3339_to_secs("2024-01-01T14:00:00+14:00"),
            Some(1_704_067_200)
        );
        // 12:00 prior day -12:00 == 00:00 UTC
        assert_eq!(
            parse_rfc3339_to_secs("2023-12-31T12:00:00-12:00"),
            Some(1_704_067_200)
        );
    }

    // Half-hour offsets (e.g. +05:30, -03:30) are valid RFC 3339.
    #[test]
    fn parses_half_hour_offsets() {
        // 05:30 +05:30 == 00:00 UTC
        assert_eq!(
            parse_rfc3339_to_secs("2024-01-01T05:30:00+05:30"),
            Some(1_704_067_200)
        );
        // 20:30 prior day -03:30 == 00:00 UTC
        assert_eq!(
            parse_rfc3339_to_secs("2023-12-31T20:30:00-03:30"),
            Some(1_704_067_200)
        );
    }

    #[test]
    fn rejects_malformed_timestamps() {
        assert!(parse_rfc3339_to_secs("").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01t00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-13-01T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-32T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T24:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:60:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00+0900").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00Z00").is_none());
        assert!(parse_rfc3339_to_secs("2024-02-30T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("1969-12-31T23:59:59Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00.1Z").is_none());
    }

    #[test]
    fn leap_day_must_be_valid_for_year() {
        assert_eq!(
            parse_rfc3339_to_secs("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
        assert!(parse_rfc3339_to_secs("2023-02-29T00:00:00Z").is_none());
    }

    // Characterization tests pinning parser behavior at calendar and
    // offset boundaries. These were written (and verified green) against
    // the original `time`-crate-backed implementation before it was
    // replaced with the in-tree integer-arithmetic implementation, so
    // they guard the swap against silent behavior drift.

    // A leap second that is not the last second of a UTC day is invalid.
    #[test]
    fn rejects_leap_second_outside_end_of_day() {
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:60Z").is_none());
    }

    // Day-of-month must respect the actual month length, including the
    // Gregorian century rule (2100 is not a leap year, 2000 is).
    #[test]
    fn respects_month_lengths_and_century_rule() {
        assert!(parse_rfc3339_to_secs("2024-04-31T00:00:00Z").is_none());
        assert_eq!(
            parse_rfc3339_to_secs("2024-04-30T00:00:00Z"),
            Some(1_714_435_200)
        );
        assert!(parse_rfc3339_to_secs("2100-02-29T00:00:00Z").is_none());
        assert_eq!(
            parse_rfc3339_to_secs("2100-02-28T00:00:00Z"),
            Some(4_107_456_000)
        );
        assert_eq!(
            parse_rfc3339_to_secs("2000-02-29T00:00:00Z"),
            Some(951_782_400)
        );
    }

    // A positive offset can push an instant before the Unix epoch; the
    // parser reports those as unrepresentable rather than wrapping.
    #[test]
    fn rejects_instants_that_offset_before_the_epoch() {
        assert!(parse_rfc3339_to_secs("1970-01-01T00:00:00+09:00").is_none());
        assert_eq!(parse_rfc3339_to_secs("1970-01-01T09:00:00+09:00"), Some(0));
    }

    // Offset fields have their own ranges: hour <= 23, minute <= 59.
    #[test]
    fn enforces_offset_component_ranges() {
        assert_eq!(
            parse_rfc3339_to_secs("2024-01-01T23:59:00+23:59"),
            Some(1_704_067_200)
        );
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00+24:00").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00+00:60").is_none());
    }

    #[test]
    fn rejects_separator_typos() {
        assert!(parse_rfc3339_to_secs("2024.01-01T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01.01T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00.00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00.00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00X").is_none());
    }

    use proptest::prelude::*;

    // Stay well inside four-digit years so formatted timestamps remain
    // 20 characters wide (`YYYY-MM-DDTHH:MM:SSZ`).
    const MAX_EPOCH_SECS: u64 = 32_503_680_000;

    proptest! {
        // Formatting an epoch-second instant and parsing it back must
        // recover the exact same second.
        #[test]
        fn pbt_rfc3339_round_trips_through_parse(secs in 0..=MAX_EPOCH_SECS) {
            let formatted = rfc3339_utc(from_secs(secs));
            prop_assert_eq!(parse_rfc3339_to_secs(&formatted), Some(secs));
        }

        // Sub-second precision is dropped: an instant with arbitrary
        // nanoseconds formats identically to its truncated second.
        #[test]
        fn pbt_rfc3339_truncates_subsecond(
            secs in 0..=MAX_EPOCH_SECS,
            nanos in 0u32..1_000_000_000,
        ) {
            let precise = UNIX_EPOCH + Duration::new(secs, nanos);
            prop_assert_eq!(rfc3339_utc(precise), rfc3339_utc(from_secs(secs)));
        }

        // Any instant before the Unix epoch clamps to the epoch string
        // rather than panicking or yielding a negative timestamp.
        #[test]
        fn pbt_rfc3339_pre_epoch_clamps_to_epoch(back in 1u64..4_000_000_000) {
            let pre = UNIX_EPOCH - Duration::from_secs(back);
            prop_assert_eq!(rfc3339_utc(pre), "1970-01-01T00:00:00Z");
        }

        // `parse_rfc3339_to_secs` is total: arbitrary input either
        // parses or returns `None`, and never panics.
        #[test]
        fn pbt_parse_is_total_on_arbitrary_strings(
            s in prop_oneof![
                crate::testing::proptest::arbitrary_command(),
                "[0-9:.+TZ-]{0,30}",
            ],
        ) {
            let _ = parse_rfc3339_to_secs(&s);
        }
    }
}
