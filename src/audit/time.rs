//! RFC3339 UTC timestamp helpers for audit records and allowlist expiry.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// Format the supplied [`SystemTime`] as an RFC3339 string in UTC with
/// second precision (e.g. `2026-05-04T12:00:00Z`). Times before the
/// Unix epoch are clamped to the epoch; they never occur in practice
/// but a panic-free fallback keeps the audit pipeline lossless.
pub fn rfc3339_utc(t: SystemTime) -> String {
    let t = t
        .duration_since(UNIX_EPOCH)
        .map(|duration| UNIX_EPOCH + Duration::from_secs(duration.as_secs()))
        .unwrap_or(UNIX_EPOCH);
    let dt = OffsetDateTime::from(t).to_offset(UtcOffset::UTC);
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
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
    let dt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let secs = dt.unix_timestamp();
    if secs < 0 { None } else { Some(secs as u64) }
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
        let t = UNIX_EPOCH - Duration::from_secs(60);
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

    #[test]
    fn rejects_separator_typos() {
        assert!(parse_rfc3339_to_secs("2024.01-01T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01.01T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00.00:00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00.00Z").is_none());
        assert!(parse_rfc3339_to_secs("2024-01-01T00:00:00X").is_none());
    }
}
