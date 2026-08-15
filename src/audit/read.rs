//! Read-only JSONL viewer for audit logs.
//!
//! Byte-oriented: lines are split on `\n` and fed to `serde_json::from_slice`
//! so invalid UTF-8 is a skipped record, not a hard failure. Fail-soft applies
//! only to line contents; real I/O errors propagate as [`io::Result`].
//!
//! Production callers land in `cli::run_audit`; until that is wired the
//! non-test lib build sees this module as unused.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "wired by cli::run_audit (issue #189)")
)]

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use super::time::parse_rfc3339_to_secs;

pub const MAX_AUDIT_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinceError {
    Invalid,
    Overflow,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub decision: Option<String>,
    pub rule_id: Option<String>,
    pub tool: Option<String>,
    pub since_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuditRecord {
    pub timestamp: String,
    pub timestamp_secs: u64,
    pub tool: String,
    pub decision: String,
    pub rule_id: Option<String>,
    pub severity: Option<String>,
    pub command_redacted: String,
}

#[derive(Debug, Clone)]
pub struct ReadOutcome {
    pub lines_read: u64,
    pub valid_records: u64,
    pub matched: u64,
    pub skipped_invalid: u64,
    pub skipped_unsupported_schema: u64,
    pub incomplete_tail: bool,
    pub records: Vec<(Value, ValidatedAuditRecord)>,
}

#[derive(Debug, Clone)]
pub struct AuditStats {
    pub lines_read: u64,
    pub valid_records: u64,
    pub matched: u64,
    pub skipped_invalid: u64,
    pub skipped_unsupported_schema: u64,
    pub incomplete_tail: bool,
    pub by_decision: Vec<(String, u64)>,
    pub by_rule: Vec<(String, u64)>,
}

pub struct Snapshot {
    reader: io::Take<File>,
    lock_failed: bool,
}

impl Snapshot {
    pub fn lock_failed(&self) -> bool {
        self.lock_failed
    }
}

impl Read for Snapshot {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

#[derive(Debug, Deserialize)]
struct RawAuditRecord {
    #[serde(rename = "schemaVersion")]
    schema_version: Option<u32>,
    timestamp: Option<String>,
    tool: Option<String>,
    decision: Option<String>,
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    severity: Option<String>,
    #[serde(rename = "commandRedacted")]
    command_redacted: Option<String>,
}

enum ScanEvent<'a> {
    Line(&'a [u8]),
    Oversize,
}

enum Classified {
    Blank,
    Invalid,
    Unsupported,
    Valid(Value, ValidatedAuditRecord),
}

enum Collector {
    List {
        limit: usize,
        items: VecDeque<(Value, ValidatedAuditRecord)>,
    },
    Stats {
        by_decision: HashMap<String, u64>,
        by_rule: HashMap<String, u64>,
    },
}

#[derive(Default)]
struct Counters {
    lines_read: u64,
    valid_records: u64,
    matched: u64,
    skipped_invalid: u64,
    skipped_unsupported_schema: u64,
    incomplete_tail: bool,
}

pub fn parse_since(value: &str, now: SystemTime) -> Result<u64, SinceError> {
    if let Some(secs) = parse_rfc3339_to_secs(value) {
        return Ok(secs);
    }
    parse_relative(value, now)
}

pub fn read_filtered<R: Read>(
    reader: R,
    filter: &AuditFilter,
    limit: usize,
) -> io::Result<ReadOutcome> {
    let mut collector = Collector::List {
        limit,
        items: VecDeque::new(),
    };
    let counters = scan_into(reader, filter, &mut collector)?;
    let records = match collector {
        Collector::List { items, .. } => Vec::from(items),
        Collector::Stats { .. } => Vec::new(),
    };
    Ok(ReadOutcome {
        lines_read: counters.lines_read,
        valid_records: counters.valid_records,
        matched: counters.matched,
        skipped_invalid: counters.skipped_invalid,
        skipped_unsupported_schema: counters.skipped_unsupported_schema,
        incomplete_tail: counters.incomplete_tail,
        records,
    })
}

pub fn stats<R: Read>(reader: R, filter: &AuditFilter) -> io::Result<AuditStats> {
    let mut collector = Collector::Stats {
        by_decision: HashMap::new(),
        by_rule: HashMap::new(),
    };
    let counters = scan_into(reader, filter, &mut collector)?;
    let (by_decision, by_rule) = match collector {
        Collector::Stats {
            by_decision,
            by_rule,
        } => (sorted_counts(by_decision), sorted_counts(by_rule)),
        Collector::List { .. } => (Vec::new(), Vec::new()),
    };
    Ok(AuditStats {
        lines_read: counters.lines_read,
        valid_records: counters.valid_records,
        matched: counters.matched,
        skipped_invalid: counters.skipped_invalid,
        skipped_unsupported_schema: counters.skipped_unsupported_schema,
        incomplete_tail: counters.incomplete_tail,
        by_decision,
        by_rule,
    })
}

pub fn open_snapshot(path: &Path) -> io::Result<Snapshot> {
    let file = File::open(path)?;
    let (len, lock_ok) = snapshot_len(&file)?;
    Ok(Snapshot {
        reader: file.take(len),
        lock_failed: !lock_ok,
    })
}

fn parse_relative(value: &str, now: SystemTime) -> Result<u64, SinceError> {
    let bytes = value.as_bytes();
    let (digits, unit) = split_relative(bytes).ok_or(SinceError::Invalid)?;
    let n = parse_digits(digits)?;
    let delta = relative_secs(n, unit)?;
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now_secs.checked_sub(delta).ok_or(SinceError::Overflow)
}

fn split_relative(bytes: &[u8]) -> Option<(&[u8], u8)> {
    let (unit, digits) = bytes.split_last()?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    matches!(*unit, b'm' | b'h' | b'd').then_some((digits, *unit))
}

fn parse_digits(digits: &[u8]) -> Result<u64, SinceError> {
    let text = std::str::from_utf8(digits).map_err(|_| SinceError::Invalid)?;
    text.parse::<u64>().map_err(|_| SinceError::Overflow)
}

fn relative_secs(n: u64, unit: u8) -> Result<u64, SinceError> {
    let mul = match unit {
        b'm' => 60,
        b'h' => 3600,
        b'd' => 86_400,
        _ => return Err(SinceError::Invalid),
    };
    n.checked_mul(mul).ok_or(SinceError::Overflow)
}

fn snapshot_len(file: &File) -> io::Result<(u64, bool)> {
    match file.lock_shared() {
        Ok(()) => {
            let len = file.metadata().map(|m| m.len());
            let _ = file.unlock();
            Ok((len?, true))
        },
        Err(_) => Ok((file.metadata()?.len(), false)),
    }
}

fn scan_into<R: Read>(
    reader: R,
    filter: &AuditFilter,
    collector: &mut Collector,
) -> io::Result<Counters> {
    let mut counters = Counters::default();
    let incomplete = scan(reader, |event| match event {
        ScanEvent::Oversize => {
            counters.lines_read += 1;
            counters.skipped_invalid += 1;
        },
        ScanEvent::Line(bytes) => {
            counters.lines_read += 1;
            apply_line(bytes, filter, collector, &mut counters);
        },
    })?;
    counters.incomplete_tail = incomplete;
    Ok(counters)
}

fn scan<R: Read, F>(mut reader: R, mut visit: F) -> io::Result<bool>
where
    F: FnMut(ScanEvent<'_>),
{
    let mut buf = Vec::new();
    let mut oversized = false;
    let mut tmp = [0u8; 8192];
    loop {
        let n = reader.read(&mut tmp)?;
        if n == 0 {
            return Ok(finish_eof(oversized, &buf, &mut visit));
        }
        feed(&tmp[..n], &mut buf, &mut oversized, &mut visit);
    }
}

fn finish_eof(oversized: bool, buf: &[u8], visit: &mut impl FnMut(ScanEvent<'_>)) -> bool {
    if oversized {
        visit(ScanEvent::Oversize);
        true
    } else {
        !buf.is_empty()
    }
}

fn feed(
    chunk: &[u8],
    buf: &mut Vec<u8>,
    oversized: &mut bool,
    visit: &mut impl FnMut(ScanEvent<'_>),
) {
    let mut rest = chunk;
    while !rest.is_empty() {
        rest = if *oversized {
            skip_oversize(rest, oversized, visit)
        } else {
            take_line(rest, buf, oversized, visit)
        };
    }
}

fn skip_oversize<'a>(
    rest: &'a [u8],
    oversized: &mut bool,
    visit: &mut impl FnMut(ScanEvent<'_>),
) -> &'a [u8] {
    match memchr::memchr(b'\n', rest) {
        Some(i) => {
            *oversized = false;
            visit(ScanEvent::Oversize);
            &rest[i + 1..]
        },
        None => &[],
    }
}

fn take_line<'a>(
    rest: &'a [u8],
    buf: &mut Vec<u8>,
    oversized: &mut bool,
    visit: &mut impl FnMut(ScanEvent<'_>),
) -> &'a [u8] {
    match memchr::memchr(b'\n', rest) {
        Some(i) => {
            buf.extend_from_slice(&rest[..i]);
            emit_complete(buf, visit);
            buf.clear();
            &rest[i + 1..]
        },
        None => absorb_tail(rest, buf, oversized),
    }
}

fn absorb_tail<'a>(rest: &'a [u8], buf: &mut Vec<u8>, oversized: &mut bool) -> &'a [u8] {
    let room = MAX_AUDIT_RECORD_BYTES
        .saturating_add(1)
        .saturating_sub(buf.len());
    let take = rest.len().min(room);
    buf.extend_from_slice(&rest[..take]);
    let leftover = &rest[take..];
    if buf.len() > MAX_AUDIT_RECORD_BYTES {
        buf.clear();
        *oversized = true;
        leftover
    } else {
        &[]
    }
}

fn emit_complete(buf: &[u8], visit: &mut impl FnMut(ScanEvent<'_>)) {
    if buf.len() > MAX_AUDIT_RECORD_BYTES {
        visit(ScanEvent::Oversize);
    } else {
        visit(ScanEvent::Line(buf));
    }
}

fn apply_line(
    bytes: &[u8],
    filter: &AuditFilter,
    collector: &mut Collector,
    counters: &mut Counters,
) {
    match classify(bytes) {
        Classified::Blank => {},
        Classified::Invalid => counters.skipped_invalid += 1,
        Classified::Unsupported => counters.skipped_unsupported_schema += 1,
        Classified::Valid(value, rec) => {
            counters.valid_records += 1;
            if filter.matches(&rec) {
                counters.matched += 1;
                collector.accept(value, rec);
            }
        },
    }
}

fn classify(bytes: &[u8]) -> Classified {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Classified::Blank;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Classified::Invalid;
    };
    let Ok(raw) = serde_json::from_value::<RawAuditRecord>(value.clone()) else {
        return Classified::Invalid;
    };
    if let Some(ver) = raw.schema_version
        && ver != 1
    {
        return Classified::Unsupported;
    }
    match validate(raw) {
        Some(rec) => Classified::Valid(value, rec),
        None => Classified::Invalid,
    }
}

fn validate(raw: RawAuditRecord) -> Option<ValidatedAuditRecord> {
    let schema_version = raw.schema_version?;
    if schema_version != 1 {
        return None;
    }
    let timestamp = raw.timestamp?;
    let timestamp_secs = parse_rfc3339_to_secs(&timestamp)?;
    let decision = raw.decision.filter(|d| is_decision(d))?;
    let tool = raw.tool.filter(|t| !t.is_empty())?;
    let command_redacted = raw.command_redacted?;
    Some(ValidatedAuditRecord {
        timestamp,
        timestamp_secs,
        tool,
        decision,
        rule_id: raw.rule_id.filter(|id| !id.is_empty()),
        severity: raw.severity,
        command_redacted,
    })
}

fn is_decision(decision: &str) -> bool {
    matches!(decision, "allow" | "monitor" | "ask" | "deny")
}

impl AuditFilter {
    fn matches(&self, rec: &ValidatedAuditRecord) -> bool {
        if let Some(decision) = &self.decision
            && rec.decision != *decision
        {
            return false;
        }
        if let Some(rule_id) = &self.rule_id
            && rec.rule_id.as_deref() != Some(rule_id.as_str())
        {
            return false;
        }
        if let Some(tool) = &self.tool
            && rec.tool != *tool
        {
            return false;
        }
        if let Some(since) = self.since_secs
            && rec.timestamp_secs < since
        {
            return false;
        }
        true
    }
}

impl Collector {
    fn accept(&mut self, value: Value, rec: ValidatedAuditRecord) {
        match self {
            Self::List { limit, items } => {
                if *limit > 0 && items.len() == *limit {
                    items.pop_front();
                }
                items.push_back((value, rec));
            },
            Self::Stats {
                by_decision,
                by_rule,
            } => {
                *by_decision.entry(rec.decision).or_insert(0) += 1;
                if let Some(rule_id) = rec.rule_id {
                    *by_rule.entry(rule_id).or_insert(0) += 1;
                }
            },
        }
    }
}

fn sorted_counts(map: HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Cursor, Write};
    use std::time::Duration;

    use crate::testing::proptest::arbitrary_utf8_bytes;
    use proptest::prelude::*;

    fn rec_line(ts: &str, decision: &str, tool: &str, rule: Option<&str>, cmd: &str) -> String {
        let mut obj = json!({
            "schemaVersion": 1,
            "timestamp": ts,
            "event": "PreToolUse",
            "tool": tool,
            "decision": decision,
            "commandRedacted": cmd,
            "mode": "enforce",
            "agent": "cli",
        });
        if let Some(rule) = rule {
            obj["ruleId"] = json!(rule);
            obj["severity"] = json!("high");
        }
        format!("{obj}\n")
    }

    fn scan_all(body: &str, filter: &AuditFilter, limit: usize) -> ReadOutcome {
        read_filtered(Cursor::new(body.as_bytes()), filter, limit).unwrap()
    }

    fn now_plus(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    struct Boom;
    impl Read for Boom {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }

    struct ThenFail {
        first: bool,
    }
    impl Read for ThenFail {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.first {
                return Err(io::Error::other("boom"));
            }
            self.first = false;
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = b'{';
            Ok(1)
        }
    }

    #[test]
    fn parse_since_accepts_relative_units() {
        let now = now_plus(1_000_000);
        assert_eq!(parse_since("1h", now), Ok(1_000_000 - 3600));
        assert_eq!(parse_since("30m", now), Ok(1_000_000 - 1800));
        assert_eq!(parse_since("24h", now), Ok(1_000_000 - 86_400));
        assert_eq!(parse_since("7d", now), Ok(1_000_000 - 7 * 86_400));
        assert_eq!(parse_since("0m", now), Ok(1_000_000));
        assert_eq!(parse_since("01h", now), Ok(1_000_000 - 3600));
    }

    #[test]
    fn parse_since_accepts_canonical_rfc3339() {
        let now = now_plus(1);
        assert_eq!(parse_since("2024-01-01T00:00:00Z", now), Ok(1_704_067_200));
        assert_eq!(
            parse_since("2024-01-01T09:00:00+09:00", now),
            Ok(1_704_067_200)
        );
    }

    #[test]
    fn parse_since_rejects_grammar_and_overflow() {
        let now = now_plus(1_000_000);
        assert_eq!(parse_since("1", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("h", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("-1h", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("1.5h", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("1H", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("1 h", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("+1h", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("1m ", now), Err(SinceError::Invalid));
        assert_eq!(parse_since("1h", UNIX_EPOCH), Err(SinceError::Overflow));
        assert_eq!(
            parse_since("18446744073709551615m", now),
            Err(SinceError::Overflow)
        );
    }

    #[test]
    fn filter_and_is_inclusive_on_since() {
        let a = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", Some("r.a"), "a");
        let b = rec_line("2024-01-01T01:00:00Z", "ask", "Read", Some("r.b"), "b");
        let c = rec_line("2024-01-01T02:00:00Z", "deny", "Bash", Some("r.a"), "c");
        let body = format!("{a}{b}{c}");
        let since = parse_rfc3339_to_secs("2024-01-01T01:00:00Z").unwrap();
        let filter = AuditFilter {
            decision: Some("deny".into()),
            rule_id: Some("r.a".into()),
            tool: Some("Bash".into()),
            since_secs: Some(since),
        };
        let out = scan_all(&body, &filter, 0);
        assert_eq!(out.valid_records, 3);
        assert_eq!(out.matched, 1);
        assert_eq!(out.records[0].1.command_redacted, "c");

        let boundary = AuditFilter {
            since_secs: Some(since),
            ..AuditFilter::default()
        };
        let out = scan_all(&body, &boundary, 0);
        assert_eq!(out.matched, 2);
        assert_eq!(out.records[0].1.command_redacted, "b");
    }

    #[test]
    fn missing_rule_id_does_not_match_rule_filter() {
        let with = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", Some("r.a"), "a");
        let without = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", None, "b");
        let filter = AuditFilter {
            rule_id: Some("r.a".into()),
            ..AuditFilter::default()
        };
        let out = scan_all(&format!("{with}{without}"), &filter, 0);
        assert_eq!(out.matched, 1);
        assert_eq!(out.records[0].1.command_redacted, "a");
    }

    #[test]
    fn tail_is_file_order_not_timestamp_sort() {
        let first = rec_line("2024-01-01T10:00:00Z", "deny", "Bash", Some("r"), "first");
        let second = rec_line("2024-01-01T08:00:00Z", "deny", "Bash", Some("r"), "second");
        let third = rec_line("2024-01-01T11:00:00Z", "deny", "Bash", Some("r"), "third");
        let body = format!("{first}{second}{third}");
        let out = scan_all(&body, &AuditFilter::default(), 2);
        assert_eq!(out.matched, 3);
        assert_eq!(out.records.len(), 2);
        assert_eq!(out.records[0].1.command_redacted, "second");
        assert_eq!(out.records[1].1.command_redacted, "third");

        let all = scan_all(&body, &AuditFilter::default(), 0);
        assert_eq!(all.records.len(), 3);
        assert_eq!(all.records[0].1.command_redacted, "first");
    }

    #[test]
    fn blank_lines_are_read_but_not_invalid() {
        let rec = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", Some("r"), "x");
        let body = format!("\n   \n\t\n{rec}\n");
        let out = scan_all(&body, &AuditFilter::default(), 0);
        assert_eq!(out.lines_read, 5);
        assert_eq!(out.valid_records, 1);
        assert_eq!(out.skipped_invalid, 0);
    }

    #[test]
    fn malformed_and_invalid_fields_are_skipped() {
        let valid = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", Some("r"), "ok");
        let mut body = Vec::new();
        body.extend_from_slice(&[0xff, 0xfe, b'\n']);
        body.extend_from_slice(b"{not json}\n");
        body.extend_from_slice(br#"{"schemaVersion":1,"timestamp":"2024-01-01T00:00:00Z"}"#);
        body.push(b'\n');
        body.extend_from_slice(
            br#"{"schemaVersion":1,"timestamp":"nope","decision":"deny","tool":"Bash","commandRedacted":"x"}"#,
        );
        body.push(b'\n');
        body.extend_from_slice(
            br#"{"schemaVersion":1,"timestamp":"2024-01-01T00:00:00Z","decision":"nope","tool":"Bash","commandRedacted":"x"}"#,
        );
        body.push(b'\n');
        body.extend_from_slice(valid.as_bytes());
        let out = read_filtered(Cursor::new(body), &AuditFilter::default(), 0).unwrap();
        assert_eq!(out.valid_records, 1);
        assert_eq!(out.skipped_invalid, 5);
        assert_eq!(out.skipped_unsupported_schema, 0);
        assert_eq!(out.records[0].1.command_redacted, "ok");
    }

    #[test]
    fn schema_version_missing_is_invalid_not_unsupported() {
        let missing = r#"{"timestamp":"2024-01-01T00:00:00Z","decision":"deny","tool":"Bash","commandRedacted":"x"}"#;
        let unsupported = r#"{"schemaVersion":2,"timestamp":"2024-01-01T00:00:00Z","decision":"deny","tool":"Bash","commandRedacted":"x"}"#;
        let body = format!("{missing}\n{unsupported}\n");
        let out = scan_all(&body, &AuditFilter::default(), 0);
        assert_eq!(out.skipped_invalid, 1);
        assert_eq!(out.skipped_unsupported_schema, 1);
        assert_eq!(out.valid_records, 0);
    }

    #[test]
    fn read_error_is_propagated() {
        read_filtered(Boom, &AuditFilter::default(), 20).unwrap_err();
        stats(Boom, &AuditFilter::default()).unwrap_err();
        read_filtered(ThenFail { first: true }, &AuditFilter::default(), 20).unwrap_err();
    }

    #[test]
    fn incomplete_tail_is_not_invalid() {
        let valid = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", Some("r"), "ok");
        let body = format!("{valid}{{\"partial\"");
        let out = scan_all(&body, &AuditFilter::default(), 0);
        assert!(out.incomplete_tail);
        assert_eq!(out.valid_records, 1);
        assert_eq!(out.skipped_invalid, 0);
        assert_eq!(out.lines_read, 1);
    }

    #[test]
    fn oversized_line_is_skipped_invalid() {
        let valid = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", Some("r"), "ok");
        let mut body = vec![b'x'; MAX_AUDIT_RECORD_BYTES + 1];
        body.push(b'\n');
        body.extend_from_slice(valid.as_bytes());
        let out = read_filtered(Cursor::new(body), &AuditFilter::default(), 0).unwrap();
        assert_eq!(out.skipped_invalid, 1);
        assert_eq!(out.valid_records, 1);
        assert!(!out.incomplete_tail);
    }

    #[test]
    fn oversized_incomplete_tail_is_invalid_and_incomplete() {
        let body = vec![b'x'; MAX_AUDIT_RECORD_BYTES + 8];
        let out = read_filtered(Cursor::new(body), &AuditFilter::default(), 0).unwrap();
        assert_eq!(out.skipped_invalid, 1);
        assert!(out.incomplete_tail);
        assert_eq!(out.valid_records, 0);
    }

    #[test]
    fn json_records_keep_unknown_fields() {
        let line = r#"{"schemaVersion":1,"timestamp":"2024-01-01T00:00:00Z","decision":"deny","tool":"Bash","commandRedacted":"x","extra":"keep"}"#;
        let out = scan_all(&format!("{line}\n"), &AuditFilter::default(), 0);
        assert_eq!(out.records[0].0["extra"], "keep");
    }

    #[test]
    fn stats_sorts_count_desc_then_id_asc_and_drops_missing_rule() {
        let mut body = String::new();
        for _ in 0..2 {
            body.push_str(&rec_line(
                "2024-01-01T00:00:00Z",
                "deny",
                "Bash",
                Some("core.b"),
                "x",
            ));
        }
        for _ in 0..2 {
            body.push_str(&rec_line(
                "2024-01-01T00:00:00Z",
                "deny",
                "Bash",
                Some("core.a"),
                "x",
            ));
        }
        body.push_str(&rec_line("2024-01-01T00:00:00Z", "ask", "Read", None, "y"));
        body.push_str(&rec_line(
            "2024-01-01T00:00:00Z",
            "ask",
            "Read",
            Some("core.a"),
            "z",
        ));
        let s = stats(Cursor::new(body.into_bytes()), &AuditFilter::default()).unwrap();
        assert_eq!(s.lines_read, 6);
        assert_eq!(s.valid_records, 6);
        assert_eq!(s.matched, 6);
        assert_eq!(s.skipped_invalid, 0);
        assert_eq!(s.skipped_unsupported_schema, 0);
        assert!(!s.incomplete_tail);
        assert_eq!(s.by_decision, vec![("deny".into(), 4), ("ask".into(), 2)]);
        assert_eq!(s.by_rule, vec![("core.a".into(), 3), ("core.b".into(), 2)]);
    }

    #[test]
    fn snapshot_ignores_bytes_appended_after_length_is_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let rec = rec_line("2024-01-01T00:00:00Z", "deny", "Bash", Some("r"), "ok");
        std::fs::write(&path, &rec).unwrap();
        let snap = open_snapshot(&path).unwrap();
        assert!(!snap.lock_failed());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"partial")
            .unwrap();
        let out = read_filtered(snap, &AuditFilter::default(), 0).unwrap();
        assert_eq!(out.valid_records, 1);
        assert!(!out.incomplete_tail);
        assert_eq!(out.records[0].1.command_redacted, "ok");
    }

    proptest! {
        #[test]
        fn pbt_read_filtered_never_panics(bytes in arbitrary_utf8_bytes()) {
            let _ = read_filtered(Cursor::new(bytes), &AuditFilter::default(), 20);
        }

        #[test]
        fn pbt_returned_respects_limit(n in 0usize..30, limit in 0usize..12) {
            let mut body = String::new();
            for i in 0..n {
                body.push_str(&rec_line(
                    "2024-01-01T00:00:00Z",
                    "deny",
                    "Bash",
                    Some("r"),
                    &format!("c{i}"),
                ));
            }
            let out = read_filtered(
                Cursor::new(body.into_bytes()),
                &AuditFilter::default(),
                limit,
            )
            .unwrap();
            prop_assert!(limit == 0 || out.records.len() <= limit);
            if limit == 0 {
                prop_assert_eq!(out.records.len(), n);
            } else {
                prop_assert_eq!(out.records.len(), n.min(limit));
            }
        }
    }
}
