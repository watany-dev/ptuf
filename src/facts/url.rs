//! Minimal URL fact extraction for `WebFetch` payloads.
//!
//! No external `url`/`http` dependency: the parser splits a string into
//! `scheme://host[:port][/path]` by hand, following the WHATWG URL rules
//! that decide which host a fetch connects to, and returns `None` when
//! no host can be found. This is enough for the policy questions
//! ptuf needs to ask (cloud-metadata host blocklist, scheme allowlist,
//! prefix matching), and keeps the dependency surface flat.

/// Parsed URL view used by rules and the plugin DSL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub raw: String,
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    /// Path component including the leading `/`. Empty string when the
    /// URL has no path (e.g. `http://example.com`).
    pub path: String,
}

/// Schemes WHATWG URL treats as "special": their authority may follow
/// any run of `/` and `\\`, and `\\` ends the authority like `/`.
const SPECIAL_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "ftp"];

/// Parse `s` into a [`Url`]. Returns `None` when `s` has no recognisable
/// host.
///
/// The host is what a WHATWG URL parser (and so the fetching agent)
/// would connect to, so `url.hostAny` cannot be sidestepped by an
/// alternate spelling:
/// - surrounding whitespace / C0 controls are trimmed and tab / newline
///   removed;
/// - the authority ends at the first `/`, `?`, `#` (and `\\` for
///   special schemes), so `https://evil.com?@ok.com` is `evil.com`;
/// - special schemes accept `https:/evil.com` and `https:evil.com`;
/// - a string without a scheme (`evil.com/x`, `//evil.com`) is read as
///   `https://`, which is what `WebFetch` does with it;
/// - the host is percent-decoded, lowercased, stripped of one trailing
///   dot, and numeric IPv4 forms (`0xa9.0xfe.0xa9.0xfe`, `2852039166`)
///   are rewritten as dotted decimal.
///
/// Non-ASCII hosts are lowercased but not IDNA-mapped.
pub(crate) fn parse(s: &str) -> Option<Url> {
    let cleaned: String = s
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let (scheme, rest) = split_scheme(&cleaned)?;
    let special = SPECIAL_SCHEMES.contains(&scheme.as_str());
    let rest = if special {
        rest.trim_start_matches(['/', '\\'])
    } else {
        rest.strip_prefix("//")?
    };
    let end = rest
        .find(|c: char| matches!(c, '/' | '?' | '#') || (special && c == '\\'))
        .unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    // Strip user-info (`user[:pass]@`) before host parsing.
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let (host, port) = split_host_port(authority)?;
    let host = normalize_host(host)?;
    Some(Url {
        raw: s.to_string(),
        scheme,
        host,
        port,
        path: path.to_string(),
    })
}

/// Split off a lowercased scheme. A string with no scheme, or whose
/// non-special "scheme" is really `host:port` (`localhost:8080/x`), is
/// read as `https`.
fn split_scheme(s: &str) -> Option<(String, &str)> {
    if let Some((scheme, rest)) = s.split_once(':')
        && is_valid_scheme(scheme)
    {
        let scheme = scheme.to_ascii_lowercase();
        if SPECIAL_SCHEMES.contains(&scheme.as_str())
            || !rest.starts_with(|c: char| c.is_ascii_digit())
        {
            return Some((scheme, rest));
        }
    }
    if s.is_empty() || s.starts_with(':') || s.contains("://") {
        return None;
    }
    Some(("https".to_string(), s))
}

/// True when a configured host (`url.hostAny` entry) names the parsed
/// `host`. The entry gets the same normalization as a parsed host, so
/// `EVIL.com.` or `0xa9fea9fe` in a policy still match.
pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
    normalize_host(pattern.trim()).is_some_and(|p| p == host)
}

/// Canonical host: percent-decoded, lowercased, without a trailing dot,
/// and with numeric IPv4 spellings rewritten as dotted decimal.
fn normalize_host(host: &str) -> Option<String> {
    if host.starts_with('[') {
        return Some(host.to_ascii_lowercase());
    }
    let decoded = percent_decode(host)?;
    let mut host = decoded.to_lowercase();
    if host.len() > 1 && host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() || host.contains(['/', '\\', '?', '#', '@', ' ', '%']) {
        return None;
    }
    Some(parse_ipv4(&host).unwrap_or(host))
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = bytes.get(i + 1..i + 3)
            && let Ok(hex) = std::str::from_utf8(hex)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// WHATWG IPv4 parser: up to four dot-separated parts in decimal, hex
/// (`0x`) or octal (leading `0`); the last part fills the remaining
/// bytes. `None` when `host` is not an IPv4 address in that sense.
fn parse_ipv4(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let numbers: Vec<u64> = parts
        .iter()
        .map(|part| parse_ipv4_number(part))
        .collect::<Option<_>>()?;
    let (last, init) = numbers.split_last()?;
    if init.iter().any(|&n| n > 255) {
        return None;
    }
    let shift = 8 * (4 - init.len());
    if shift < 32 && *last >= 1u64 << shift {
        return None;
    }
    let mut value = *last;
    for (i, &n) in init.iter().enumerate() {
        value += n << (8 * (3 - i));
    }
    let value = u32::try_from(value).ok()?;
    Some(std::net::Ipv4Addr::from(value).to_string())
}

fn parse_ipv4_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (part, 10)
        };
    // Every byte must be a digit of `radix`: `from_str_radix` would also
    // take a leading `+`, which WHATWG does not.
    if !digits.bytes().all(|b| char::from(b).is_digit(radix)) {
        return None;
    }
    // Leading zeros carry no value and WHATWG allows any number of them,
    // so the overflow cap applies to the significant digits only.
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Some(0);
    }
    if significant.len() > 12 {
        return None;
    }
    u64::from_str_radix(significant, radix).ok()
}

fn is_valid_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.starts_with('[') {
        // IPv6 literal: `[..]` optionally followed by `:port`.
        let end = authority.find(']')?;
        let host = &authority[..=end];
        let rest = &authority[end + 1..];
        let port = parse_port_suffix(rest)?;
        return Some((host, port));
    }
    match authority.rfind(':') {
        Some(i) if authority[i + 1..].is_empty() => Some((&authority[..i], None)),
        Some(i) => {
            let host = &authority[..i];
            let port: u16 = authority[i + 1..].parse().ok()?;
            Some((host, Some(port)))
        },
        None => Some((authority, None)),
    }
}

fn parse_port_suffix(rest: &str) -> Option<Option<u16>> {
    if rest.is_empty() {
        return Some(None);
    }
    let port_str = rest.strip_prefix(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some(Some(port))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parses_https_and_http_url_shapes() {
        let cases = [
            (
                "https://example.com/foo",
                "https",
                "example.com",
                None,
                "/foo",
            ),
            ("http://example.com", "http", "example.com", None, ""),
            (
                "http://localhost:8080/admin",
                "http",
                "localhost",
                Some(8080),
                "/admin",
            ),
            (
                "http://169.254.169.254/latest/meta-data/",
                "http",
                "169.254.169.254",
                None,
                "/latest/meta-data/",
            ),
        ];
        for (raw, scheme, host, port, path) in cases {
            let u = parse(raw).unwrap();
            assert_eq!(u.scheme, scheme, "raw={raw}");
            assert_eq!(u.host, host, "raw={raw}");
            assert_eq!(u.port, port, "raw={raw}");
            assert_eq!(u.path, path, "raw={raw}");
            assert_eq!(u.raw, raw);
        }
    }

    #[test]
    fn lowercases_scheme_and_host() {
        let u = parse("HTTPS://EXAMPLE.COM/Path").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "example.com");
        // Path keeps its case.
        assert_eq!(u.path, "/Path");
    }

    #[test]
    fn strips_userinfo_from_authority() {
        let u = parse("https://user:pass@example.com/x").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.path, "/x");
    }

    #[test]
    fn parses_ipv6_literal_with_port() {
        let u = parse("http://[::1]:8080/").unwrap();
        assert_eq!(u.host, "[::1]");
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.path, "/");
    }

    #[test]
    fn parses_ipv6_literal_without_port() {
        let u = parse("http://[::1]/").unwrap();
        assert_eq!(u.host, "[::1]");
        assert_eq!(u.port, None);
    }

    #[test]
    fn missing_scheme_reads_as_https() {
        for raw in ["example.com/foo", "//example.com/foo", "localhost:8080/x"] {
            let u = parse(raw).unwrap();
            assert_eq!(u.scheme, "https", "raw={raw}");
            assert!(
                u.host == "example.com" || u.host == "localhost",
                "raw={raw}"
            );
        }
        assert_eq!(parse("localhost:8080/x").unwrap().port, Some(8080));
    }

    #[test]
    fn authority_ends_at_query_fragment_and_backslash() {
        // #329: an `@` past the authority is not userinfo.
        for raw in [
            "https://evil.com?@ok.com",
            "https://evil.com#@ok.com",
            "https://evil.com\\@ok.com",
            "https://evil.com/@ok.com",
        ] {
            assert_eq!(parse(raw).unwrap().host, "evil.com", "raw={raw}");
        }
        // Non-special schemes keep `\\` in the authority.
        assert_eq!(parse("foo://a\\b@c/").unwrap().host, "c");
    }

    #[test]
    fn normalizes_alternate_host_spellings() {
        // #330.
        for raw in [
            "https://EVIL.com./x",
            "https://evil%2ecom/x",
            "https://%65vil.com/x",
            "https:/evil.com/x",
            "https:evil.com/x",
            "https:\\\\evil.com/x",
            " https://evil.com/x",
            "\thttps://evil.com/x\n",
            "https://ev\nil.com/x",
            "evil.com/x",
            "https://evil.com:/x",
        ] {
            assert_eq!(parse(raw).unwrap().host, "evil.com", "raw={raw:?}");
        }
    }

    #[test]
    fn host_matches_normalizes_pattern() {
        let u = parse("http://0xa9fea9fe/latest").unwrap();
        assert!(host_matches("169.254.169.254", &u.host));
        assert!(host_matches("0xa9fea9fe", &u.host));
        let u = parse("https://evil.com./x").unwrap();
        assert!(host_matches("EVIL.COM.", &u.host));
        assert!(!host_matches("ok.com", &u.host));
    }

    #[test]
    fn normalizes_numeric_ipv4_hosts() {
        for raw in [
            "http://169.254.169.254/",
            "http://2852039166/",
            "http://0xa9.0xfe.0xa9.0xfe/",
            "http://0251.0376.0251.0376/",
            "http://169.254.43518/",
            "http://169.16689662/",
            "http://169.254.169.254./",
        ] {
            assert_eq!(parse(raw).unwrap().host, "169.254.169.254", "raw={raw}");
        }
        // Not an address: left as a name.
        assert_eq!(parse("http://1.2.3.4.5/").unwrap().host, "1.2.3.4.5");
        assert_eq!(parse("http://0x1g/").unwrap().host, "0x1g");
    }

    // WHATWG (and curl's `ipv4_normalize`) accept any number of leading
    // zeros in an IPv4 part; a 12-digit cap on the raw text left these
    // spellings un-normalized, so `url.hostAny: ["169.254.169.254"]`
    // missed them. Pinned exhaustively by
    // `ipv4_number_matches_whatwg_exhaustively`.
    #[test]
    fn normalizes_ipv4_parts_with_long_leading_zero_runs() {
        for raw in [
            "http://0x00000000000a9.0xfe.0xa9.0xfe/",
            "http://00000000000000251.254.169.254/",
            "http://169.254.169.0000000000000000376/",
            "http://0x00000000000000000000a9fea9fe/",
        ] {
            assert_eq!(parse(raw).unwrap().host, "169.254.169.254", "raw={raw}");
            let oracle = ::url::Url::parse(raw).unwrap();
            assert_eq!(oracle.host_str(), Some("169.254.169.254"), "raw={raw}");
        }
    }

    /// WHATWG "IPv4 number parser", written straight from the spec with
    /// saturating arithmetic. `None` = failure.
    fn whatwg_ipv4_number(s: &[u8]) -> Option<u128> {
        if s.is_empty() {
            return None;
        }
        let (digits, radix): (&[u8], u32) = if s.len() >= 2 && s[0] == b'0' && (s[1] | 0x20) == b'x'
        {
            (&s[2..], 16)
        } else if s.len() >= 2 && s[0] == b'0' {
            (&s[1..], 8)
        } else {
            (s, 10)
        };
        let mut value: u128 = 0;
        for &b in digits {
            let d = char::from(b).to_digit(radix)?;
            value = value
                .saturating_mul(u128::from(radix))
                .saturating_add(u128::from(d));
        }
        Some(value)
    }

    // Bounded-exhaustive check of `parse_ipv4_number` against WHATWG over
    // every part shaped `prefix ++ "0" * zeros ++ tail`: radix prefix
    // (none / `0` / `0x` / `0X`), 0..=16 leading zeros (the shape that
    // slipped past the old 12-digit cap) and every 0..=2-byte tail over
    // digits, hex letters and the signs `from_str_radix` treats specially.
    // Parts that cannot form an IPv4 address (value > u32::MAX) only have
    // to stay out of range. A Kani harness for the same property found
    // the leading-zero bug but cannot finish the proof in nightly time.
    #[test]
    fn ipv4_number_matches_whatwg_exhaustively() {
        const ALPHABET: &[u8] = b"0123456789abcdefABFgxX+-";
        let mut tails: Vec<Vec<u8>> = vec![Vec::new()];
        for &a in ALPHABET {
            tails.push(vec![a]);
            for &b in ALPHABET {
                tails.push(vec![a, b]);
            }
        }
        for prefix in [&b""[..], b"0", b"0x", b"0X"] {
            for zeros in 0..=16 {
                for tail in &tails {
                    let mut part = prefix.to_vec();
                    part.extend(std::iter::repeat_n(b'0', zeros));
                    part.extend_from_slice(tail);
                    let text = std::str::from_utf8(&part).unwrap();
                    let got = parse_ipv4_number(text);
                    match whatwg_ipv4_number(&part) {
                        None => assert_eq!(got, None, "part={text}"),
                        Some(v) if v <= u128::from(u32::MAX) => {
                            assert_eq!(got.map(u128::from), Some(v), "part={text}");
                        },
                        Some(_) => assert!(
                            got.is_none_or(|g| g > u64::from(u32::MAX)),
                            "part={text} got={got:?}",
                        ),
                    }
                }
            }
        }
    }

    // `u64::from_str_radix` accepts a leading `+`; WHATWG does not, so
    // `1.2.3.+4` is a name, not `1.2.3.4`.
    #[test]
    fn ipv4_part_with_plus_sign_is_not_a_number() {
        assert_eq!(parse("http://1.2.3.+4/").unwrap().host, "1.2.3.+4");
    }

    #[test]
    fn ipv4_part_overflow_is_still_rejected() {
        // 2^64 + 1 in hex: too large for any IPv4 address.
        let raw = "http://0x10000000000000001/";
        assert_eq!(parse(raw).unwrap().host, "0x10000000000000001");
    }

    #[test]
    fn rejects_invalid_scheme_chars() {
        assert!(parse("1http://example.com").is_none());
        assert!(parse("ht tp://example.com").is_none());
    }

    #[test]
    fn rejects_empty_authority() {
        assert!(parse("foo:///bar").is_none());
        assert!(parse("http://").is_none());
        // Special schemes skip extra slashes, as browsers do.
        assert_eq!(parse("http:///foo").unwrap().host, "foo");
    }

    #[test]
    fn rejects_malformed_port() {
        assert!(parse("http://example.com:notaport/").is_none());
        assert!(parse("http://[::1]:abc/").is_none());
    }

    use crate::testing::proptest::web_url;
    use proptest::prelude::*;

    proptest! {
        // The parser must not panic for arbitrary printable ASCII.
        #[test]
        fn pbt_parse_never_panics(s in web_url()) {
            let _ = parse(&s);
        }

        // Adversarial: arbitrary bytes (mod proptest's regex limits) also
        // never panic.
        #[test]
        fn pbt_parse_arbitrary_never_panics(s in "[ -~]{0,80}") {
            let _ = parse(&s);
        }

        // Whenever parsing succeeds, scheme and host are lowercased.
        #[test]
        fn pbt_scheme_and_host_are_lowercased(s in web_url()) {
            if let Some(u) = parse(&s) {
                prop_assert_eq!(&u.scheme, &u.scheme.to_ascii_lowercase());
                prop_assert_eq!(&u.host, &u.host.to_ascii_lowercase());
            }
        }

        // Successful parses preserve the original string in `raw`.
        #[test]
        fn pbt_raw_round_trips(s in web_url()) {
            if let Some(u) = parse(&s) {
                prop_assert_eq!(u.raw, s);
            }
        }

        // userinfo (user[:pass]@) is stripped: the parsed host equals
        // the supplied host literal verbatim (after lowercasing) and
        // never contains an `@`.
        #[test]
        fn pbt_userinfo_stripped_from_host(
            user in "[a-z][a-z0-9]{0,8}",
            pass in "[a-zA-Z0-9_]{1,12}",
            host in "[a-z][a-z0-9-]{1,16}\\.com",
        ) {
            let s = format!("https://{user}:{pass}@{host}/x");
            let u = parse(&s).expect("parse");
            prop_assert!(!u.host.contains('@'));
            prop_assert_eq!(u.host, host.to_ascii_lowercase());
        }

        // Constructed canonical URLs always parse with the requested
        // scheme and host (lowercased).
        #[test]
        fn pbt_canonical_urls_round_trip(
            scheme in "(?:https?|ftp)",
            host in "[a-z][a-z0-9.-]{0,15}[a-z0-9]",
            path in "[a-z0-9/._-]{0,16}",
        ) {
            let s = format!("{scheme}://{host}/{path}");
            let u = parse(&s).expect("parse");
            prop_assert_eq!(u.scheme, scheme.to_ascii_lowercase());
            prop_assert_eq!(u.host, host.to_ascii_lowercase());
            prop_assert_eq!(u.path, format!("/{path}"));
            prop_assert_eq!(u.port, None);
        }

        // Explicit port stays in u16 range and round-trips.
        #[test]
        fn pbt_port_round_trips(port in 0u16..=65_535) {
            let s = format!("http://example.com:{port}/x");
            let u = parse(&s).expect("parse");
            prop_assert_eq!(u.port, Some(port));
        }

        // A scheme-less `host/path` reads as `https://host/path`.
        #[test]
        fn pbt_scheme_less_reads_as_https(
            host in "[a-z][a-z0-9-]{0,12}\\.[a-z]{2,6}",
            path in "[a-z0-9/._-]{0,16}",
        ) {
            let u = parse(&format!("{host}/{path}")).expect("parse");
            prop_assert_eq!(u.scheme, "https");
            prop_assert_eq!(u.host, host);
        }

        // Differential: for special-scheme URLs the `url` crate (a
        // WHATWG implementation) accepts with an ASCII host, ptuf
        // agrees on the host (modulo one trailing dot) and port.
        #[test]
        fn pbt_host_matches_whatwg(
            scheme in "(?:https?|wss?|ftp)",
            sep in "(?:://|:/|:|:///|:\\\\\\\\|:/\\\\)",
            user in "(?:|[a-z]{1,4}(?::[a-z0-9]{0,4})?@)",
            host in "(?:[a-zA-Z0-9%.-]{1,12}|[0-9x.]{1,15})",
            port in "(?:|:[0-9]{1,4})",
            tail in "(?:|[/?#\\\\][ -~]{0,12})",
        ) {
            let raw = format!("{scheme}{sep}{user}{host}{port}{tail}");
            let Ok(oracle) = ::url::Url::parse(&raw) else {
                return Ok(());
            };
            if matches!(oracle.host(), None | Some(::url::Host::Ipv6(_))) {
                return Ok(());
            }
            let host = oracle.host_str().expect("host");
            let want = host.strip_suffix('.').filter(|h| !h.is_empty()).unwrap_or(host);
            let got = parse(&raw).expect("ptuf parses what WHATWG parses");
            prop_assert_eq!(&got.host, want, "raw={}", raw);
            // The `url` crate drops a scheme's default port.
            let default = oracle.port_or_known_default();
            prop_assert_eq!(got.port.or(default), default, "raw={}", raw);
        }
    }
}
