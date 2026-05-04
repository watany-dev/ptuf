//! Minimal URL fact extraction for `WebFetch` payloads.
//!
//! No external `url`/`http` dependency: the parser splits a string into
//! `scheme://host[:port][/path]` by hand and returns `None` when the
//! shape is unrecognisable. This is enough for the policy questions
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

/// Parse `s` into a [`Url`]. Returns `None` when `s` lacks a recognisable
/// `scheme://host` prefix.
pub fn parse(s: &str) -> Option<Url> {
    let (scheme, rest) = s.split_once("://")?;
    if scheme.is_empty() || !is_valid_scheme(scheme) {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return None;
    }
    // Strip user-info (`user[:pass]@`) before host parsing.
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let (host, port) = split_host_port(authority)?;
    if host.is_empty() {
        return None;
    }
    Some(Url {
        raw: s.to_string(),
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_string(),
    })
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
        Some(i) => {
            let host = &authority[..i];
            let port: u16 = authority[i + 1..].parse().ok()?;
            Some((host, Some(port)))
        }
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_simple_https_url() {
        let u = parse("https://example.com/foo").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, None);
        assert_eq!(u.path, "/foo");
        assert_eq!(u.raw, "https://example.com/foo");
    }

    #[test]
    fn parses_url_without_path() {
        let u = parse("http://example.com").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.path, "");
    }

    #[test]
    fn parses_url_with_port() {
        let u = parse("http://localhost:8080/admin").unwrap();
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.path, "/admin");
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
    fn parses_cloud_metadata_endpoint() {
        let u = parse("http://169.254.169.254/latest/meta-data/").unwrap();
        assert_eq!(u.host, "169.254.169.254");
        assert_eq!(u.path, "/latest/meta-data/");
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
    fn rejects_missing_scheme() {
        assert!(parse("example.com/foo").is_none());
        assert!(parse("//example.com/foo").is_none());
    }

    #[test]
    fn rejects_invalid_scheme_chars() {
        assert!(parse("1http://example.com").is_none());
        assert!(parse("ht tp://example.com").is_none());
    }

    #[test]
    fn rejects_empty_authority() {
        assert!(parse("http:///foo").is_none());
    }

    #[test]
    fn rejects_malformed_port() {
        assert!(parse("http://example.com:notaport/").is_none());
        assert!(parse("http://[::1]:abc/").is_none());
    }
}
