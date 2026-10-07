use std::net::IpAddr;
use std::str::FromStr;

use crate::Headers;

/// Reads the entries of a forwarding header, rightmost last.
///
/// The [`FORWARDED`](crate::header::FORWARDED) header is parsed as RFC 7239 `for=`
/// parameters, any other header as a comma-separated list. Multiple header lines
/// are combined in order. Unparseable entries are kept as `None` so rightmost
/// walks stop at them instead of skipping to an address further left.
pub(crate) fn forwarded_ips<H: Headers>(headers: &H, name: &str) -> Vec<Option<IpAddr>> {
    let forwarded = name.eq_ignore_ascii_case(crate::header::FORWARDED);
    let mut ips = Vec::new();
    for value in headers.get_all_str(name) {
        let Some(value) = value else {
            ips.push(None);
            continue;
        };
        for element in split_unquoted(value, ',') {
            let ip = if forwarded {
                forwarded_param(element, "for").and_then(parse_ip)
            } else {
                parse_ip(element)
            };
            ips.push(ip);
        }
    }
    ips
}

/// Reads a header that holds a single IP; the last header line wins.
pub(crate) fn single_ip<H: Headers>(headers: &H, name: &str) -> Option<IpAddr> {
    headers.get_all_str(name).pop().flatten().and_then(parse_ip)
}

/// Reads a header that holds a single `ip:port`; the last header line wins.
pub(crate) fn single_ip_with_port<H: Headers>(headers: &H, name: &str) -> Option<IpAddr> {
    headers
        .get_all_str(name)
        .pop()
        .flatten()
        .and_then(parse_ip_with_port)
}

/// Parses `ip:port` where the port is always present, so unbracketed IPv6
/// addresses such as `2001:db8::1:443` are split at the last colon.
pub(crate) fn parse_ip_with_port(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim().trim_matches('"').trim();
    if entry.starts_with('[') {
        return parse_ip(entry);
    }
    let (host, port) = entry.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let host = host.split_once('%').map_or(host, |(addr, _zone)| addr);
    IpAddr::from_str(host).ok().map(|ip| ip.to_canonical())
}

/// The IPs of the `for=` parameters in one RFC 7239 `Forwarded` header value.
pub(crate) fn forwarded_header_ips(value: &str) -> Vec<Option<IpAddr>> {
    split_unquoted(value, ',')
        .map(|element| forwarded_param(element, "for").and_then(parse_ip))
        .collect()
}

/// The last element of a `Forwarded` header value, added by the nearest proxy.
pub(crate) fn last_forwarded_element(value: &str) -> Option<&str> {
    split_unquoted(value, ',').last()
}

/// The value of parameter `name` in one RFC 7239 element, e.g. `for` in
/// `for=192.0.2.60;proto=http`. Quotes are kept.
pub(crate) fn forwarded_param<'a>(element: &'a str, name: &str) -> Option<&'a str> {
    split_unquoted(element, ';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim().eq_ignore_ascii_case(name).then_some(value)
    })
}

/// Splits on `separator`, ignoring separators inside double quotes.
fn split_unquoted(value: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;
    value.split(move |c: char| {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        c == separator && !in_quotes
    })
}

/// Parses an IP from a header entry, accepting ports, brackets, quotes and IPv6 zones:
/// `192.0.2.1`, `192.0.2.1:80`, `"[2001:db8::1]:443"`, `fe80::1%eth0`.
pub(crate) fn parse_ip(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim().trim_matches('"').trim();
    let host = if let Some(rest) = entry.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if !(after.is_empty() || after.starts_with(':')) {
            return None;
        }
        host
    } else if entry.matches(':').count() == 1 {
        entry.split_once(':')?.0
    } else {
        entry
    };
    let host = host.split_once('%').map_or(host, |(addr, _zone)| addr);
    IpAddr::from_str(host).ok().map(|ip| ip.to_canonical())
}

pub(crate) fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` and `fc00::/7`.
pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            ip.is_private() || (a == 100 && (b & 0xc0) == 64)
        }
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::*;
    use crate::header::{FORWARDED, X_FORWARDED_FOR, X_REAL_IP};

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    fn header_map(name: &'static str, values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn parses_entry_forms() {
        assert_eq!(parse_ip(" 192.0.2.1 "), ip("192.0.2.1"));
        assert_eq!(parse_ip("192.0.2.1:8080"), ip("192.0.2.1"));
        assert_eq!(parse_ip("2001:db8::1"), ip("2001:db8::1"));
        assert_eq!(parse_ip("[2001:db8::1]"), ip("2001:db8::1"));
        assert_eq!(parse_ip("\"[2001:db8::1]:443\""), ip("2001:db8::1"));
        assert_eq!(parse_ip("fe80::1%eth0"), ip("fe80::1"));
        assert_eq!(parse_ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_eq!(parse_ip("unknown"), None);
        assert_eq!(parse_ip("[2001:db8::1]x"), None);
        assert_eq!(parse_ip(""), None);
    }

    #[test]
    fn combines_x_forwarded_for_lines() {
        let headers = header_map(X_FORWARDED_FOR, &["1.1.1.1, 2.2.2.2", "3.3.3.3"]);
        assert_eq!(
            forwarded_ips(&headers, X_FORWARDED_FOR),
            vec![ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")]
        );
    }

    #[test]
    fn keeps_invalid_entries_in_place() {
        let headers = header_map(X_FORWARDED_FOR, &["1.1.1.1, garbage, 3.3.3.3"]);
        assert_eq!(
            forwarded_ips(&headers, X_FORWARDED_FOR),
            vec![ip("1.1.1.1"), None, ip("3.3.3.3")]
        );
    }

    #[test]
    fn parses_rfc7239_forwarded() {
        let headers = header_map(
            FORWARDED,
            &[
                "for=192.0.2.60;proto=http;by=203.0.113.43, For=\"[2001:db8:cafe::17]:4711\"",
                "for=unknown, proto=https, for=_hidden",
            ],
        );
        assert_eq!(
            forwarded_ips(&headers, FORWARDED),
            vec![ip("192.0.2.60"), ip("2001:db8:cafe::17"), None, None, None]
        );
    }

    #[test]
    fn parses_entries_with_port() {
        assert_eq!(
            parse_ip_with_port("198.51.100.10:46532"),
            ip("198.51.100.10")
        );
        assert_eq!(parse_ip_with_port("2001:db8::1:443"), ip("2001:db8::1"));
        assert_eq!(
            parse_ip_with_port("2001:0db8:85a3:0000:0000:8a2e:0370:7334:46532"),
            ip("2001:db8:85a3::8a2e:370:7334")
        );
        assert_eq!(parse_ip_with_port("[2001:db8::1]:443"), ip("2001:db8::1"));
        assert_eq!(parse_ip_with_port("198.51.100.10"), None);
        assert_eq!(parse_ip_with_port("198.51.100.10:"), None);
        assert_eq!(parse_ip_with_port("198.51.100.10:http"), None);
    }

    #[test]
    fn single_ip_uses_last_line() {
        let headers = header_map(X_REAL_IP, &["1.1.1.1", "2.2.2.2"]);
        assert_eq!(single_ip(&headers, X_REAL_IP), ip("2.2.2.2"));
        let headers = header_map(X_REAL_IP, &["1.1.1.1, 2.2.2.2"]);
        assert_eq!(single_ip(&headers, X_REAL_IP), None);
    }

    #[test]
    fn classifies_addresses() {
        for private in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "fd00::1",
        ] {
            assert!(is_private(private.parse().unwrap()), "{private}");
        }
        for not_private in ["100.128.0.1", "8.8.8.8", "fe80::1"] {
            assert!(!is_private(not_private.parse().unwrap()), "{not_private}");
        }
        for link_local in ["169.254.1.1", "fe80::1"] {
            assert!(is_link_local(link_local.parse().unwrap()), "{link_local}");
        }
    }
}
