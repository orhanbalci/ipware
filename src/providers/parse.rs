//! Parsers for the IP range lists providers publish, to refresh the built-in
//! snapshots at runtime with your own HTTP client.
//!
//! ```rust
//! use ipware::providers::parse;
//!
//! // Body of https://api.fastly.com/public-ip-list
//! let body = r#"{"addresses":["23.235.32.0/20"],"ipv6_addresses":["2a04:4e40::/32"]}"#;
//! let ranges = parse::fastly(body).unwrap();
//! assert!(ranges.contains("23.235.33.1".parse().unwrap()));
//! ```

use std::fmt;

use serde_json::Value;

use crate::{IpRangeError, IpRanges};

/// Returned when a provider's list cannot be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        ParseError { message: message.into() }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

impl From<IpRangeError> for ParseError {
    fn from(err: IpRangeError) -> Self {
        ParseError::new(err.to_string())
    }
}

/// One address or range per line; blank lines and `#` comments are skipped.
///
/// Fits <https://www.cloudflare.com/ips-v4>, <https://www.cloudflare.com/ips-v6>
/// and <https://check.torproject.org/torbulkexitlist>.
pub fn lines(text: &str) -> Result<IpRanges, ParseError> {
    let entries = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty());
    Ok(IpRanges::parse(entries)?)
}

/// <https://api.cloudflare.com/client/v4/ips>: `result.ipv4_cidrs` and `result.ipv6_cidrs`.
pub fn cloudflare(json: &str) -> Result<IpRanges, ParseError> {
    let value = parse_json(json)?;
    let result = field(&value, "result")?;
    ranges([
        strings(field(result, "ipv4_cidrs")?)?,
        strings(field(result, "ipv6_cidrs")?)?,
    ])
}

/// <https://ip-ranges.amazonaws.com/ip-ranges.json>: the ranges of one `service`,
/// such as `CLOUDFRONT_ORIGIN_FACING`.
pub fn aws(json: &str, service: &str) -> Result<IpRanges, ParseError> {
    let value = parse_json(json)?;
    let mut entries = Vec::new();
    for (list, key) in [("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")] {
        let Value::Array(prefixes) = field(&value, list)? else {
            return Err(ParseError::new(format!("`{list}` is not an array")));
        };
        for prefix in prefixes {
            if prefix.get("service").and_then(Value::as_str) == Some(service) {
                let range = field(prefix, key)?
                    .as_str()
                    .ok_or_else(|| ParseError::new(format!("`{key}` is not a string")))?;
                entries.push(range.to_owned());
            }
        }
    }
    if entries.is_empty() {
        return Err(ParseError::new(format!(
            "no ranges for AWS service `{service}`"
        )));
    }
    ranges([entries])
}

/// <https://api.fastly.com/public-ip-list>: `addresses` and `ipv6_addresses`.
pub fn fastly(json: &str) -> Result<IpRanges, ParseError> {
    let value = parse_json(json)?;
    ranges([
        strings(field(&value, "addresses")?)?,
        strings(field(&value, "ipv6_addresses")?)?,
    ])
}

/// <https://api.github.com/meta>: one list such as `hooks`, `actions` or `web`.
pub fn github_meta(json: &str, key: &str) -> Result<IpRanges, ParseError> {
    let value = parse_json(json)?;
    ranges([strings(field(&value, key)?)?])
}

/// Stripe's IP lists such as <https://stripe.com/files/ips/ips_webhooks.json>:
/// one list such as `WEBHOOKS` or `API`.
pub fn stripe(json: &str, key: &str) -> Result<IpRanges, ParseError> {
    let value = parse_json(json)?;
    ranges([strings(field(&value, key)?)?])
}

fn parse_json(json: &str) -> Result<Value, ParseError> {
    serde_json::from_str(json).map_err(|err| ParseError::new(format!("invalid JSON: {err}")))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, ParseError> {
    value
        .get(key)
        .ok_or_else(|| ParseError::new(format!("missing field `{key}`")))
}

fn strings(value: &Value) -> Result<Vec<String>, ParseError> {
    let Value::Array(items) = value else {
        return Err(ParseError::new("expected an array of strings"));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| ParseError::new("expected an array of strings"))
        })
        .collect()
}

fn ranges<const N: usize>(lists: [Vec<String>; N]) -> Result<IpRanges, ParseError> {
    let entries: Vec<String> = lists.into_iter().flatten().collect();
    if entries.is_empty() {
        return Err(ParseError::new("the list is empty"));
    }
    Ok(IpRanges::parse(entries)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(ranges: &IpRanges, ip: &str) -> bool {
        ranges.contains(ip.parse().unwrap())
    }

    #[test]
    fn parses_lines() {
        let ranges = lines("# Cloudflare\n173.245.48.0/20\n\n2400:cb00::/32 # v6\n").unwrap();
        assert!(has(&ranges, "173.245.48.1"));
        assert!(has(&ranges, "2400:cb00::1"));
        assert!(lines("173.245.48.0/20\nnot-an-ip\n").is_err());
    }

    #[test]
    fn parses_cloudflare() {
        let json = r#"{"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":["2400:cb00::/32"]},"success":true}"#;
        let ranges = cloudflare(json).unwrap();
        assert!(has(&ranges, "173.245.48.1"));
        assert!(has(&ranges, "2400:cb00::1"));
    }

    #[test]
    fn parses_aws_service() {
        let json = r#"{
            "prefixes": [
                {"ip_prefix": "3.4.12.4/32", "service": "AMAZON"},
                {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT_ORIGIN_FACING"}
            ],
            "ipv6_prefixes": [
                {"ipv6_prefix": "2600:9000:2000::/36", "service": "CLOUDFRONT_ORIGIN_FACING"}
            ]
        }"#;
        let ranges = aws(json, "CLOUDFRONT_ORIGIN_FACING").unwrap();
        assert!(has(&ranges, "13.33.0.1"));
        assert!(has(&ranges, "2600:9000:2000::1"));
        assert!(!has(&ranges, "3.4.12.4"));
        assert!(aws(json, "EC2").is_err());
    }

    #[test]
    fn parses_github_and_stripe() {
        let ranges =
            github_meta(r#"{"hooks":["192.30.252.0/22","2606:50c0::/32"]}"#, "hooks").unwrap();
        assert!(has(&ranges, "192.30.252.1"));
        let ranges = stripe(r#"{"WEBHOOKS":["3.18.12.63"]}"#, "WEBHOOKS").unwrap();
        assert!(has(&ranges, "3.18.12.63"));
        assert!(stripe(r#"{"WEBHOOKS":["3.18.12.63"]}"#, "API").is_err());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(fastly("not json").is_err());
        assert!(fastly(r#"{"addresses":[1],"ipv6_addresses":[]}"#).is_err());
        assert!(fastly(r#"{"addresses":[],"ipv6_addresses":[]}"#).is_err());
        assert!(fastly(r#"{"addresses":["10.0.0.0/33"],"ipv6_addresses":[]}"#).is_err());
    }
}
