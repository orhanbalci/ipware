use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// A list of IP addresses and CIDR ranges.
///
/// ```rust
/// use ipware::IpRanges;
///
/// let ranges = IpRanges::parse(["10.0.0.0/8", "2001:db8::/32", "192.0.2.1"]).unwrap();
/// assert!(ranges.contains("10.1.2.3".parse().unwrap()));
/// assert!(!ranges.contains("192.0.2.2".parse().unwrap()));
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpRanges(Vec<IpNet>);

impl IpRanges {
    /// Creates an empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses IP addresses (`192.0.2.1`) and CIDR ranges (`10.0.0.0/8`).
    pub fn parse<I, R>(ranges: I) -> Result<Self, IpRangeError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        let mut result = Self::new();
        result.extend(ranges)?;
        Ok(result)
    }

    /// Parses and appends IP addresses and CIDR ranges.
    ///
    /// Nothing is appended when any entry fails to parse.
    pub fn extend<I, R>(&mut self, ranges: I) -> Result<(), IpRangeError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        let parsed = ranges
            .into_iter()
            .map(|range| parse_range(range.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        self.0.extend(parsed);
        Ok(())
    }

    /// Returns `true` when the list has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns `true` when `ip` is in any of the ranges.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) match IPv4 ranges.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|net| net.contains(&ip))
    }
}

fn parse_range(range: &str) -> Result<IpNet, IpRangeError> {
    let range = range.trim();
    let parsed = if range.contains('/') {
        IpNet::from_str(range).ok()
    } else {
        IpAddr::from_str(range).ok().map(IpNet::from)
    };
    parsed.ok_or_else(|| IpRangeError { range: range.to_owned() })
}

/// Returned when an entry is neither an IP address nor a CIDR range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpRangeError {
    range: String,
}

impl IpRangeError {
    /// The entry that failed to parse.
    pub fn range(&self) -> &str {
        &self.range
    }
}

impl fmt::Display for IpRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid IP range `{}`: expected an IP address or CIDR range",
            self.range
        )
    }
}

impl std::error::Error for IpRangeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_single_addresses_and_ranges() {
        let ranges = IpRanges::parse(["10.0.0.0/8", "192.168.1.5", "2001:db8::/32"]).unwrap();
        assert!(ranges.contains("10.1.2.3".parse().unwrap()));
        assert!(ranges.contains("192.168.1.5".parse().unwrap()));
        assert!(!ranges.contains("192.168.1.6".parse().unwrap()));
        assert!(ranges.contains("2001:db8::1".parse().unwrap()));
        assert!(!ranges.contains("2001:db9::1".parse().unwrap()));
        assert!(ranges.contains("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn host_bits_in_cidr_are_accepted() {
        let ranges = IpRanges::parse(["10.1.2.3/8"]).unwrap();
        assert!(ranges.contains("10.200.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_ranges_without_partial_extend() {
        let mut ranges = IpRanges::new();
        let err = ranges.extend(["10.0.0.0/8", "10.0.0.*"]).unwrap_err();
        assert_eq!(err.range(), "10.0.0.*");
        assert!(ranges.is_empty());
        assert!(IpRanges::parse(["10.0.0.0/33"]).is_err());
    }
}
