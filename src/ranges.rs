use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;

/// A set of IP addresses and CIDR ranges.
///
/// Ranges are stored as sorted, merged intervals, so [`contains`](Self::contains)
/// is a binary search and stays fast for blocklists with hundreds of thousands
/// of entries. Overlapping and adjacent ranges are merged, and two sets are equal
/// when they cover the same addresses.
///
/// ```rust
/// use ipware::IpRanges;
///
/// let ranges = IpRanges::parse(["10.0.0.0/8", "2001:db8::/32", "192.0.2.1"]).unwrap();
/// assert!(ranges.contains("10.1.2.3".parse().unwrap()));
/// assert!(!ranges.contains("192.0.2.2".parse().unwrap()));
/// ```
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct IpRanges {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpRanges {
    /// Creates an empty set.
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

    /// Parses and adds IP addresses and CIDR ranges.
    ///
    /// Nothing is added when any entry fails to parse.
    pub fn extend<I, R>(&mut self, ranges: I) -> Result<(), IpRangeError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        let parsed = ranges
            .into_iter()
            .map(|range| parse_range(range.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        for net in parsed {
            match canonical_net(net) {
                IpNet::V4(net) => self
                    .v4
                    .push((u32::from(net.network()), u32::from(net.broadcast()))),
                IpNet::V6(net) => self
                    .v6
                    .push((u128::from(net.network()), u128::from(net.broadcast()))),
            }
        }
        merge(&mut self.v4);
        merge(&mut self.v6);
        Ok(())
    }

    /// Returns `true` when the set has no addresses.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// The number of IPv4 addresses in the set.
    ///
    /// ```rust
    /// use ipware::IpRanges;
    ///
    /// let ranges = IpRanges::parse(["10.0.0.0/24", "10.0.0.128/25", "192.0.2.1"]).unwrap();
    /// assert_eq!(ranges.ipv4_address_count(), 257);
    /// ```
    pub fn ipv4_address_count(&self) -> u64 {
        self.v4
            .iter()
            .map(|&(start, end)| u64::from(end - start) + 1)
            .sum()
    }

    /// The number of IPv6 addresses in the set, saturating at `u128::MAX` for `::/0`.
    pub fn ipv6_address_count(&self) -> u128 {
        self.v6.iter().fold(0u128, |total, &(start, end)| {
            total.saturating_add((end - start).saturating_add(1))
        })
    }

    /// Returns `true` when `ip` is in any of the ranges.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) match IPv4 ranges.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => search(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => search(&self.v6, u128::from(ip)),
        }
    }
}

impl From<IpAddr> for IpRanges {
    fn from(ip: IpAddr) -> Self {
        let mut ranges = IpRanges::new();
        match ip.to_canonical() {
            IpAddr::V4(ip) => ranges.v4.push((u32::from(ip), u32::from(ip))),
            IpAddr::V6(ip) => ranges.v6.push((u128::from(ip), u128::from(ip))),
        }
        ranges
    }
}

impl fmt::Debug for IpRanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v4 = self.v4.iter().map(|&(start, end)| {
            (
                IpAddr::from(Ipv4Addr::from(start)),
                IpAddr::from(Ipv4Addr::from(end)),
            )
        });
        let v6 = self.v6.iter().map(|&(start, end)| {
            (
                IpAddr::from(Ipv6Addr::from(start)),
                IpAddr::from(Ipv6Addr::from(end)),
            )
        });
        f.debug_list()
            .entries(v4.chain(v6).map(|(start, end)| format!("{start}-{end}")))
            .finish()
    }
}

/// IPv4-mapped IPv6 ranges (`::ffff:10.0.0.0/104`) become IPv4 ranges, so they
/// match the canonical form [`contains`](IpRanges::contains) looks up.
fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net {
        if let (Some(v4), true) = (v6.network().to_ipv4_mapped(), v6.prefix_len() >= 96) {
            if let Ok(net) = ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96) {
                return IpNet::V4(net);
            }
        }
    }
    net
}

/// Sorts intervals and merges overlapping and adjacent ones.
fn merge<T: Copy + Ord + Successor>(intervals: &mut Vec<(T, T)>) {
    intervals.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(intervals.len());
    for &(start, end) in intervals.iter() {
        match merged.last_mut() {
            Some(last) if last.1.successor().map_or(true, |next| start <= next) => {
                last.1 = last.1.max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    *intervals = merged;
}

/// Binary search for the interval that could hold `value`.
fn search<T: Copy + Ord>(intervals: &[(T, T)], value: T) -> bool {
    let after = intervals.partition_point(|&(start, _)| start <= value);
    after > 0 && value <= intervals[after - 1].1
}

trait Successor: Sized {
    fn successor(self) -> Option<Self>;
}

impl Successor for u32 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl Successor for u128 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
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
    fn merges_overlapping_and_adjacent_ranges() {
        let ranges =
            IpRanges::parse(["10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25", "10.0.3.0/24"])
                .unwrap();
        assert_eq!(ranges.v4.len(), 2);
        assert!(ranges.contains("10.0.1.255".parse().unwrap()));
        assert!(!ranges.contains("10.0.2.0".parse().unwrap()));
        assert!(ranges.contains("10.0.3.0".parse().unwrap()));
    }

    #[test]
    fn counts_addresses() {
        let ranges = IpRanges::parse(["10.0.0.0/8", "10.0.0.0/24", "2001:db8::/120"]).unwrap();
        assert_eq!(ranges.ipv4_address_count(), 1 << 24);
        assert_eq!(ranges.ipv6_address_count(), 256);
        let all = IpRanges::parse(["0.0.0.0/0", "::/0"]).unwrap();
        assert_eq!(all.ipv4_address_count(), 1 << 32);
        assert_eq!(all.ipv6_address_count(), u128::MAX);
        assert_eq!(IpRanges::new().ipv4_address_count(), 0);
    }

    #[test]
    fn equality_is_by_addresses() {
        let split = IpRanges::parse(["10.0.0.0/25", "10.0.0.128/25", "2001:db8::/32"]).unwrap();
        let whole = IpRanges::parse(["2001:db8::/32", "10.0.0.0/24"]).unwrap();
        assert_eq!(split, whole);
    }

    #[test]
    fn handles_full_and_edge_ranges() {
        let all = IpRanges::parse(["0.0.0.0/0", "::/0"]).unwrap();
        for ip in [
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(all.contains(ip.parse().unwrap()), "{ip}");
        }
        let edges = IpRanges::parse(["255.255.255.255", "255.255.255.254", "0.0.0.0"]).unwrap();
        assert_eq!(edges.v4.len(), 2);
        assert!(edges.contains("255.255.255.255".parse().unwrap()));
        assert!(!edges.contains("0.0.0.1".parse().unwrap()));
        assert!(IpRanges::new().is_empty());
        assert!(!IpRanges::new().contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ranges_match_ipv4() {
        let ranges = IpRanges::parse(["::ffff:10.0.0.0/104"]).unwrap();
        assert!(ranges.contains("10.1.2.3".parse().unwrap()));
        assert!(ranges.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!ranges.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn extend_merges_with_existing_ranges() {
        let mut ranges = IpRanges::parse(["10.0.0.0/24"]).unwrap();
        ranges.extend(["10.0.1.0/24"]).unwrap();
        assert_eq!(ranges, IpRanges::parse(["10.0.0.0/23"]).unwrap());
    }

    /// Compares lookups with a linear scan over random ranges and addresses.
    #[test]
    fn matches_linear_scan() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..20 {
            let mut entries = Vec::new();
            for _ in 0..200 {
                let bits = next();
                let entry = if bits % 4 == 0 {
                    let ip =
                        std::net::Ipv6Addr::from(u128::from(next()) << 64 | u128::from(next()));
                    format!("{ip}/{}", bits % 129)
                } else {
                    // Cluster IPv4 ranges so they overlap often.
                    let ip = std::net::Ipv4Addr::from((next() as u32) & 0x0fff_ffff);
                    format!("{ip}/{}", 8 + bits % 25)
                };
                entries.push(entry);
            }
            let ranges = IpRanges::parse(&entries).unwrap();
            let nets: Vec<IpNet> = entries.iter().map(|e| e.parse().unwrap()).collect();
            for _ in 0..2_000 {
                let ip = if next() % 4 == 0 {
                    IpAddr::from(std::net::Ipv6Addr::from(
                        u128::from(next()) << 64 | u128::from(next()),
                    ))
                } else {
                    IpAddr::from(std::net::Ipv4Addr::from((next() as u32) & 0x0fff_ffff))
                };
                let expected = nets.iter().any(|net| net.contains(&ip));
                assert_eq!(ranges.contains(ip), expected, "round {round}, {ip}");
            }
        }
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
