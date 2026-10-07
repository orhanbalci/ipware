use std::borrow::Cow;
use std::net::IpAddr;

use crate::parse::{self, forwarded_ips, single_ip};
use crate::{Headers, IpRanges, IpWare};

/// How [`ClientIpResolver`] reads the client IP from request headers.
///
/// The rightmost strategies read `X-Forwarded-For`-style lists or, for the
/// [`FORWARDED`](crate::header::FORWARDED) header, RFC 7239 `for=` parameters.
/// They walk from the right, where entries were added by your own proxies, and
/// stop at the first entry they cannot parse.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ClientIpStrategy {
    /// The TCP peer address only. Headers are ignored.
    Peer,
    /// [`IpWare`]'s header lookup. The header address is used when ipware reports
    /// a trusted route, or when [`ClientIpResolver::allow_untrusted`] is enabled.
    Ipware {
        /// The ipware instance.
        ipware: IpWare,
        /// Passed to [`IpWare::get_client_ip`].
        strict: bool,
    },
    /// A header that holds a single IP set by the proxy, such as
    /// [`CF_CONNECTING_IP`](crate::header::CF_CONNECTING_IP) or
    /// [`X_REAL_IP`](crate::header::X_REAL_IP). The last header line is used.
    SingleHeader(Cow<'static, str>),
    /// The first IP from the right that is a public internet address.
    RightmostNonPrivate(Cow<'static, str>),
    /// The IP added by the outermost of a fixed number of proxies: with `n`
    /// proxies in front of the app, the `n`th entry from the right.
    ///
    /// The proxy connecting to the app does not appear in the header, so one
    /// proxy means the rightmost entry is the client. Note that this differs from
    /// [`IpWareProxy`](crate::IpWareProxy)'s `proxy_count`.
    RightmostTrustedCount(Cow<'static, str>, usize),
    /// The first IP from the right that is not a trusted proxy, using
    /// [`ClientIpResolver::trusted_proxies`] and the trust switches.
    RightmostTrustedRange(Cow<'static, str>),
    /// The first strategy in the list that yields an address.
    Chain(Vec<ClientIpStrategy>),
}

impl ClientIpStrategy {
    /// [`ClientIpStrategy::Ipware`].
    pub fn ipware(ipware: IpWare, strict: bool) -> Self {
        ClientIpStrategy::Ipware { ipware, strict }
    }

    /// [`ClientIpStrategy::SingleHeader`].
    pub fn single_header(header: impl Into<Cow<'static, str>>) -> Self {
        ClientIpStrategy::SingleHeader(header.into())
    }

    /// [`ClientIpStrategy::RightmostNonPrivate`].
    pub fn rightmost_non_private(header: impl Into<Cow<'static, str>>) -> Self {
        ClientIpStrategy::RightmostNonPrivate(header.into())
    }

    /// [`ClientIpStrategy::RightmostTrustedCount`].
    pub fn rightmost_trusted_count(header: impl Into<Cow<'static, str>>, count: usize) -> Self {
        ClientIpStrategy::RightmostTrustedCount(header.into(), count)
    }

    /// [`ClientIpStrategy::RightmostTrustedRange`].
    pub fn rightmost_trusted_range(header: impl Into<Cow<'static, str>>) -> Self {
        ClientIpStrategy::RightmostTrustedRange(header.into())
    }

    /// [`ClientIpStrategy::Chain`].
    pub fn chain(strategies: impl IntoIterator<Item = ClientIpStrategy>) -> Self {
        ClientIpStrategy::Chain(strategies.into_iter().collect())
    }
}

/// Where a [`ResolvedIp`] was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpSource {
    /// A request header.
    Header {
        /// `true` when the route was verified: the peer is a trusted proxy, and for
        /// [`ClientIpStrategy::Ipware`] ipware also reported a trusted route.
        trusted_route: bool,
    },
    /// The TCP peer address.
    Peer,
}

/// A client IP resolved by [`ClientIpResolver`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedIp {
    /// The client IP address. IPv4-mapped IPv6 addresses are converted to IPv4.
    pub ip: IpAddr,
    /// Where the address came from.
    pub source: IpSource,
}

/// Resolves the client IP from request headers and the TCP peer address.
///
/// Headers are only read when the peer is a trusted proxy, so clients that reach
/// the server directly cannot spoof their IP. When the peer is not trusted, or
/// the strategy yields no address, the peer address is returned.
///
/// ```rust
/// use ipware::{header, ClientIpResolver, ClientIpStrategy, HeaderMap, IpRanges, IpSource};
///
/// let resolver = ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
///     header::X_FORWARDED_FOR,
/// ))
/// .trusted_proxies(IpRanges::parse(["10.0.0.0/8"]).unwrap());
///
/// let mut headers = HeaderMap::new();
/// headers.insert(
///     "x-forwarded-for",
///     "6.6.6.6, 93.184.216.34, 10.0.0.5".parse().unwrap(),
/// );
///
/// // Through the load balancer at 10.0.0.2: the header is used.
/// let resolved = resolver
///     .resolve(&headers, Some("10.0.0.2".parse().unwrap()))
///     .unwrap();
/// assert_eq!(
///     resolved.ip,
///     "93.184.216.34".parse::<std::net::IpAddr>().unwrap()
/// );
/// assert_eq!(resolved.source, IpSource::Header { trusted_route: true });
///
/// // Directly from the internet: the header is ignored.
/// let resolved = resolver
///     .resolve(&headers, Some("198.51.100.1".parse().unwrap()))
///     .unwrap();
/// assert_eq!(resolved.source, IpSource::Peer);
/// ```
#[derive(Clone, Debug)]
pub struct ClientIpResolver {
    strategy: ClientIpStrategy,
    trusted_proxies: IpRanges,
    trust_loopback: bool,
    trust_private: bool,
    trust_link_local: bool,
    allow_untrusted: bool,
    max_forwarded_hops: Option<usize>,
}

impl Default for ClientIpResolver {
    /// A resolver that uses the peer address only.
    fn default() -> Self {
        Self::new(ClientIpStrategy::Peer)
    }
}

impl ClientIpResolver {
    /// Creates a resolver with no trusted proxies.
    pub fn new(strategy: ClientIpStrategy) -> Self {
        ClientIpResolver {
            strategy,
            trusted_proxies: IpRanges::new(),
            trust_loopback: false,
            trust_private: false,
            trust_link_local: false,
            allow_untrusted: false,
            max_forwarded_hops: None,
        }
    }

    /// Sets the IP addresses and ranges of the proxies in front of the server.
    pub fn trusted_proxies(mut self, ranges: IpRanges) -> Self {
        self.trusted_proxies = ranges;
        self
    }

    /// Treats loopback addresses (`127.0.0.0/8`, `::1`) as trusted proxies.
    pub fn trust_loopback(mut self, trust: bool) -> Self {
        self.trust_loopback = trust;
        self
    }

    /// Treats private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
    /// `100.64.0.0/10`, `fc00::/7`) as trusted proxies.
    pub fn trust_private(mut self, trust: bool) -> Self {
        self.trust_private = trust;
        self
    }

    /// Treats link-local addresses (`169.254.0.0/16`, `fe80::/10`) as trusted proxies.
    pub fn trust_link_local(mut self, trust: bool) -> Self {
        self.trust_link_local = trust;
        self
    }

    /// Reads headers even when the peer is not a trusted proxy, and accepts
    /// [`ClientIpStrategy::Ipware`] results without a trusted route.
    ///
    /// Clients can set these headers themselves, so only enable this when every
    /// request reaches the server through a proxy that overwrites them.
    pub fn allow_untrusted(mut self, allow: bool) -> Self {
        self.allow_untrusted = allow;
        self
    }

    /// Reads at most `hops` entries from the right of forwarding headers.
    ///
    /// Applies to the rightmost strategies; addresses further left are never used.
    pub fn max_forwarded_hops(mut self, hops: usize) -> Self {
        self.max_forwarded_hops = Some(hops);
        self
    }

    /// Returns `true` when `ip` is a trusted proxy.
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted_proxies.contains(ip)
            || (self.trust_loopback && ip.is_loopback())
            || (self.trust_private && parse::is_private(ip))
            || (self.trust_link_local && parse::is_link_local(ip))
    }

    /// Resolves the client IP.
    ///
    /// `peer` is the TCP peer address of the request, if known. `None` is returned
    /// only when neither the headers nor the peer yield an address.
    pub fn resolve<H: Headers>(&self, headers: &H, peer: Option<IpAddr>) -> Option<ResolvedIp> {
        let peer = peer.map(|ip| ResolvedIp { ip: ip.to_canonical(), source: IpSource::Peer });
        let trusted_peer = peer.is_some_and(|peer| self.is_trusted_proxy(peer.ip));
        if !(trusted_peer || self.allow_untrusted) {
            return peer;
        }
        let lookup = Lookup { resolver: self, headers, peer, trusted_peer };
        lookup.resolve(&self.strategy).or(peer)
    }
}

/// Reads the client IP from one request.
struct Lookup<'a, H> {
    resolver: &'a ClientIpResolver,
    headers: &'a H,
    peer: Option<ResolvedIp>,
    trusted_peer: bool,
}

impl<H: Headers> Lookup<'_, H> {
    fn resolve(&self, strategy: &ClientIpStrategy) -> Option<ResolvedIp> {
        let ip = match strategy {
            ClientIpStrategy::Peer => return self.peer,
            ClientIpStrategy::Ipware { ipware, strict } => {
                let (ip, trusted_route) = ipware.get_client_ip(self.headers, *strict);
                let ip = ip.filter(|_| trusted_route || self.resolver.allow_untrusted)?;
                return Some(ResolvedIp {
                    ip: ip.to_canonical(),
                    source: IpSource::Header { trusted_route: trusted_route && self.trusted_peer },
                });
            }
            ClientIpStrategy::Chain(strategies) => {
                return strategies
                    .iter()
                    .find_map(|strategy| self.resolve(strategy));
            }
            ClientIpStrategy::SingleHeader(name) => single_ip(self.headers, name),
            ClientIpStrategy::RightmostNonPrivate(name) => {
                self.rightmost(name, |ip| ip_rfc::global(&ip))
            }
            ClientIpStrategy::RightmostTrustedRange(name) => {
                self.rightmost(name, |ip| !self.resolver.is_trusted_proxy(ip))
            }
            ClientIpStrategy::RightmostTrustedCount(name, count) => count
                .checked_sub(1)
                .and_then(|index| self.hops(name).get(index).copied().flatten()),
        }?;
        Some(ResolvedIp {
            ip,
            source: IpSource::Header { trusted_route: self.trusted_peer },
        })
    }

    /// Forwarding header entries from the right, limited to `max_forwarded_hops`.
    fn hops(&self, name: &str) -> Vec<Option<IpAddr>> {
        let limit = self.resolver.max_forwarded_hops.unwrap_or(usize::MAX);
        forwarded_ips(self.headers, name)
            .into_iter()
            .rev()
            .take(limit)
            .collect()
    }

    /// The first entry from the right accepted by `is_client`. Stops at an
    /// unparseable entry, since anything left of it cannot be trusted.
    fn rightmost(&self, name: &str, is_client: impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
        for ip in self.hops(name) {
            let ip = ip?;
            if is_client(ip) {
                return Some(ip);
            }
        }
        None
    }
}
