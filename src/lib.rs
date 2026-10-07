// This crate is entirely safe
#![forbid(unsafe_code)]
// Ensures that `pub` means published in the public API.
// This property is useful for reasoning about breaking API changes.
#![deny(unreachable_pub)]

//! Client IP extraction for Rust HTTP servers.
//!
//! ipware finds the IP address of the client behind an HTTP request, using proxy
//! headers such as `X-Forwarded-For` and `Forwarded` together with the TCP peer
//! address. It works with any framework built on the `http` crate, version 1.x or 0.2.
//!
//! It offers two APIs:
//!
//! - [`ClientIpResolver`] (recommended): reads headers only when the request comes
//!   from one of your trusted proxies, and walks forwarding headers from the right,
//!   so clients cannot spoof their IP.
//! - [`IpWare`]: the header precedence lookup ported from
//!   [python-ipware](https://github.com/un33k/python-ipware), with optional proxy
//!   count and trusted proxy checks.
//!
//! ## 📦 Installation
//!
//! ```toml
//! [dependencies]
//! ipware = "0.5"
//! ```
//!
//! ### Features
//!
//! ipware reads headers from the `HeaderMap` of the `http` crate. Enable the version
//! your framework uses; both can be enabled at the same time.
//!
//! | Feature           | `http` version | Frameworks                                     |
//! | ----------------- | -------------- | ---------------------------------------------- |
//! | `http1` (default) | 1.x            | axum 0.7+, hyper 1, tonic 0.12+, reqwest 0.12+ |
//! | `http02`          | 0.2            | actix-web 4, hyper 0.14, warp 0.3              |
//! | `providers`       |                | platform presets and provider IP ranges        |
//!
//! ```toml
//! # actix-web 4
//! ipware = { version = "0.5", default-features = false, features = ["http02"] }
//! ```
//!
//! `http` 1.x types are re-exported at the crate root (`ipware::HeaderMap`), and each
//! enabled `http` crate is re-exported as `ipware::http` / `ipware::http02`.
//!
//! ## 🚀 Quick start
//!
//! ```rust
//! # #[cfg(feature = "http1")] {
//! use std::net::IpAddr;
//!
//! use ipware::{header, ClientIpResolver, ClientIpStrategy, HeaderMap, IpRanges, IpSource};
//!
//! // Load balancers in 10.0.0.0/8 append the client address to X-Forwarded-For.
//! let resolver = ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
//!     header::X_FORWARDED_FOR,
//! ))
//! .trusted_proxies(IpRanges::parse(["10.0.0.0/8"]).unwrap());
//!
//! let mut headers = HeaderMap::new();
//! headers.insert(
//!     "x-forwarded-for",
//!     "203.0.113.9, 93.184.216.34, 10.0.0.5".parse().unwrap(),
//! );
//!
//! // The request arrived from the load balancer at 10.0.0.2.
//! let peer: IpAddr = "10.0.0.2".parse().unwrap();
//! let client = resolver.resolve(&headers, Some(peer)).unwrap();
//! assert_eq!(client.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
//! assert_eq!(client.source, IpSource::Header { trusted_route: true });
//!
//! // The same headers sent straight to the server are ignored.
//! let direct: IpAddr = "198.51.100.1".parse().unwrap();
//! let client = resolver.resolve(&headers, Some(direct)).unwrap();
//! assert_eq!(client.ip, direct);
//! assert_eq!(client.source, IpSource::Peer);
//! # }
//! ```
//!
//! The peer address comes from your server, for example axum's `ConnectInfo` or
//! actix-web's `HttpRequest::peer_addr`.
//!
//! ## 🛡️ Why trusted proxies matter
//!
//! Each proxy appends the address it received a request from to `X-Forwarded-For`.
//! The rightmost entries were added by your own proxies; everything to their left
//! was sent by the client and can be anything. A client that reaches the server
//! directly can also send the whole header itself.
//!
//! `ClientIpResolver` handles both:
//!
//! 1. Headers are read only when the TCP peer is a trusted proxy. Otherwise the peer
//!    address is the client IP.
//! 2. The rightmost strategies skip your proxies from the right and stop at the
//!    first address they did not add.
//!
//! ## 🧭 Strategies
//!
//! | Strategy | Use when |
//! | --- | --- |
//! | `rightmost_trusted_range(header)` | your proxies' address ranges are known |
//! | `rightmost_trusted_count(header, n)` | a fixed number of proxies sit in front of the server |
//! | `rightmost_non_private(header)` | proxies are on private networks, clients on the internet |
//! | `single_header(header)` | a CDN sets one header, such as `CF-Connecting-IP` |
//! | `ipware(ipware, strict)` | [`IpWare`]'s header lookup, gated on a trusted peer |
//! | `Peer` | there is no proxy |
//! | `chain(strategies)` | try several strategies in order |
//!
//! ```rust
//! use ipware::{header, ClientIpResolver, ClientIpStrategy, IpRanges};
//!
//! # fn main() -> Result<(), ipware::IpRangeError> {
//! // Behind Cloudflare: trust CF-Connecting-IP from Cloudflare's ranges
//! // (see https://www.cloudflare.com/ips/).
//! let cloudflare =
//!     ClientIpResolver::new(ClientIpStrategy::single_header(header::CF_CONNECTING_IP))
//!         .trusted_proxies(IpRanges::parse(["173.245.48.0/20", "103.21.244.0/22"])?);
//!
//! // A CDN in front of a load balancer on a private network.
//! let two_proxies = ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_count(
//!     header::X_FORWARDED_FOR,
//!     2,
//! ))
//! .trust_private(true);
//!
//! // Prefer RFC 7239 Forwarded, fall back to X-Forwarded-For.
//! let chain = ClientIpResolver::new(ClientIpStrategy::chain([
//!     ClientIpStrategy::rightmost_trusted_range(header::FORWARDED),
//!     ClientIpStrategy::rightmost_trusted_range(header::X_FORWARDED_FOR),
//! ]))
//! .trust_private(true)
//! .max_forwarded_hops(10);
//! # Ok(())
//! # }
//! ```
//!
//! ### Resolver options
//!
//! | Option | Effect |
//! | --- | --- |
//! | `trusted_proxies(ranges)` | addresses and CIDR ranges of your proxies |
//! | `trust_loopback(true)` | treat `127.0.0.0/8` and `::1` as trusted proxies |
//! | `trust_private(true)` | treat `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7` as trusted proxies |
//! | `trust_link_local(true)` | treat `169.254/16` and `fe80::/10` as trusted proxies |
//! | `max_forwarded_hops(n)` | read at most `n` entries from the right |
//! | `allow_untrusted(true)` | read headers from any peer; only safe when every request passes a proxy that overwrites them |
//!
//! `resolve` returns a [`ResolvedIp`] with the address and its [`IpSource`]: a
//! header, with `trusted_route` set when the route was verified, or the peer.
//! IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) are returned as IPv4.
//!
//! ### Header parsing
//!
//! - `X-Forwarded-For`-style headers are comma-separated lists; [`header::FORWARDED`]
//!   is parsed as RFC 7239 `for=` parameters.
//! - Entries may carry ports, brackets, quotes and IPv6 zones: `192.0.2.1:80`,
//!   `"[2001:db8::1]:443"`, `fe80::1%eth0`.
//! - Multiple header lines are combined in order.
//! - The rightmost strategies stop at the first entry they cannot parse, such as
//!   `unknown`, since nothing to its left can be trusted.
//!
//! ## 🌐 Platform presets
//!
//! With the `providers` feature, [`ClientIpResolver::platform`] builds a resolver
//! for a CDN or hosting platform from its client IP header and published proxy
//! ranges:
//!
//! | Platform | Header | Trusted proxies |
//! | --- | --- | --- |
//! | `Cloudflare` | `CF-Connecting-IP` | Cloudflare edge ranges |
//! | `CloudFront` | `CloudFront-Viewer-Address` | CloudFront origin-facing ranges |
//! | `Fastly` | `X-Forwarded-For`, from the right | Fastly edge ranges |
//! | `GoogleCloudLoadBalancer` | `X-Forwarded-For`: `client, load-balancer` | `35.191.0.0/16`, `130.211.0.0/22` |
//! | `FlyIo` | `Fly-Client-IP` | private networks |
//!
//! ```toml
//! ipware = { version = "0.5", features = ["providers"] }
//! ```
//!
//! ```rust
//! # #[cfg(feature = "providers")] {
//! use ipware::providers::Platform;
//! use ipware::ClientIpResolver;
//!
//! let resolver = ClientIpResolver::platform(Platform::Cloudflare);
//! # }
//! ```
//!
//! `ipware::providers` also has the GitHub and Stripe webhook ranges for allow
//! lists, and parsers for each provider's published list. The built-in ranges are
//! snapshots from the date in `providers::SNAPSHOT_DATE`; providers change them
//! over time, so update the crate regularly or fetch fresh lists and read them with
//! `providers::parse`.
//!
//! ## 📋 IP ranges
//!
//! [`IpRanges`] parses IP addresses and CIDR ranges, for trusted proxies or your own
//! allow and block lists. Ranges are merged and looked up by binary search, so
//! blocklists with hundreds of thousands of entries stay fast.
//!
//! ```rust
//! use ipware::IpRanges;
//!
//! let ranges = IpRanges::parse(["10.0.0.0/8", "2001:db8::/32", "192.0.2.1"]).unwrap();
//! assert!(ranges.contains("10.1.2.3".parse().unwrap()));
//! assert!(!ranges.contains("192.0.2.2".parse().unwrap()));
//! ```
//!
//! ## 🔢 IpWare: header precedence lookup
//!
//! [`IpWare`] checks a list of headers in order and returns the first public client
//! IP it finds, preferring public addresses over private and loopback ones.
//!
//! ```rust
//! # #[cfg(feature = "http1")] {
//! use std::net::IpAddr;
//!
//! use ipware::{HeaderMap, IpWare, IpWareConfig, IpWareProxy};
//!
//! let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
//!
//! let mut headers = HeaderMap::new();
//! headers.insert(
//!     "x-forwarded-for",
//!     "177.139.233.139, 198.84.193.157, 198.84.193.158"
//!         .parse()
//!         .unwrap(),
//! );
//! let (ip, trusted_route) = ipware.get_client_ip(&headers, false);
//! assert_eq!(ip, Some("177.139.233.139".parse::<IpAddr>().unwrap()));
//! assert!(!trusted_route);
//! # }
//! ```
//!
//! Without a proxy count or trusted proxy list, `IpWare` returns the leftmost
//! address, which the client controls. Configure one of them below, and gate the
//! lookup on the peer address with `ClientIpStrategy::ipware`.
//!
//! ### Header precedence
//!
//! Headers are checked from top to bottom. Each name is tried as written and with
//! `_` replaced by `-`.
//!
//! ```text
//! x_forwarded_for           Load balancers and proxies such as AWS ELB
//! http_x_forwarded_for
//! http_client_ip            Amazon EC2, Heroku
//! http_x_real_ip
//! http_x_forwarded          Squid
//! http_x_cluster_client_ip  Rackspace LB, Riverbed Stingray
//! http_forwarded_for
//! http_forwarded
//! http_via                  Squid
//! x-real-ip                 nginx
//! x-cluster-client-ip       Rackspace Cloud Load Balancers
//! x_forwarded               Squid
//! forwarded_for
//! cf-connecting-ip          Cloudflare
//! true-client-ip            Akamai, Cloudflare Enterprise
//! fastly-client-ip          Fastly, Firebase
//! forwarded
//! client-ip
//! remote_addr
//! ```
//!
//! Provide your own order with [`IpWareConfig::new`]:
//!
//! ```rust
//! use ipware::IpWareConfig;
//!
//! let config = IpWareConfig::new(["cf-connecting-ip", "x-forwarded-for"], true);
//! ```
//!
//! ### Proxy count
//!
//! With a known number of proxies, `proxy_count` is the number of proxy addresses
//! after the client in the header: `client, proxy1` is a count of 1.
//!
//! ```rust
//! # #[cfg(feature = "http1")] {
//! use std::net::IpAddr;
//!
//! use ipware::{HeaderMap, IpWare, IpWareConfig, IpWareProxy};
//!
//! let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, vec![]));
//!
//! let mut headers = HeaderMap::new();
//! headers.insert(
//!     "x-forwarded-for",
//!     "177.139.233.139, 198.84.193.158".parse().unwrap(),
//! );
//! let (ip, trusted_route) = ipware.get_client_ip(&headers, true);
//! assert_eq!(ip, Some("177.139.233.139".parse::<IpAddr>().unwrap()));
//! assert!(trusted_route);
//! # }
//! ```
//!
//! ### Trusted proxy list
//!
//! With known proxy addresses, `proxy_list` must match the rightmost entries of the
//! header exactly and in order.
//!
//! ```rust
//! # #[cfg(feature = "http1")] {
//! use std::net::IpAddr;
//!
//! use ipware::{HeaderMap, IpWare, IpWareConfig, IpWareProxy};
//!
//! let proxies: Vec<IpAddr> = vec![
//!     "198.84.193.157".parse().unwrap(),
//!     "198.84.193.158".parse().unwrap(),
//! ];
//! let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));
//!
//! let mut headers = HeaderMap::new();
//! headers.insert(
//!     "x-forwarded-for",
//!     "6.6.6.6, 177.139.233.139, 198.84.193.157, 198.84.193.158"
//!         .parse()
//!         .unwrap(),
//! );
//! // Non-strict: extra entries on the left are ignored.
//! let (ip, trusted_route) = ipware.get_client_ip(&headers, false);
//! assert_eq!(ip, Some("177.139.233.139".parse::<IpAddr>().unwrap()));
//! assert!(trusted_route);
//!
//! // Strict: the header must hold exactly the client and the proxies.
//! let (ip, _) = ipware.get_client_ip(&headers, true);
//! assert_eq!(ip, None);
//! # }
//! ```
//!
//! `trusted_route` is `true` when a proxy count or proxy list was configured and
//! matched.
//!
//! ### Rightmost client
//!
//! Some legacy networks put the client on the right: `proxy2, proxy1, client`. Use
//! `leftmost(false)` for them.
//!
//! ```rust
//! use ipware::{IpWare, IpWareConfig, IpWareProxy};
//!
//! let ipware = IpWare::new(
//!     IpWareConfig::default().leftmost(false),
//!     IpWareProxy::default(),
//! );
//! ```
//!
//! Header entries may be IPv4 or IPv6 addresses, with or without a port. A header
//! with an entry that does not parse is skipped.
//!
//! ## 🔌 Framework integrations
//!
//! - [axum-ipware](https://github.com/orhanbalci/axum-ipware): IP filtering
//!   middleware and a `ClientIp` extractor for axum.
//! - [actix-ip-filter](https://github.com/jhen0409/actix-ip-filter): IP filtering
//!   middleware for actix-web.
//!
//! ## 🙏 Credits
//!
//! `IpWare` is ported from [python-ipware](https://github.com/un33k/python-ipware)
//! by [@un33k](https://github.com/un33k).
//!
//! [`ClientIpResolver`]: https://docs.rs/ipware/latest/ipware/struct.ClientIpResolver.html
//! [`IpWare`]: https://docs.rs/ipware/latest/ipware/struct.IpWare.html
//! [`ResolvedIp`]: https://docs.rs/ipware/latest/ipware/struct.ResolvedIp.html
//! [`IpSource`]: https://docs.rs/ipware/latest/ipware/enum.IpSource.html
//! [`IpRanges`]: https://docs.rs/ipware/latest/ipware/struct.IpRanges.html
//! [`IpWareConfig::new`]: https://docs.rs/ipware/latest/ipware/struct.IpWareConfig.html#method.new
//! [`header::FORWARDED`]: https://docs.rs/ipware/latest/ipware/header/constant.FORWARDED.html
//! [`ClientIpResolver::platform`]: https://docs.rs/ipware/latest/ipware/struct.ClientIpResolver.html#method.platform

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[cfg(not(any(feature = "http1", feature = "http02")))]
compile_error!("ipware requires at least one of the `http1` or `http02` features");

#[cfg(feature = "http1")]
pub use http;
#[cfg(feature = "http1")]
pub use http::header::{HeaderMap, HeaderName, HeaderValue};
#[cfg(feature = "http02")]
pub use http02;

pub mod header;
mod parse;
#[cfg(feature = "providers")]
pub mod providers;
mod ranges;
mod resolver;

pub use ranges::{IpRangeError, IpRanges};
pub use resolver::{ClientIpResolver, ClientIpStrategy, ForwardedOrigin, IpSource, ResolvedIp};

/// `Forwarded` and its CGI-style name hold RFC 7239 values rather than plain lists.
fn is_forwarded_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("forwarded") || name.eq_ignore_ascii_case("http_forwarded")
}

#[allow(unreachable_pub)]
mod sealed {
    pub trait Sealed {}
}

/// Header collections [`IpWare::get_client_ip`] can read from.
///
/// Implemented for `HeaderMap` of `http` 1.x (feature `http1`) and `http` 0.2
/// (feature `http02`). This trait is sealed and cannot be implemented outside
/// this crate.
pub trait Headers: sealed::Sealed {
    #[doc(hidden)]
    fn get_str(&self, name: &str) -> Option<&str>;

    /// Every line of the header, `None` for values that are not valid UTF-8.
    #[doc(hidden)]
    fn get_all_str(&self, name: &str) -> Vec<Option<&str>>;
}

#[cfg(feature = "http1")]
impl sealed::Sealed for http::HeaderMap {}

#[cfg(feature = "http1")]
impl Headers for http::HeaderMap {
    fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|value| value.to_str().ok())
    }

    fn get_all_str(&self, name: &str) -> Vec<Option<&str>> {
        self.get_all(name)
            .iter()
            .map(|value| value.to_str().ok())
            .collect()
    }
}

#[cfg(feature = "http02")]
impl sealed::Sealed for http02::HeaderMap {}

#[cfg(feature = "http02")]
impl Headers for http02::HeaderMap {
    fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|value| value.to_str().ok())
    }

    fn get_all_str(&self, name: &str) -> Vec<Option<&str>> {
        self.get_all(name)
            .iter()
            .map(|value| value.to_str().ok())
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct IpWareConfig {
    precedence: Vec<String>,
    leftmost: bool,
}

impl Default for IpWareConfig {
    fn default() -> Self {
        IpWareConfig {
            precedence: [
                "x_forwarded_for", /* Load balancers or proxies such as AWS ELB (default client is `left-most` [`<client>, <proxy1>, <proxy2>`]), */
                "http_x_forwarded_for", // Similar to X_FORWARDED_TO
                "http_client_ip", /* Standard headers used by providers such as Amazon EC2, Heroku etc. */
                "http_x_real_ip", /* Standard headers used by providers such as Amazon EC2, Heroku etc. */
                "http_x_forwarded", // Squid and others
                "http_x_cluster_client_ip", /* Rackspace LB and Riverbed Stingray */
                "http_forwarded_for",       // RFC 7239
                "http_forwarded",           // RFC 7239
                "http_via",                 // Squid and others
                "x-real-ip",                // NGINX
                "x-cluster-client-ip", // Rackspace Cloud Load Balancers
                "x_forwarded",         // Squid
                "forwarded_for",       // RFC 7239
                "cf-connecting-ip",    // CloudFlare
                "true-client-ip",      // CloudFlare Enterprise,
                "fastly-client-ip",    // Firebase, Fastly
                "forwarded",           // RFC 7239
                "client-ip", /* Akamai and Cloudflare: True-Client-IP and Fastly: Fastly-Client-IP */
                "remote_addr", // Default
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            leftmost: true,
        }
    }
}

impl IpWareConfig {
    /// Creates a config with the given header lookup order.
    ///
    /// Header names can be `HeaderName`s of either `http` version, or plain strings.
    pub fn new<T, N>(precedence: T, leftmost: bool) -> Self
    where
        T: IntoIterator<Item = N>,
        N: AsRef<str>,
    {
        IpWareConfig {
            precedence: precedence
                .into_iter()
                .map(|name| name.as_ref().to_ascii_lowercase())
                .collect(),
            leftmost,
        }
    }

    pub fn leftmost(mut self, leftmost: bool) -> Self {
        self.leftmost = leftmost;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct IpWareProxy {
    proxy_count: u16,
    /// One entry per proxy position, matched against the rightmost header entries.
    proxy_list: Vec<IpRanges>,
}

impl IpWareProxy {
    /// Creates a proxy config with a proxy count and the exact addresses of the
    /// trusted proxies, in header order.
    pub fn new<T>(proxy_count: u16, proxy_list: T) -> Self
    where
        T: Into<Vec<IpAddr>>,
    {
        let proxy_list = proxy_list.into().into_iter().map(IpRanges::from).collect();
        IpWareProxy { proxy_count, proxy_list }
    }

    /// Creates a proxy config whose trusted proxies may be CIDR ranges. Each
    /// entry is one proxy position, in header order.
    ///
    /// ```rust
    /// use ipware::IpWareProxy;
    ///
    /// // The second-to-last proxy is any load balancer in 10.1.0.0/16, the last
    /// // one a fixed address.
    /// let proxy = IpWareProxy::parse(0, ["10.1.0.0/16", "198.84.193.158"]).unwrap();
    /// ```
    pub fn parse<I, R>(proxy_count: u16, proxy_list: I) -> Result<Self, IpRangeError>
    where
        I: IntoIterator<Item = R>,
        R: AsRef<str>,
    {
        let proxy_list = proxy_list
            .into_iter()
            .map(|proxy| IpRanges::parse([proxy]))
            .collect::<Result<_, _>>()?;
        Ok(IpWareProxy { proxy_count, proxy_list })
    }

    pub fn is_proxy_count_valid<'a, I>(&self, ip_list: I, strict: bool) -> bool
    where
        I: IntoIterator<Item = &'a IpAddr>,
    {
        if self.proxy_count < 1 {
            return true;
        }

        let ip_count = ip_list.into_iter().count();
        if ip_count < 1 {
            return false;
        }
        let proxy_count = usize::from(self.proxy_count);
        if strict {
            return ip_count - 1 == proxy_count;
        }

        ip_count > proxy_count
    }

    pub fn is_proxy_trusted_list_valid<'a, I>(&self, ip_list: I, strict: bool) -> bool
    where
        I: IntoIterator<Item = &'a IpAddr>,
    {
        if self.proxy_list.is_empty() {
            return true;
        }
        let ip_list = ip_list.into_iter().collect::<Vec<_>>();
        let ip_count = ip_list.len();
        let proxy_count = self.proxy_list.len();
        if ip_count == 0 || (strict && ip_count - 1 != proxy_count) || ip_count - 1 < proxy_count {
            return false;
        }
        ip_list
            .into_iter()
            .rev()
            .take(proxy_count)
            .rev()
            .zip(self.proxy_list.iter())
            .all(|(ip_addr, proxy)| proxy.contains(*ip_addr))
    }
}

#[derive(Clone, Debug, Default)]
pub struct IpWare {
    config: IpWareConfig,
    proxy: IpWareProxy,
}

impl IpWare {
    pub fn new(config: IpWareConfig, proxy: IpWareProxy) -> Self {
        IpWare { config, proxy }
    }

    fn get_meta_value<'a, H: Headers>(&self, headers: &'a H, name: &str) -> Option<&'a str> {
        match headers.get_str(name) {
            Some(value) => Some(value),
            None => headers.get_str(&name.replace('_', "-")),
        }
    }

    fn get_meta_values<'a, 'b, H: Headers>(&'b self, headers: &'a H) -> Vec<(&'b str, &'a str)> {
        self.config
            .precedence
            .iter()
            .filter_map(|header_name| {
                let value = self.get_meta_value(headers, header_name)?;
                Some((header_name.as_str(), value))
            })
            .collect()
    }

    /// Returns the client's IP address.
    ///
    /// `headers` can be a `HeaderMap` from `http` 1.x or 0.2, depending on enabled features.
    pub fn get_client_ip<H: Headers>(&self, headers: &H, strict: bool) -> (Option<IpAddr>, bool) {
        let mut loopback_list = vec![];
        let mut private_list = vec![];
        let meta_values = self.get_meta_values(headers);
        for &(header_name, meta_value) in meta_values.iter() {
            let meta_ips = if is_forwarded_header(header_name) {
                self.get_ips_from_forwarded(meta_value)
            } else {
                self.get_ips_from_string(meta_value)
            };
            if meta_ips.is_empty() {
                continue;
            }
            let proxy_count_validated = self.proxy.is_proxy_count_valid(&meta_ips, strict);
            if !proxy_count_validated {
                continue;
            }
            let proxy_list_validated = self.proxy.is_proxy_trusted_list_valid(&meta_ips, strict);
            if !proxy_list_validated {
                continue;
            }
            let (client_ip, trusted_route) =
                self.get_best_ip(&meta_ips, proxy_count_validated, proxy_list_validated);
            if let Some(client_ip) = client_ip {
                if ip_rfc::global(client_ip) {
                    return (Some(*client_ip), trusted_route);
                }
                if client_ip.is_loopback() {
                    loopback_list.push((*client_ip, trusted_route));
                } else {
                    private_list.push((*client_ip, trusted_route));
                }
            }
        }

        match private_list.first().or(loopback_list.first()) {
            Some(&(client_ip, trusted_route)) => (Some(client_ip), trusted_route),
            None => (None, false),
        }
    }

    /// Parses ip addresses from given list. Ip addresses assumed to be seperated with ,
    /// If any of the parts contains invalid string function returns empty vec.
    ///
    /// # Arguments
    /// * `ip_str` - String contains , seperated ip addresses
    fn get_ips_from_string(&self, ip_str: &str) -> Vec<IpAddr> {
        let Ok(mut result): Result<Vec<_>, _> = ip_str
            .split(',')
            .map(|single_ip| single_ip.trim())
            .map(|trimmed_ip| match IpAddr::from_str(trimmed_ip) {
                Ok(ip) => Ok(ip),
                Err(_) => SocketAddr::from_str(trimmed_ip).map(|socket_addr| socket_addr.ip()),
            })
            .collect()
        else {
            return Vec::new();
        };
        if !self.config.leftmost {
            result.reverse();
        }
        result
    }

    /// Parses the `for=` addresses of an RFC 7239 `Forwarded` header. Returns an
    /// empty vec when any element has no parseable address.
    fn get_ips_from_forwarded(&self, value: &str) -> Vec<IpAddr> {
        let Some(mut result) = parse::forwarded_header_ips(value)
            .into_iter()
            .collect::<Option<Vec<_>>>()
        else {
            return Vec::new();
        };
        if !self.config.leftmost {
            result.reverse();
        }
        result
    }

    fn get_best_ip<'a>(
        &self,
        ip_list: &'a [IpAddr],
        proxy_count_validated: bool,
        proxy_list_validated: bool,
    ) -> (Option<&'a IpAddr>, bool) {
        if ip_list.is_empty() {
            return (None, false);
        }
        if !self.proxy.proxy_list.is_empty() && proxy_list_validated {
            return (ip_list.iter().rev().nth(self.proxy.proxy_list.len()), true);
        }

        if self.proxy.proxy_count > 0 && proxy_count_validated {
            return (
                ip_list.iter().rev().nth(self.proxy.proxy_count as usize),
                true,
            );
        }
        (ip_list.first(), false)
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv4_common {
    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn empty_header() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let headers = HeaderMap::new();
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn single_header() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_some();
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn multi_header() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        headers.insert("REMOTE_ADDR", "177.139.233.133".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_some();
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn multi_precedence_order() {
        let ipware = IpWare::new(
            IpWareConfig::new(
                vec![
                    HeaderName::from_static("http_x_forwarded_for"),
                    HeaderName::from_static("x_forwarded_for"),
                ],
                true,
            ),
            IpWareProxy::default(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "X_FORWARDED_FOR",
            "177.139.233.138, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        headers.insert("REMOTE_ADDR", "177.139.233.133".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_some();
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn multi_precedence_private_first() {
        let ipware = IpWare::new(
            IpWareConfig::new(
                vec![
                    HeaderName::from_static("http_x_forwarded_for"),
                    HeaderName::from_static("x_forwarded_for"),
                ],
                true,
            ),
            IpWareProxy::default(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "10.0.0.0, 10.0.0.1, 10.0.0.2".parse().unwrap(),
        );
        headers.insert(
            "X_FORWARDED_FOR",
            "177.139.233.138, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        headers.insert("REMOTE_ADDR", "177.139.233.133".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_some();
        assert_that!(ip_addr).contains_value("177.139.233.138".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn multi_precedence_invalid_first() {
        let ipware = IpWare::new(
            IpWareConfig::new(
                vec![
                    HeaderName::from_static("http_x_forwarded_for"),
                    HeaderName::from_static("x_forwarded_for"),
                ],
                true,
            ),
            IpWareProxy::default(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "unknown, 10.0.0.1, 10.0.0.2".parse().unwrap(),
        );
        headers.insert(
            "X_FORWARDED_FOR",
            "177.139.233.138, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        headers.insert("REMOTE_ADDR", "177.139.233.133".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_some();
        assert_that!(ip_addr).contains_value("177.139.233.138".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn error_only() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "unknown, 177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn error_first() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "unknown, 177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "X_FORWARDED_FOR",
            "177.139.233.138, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.139.233.138".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn singleton() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "177.139.233.139".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn singleton_private_fallback() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "10.0.0.0".parse().unwrap());
        headers.insert("HTTP_X_REAL_IP", "177.139.233.139".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn best_matched_ip() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("REMOTE_ADDR", "177.31.233.133".parse().unwrap());
        headers.insert("HTTP_X_REAL_IP", "192.168.1.1".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.31.233.133".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn best_matched_ip_public() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("REMOTE_ADDR", "177.31.233.133".parse().unwrap());
        headers.insert("HTTP_X_REAL_IP", "177.31.233.122".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.31.233.122".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn best_matched_ip_private() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("REMOTE_ADDR", "127.0.0.1".parse().unwrap());
        headers.insert("HTTP_X_REAL_IP", "192.168.1.1".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("192.168.1.1".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn best_matched_ip_private_loopback_precedence() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("REMOTE_ADDR", "192.168.1.1".parse().unwrap());
        headers.insert("HTTP_X_REAL_IP", "127.0.0.1".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("192.168.1.1".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn best_matched_ip_private_precedence() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("REMOTE_ADDR", "172.25.0.3".parse().unwrap());
        headers.insert("HTTP_X_FORWARDED_FOR", "172.25.0.1".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("172.25.0.1".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn hundred_low_range_public() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_REAL_IP", "100.63.0.9".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("100.63.0.9".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn hundred_block_private() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_REAL_IP", "100.76.0.9".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("100.76.0.9".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn hundred_high_range_public() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_REAL_IP", "100.128.0.9".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("100.128.0.9".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn proxy_order_right_most() {
        let ipware = IpWare::new(
            IpWareConfig::default().leftmost(false),
            IpWareProxy::default(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("198.84.193.158".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv4_proxy_count {
    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn singleton_proxy_count() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "177.139.233.139".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn singleton_proxy_count_private() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "10.0.0.0".parse().unwrap());
        headers.insert("X_REAL_IP", "177.139.233.139".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn proxy_count_relax() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("198.84.193.157".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn proxy_count_strict() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.138, 177.139.233.139, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn proxy_count_strict_exact() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.158".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn multi_proxy_count_strict_exact() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(2, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn multi_proxy_count_too_few_ips() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(2, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.158".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv4_proxy_list {
    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn proxy_list_strict_success() {
        let proxies = vec![
            "198.84.193.157".parse::<IpAddr>().unwrap(),
            "198.84.193.158".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));

        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn proxy_list_strict_failure() {
        let proxies = vec![
            "198.84.193.157".parse::<IpAddr>().unwrap(),
            "198.84.193.158".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));

        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn proxy_list_success() {
        let proxies = vec![
            "198.84.193.157".parse::<IpAddr>().unwrap(),
            "198.84.193.158".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));

        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }
}
#[cfg(all(test, feature = "http1"))]
mod tests_ipv4_proxy_count_proxy_list {
    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn proxy_list_relax() {
        let proxies = vec![
            "198.84.193.157".parse::<IpAddr>().unwrap(),
            "198.84.193.158".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(2, proxies));

        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn proxy_list_strict() {
        let proxies = vec![
            "198.84.193.157".parse::<IpAddr>().unwrap(),
            "198.84.193.158".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(2, proxies));

        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.138, 177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv4_port {

    use spectral::assert_that;
    use spectral::option::ContainingOptionAssertions;

    use super::*;

    #[test]
    fn ipv4_public_with_port() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());

        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139:80".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn ipv4_private_with_port() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());

        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "10.0.0.1:443, 10.0.0.1, 10.0.0.2".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("10.0.0.1".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn ipv4_loopback_with_port() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());

        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "127.0.0.1:80".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv6_common {

    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn single_header() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }

    #[test]
    fn multi_header() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        headers.insert("REMOTE_ADDR", "74dc:2bc".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }

    #[test]
    fn multi_precedence_order() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("X_FORWARDED_FOR", "74dc:2be, 74dc:2bf".parse().unwrap());
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        headers.insert("REMOTE_ADDR", "74dc:2bc".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }

    #[test]
    fn multi_precedence_private_first() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        headers.insert("HTTP_X_FORWARDED_FOR", "2001:db8:, ::1".parse().unwrap());
        headers.insert("REMOTE_ADDR", "74dc:2bc".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }

    #[test]
    fn multi_precedence_invalid_first() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "unknown, 2001:db8:, ::1".parse().unwrap(),
        );
        headers.insert("REMOTE_ADDR", "74dc:2bc".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }

    #[test]
    fn error_only() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "X_FORWARDED_FOR",
            "unknown, 3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn first_error_bailout() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "unknown, 3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn error_beast_match() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "unknown, 3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }

    #[test]
    fn singleton() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }

    #[test]
    fn singleton_private_fallback() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "::1".parse().unwrap());
        headers.insert(
            "HTTP_X_REAL_IP",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv6_proxy_count {

    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn singleton_proxy_count() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf".parse().unwrap(),
        );
        headers.insert("HTTP_X_REAL_IP", "2606:4700:4700::1111".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn singleton_proxy_count_private() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "::1".parse().unwrap());
        headers.insert(
            "HTTP_X_REAL_IP",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn proxy_count_strict_exact() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 74dc::02ba"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv6_proxy_list {

    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn proxy_trusted_proxy_strict() {
        let proxies = vec![
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(trusted_route);
    }

    #[test]
    fn proxy_trusted_proxy_not_strict() {
        let proxies = vec![
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(trusted_route);
    }

    #[test]
    fn proxy_trusted_proxy_not_strict_long() {
        let proxies = vec![
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "2001:4860:4860::7777,3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf"
                .parse::<IpAddr>()
                .unwrap(),
        );
        assert!(trusted_route);
    }

    #[test]
    fn proxy_trusted_proxy_error() {
        let proxies = vec![
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap(),
        ];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "3ffe:1900:4545:3:200:f8ff:fe21:67cf, 2606:4700:4700::1111, 74dc::2bb"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv6_encapsulation {

    use std::net::Ipv4Addr;

    use spectral::assert_that;
    use spectral::option::ContainingOptionAssertions;

    use super::*;

    #[test]
    fn ipv6_encapsulation_of_ipv4_private() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "::ffff:127.0.0.1".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr)
            .contains_value(IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped()));
        assert!(!trusted_route);
    }

    #[test]
    fn ipv6_encapsulation_of_ipv4_public() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "::ffff:177.139.233.139".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(IpAddr::V6(
            Ipv4Addr::new(177, 139, 233, 139).to_ipv6_mapped(),
        ));
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_ipv6_with_port {

    use std::net::{Ipv4Addr, Ipv6Addr};

    use spectral::assert_that;
    use spectral::option::ContainingOptionAssertions;

    use super::*;

    #[test]
    fn encapsulation_of_ipv4_public_with_port() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "[::ffff:177.139.233.139]:80".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(IpAddr::V6(
            Ipv4Addr::new(177, 139, 233, 139).to_ipv6_mapped(),
        ));
        assert!(!trusted_route);
    }

    #[test]
    fn ipv6_public_with_port() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "[3ffe:1900:4545:3:200:f8ff:fe21:67cf]:443, 2606:4700:4700::1111, 2001:4860:4860::8888"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(IpAddr::V6(Ipv6Addr::new(
            0x3ffe, 0x1900, 0x4545, 0x3, 0x200, 0xf8ff, 0xfe21, 0x67cf,
        )));
        assert!(!trusted_route);
    }

    #[test]
    fn ipv6_loopback_with_port() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "[::1]:80".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value(IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap()));
        assert!(!trusted_route);
    }
}

#[cfg(all(test, feature = "http02"))]
mod tests_http02 {
    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn single_header() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let mut headers = http02::HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.157, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_some();
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn precedence_from_header_names() {
        let ipware = IpWare::new(
            IpWareConfig::new(
                vec![
                    http02::HeaderName::from_static("x_forwarded_for"),
                    http02::HeaderName::from_static("http_x_forwarded_for"),
                ],
                true,
            ),
            IpWareProxy::new(1, vec!["198.84.193.158".parse::<IpAddr>().unwrap()]),
        );
        let mut headers = http02::HeaderMap::new();
        headers.insert(
            "HTTP_X_FORWARDED_FOR",
            "177.139.233.139, 198.84.193.158".parse().unwrap(),
        );
        headers.insert(
            "X-FORWARDED-FOR",
            "177.139.233.138, 198.84.193.158".parse().unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value("177.139.233.138".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_private_trusted_route {
    use spectral::assert_that;
    use spectral::option::ContainingOptionAssertions;

    use super::*;

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-FORWARDED-FOR", value.parse().unwrap());
        headers
    }

    #[test]
    fn private_client_behind_proxy_count() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, vec![]));
        let (ip_addr, trusted_route) = ipware.get_client_ip(&xff("10.1.2.3, 10.0.0.2"), true);
        assert_that!(ip_addr).contains_value("10.1.2.3".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn private_client_behind_proxy_list() {
        let proxies = vec!["10.0.0.2".parse::<IpAddr>().unwrap()];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));
        let (ip_addr, trusted_route) = ipware.get_client_ip(&xff("192.168.1.7, 10.0.0.2"), false);
        assert_that!(ip_addr).contains_value("192.168.1.7".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn loopback_client_behind_proxy_count() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, vec![]));
        let (ip_addr, trusted_route) = ipware.get_client_ip(&xff("127.0.0.1, 10.0.0.2"), false);
        assert_that!(ip_addr).contains_value("127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }

    #[test]
    fn private_client_without_proxy_config_is_untrusted() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&xff("10.1.2.3, 10.0.0.2"), false);
        assert_that!(ip_addr).contains_value("10.1.2.3".parse::<IpAddr>().unwrap());
        assert!(!trusted_route);
    }

    #[test]
    fn public_client_preferred_over_private() {
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, vec![]));
        let mut headers = xff("10.1.2.3, 10.0.0.2");
        headers.insert("X-REAL-IP", "93.184.216.34, 10.0.0.2".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).contains_value("93.184.216.34".parse::<IpAddr>().unwrap());
        assert!(trusted_route);
    }
}

#[cfg(all(test, feature = "http1"))]
mod tests_proxy_ranges_and_forwarded {
    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn proxy_list_accepts_cidr_ranges() {
        let proxy = IpWareProxy::parse(0, ["10.1.0.0/16", "198.84.193.158"]).unwrap();
        let ipware = IpWare::new(IpWareConfig::default(), proxy);
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-FORWARDED-FOR",
            "177.139.233.139, 10.1.42.7, 198.84.193.158"
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(trusted_route);

        // A proxy outside the range breaks the trusted route.
        headers.insert(
            "X-FORWARDED-FOR",
            "177.139.233.139, 10.2.0.1, 198.84.193.158".parse().unwrap(),
        );
        let (_, trusted_route) = ipware.get_client_ip(&headers, true);
        assert!(!trusted_route);
        assert!(IpWareProxy::parse(0, ["10.1.0.0/33"]).is_err());
    }

    #[test]
    fn empty_ip_list_is_not_a_trusted_route() {
        let proxy = IpWareProxy::new(0, vec!["198.84.193.158".parse::<IpAddr>().unwrap()]);
        assert!(!proxy.is_proxy_trusted_list_valid(&[], false));
        assert!(!IpWareProxy::new(1, vec![]).is_proxy_count_valid(&[], false));
    }

    #[test]
    fn reads_rfc7239_forwarded_header() {
        let ipware = IpWare::new(
            IpWareConfig::new(["forwarded"], true),
            IpWareProxy::new(1, vec![]),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=177.139.233.139;proto=https, for=\"[2001:db8::1]:443\""
                .parse()
                .unwrap(),
        );
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, true);
        assert_that!(ip_addr).contains_value("177.139.233.139".parse::<IpAddr>().unwrap());
        assert!(trusted_route);

        // An element without a parseable `for=` skips the header.
        headers.insert(
            "forwarded",
            "for=unknown, for=198.84.193.158".parse().unwrap(),
        );
        let (ip_addr, _) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
    }
}
