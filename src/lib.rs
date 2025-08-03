// This crate is entirely safe
#![forbid(unsafe_code)]
// Ensures that `pub` means published in the public API.
// This property is useful for reasoning about breaking API changes.
#![deny(unreachable_pub)]

//! This library aims to extract ip address of http request clients by using
//! different http-header values. Ported from [python-ipware](https://github.com/un33k/python-ipware)
//! developped by [@un33k](https://github.com/un33k)
//!
//! ## 📦 Cargo.toml
//!
//! ```toml
//! [dependencies]
//! ipware = "0.1"
//! ```
//!
//! ## 🔧 Example
//!
//! ```rust
//! use http::{HeaderMap, HeaderName};
//! use ipware::{IpWare, IpWareConfig, IpWareProxy};
//!
//! let ipware = IpWare::new(
//!     IpWareConfig::new(
//!         vec![
//!             HeaderName::from_static("http_x_forwarded_for"),
//!             HeaderName::from_static("x_forwarded_for"),
//!         ],
//!         true,
//!     ),
//!     IpWareProxy::default(),
//! );
//! let mut headers = HeaderMap::new();
//! headers.insert(
//!     "HTTP_X_FORWARDED_FOR",
//!     "177.139.233.139, 198.84.193.157, 198.84.193.158"
//!         .parse()
//!         .unwrap(),
//! );
//! headers.insert(
//!     "X_FORWARDED_FOR",
//!     "177.139.233.138, 198.84.193.157, 198.84.193.158"
//!         .parse()
//!         .unwrap(),
//! );
//! headers.insert("REMOTE_ADDR", "177.139.233.133".parse().unwrap());
//! let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
//! println!("{} {}", ip_addr.unwrap(), trusted_route);
//! ```
//!
//!
//! ## 🖨️ Output
//!
//! ```text
//! 177.139.233.139 false
//! ```
//!
//! ## ⚙️ Configuration
//!
//! |        Params   |  Description                                                                                                                                                                                                                                                                                                                                                     |
//! | --------------  | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
//! | `proxy_count`   |  Total number of expected proxies (pattern: `client, proxy1, ..., proxy2`)<br> if `proxy_count = 0` then `client`<br> if `proxy_count = 1` then `client, proxy1`<br> if `proxy_count = 2` then `client, proxy1, proxy2` <br> if `proxy_count = 3` then `client, proxy1, proxy2 proxy3`                                                                       |
//! |  `proxy_list`   |  List of trusted proxies (pattern: `client, proxy1, ..., proxy2`)<br> if `proxy_list = ['10.1.']` then `client, 10.1.1.1` OR `client, proxy1, 10.1.1.1`<br> if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1` OR `client, proxy1, 10.2.2.2`<br> if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1 10.2.2.2` OR `client, 10.1.1.1 10.2.2.2` |
//! |    `leftmost`   |  `leftmost = True` is default for de-facto standard.<br> `leftmost = False` for rare legacy networks that are configured with the `rightmost` pattern.<br> It converts `client, proxy1 proxy2` to `proxy2, proxy1, client`                                                                                                                                     |
//!
//! |          Output   |  Description                                                                                 |
//! | ----------------  | -------------------------------------------------------------------------------------------  |
//! |            `ip`   |  Client IP address object of type IPv4Addr or IPv6Addr                                       |
//! | `trusted_route`   |  If proxy `proxy_count` and/or `proxy_list` were provided and matched, `true`, else `false`  |
//!
//!
//! ### 🔢 Http Header Precedence Order
//!
//! The client IP address can be found in one or more request headers attributes. The lookup order is top to bottom and the default attributes are as follow.
//!
//! ```rust
//! pub use http::HeaderName;
//! let request_headers_precedence = vec![
//!     HeaderName::from_static("x_forwarded_for"), /* Load balancers or proxies such as AWS ELB (default client is `left-most` [`<client>, <proxy1>, <proxy2>`]), */
//!     HeaderName::from_static("http_x_forwarded_for"), // Similar to X_FORWARDED_TO
//!     HeaderName::from_static("http_client_ip"), /* Standard headers used by providers such as Amazon EC2, Heroku etc. */
//!     HeaderName::from_static("http_x_real_ip"), /* Standard headers used by providers such as Amazon EC2, Heroku etc. */
//!     HeaderName::from_static("http_x_forwarded"), // Squid and others
//!     HeaderName::from_static("http_x_cluster_client_ip"), /* Rackspace LB and Riverbed Stingray */
//!     HeaderName::from_static("http_forwarded_for"),       // RFC 7239
//!     HeaderName::from_static("http_forwarded"),           // RFC 7239
//!     HeaderName::from_static("http_via"),                 // Squid and others
//!     HeaderName::from_static("x-real-ip"),                // NGINX
//!     HeaderName::from_static("x-cluster-client-ip"), // Rackspace Cloud Load Balancers
//!     HeaderName::from_static("x_forwarded"),         // Squid
//!     HeaderName::from_static("forwarded_for"),       // RFC 7239
//!     HeaderName::from_static("cf-connecting-ip"),    // CloudFlare
//!     HeaderName::from_static("true-client-ip"),      // CloudFlare Enterprise,
//!     HeaderName::from_static("fastly-client-ip"),    // Firebase, Fastly
//!     HeaderName::from_static("forwarded"),           // RFC 7239
//!     HeaderName::from_static("client-ip"), /* Akamai and Cloudflare: True-Client-IP and Fastly: Fastly-Client-IP */
//!     HeaderName::from_static("remote_addr"), // Default
//! ];
//! ```
//!
//! You can customize the order by providing your own list using IpWareConfig.
//! ```rust
//! use ipware::IpWareConfig;
//! use http::HeaderName;
//! // specific header name
//! IpWareConfig::new(vec![HeaderName::from_static("http_x_forwarded_for")],true);
//!
//! // multiple header names
//! IpWareConfig::new(
//!                vec![
//!                    HeaderName::from_static("http_x_forwarded_for"),
//!                    HeaderName::from_static("x_forwarded_for"),
//!                ],
//!                true,
//!            );
//! ```
//!
//! ### 🤝 Trusted Proxies
//!
//! If your http server is behind one or more known proxy server(s), you can filter out unwanted requests
//! by providing a `trusted proxy list`, or a known proxy `count`.
//!
//! You can customize the proxy IP prefixes by providing your own list by using IpWareProxy.
//! You can pass your custom list on every call, when calling the proxy-aware api to fetch the ip.
//!
//! ```rust
//! // In the above scenario, use your load balancer IP address as a way to filter out unwanted requests.
//! use std::net::IpAddr;
//! use ipware::IpWare;
//! use ipware::IpWareConfig;
//! use ipware::IpWareProxy;
//! use http::HeaderMap;
//!
//! let headers = HeaderMap::new(); // replace this with your own headers
//! let proxies = vec![
//!             "198.84.193.157".parse::<IpAddr>().unwrap(),
//!             "198.84.193.158".parse::<IpAddr>().unwrap(),
//!         ];
//! let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));
//!
//! // usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
//! // The request went through our <proxy1> and <proxy2>, then our server
//! // We choose the <client> ip address to the left our <proxy1> and ignore other ips
//! let (ip, trusted_route) = ipware.get_client_ip(&headers, false);
//!
//! // usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
//! // The request went through our <proxy1> and <proxy2>, then our server
//! // Total ip address are total trusted proxies + client ip
//! // We don't allow far-end proxies, or fake addresses (exact or None)
//! let (ip, trusted_route) = ipware.get_client_ip(&headers, true);
//! ```
//!
//! ### Proxy Count
//!
//! If your http server is behind a `known` number of proxies, but you deploy on multiple providers and don't want to track proxy IPs, you still can filter out unwanted requests by providing proxy `count`.
//!
//! You can customize the proxy count by providing your `proxy_count` using IpWareProxy.
//! ```rust
//! use ipware::*;
//! use std::net::IpAddr;
//!
//! // In the above scenario, the total number of proxies can be used as a way to filter out unwanted requests.
//! // enforce proxy count
//!
//! let headers = HeaderMap::new(); // replace this with your own headers
//! let proxies = vec![];
//! let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
//!
//! // enforce proxy count and trusted proxies
//! let proxies = vec!["198.84.193.157".parse::<IpAddr>().unwrap()];
//! let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
//!
//! // usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
//! // total number of ip addresses are greater than the total count
//! let (ip, trusted_route) = ipware.get_client_ip(&headers, false);
//!
//! // usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
//! // total number of ip addresses are exactly equal to client ip + proxy_count
//! let (ip, trusted_route) = ipware.get_client_ip(&headers, true);
//! ```
//!
//! ### Support for IPv4, Ipv6, and IP:Port patterns and encapsulation
//! ```text
//! - Library looks for an IpAddr in header values. If this fails algorithm tries to parse a SocketAddr (This on contains ports in addition to IpAddr)
//! - get_client_ip call returns an IpAddr enum. User can match for V4 or V6 variants. If a V6 ip is retrieved user can utilize `to_ipv4_mapped` to
//!    retrieve wrapped V4 address if available.
//! ```
//!
//! ### Originating Request
//! ```test
//! Please note that the [de-facto](https:#developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) standard
//! for the originating client IP address is the `leftmost`as per`client, proxy1, proxy2`, and the `rightmost` proxy is the most
//! trusted proxy.
//! However, in rare cases your network has a `custom` configuration where the `rightmost` IP address is that of the originating client. If that is the case, then indicate it when creating:
//! ```
//!```rust
//! use ipware::*;
//! let ipware = IpWare::new(
//!     IpWareConfig::default().leftmost(false),
//!     IpWareProxy::default(),
//! );
//! ```

use std::net::{IpAddr, SocketAddr};
use std::string::ToString;

pub use http::header::*;
pub use http::HeaderName;

pub struct IpWareConfig {
    precedence: Vec<HeaderName>,
    leftmost: bool,
}

impl Default for IpWareConfig {
    fn default() -> Self {
        IpWareConfig {
            precedence: vec![
                HeaderName::from_static("x_forwarded_for"), /* Load balancers or proxies such as AWS ELB (default client is `left-most` [`<client>, <proxy1>, <proxy2>`]), */
                HeaderName::from_static("http_x_forwarded_for"), // Similar to X_FORWARDED_TO
                HeaderName::from_static("http_client_ip"), /* Standard headers used by providers such as Amazon EC2, Heroku etc. */
                HeaderName::from_static("http_x_real_ip"), /* Standard headers used by providers such as Amazon EC2, Heroku etc. */
                HeaderName::from_static("http_x_forwarded"), // Squid and others
                HeaderName::from_static("http_x_cluster_client_ip"), /* Rackspace LB and Riverbed Stingray */
                HeaderName::from_static("http_forwarded_for"),       // RFC 7239
                HeaderName::from_static("http_forwarded"),           // RFC 7239
                HeaderName::from_static("http_via"),                 // Squid and others
                HeaderName::from_static("x-real-ip"),                // NGINX
                HeaderName::from_static("x-cluster-client-ip"), // Rackspace Cloud Load Balancers
                HeaderName::from_static("x_forwarded"),         // Squid
                HeaderName::from_static("forwarded_for"),       // RFC 7239
                HeaderName::from_static("cf-connecting-ip"),    // CloudFlare
                HeaderName::from_static("true-client-ip"),      // CloudFlare Enterprise,
                HeaderName::from_static("fastly-client-ip"),    // Firebase, Fastly
                HeaderName::from_static("forwarded"),           // RFC 7239
                HeaderName::from_static("client-ip"), /* Akamai and Cloudflare: True-Client-IP and Fastly: Fastly-Client-IP */
                HeaderName::from_static("remote_addr"), // Default
            ],
            leftmost: true,
        }
    }
}

impl IpWareConfig {
    pub fn new<T>(precedence: T, leftmost: bool) -> Self
    where
        T: Into<Vec<HeaderName>>,
    {
        IpWareConfig { precedence: precedence.into(), leftmost }
    }

    pub fn leftmost(mut self, leftmost: bool) -> Self {
        self.leftmost = leftmost;
        self
    }
}

#[derive(Default)]
pub struct IpWareProxy<'a> {
    proxy_count: u16,
    proxy_list: &'a [IpAddr],
}

impl<'a> IpWareProxy<'a> {
    pub fn new(proxy_count: u16, proxy_list: &'a [IpAddr]) -> Self {
        IpWareProxy { proxy_count, proxy_list }
    }

    pub fn is_proxy_count_valid<'b, I: IntoIterator<Item = &'b IpAddr>>(
        &self,
        ip_list: I,
        strict: bool,
    ) -> bool {
        if self.proxy_count < 1 {
            true
        } else {
            let ip_count = ip_list.into_iter().collect::<Vec<_>>().len();

            if ip_count < 1 {
                false
            } else if strict {
                self.proxy_list.len() == ip_count - 1
            } else {
                ip_count - 1 > self.proxy_list.len()
            }
        }
    }

    pub fn is_proxy_trusted_list_valid<'b, I: IntoIterator<Item = &'b IpAddr>>(
        &self,
        ip_list: I,
        strict: bool,
    ) -> bool {
        if self.proxy_list.is_empty() {
            true
        } else {
            let ip_list = ip_list.into_iter().collect::<Vec<_>>();
            let ip_count = ip_list.len();
            let proxy_count = self.proxy_list.len();
            if (strict && ip_count - 1 != proxy_count) || (ip_count - 1 < proxy_count) {
                false
            } else {
                ip_list
                    .into_iter()
                    .rev()
                    .take(proxy_count)
                    .rev()
                    .zip(self.proxy_list.iter())
                    .all(|(ip_addr, proxy_addr)| *ip_addr == *proxy_addr)
            }
        }
    }
}

pub struct IpWare<'a> {
    config: IpWareConfig,
    proxy: IpWareProxy<'a>,
}

impl<'a> IpWare<'a> {
    pub fn new(config: IpWareConfig, proxy: IpWareProxy<'a>) -> Self {
        IpWare { config, proxy }
    }

    fn get_meta_value<'b>(
        &self,
        headers: &'b HeaderMap,
        name: &HeaderName,
    ) -> Option<&'b HeaderValue> {
        let value = headers.get(name);
        match value {
            Some(_) => value,
            None => headers.get(name.to_string().replace('_', "-")),
        }
    }

    fn get_meta_values<'b>(&self, headers: &'b HeaderMap) -> Vec<&'b HeaderValue> {
        self.config
            .precedence
            .iter()
            .filter_map(|header_name| self.get_meta_value(headers, header_name))
            .collect::<Vec<_>>()
    }

    pub fn get_client_ip(&self, headers: &HeaderMap, strict: bool) -> (Option<IpAddr>, bool) {
        let mut loopback_list = vec![];
        let mut private_list = vec![];
        let meta_values = self.get_meta_values(headers);
        dbg!(&self.proxy.proxy_list.len());
        for &meta_value in meta_values.iter() {
            let meta_ips = self.get_ips_from_string(meta_value.to_str().unwrap().to_owned());
            if meta_ips.is_empty() {
                continue;
            }
            let proxy_count_validated = self.proxy.is_proxy_count_valid(&meta_ips, strict);
            dbg!(&proxy_count_validated);
            if !proxy_count_validated {
                continue;
            }
            let proxy_list_validated = self.proxy.is_proxy_trusted_list_valid(&meta_ips, strict);
            dbg!(&proxy_list_validated);
            if !proxy_list_validated {
                continue;
            }
            dbg!(meta_ips.clone());
            let (client_ip, trusted_route) =
                self.get_best_ip(&meta_ips, proxy_count_validated, proxy_list_validated);
            if let Some(client_ip) = client_ip {
                if ip_rfc::global(client_ip) {
                    return (Some(*client_ip), trusted_route);
                }
                if client_ip.is_loopback() {
                    loopback_list.push(*client_ip);
                } else {
                    private_list.push(*client_ip);
                }
            }
        }

        if !private_list.is_empty() {
            return (private_list.first().cloned(), false);
        }

        if !loopback_list.is_empty() {
            return (loopback_list.first().cloned(), false);
        }

        (None, false)
    }

    /// Parses ip addresses from given list. Ip addresses assumed to be seperated with ,
    /// If any of the parts contains invalid string function returns empty vec.
    ///
    /// # Arguments
    /// * `ip_str` - String contains , seperated ip addresses
    fn get_ips_from_string(&self, ip_str: String) -> Vec<IpAddr> {
        let mut result = ip_str
            .split(',')
            .map(|single_ip| {
                let trimmed_ip = single_ip.trim_start().trim_end();
                let maybe_ipaddr = trimmed_ip.parse::<IpAddr>();
                match maybe_ipaddr {
                    Ok(_) => maybe_ipaddr.ok(),
                    Err(_) => trimmed_ip
                        .parse::<SocketAddr>()
                        .map(|socket_addr| socket_addr.ip())
                        .ok(),
                }
            })
            .collect::<Vec<_>>();
        if result.iter().any(|maybe_ipaddr| maybe_ipaddr.is_none()) {
            return vec![];
        } else if !self.config.leftmost {
            result.reverse();
        }
        result
            .iter()
            .map(|maybe_ipaddr| maybe_ipaddr.unwrap())
            .collect::<Vec<_>>()
    }

    fn get_best_ip<'b>(
        &self,
        ip_list: &'b [IpAddr],
        proxy_count_validated: bool,
        proxy_list_validated: bool,
    ) -> (Option<&'b IpAddr>, bool) {
        if ip_list.is_empty() {
            return (None, false);
        }
        dbg!(&self.proxy.proxy_list);
        if !self.proxy.proxy_list.is_empty() && proxy_list_validated {
            return (ip_list.iter().rev().nth(self.proxy.proxy_list.len()), true);
        }

        if self.proxy.proxy_count > 0 && proxy_count_validated {
            return (
                ip_list.iter().rev().nth(self.proxy.proxy_count as usize),
                true,
            );
        }
        return (ip_list.first(), false);
    }
}

#[cfg(test)]
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

#[cfg(test)]
mod tests_ipv4_proxy_count {
    use spectral::assert_that;
    use spectral::option::{ContainingOptionAssertions, OptionAssertions};

    use super::*;

    #[test]
    fn singleton_proxy_count() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
        let mut headers = HeaderMap::new();
        headers.insert("HTTP_X_FORWARDED_FOR", "177.139.233.139".parse().unwrap());
        let (ip_addr, trusted_route) = ipware.get_client_ip(&headers, false);
        assert_that!(ip_addr).is_none();
        assert!(!trusted_route);
    }

    #[test]
    fn singleton_proxy_count_private() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
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
}

#[cfg(test)]
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));

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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));

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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));

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
#[cfg(test)]
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(2, &proxies));

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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(2, &proxies));

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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
mod tests_ipv6_proxy_count {

    use spectral::assert_that;
    use spectral::option::OptionAssertions;

    use super::*;

    #[test]
    fn singleton_proxy_count() {
        let proxies = vec![];
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));
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
}

#[cfg(test)]
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));
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
        let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));
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

#[cfg(test)]
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

#[cfg(test)]
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
