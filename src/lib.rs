// This crate is entirely safe
#![forbid(unsafe_code)]
// Ensures that `pub` means published in the public API.
// This property is useful for reasoning about breaking API changes.
#![deny(unreachable_pub)]
// Enable is_global call
#![feature(ip)]

pub use http::header::*;
pub use http::HeaderName;
use std::net::IpAddr;
use std::string::ToString;

pub struct IpWareConfig {
    precedence: Vec<HeaderName>,
    leftmost: bool,
}

impl Default for IpWareConfig {
    fn default() -> Self {
        IpWareConfig {
            precedence: vec![
                HeaderName::from_static("x_forwarded_for"), // Load balancers or proxies such as AWS ELB (default client is `left-most` [`<client>, <proxy1>, <proxy2>`]),
                HeaderName::from_static("http_x_forwarded_for"), // Similar to X_FORWARDED_TO
                HeaderName::from_static("http_client_ip"), // Standard headers used by providers such as Amazon EC2, Heroku etc.
                HeaderName::from_static("http_x_real_ip"), // Standard headers used by providers such as Amazon EC2, Heroku etc.
                HeaderName::from_static("http_x_forwarded"), // Squid and others
                HeaderName::from_static("http_x_cluster_client_ip"), // Rackspace LB and Riverbed Stingray
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
                HeaderName::from_static("client-ip"), // Akamai and Cloudflare: True-Client-IP and Fastly: Fastly-Client-IP
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
        IpWareConfig {
            precedence: precedence.into(),
            leftmost,
        }
    }
}

#[derive(Default)]
pub struct IpWareProxy {
    proxy_count: u16,
    proxy_list: Vec<IpAddr>,
}

impl IpWareProxy {
    pub fn new<T>(proxy_count: u16, proxy_list: T) -> Self
    where
        T: Into<Vec<IpAddr>>,
    {
        IpWareProxy {
            proxy_count,
            proxy_list: proxy_list.into(),
        }
    }

    pub fn is_proxy_count_valid<'a, I: IntoIterator<Item = &'a IpAddr>>(
        &self,
        ip_list: I,
        strict: bool,
    ) -> bool {
        if self.proxy_list.is_empty() {
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

    pub fn is_proxy_trusted_list_valid<'a, I: IntoIterator<Item = &'a IpAddr>>(
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
            if strict && ip_count - 1 != proxy_count {
                false
            } else if ip_count - 1 < proxy_count {
                false
            } else {
                ip_list
                    .into_iter()
                    .rev()
                    .take(proxy_count)
                    .zip(self.proxy_list.iter())
                    .all(|(ip_addr, proxy_addr)| *ip_addr == *proxy_addr)
            }
        }
    }
}

pub struct IpWare {
    config: IpWareConfig,
    proxy: IpWareProxy,
}

impl IpWare {
    pub fn new(config: IpWareConfig, proxy: IpWareProxy) -> Self {
        IpWare { config, proxy }
    }

    fn get_meta_value<'a>(
        &self,
        headers: &'a HeaderMap,
        name: &HeaderName,
    ) -> Option<&'a HeaderValue> {
        let value = headers.get(name);
        match value {
            Some(_) => value,
            None => headers.get(name.to_string().replace('_', "-")),
        }
    }

    fn get_meta_values<'a>(&self, headers: &'a HeaderMap) -> Vec<&'a HeaderValue> {
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
        // dbg!(meta_values.clone());
        for &meta_value in meta_values.iter() {
            let meta_ips = self.get_ips_from_string(meta_value.to_str().unwrap().to_owned());
            // dbg!(meta_ips.clone());
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
                if client_ip.is_global() {
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
    /// # Arguments
    /// * `ip_str` - String contains , seperated ip addresses
    fn get_ips_from_string(&self, ip_str: String) -> Vec<IpAddr> {
        let mut result = ip_str
            .split(',')
            .map(|single_ip| single_ip.trim_start().trim_end().parse().ok())
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
            return (
                ip_list.iter().rev().nth(self.proxy.proxy_list.len() + 1),
                true,
            );
        }

        if self.proxy.proxy_count > 0 && proxy_count_validated {
            return (
                ip_list
                    .iter()
                    .rev()
                    .nth(self.proxy.proxy_count as usize + 1),
                true,
            );
        }
        return (ip_list.first(), false);
    }
}

#[cfg(test)]
mod tests_ipv4 {
    use super::*;
    use spectral::assert_that;
    use spectral::option::ContainingOptionAssertions;
    use spectral::option::OptionAssertions;

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
}
