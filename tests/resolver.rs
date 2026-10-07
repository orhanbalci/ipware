#![cfg(feature = "http1")]

use std::net::IpAddr;

use ipware::{
    header,
    ClientIpResolver,
    ClientIpStrategy,
    HeaderMap,
    IpRanges,
    IpSource,
    IpWare,
    IpWareConfig,
    IpWareProxy,
    ResolvedIp,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn xff(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", value.parse().unwrap());
    headers
}

fn behind_proxy(strategy: ClientIpStrategy) -> ClientIpResolver {
    ClientIpResolver::new(strategy).trusted_proxies(IpRanges::parse(["10.0.0.0/8"]).unwrap())
}

fn header_ip(s: &str) -> Option<ResolvedIp> {
    Some(ResolvedIp {
        ip: ip(s),
        source: IpSource::Header { trusted_route: true },
    })
}

fn peer_ip(s: &str) -> Option<ResolvedIp> {
    Some(ResolvedIp { ip: ip(s), source: IpSource::Peer })
}

#[test]
fn default_uses_peer() {
    let resolver = ClientIpResolver::default();
    let resolved = resolver.resolve(&xff("93.184.216.34"), Some(ip("10.0.0.2")));
    assert_eq!(resolved, peer_ip("10.0.0.2"));
    assert_eq!(resolver.resolve(&HeaderMap::new(), None), None);
}

#[test]
fn ignores_headers_from_untrusted_peer() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_non_private(
        header::X_FORWARDED_FOR,
    ));
    let resolved = resolver.resolve(&xff("93.184.216.34"), Some(ip("198.51.100.1")));
    assert_eq!(resolved, peer_ip("198.51.100.1"));
}

#[test]
fn rightmost_trusted_range_skips_proxies() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ));
    let headers = xff("6.6.6.6, 93.184.216.34, 10.0.0.9, 10.0.0.5");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("93.184.216.34")
    );
}

#[test]
fn rightmost_trusted_range_keeps_private_clients() {
    let resolver = ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ))
    .trusted_proxies(IpRanges::parse(["10.0.0.0/24"]).unwrap());
    let headers = xff("10.1.2.3, 10.0.0.5");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("10.1.2.3")
    );
}

#[test]
fn rightmost_stops_at_invalid_entry() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ));
    let headers = xff("93.184.216.34, garbage, 10.0.0.5");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        peer_ip("10.0.0.2")
    );
}

#[test]
fn rightmost_non_private() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_non_private(
        header::X_FORWARDED_FOR,
    ));
    let headers = xff("6.6.6.6, 93.184.216.34, 192.168.1.1");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("93.184.216.34")
    );
}

#[test]
fn rightmost_trusted_count() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_trusted_count(
        header::X_FORWARDED_FOR,
        2,
    ));
    let headers = xff("6.6.6.6, 93.184.216.34, 10.0.0.9");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("93.184.216.34")
    );
    // Fewer entries than proxies: fall back to the peer.
    let headers = xff("93.184.216.34");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        peer_ip("10.0.0.2")
    );
}

#[test]
fn single_header() {
    let resolver = behind_proxy(ClientIpStrategy::single_header(header::X_REAL_IP));
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "93.184.216.34".parse().unwrap());
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("93.184.216.34")
    );
}

#[test]
fn forwarded_header() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_trusted_range(header::FORWARDED));
    let mut headers = HeaderMap::new();
    headers.insert(
        "forwarded",
        "for=6.6.6.6, for=\"[2606:4700::1111]:443\";proto=https, for=10.0.0.5"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("2606:4700::1111")
    );
}

#[test]
fn chain_falls_through() {
    let resolver = behind_proxy(ClientIpStrategy::chain([
        ClientIpStrategy::single_header(header::CF_CONNECTING_IP),
        ClientIpStrategy::rightmost_trusted_range(header::X_FORWARDED_FOR),
    ]));
    let headers = xff("93.184.216.34, 10.0.0.5");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("93.184.216.34")
    );
}

#[test]
fn ipware_strategy_needs_trusted_peer_and_route() {
    let ipware = IpWare::new(
        IpWareConfig::new(["x-forwarded-for"], true),
        IpWareProxy::new(1, vec![]),
    );
    let resolver = behind_proxy(ClientIpStrategy::ipware(ipware, false));
    let headers = xff("93.184.216.34, 10.0.0.2");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("93.184.216.34")
    );
    // A direct client forging a route that ipware would accept.
    assert_eq!(
        resolver.resolve(&headers, Some(ip("198.51.100.1"))),
        peer_ip("198.51.100.1")
    );
    // Default ipware cannot verify the route.
    let resolver = behind_proxy(ClientIpStrategy::ipware(IpWare::default(), false));
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        peer_ip("10.0.0.2")
    );
}

#[test]
fn allow_untrusted_reads_headers_from_any_peer() {
    let resolver = ClientIpResolver::new(ClientIpStrategy::rightmost_non_private(
        header::X_FORWARDED_FOR,
    ))
    .allow_untrusted(true);
    let resolved = resolver.resolve(&xff("93.184.216.34"), Some(ip("198.51.100.1")));
    let untrusted = IpSource::Header { trusted_route: false };
    assert_eq!(
        resolved,
        Some(ResolvedIp { ip: ip("93.184.216.34"), source: untrusted })
    );
}

#[test]
fn trust_switches() {
    let strategy = ClientIpStrategy::rightmost_trusted_range(header::X_FORWARDED_FOR);
    let resolver = ClientIpResolver::new(strategy.clone()).trust_private(true);
    let headers = xff("93.184.216.34, 172.16.0.9");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("192.168.0.2"))),
        header_ip("93.184.216.34")
    );

    let resolver = ClientIpResolver::new(strategy.clone()).trust_loopback(true);
    let headers = xff("93.184.216.34");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("127.0.0.1"))),
        header_ip("93.184.216.34")
    );

    let resolver = ClientIpResolver::new(strategy).trust_link_local(true);
    assert_eq!(
        resolver.resolve(&headers, Some(ip("fe80::1"))),
        header_ip("93.184.216.34")
    );
}

#[test]
fn max_forwarded_hops_limits_walk() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ))
    .max_forwarded_hops(2);
    let headers = xff("93.184.216.34, 10.0.0.7, 10.0.0.6, 10.0.0.5");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        peer_ip("10.0.0.2")
    );
}

#[test]
fn ipv4_mapped_peer_is_canonical() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ));
    let headers = xff("93.184.216.34");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("::ffff:10.0.0.2"))),
        header_ip("93.184.216.34")
    );
    let resolved = ClientIpResolver::default().resolve(&headers, Some(ip("::ffff:192.0.2.1")));
    assert_eq!(resolved, peer_ip("192.0.2.1"));
}

#[cfg(feature = "http02")]
#[test]
fn works_with_http02_headers() {
    let resolver = behind_proxy(ClientIpStrategy::rightmost_trusted_range(
        header::X_FORWARDED_FOR,
    ));
    let mut headers = ipware::http02::HeaderMap::new();
    headers.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
    headers.append(
        "x-forwarded-for",
        "93.184.216.34, 10.0.0.5".parse().unwrap(),
    );
    assert_eq!(
        resolver.resolve(&headers, Some(ip("10.0.0.2"))),
        header_ip("93.184.216.34")
    );
}
