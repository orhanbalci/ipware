#![cfg(all(feature = "providers", feature = "http1"))]

use std::net::IpAddr;

use ipware::providers::{self, Platform};
use ipware::{ClientIpResolver, HeaderMap, IpSource, ResolvedIp};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn header(name: &'static str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(name, value.parse().unwrap());
    headers
}

fn from_header(s: &str) -> Option<ResolvedIp> {
    Some(ResolvedIp {
        ip: ip(s),
        source: IpSource::Header { trusted_route: true },
    })
}

fn from_peer(s: &str) -> Option<ResolvedIp> {
    Some(ResolvedIp { ip: ip(s), source: IpSource::Peer })
}

#[test]
fn cloudflare() {
    let resolver = ClientIpResolver::platform(Platform::Cloudflare);
    let headers = header("cf-connecting-ip", "93.184.216.34");
    // 173.245.48.0/20 is a Cloudflare range.
    assert_eq!(
        resolver.resolve(&headers, Some(ip("173.245.48.10"))),
        from_header("93.184.216.34")
    );
    assert_eq!(
        resolver.resolve(&headers, Some(ip("198.51.100.1"))),
        from_peer("198.51.100.1")
    );
}

#[test]
fn cloudfront_strips_port() {
    let resolver = ClientIpResolver::platform(Platform::CloudFront);
    let edge = providers::cloudfront();
    let peer = [
        "13.32.0.1",
        "13.224.0.1",
        "52.84.0.1",
        "54.230.0.1",
        "130.176.0.1",
    ]
    .into_iter()
    .map(ip)
    .find(|candidate| edge.contains(*candidate))
    .expect("a known CloudFront origin-facing address");
    let headers = header("cloudfront-viewer-address", "2001:db8::1:46532");
    assert_eq!(
        resolver.resolve(&headers, Some(peer)),
        from_header("2001:db8::1")
    );
    let headers = header("cloudfront-viewer-address", "198.51.100.10:46532");
    assert_eq!(
        resolver.resolve(&headers, Some(peer)),
        from_header("198.51.100.10")
    );
}

#[test]
fn fastly() {
    let resolver = ClientIpResolver::platform(Platform::Fastly);
    // 151.101.0.0/16 is a Fastly range.
    let headers = header("x-forwarded-for", "6.6.6.6, 93.184.216.34, 151.101.1.1");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("151.101.2.2"))),
        from_header("93.184.216.34")
    );
}

#[test]
fn google_cloud_load_balancer() {
    let resolver = ClientIpResolver::platform(Platform::GoogleCloudLoadBalancer);
    let headers = header("x-forwarded-for", "6.6.6.6, 93.184.216.34, 34.120.0.10");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("35.191.0.5"))),
        from_header("93.184.216.34")
    );
    assert_eq!(
        resolver.resolve(&headers, Some(ip("34.120.0.10"))),
        from_peer("34.120.0.10")
    );
}

#[test]
fn fly_io() {
    let resolver = ClientIpResolver::platform(Platform::FlyIo);
    let headers = header("fly-client-ip", "93.184.216.34");
    assert_eq!(
        resolver.resolve(&headers, Some(ip("172.16.5.2"))),
        from_header("93.184.216.34")
    );
    assert_eq!(
        resolver.resolve(&headers, Some(ip("fdaa:0:1::3"))),
        from_header("93.184.216.34")
    );
    assert_eq!(
        resolver.resolve(&headers, Some(ip("198.51.100.1"))),
        from_peer("198.51.100.1")
    );
}

#[test]
fn webhook_ranges() {
    // 140.82.112.0/20 is a GitHub hooks range.
    assert!(providers::github_hooks().contains(ip("140.82.112.1")));
    assert!(!providers::github_hooks().contains(ip("93.184.216.34")));
    assert!(!providers::stripe_webhooks().is_empty());
}
