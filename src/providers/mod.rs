//! Published IP ranges of CDNs, cloud load balancers and webhook senders, and
//! ready-made resolvers for hosting platforms. Requires the `providers` feature.
//!
//! ```rust
//! use ipware::providers::Platform;
//! use ipware::ClientIpResolver;
//!
//! // CF-Connecting-IP, trusted only from Cloudflare's ranges.
//! let resolver = ClientIpResolver::platform(Platform::Cloudflare);
//! ```
//!
//! The ranges are snapshots taken on [`SNAPSHOT_DATE`] and drift as providers
//! change them. Update the crate regularly, or fetch the current lists and read
//! them with [`parse`]:
//!
//! ```rust,no_run
//! use ipware::providers::{parse, Platform};
//! use ipware::ClientIpResolver;
//!
//! # fn fetch(_url: &str) -> String { String::new() }
//! let body = fetch("https://api.cloudflare.com/client/v4/ips");
//! let resolver = ClientIpResolver::platform(Platform::Cloudflare)
//!     .trusted_proxies(parse::cloudflare(&body).unwrap());
//! ```

#[rustfmt::skip]
mod data;
pub mod parse;

pub use data::SNAPSHOT_DATE;

use crate::{header, ClientIpResolver, ClientIpStrategy, IpRanges};

/// A hosting platform or CDN with a known client IP header and proxy ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Platform {
    /// Cloudflare: `CF-Connecting-IP` from [`cloudflare`] ranges.
    Cloudflare,
    /// AWS CloudFront: `CloudFront-Viewer-Address` from [`cloudfront`] ranges.
    ///
    /// Add the header to the distribution's origin request policy.
    CloudFront,
    /// Fastly: `X-Forwarded-For` from the right, skipping [`fastly`] ranges.
    Fastly,
    /// Google Cloud global external Application Load Balancer: `X-Forwarded-For`
    /// ending in `client, load-balancer`, from [`google_cloud_load_balancers`].
    GoogleCloudLoadBalancer,
    /// Fly.io: `Fly-Client-IP` from Fly's proxy on the private network.
    ///
    /// Any machine on your private network can set the header, so only use this
    /// when nothing else reaches the app over it.
    FlyIo,
}

impl Platform {
    /// A resolver for this platform.
    pub fn resolver(self) -> ClientIpResolver {
        match self {
            Platform::Cloudflare => {
                ClientIpResolver::new(ClientIpStrategy::single_header(header::CF_CONNECTING_IP))
                    .trusted_proxies(cloudflare())
            }
            Platform::CloudFront => ClientIpResolver::new(
                ClientIpStrategy::single_header_with_port(header::CLOUDFRONT_VIEWER_ADDRESS),
            )
            .trusted_proxies(cloudfront()),
            Platform::Fastly => ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
                header::X_FORWARDED_FOR,
            ))
            .trusted_proxies(fastly()),
            Platform::GoogleCloudLoadBalancer => ClientIpResolver::new(
                ClientIpStrategy::rightmost_trusted_count(header::X_FORWARDED_FOR, 2),
            )
            .trusted_proxies(google_cloud_load_balancers()),
            Platform::FlyIo => {
                ClientIpResolver::new(ClientIpStrategy::single_header(header::FLY_CLIENT_IP))
                    .trust_private(true)
            }
        }
    }
}

impl ClientIpResolver {
    /// A resolver for a hosting platform or CDN. Requires the `providers` feature.
    ///
    /// Options such as [`max_forwarded_hops`](Self::max_forwarded_hops) can be added;
    /// [`trusted_proxies`](Self::trusted_proxies) replaces the built-in ranges.
    pub fn platform(platform: Platform) -> Self {
        platform.resolver()
    }
}

/// Cloudflare edge ranges, from <https://www.cloudflare.com/ips/>.
pub fn cloudflare() -> IpRanges {
    snapshot(data::CLOUDFLARE)
}

/// AWS CloudFront origin-facing ranges (`CLOUDFRONT_ORIGIN_FACING` in
/// <https://ip-ranges.amazonaws.com/ip-ranges.json>), the addresses CloudFront
/// connects to origins from.
pub fn cloudfront() -> IpRanges {
    snapshot(data::CLOUDFRONT_ORIGIN_FACING)
}

/// Fastly edge ranges, from <https://api.fastly.com/public-ip-list>.
pub fn fastly() -> IpRanges {
    snapshot(data::FASTLY)
}

/// Google Cloud load balancer proxy ranges (`35.191.0.0/16`, `130.211.0.0/22`),
/// documented for global external Application Load Balancers.
pub fn google_cloud_load_balancers() -> IpRanges {
    snapshot(data::GOOGLE_CLOUD_LOAD_BALANCERS)
}

/// GitHub webhook delivery ranges (`hooks` in <https://api.github.com/meta>),
/// for allow lists on webhook endpoints.
pub fn github_hooks() -> IpRanges {
    snapshot(data::GITHUB_HOOKS)
}

/// Stripe webhook delivery addresses, from
/// <https://stripe.com/files/ips/ips_webhooks.json>, for allow lists on webhook endpoints.
pub fn stripe_webhooks() -> IpRanges {
    snapshot(data::STRIPE_WEBHOOKS)
}

fn snapshot(ranges: &[&str]) -> IpRanges {
    IpRanges::parse(ranges).expect("snapshot ranges are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_parse_and_are_not_empty() {
        for (name, ranges) in [
            ("cloudflare", data::CLOUDFLARE),
            ("cloudfront", data::CLOUDFRONT_ORIGIN_FACING),
            ("fastly", data::FASTLY),
            ("google", data::GOOGLE_CLOUD_LOAD_BALANCERS),
            ("github", data::GITHUB_HOOKS),
            ("stripe", data::STRIPE_WEBHOOKS),
        ] {
            assert!(!ranges.is_empty(), "{name}");
            assert!(IpRanges::parse(ranges).is_ok(), "{name}");
        }
    }

    #[test]
    fn snapshot_date_is_iso() {
        let parts: Vec<&str> = SNAPSHOT_DATE.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts
            .iter()
            .all(|part| part.bytes().all(|b| b.is_ascii_digit())));
    }
}
