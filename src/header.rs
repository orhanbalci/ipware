//! Names of headers proxies and CDNs use to pass the client IP.
//!
//! Use them with [`ClientIpStrategy`](crate::ClientIpStrategy).

/// RFC 7239 `Forwarded`.
pub const FORWARDED: &str = "forwarded";
/// `X-Forwarded-For`, a list appended to by each proxy.
pub const X_FORWARDED_FOR: &str = "x-forwarded-for";
/// `X-Real-IP`, set by nginx.
pub const X_REAL_IP: &str = "x-real-ip";
/// `CF-Connecting-IP`, set by Cloudflare.
pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";
/// `True-Client-IP`, set by Akamai and Cloudflare Enterprise.
pub const TRUE_CLIENT_IP: &str = "true-client-ip";
/// `Fly-Client-IP`, set by Fly.io.
pub const FLY_CLIENT_IP: &str = "fly-client-ip";
/// `Fastly-Client-IP`, set by Fastly.
pub const FASTLY_CLIENT_IP: &str = "fastly-client-ip";
/// `X-Envoy-External-Address`, set by Envoy and Istio.
pub const X_ENVOY_EXTERNAL_ADDRESS: &str = "x-envoy-external-address";
