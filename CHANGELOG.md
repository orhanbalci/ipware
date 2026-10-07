# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-10-07

### Added

- `IpRanges::ipv4_address_count` and `ipv6_address_count`.
- `IpWareProxy::parse` for trusted proxy lists with CIDR ranges, and
  `From<IpAddr>` for `IpRanges`.
- `IpWare` reads RFC 7239 `Forwarded` headers (`forwarded`, `http_forwarded`) by
  their `for=` parameters instead of skipping them.
- `ClientIpResolver::forwarded_origin` returns the scheme and host the client
  requested, from `Forwarded` or `X-Forwarded-Proto` / `X-Forwarded-Host`, only
  for trusted proxies and only when the values are valid.

### Fixed

- `IpWareProxy::is_proxy_trusted_list_valid` no longer panics on an empty list.

## [0.5.0] - 2026-10-07

### Added

- `ClientIpResolver`: resolves the client IP from headers and the TCP peer
  address, reading headers only when the peer is a trusted proxy.
- `ClientIpStrategy`: `Peer`, `Ipware`, `SingleHeader`, `RightmostNonPrivate`,
  `RightmostTrustedCount`, `RightmostTrustedRange`, and `Chain`.
- RFC 7239 `Forwarded` header parsing; forwarding header entries with ports,
  brackets, quotes and IPv6 zones; multiple header lines are combined.
- Trust switches for loopback, private, and link-local proxies, and
  `max_forwarded_hops` to limit how far the rightmost strategies walk.
- `IpRanges` and `IpRangeError` for parsing and matching IP addresses and CIDR
  ranges. Ranges are stored as sorted, merged intervals and looked up by binary
  search: about 20 ns per lookup with 100,000 ranges, where a linear scan takes
  hundreds of microseconds (`cargo bench --bench ranges`).
- `header` module with common client IP header names.
- `ClientIpStrategy::SingleHeaderWithPort` for headers that always carry
  `ip:port`, such as `CloudFront-Viewer-Address`, including unbracketed IPv6.
- `providers` feature (off by default): `ClientIpResolver::platform` presets for
  Cloudflare, CloudFront, Fastly, Google Cloud load balancers and Fly.io;
  snapshots of provider ranges plus GitHub and Stripe webhook ranges; and
  `providers::parse` to read each provider's published list at runtime.

### Documentation

- Rewrote the README and crate docs: quick start with `ClientIpResolver`, why
  trusted proxies matter, strategy and option reference, and a corrected `IpWare`
  section (exact, ordered proxy list matching; strict mode; spoofing warning).
  Every example is now a tested doc example, including with only the `http02`
  or `providers` feature enabled.

### Changed

- Declare the minimum supported Rust version: 1.75 (`rust-version`).
- New package description, keywords and categories; `layout.kdl` and
  `rustfmt.toml` are no longer included in the published crate.

### Fixed

- Proxy count validation compared the header's IP count against the length of
  the trusted proxy list instead of `proxy_count`. In strict mode, headers with
  exactly `proxy_count` proxies were rejected; they now resolve with a trusted route.
- Private and loopback client IPs always returned `trusted_route = false`, even
  when the proxy count or trusted proxy list matched. They now report the
  validated route, as documented. Public IPs are still preferred over private ones.

## [0.4.0] - 2026-10-07

### Added

- `http1` feature (default): read headers from `http` 1.x `HeaderMap`
  (axum 0.7+, hyper 1, tonic 0.12+, reqwest 0.12+).
- `http02` feature: read headers from `http` 0.2 `HeaderMap`
  (actix-web 4, hyper 0.14, warp 0.3). Both features can be enabled together.
- Enabled `http` crates are re-exported as `ipware::http` and `ipware::http02`.
- `IpWareConfig::new` accepts plain strings as header names in addition to
  `HeaderName`s of either `http` version.

### Changed

- **Breaking:** `ipware::{HeaderMap, HeaderName, HeaderValue}` now re-export
  `http` 1.x types and are only available with the `http1` feature.
  `http` 0.2 users should enable `http02` and use `ipware::http02::*`.
- **Breaking:** `IpWareConfig::new` now takes `IntoIterator<Item = impl AsRef<str>>`
  instead of `Into<Vec<HeaderName>>`. Existing `Vec<HeaderName>` arguments still compile.
- **Breaking:** `IpWare::get_client_ip` is generic over the sealed `Headers`
  trait, implemented for the `HeaderMap` of each enabled `http` version.

### Migrating from 0.3

For `http` 0.2 based frameworks such as actix-web 4:

```toml
ipware = { version = "0.4", default-features = false, features = ["http02"] }
```

```rust
use ipware::http02::{HeaderMap, HeaderName};
```

For `http` 1.x based frameworks no code changes are needed.

## [0.3.0] - 2025-08-04

### Changed

- Removed the lifetime parameter from `IpWareProxy`.
- Derived additional traits on public types.
- Applied clippy suggestions and updated docs.

### Fixed

- Avoid an unwrap panic and skip header values that are not valid UTF-8.

## [0.2.0] - 2025-08-03

### Changed

- Builds on stable Rust by using the `ip_rfc` crate instead of the nightly `ip` feature.

## [0.1.0] - 2023-04-03

- Initial release, ported from [python-ipware](https://github.com/un33k/python-ipware).

[Unreleased]: https://github.com/orhanbalci/ipware/compare/v0.5.1...main
[0.5.1]: https://github.com/orhanbalci/ipware/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/orhanbalci/ipware/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/orhanbalci/ipware/compare/bc46f50...v0.4.0
[0.3.0]: https://github.com/orhanbalci/ipware/compare/3e280fa...bc46f50
[0.2.0]: https://github.com/orhanbalci/ipware/compare/3edb891...3e280fa
[0.1.0]: https://github.com/orhanbalci/ipware/tree/3edb891
