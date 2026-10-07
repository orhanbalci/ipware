# ipware

[![Crates.io](https://img.shields.io/crates/v/ipware.svg)](https://crates.io/crates/ipware)
[![Documentation](https://docs.rs/ipware/badge.svg)](https://docs.rs/ipware)
[![License](https://img.shields.io/github/license/orhanbalci/ipware.svg)](https://github.com/orhanbalci/ipware/blob/main/LICENSE)

<!-- cargo-rdme start -->

Client IP extraction for Rust HTTP servers.

ipware finds the IP address of the client behind an HTTP request, using proxy
headers such as `X-Forwarded-For` and `Forwarded` together with the TCP peer
address. It works with any framework built on the `http` crate, version 1.x or 0.2.

It offers two APIs:

- [`ClientIpResolver`] (recommended): reads headers only when the request comes
  from one of your trusted proxies, and walks forwarding headers from the right,
  so clients cannot spoof their IP.
- [`IpWare`]: the header precedence lookup ported from
  [python-ipware](https://github.com/un33k/python-ipware), with optional proxy
  count and trusted proxy checks.

### 📦 Installation

```toml
[dependencies]
ipware = "0.4"
```

#### Features

ipware reads headers from the `HeaderMap` of the `http` crate. Enable the version
your framework uses; both can be enabled at the same time.

| Feature           | `http` version | Frameworks                                     |
| ----------------- | -------------- | ---------------------------------------------- |
| `http1` (default) | 1.x            | axum 0.7+, hyper 1, tonic 0.12+, reqwest 0.12+ |
| `http02`          | 0.2            | actix-web 4, hyper 0.14, warp 0.3              |
| `providers`       |                | platform presets and provider IP ranges        |

```toml
# actix-web 4
ipware = { version = "0.4", default-features = false, features = ["http02"] }
```

`http` 1.x types are re-exported at the crate root (`ipware::HeaderMap`), and each
enabled `http` crate is re-exported as `ipware::http` / `ipware::http02`.

### 🚀 Quick start

```rust
use std::net::IpAddr;

use ipware::{header, ClientIpResolver, ClientIpStrategy, HeaderMap, IpRanges, IpSource};

// Load balancers in 10.0.0.0/8 append the client address to X-Forwarded-For.
let resolver = ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_range(
    header::X_FORWARDED_FOR,
))
.trusted_proxies(IpRanges::parse(["10.0.0.0/8"]).unwrap());

let mut headers = HeaderMap::new();
headers.insert(
    "x-forwarded-for",
    "203.0.113.9, 93.184.216.34, 10.0.0.5".parse().unwrap(),
);

// The request arrived from the load balancer at 10.0.0.2.
let peer: IpAddr = "10.0.0.2".parse().unwrap();
let client = resolver.resolve(&headers, Some(peer)).unwrap();
assert_eq!(client.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
assert_eq!(client.source, IpSource::Header { trusted_route: true });

// The same headers sent straight to the server are ignored.
let direct: IpAddr = "198.51.100.1".parse().unwrap();
let client = resolver.resolve(&headers, Some(direct)).unwrap();
assert_eq!(client.ip, direct);
assert_eq!(client.source, IpSource::Peer);
```

The peer address comes from your server, for example axum's `ConnectInfo` or
actix-web's `HttpRequest::peer_addr`.

### 🛡️ Why trusted proxies matter

Each proxy appends the address it received a request from to `X-Forwarded-For`.
The rightmost entries were added by your own proxies; everything to their left
was sent by the client and can be anything. A client that reaches the server
directly can also send the whole header itself.

`ClientIpResolver` handles both:

1. Headers are read only when the TCP peer is a trusted proxy. Otherwise the peer
   address is the client IP.
2. The rightmost strategies skip your proxies from the right and stop at the
   first address they did not add.

### 🧭 Strategies

| Strategy | Use when |
| --- | --- |
| `rightmost_trusted_range(header)` | your proxies' address ranges are known |
| `rightmost_trusted_count(header, n)` | a fixed number of proxies sit in front of the server |
| `rightmost_non_private(header)` | proxies are on private networks, clients on the internet |
| `single_header(header)` | a CDN sets one header, such as `CF-Connecting-IP` |
| `ipware(ipware, strict)` | [`IpWare`]'s header lookup, gated on a trusted peer |
| `Peer` | there is no proxy |
| `chain(strategies)` | try several strategies in order |

```rust
use ipware::{header, ClientIpResolver, ClientIpStrategy, IpRanges};

// Behind Cloudflare: trust CF-Connecting-IP from Cloudflare's ranges
// (see https://www.cloudflare.com/ips/).
let cloudflare =
    ClientIpResolver::new(ClientIpStrategy::single_header(header::CF_CONNECTING_IP))
        .trusted_proxies(IpRanges::parse(["173.245.48.0/20", "103.21.244.0/22"])?);

// A CDN in front of a load balancer on a private network.
let two_proxies = ClientIpResolver::new(ClientIpStrategy::rightmost_trusted_count(
    header::X_FORWARDED_FOR,
    2,
))
.trust_private(true);

// Prefer RFC 7239 Forwarded, fall back to X-Forwarded-For.
let chain = ClientIpResolver::new(ClientIpStrategy::chain([
    ClientIpStrategy::rightmost_trusted_range(header::FORWARDED),
    ClientIpStrategy::rightmost_trusted_range(header::X_FORWARDED_FOR),
]))
.trust_private(true)
.max_forwarded_hops(10);
```

#### Resolver options

| Option | Effect |
| --- | --- |
| `trusted_proxies(ranges)` | addresses and CIDR ranges of your proxies |
| `trust_loopback(true)` | treat `127.0.0.0/8` and `::1` as trusted proxies |
| `trust_private(true)` | treat `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7` as trusted proxies |
| `trust_link_local(true)` | treat `169.254/16` and `fe80::/10` as trusted proxies |
| `max_forwarded_hops(n)` | read at most `n` entries from the right |
| `allow_untrusted(true)` | read headers from any peer; only safe when every request passes a proxy that overwrites them |

`resolve` returns a [`ResolvedIp`] with the address and its [`IpSource`]: a
header, with `trusted_route` set when the route was verified, or the peer.
IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) are returned as IPv4.

#### Header parsing

- `X-Forwarded-For`-style headers are comma-separated lists; [`header::FORWARDED`]
  is parsed as RFC 7239 `for=` parameters.
- Entries may carry ports, brackets, quotes and IPv6 zones: `192.0.2.1:80`,
  `"[2001:db8::1]:443"`, `fe80::1%eth0`.
- Multiple header lines are combined in order.
- The rightmost strategies stop at the first entry they cannot parse, such as
  `unknown`, since nothing to its left can be trusted.

### 🌐 Platform presets

With the `providers` feature, [`ClientIpResolver::platform`] builds a resolver
for a CDN or hosting platform from its client IP header and published proxy
ranges:

| Platform | Header | Trusted proxies |
| --- | --- | --- |
| `Cloudflare` | `CF-Connecting-IP` | Cloudflare edge ranges |
| `CloudFront` | `CloudFront-Viewer-Address` | CloudFront origin-facing ranges |
| `Fastly` | `X-Forwarded-For`, from the right | Fastly edge ranges |
| `GoogleCloudLoadBalancer` | `X-Forwarded-For`: `client, load-balancer` | `35.191.0.0/16`, `130.211.0.0/22` |
| `FlyIo` | `Fly-Client-IP` | private networks |

```toml
ipware = { version = "0.4", features = ["providers"] }
```

```rust
use ipware::providers::Platform;
use ipware::ClientIpResolver;

let resolver = ClientIpResolver::platform(Platform::Cloudflare);
```

`ipware::providers` also has the GitHub and Stripe webhook ranges for allow
lists, and parsers for each provider's published list. The built-in ranges are
snapshots from the date in `providers::SNAPSHOT_DATE`; providers change them
over time, so update the crate regularly or fetch fresh lists and read them with
`providers::parse`.

### 📋 IP ranges

[`IpRanges`] parses IP addresses and CIDR ranges, for trusted proxies or your own
allow and block lists.

```rust
use ipware::IpRanges;

let ranges = IpRanges::parse(["10.0.0.0/8", "2001:db8::/32", "192.0.2.1"]).unwrap();
assert!(ranges.contains("10.1.2.3".parse().unwrap()));
assert!(!ranges.contains("192.0.2.2".parse().unwrap()));
```

### 🔢 IpWare: header precedence lookup

[`IpWare`] checks a list of headers in order and returns the first public client
IP it finds, preferring public addresses over private and loopback ones.

```rust
use std::net::IpAddr;

use ipware::{HeaderMap, IpWare, IpWareConfig, IpWareProxy};

let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::default());

let mut headers = HeaderMap::new();
headers.insert(
    "x-forwarded-for",
    "177.139.233.139, 198.84.193.157, 198.84.193.158"
        .parse()
        .unwrap(),
);
let (ip, trusted_route) = ipware.get_client_ip(&headers, false);
assert_eq!(ip, Some("177.139.233.139".parse::<IpAddr>().unwrap()));
assert!(!trusted_route);
```

Without a proxy count or trusted proxy list, `IpWare` returns the leftmost
address, which the client controls. Configure one of them below, and gate the
lookup on the peer address with `ClientIpStrategy::ipware`.

#### Header precedence

Headers are checked from top to bottom. Each name is tried as written and with
`_` replaced by `-`.

```text
x_forwarded_for           Load balancers and proxies such as AWS ELB
http_x_forwarded_for
http_client_ip            Amazon EC2, Heroku
http_x_real_ip
http_x_forwarded          Squid
http_x_cluster_client_ip  Rackspace LB, Riverbed Stingray
http_forwarded_for
http_forwarded
http_via                  Squid
x-real-ip                 nginx
x-cluster-client-ip       Rackspace Cloud Load Balancers
x_forwarded               Squid
forwarded_for
cf-connecting-ip          Cloudflare
true-client-ip            Akamai, Cloudflare Enterprise
fastly-client-ip          Fastly, Firebase
forwarded
client-ip
remote_addr
```

Provide your own order with [`IpWareConfig::new`]:

```rust
use ipware::IpWareConfig;

let config = IpWareConfig::new(["cf-connecting-ip", "x-forwarded-for"], true);
```

#### Proxy count

With a known number of proxies, `proxy_count` is the number of proxy addresses
after the client in the header: `client, proxy1` is a count of 1.

```rust
use std::net::IpAddr;

use ipware::{HeaderMap, IpWare, IpWareConfig, IpWareProxy};

let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, vec![]));

let mut headers = HeaderMap::new();
headers.insert(
    "x-forwarded-for",
    "177.139.233.139, 198.84.193.158".parse().unwrap(),
);
let (ip, trusted_route) = ipware.get_client_ip(&headers, true);
assert_eq!(ip, Some("177.139.233.139".parse::<IpAddr>().unwrap()));
assert!(trusted_route);
```

#### Trusted proxy list

With known proxy addresses, `proxy_list` must match the rightmost entries of the
header exactly and in order.

```rust
use std::net::IpAddr;

use ipware::{HeaderMap, IpWare, IpWareConfig, IpWareProxy};

let proxies: Vec<IpAddr> = vec![
    "198.84.193.157".parse().unwrap(),
    "198.84.193.158".parse().unwrap(),
];
let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, proxies));

let mut headers = HeaderMap::new();
headers.insert(
    "x-forwarded-for",
    "6.6.6.6, 177.139.233.139, 198.84.193.157, 198.84.193.158"
        .parse()
        .unwrap(),
);
// Non-strict: extra entries on the left are ignored.
let (ip, trusted_route) = ipware.get_client_ip(&headers, false);
assert_eq!(ip, Some("177.139.233.139".parse::<IpAddr>().unwrap()));
assert!(trusted_route);

// Strict: the header must hold exactly the client and the proxies.
let (ip, _) = ipware.get_client_ip(&headers, true);
assert_eq!(ip, None);
```

`trusted_route` is `true` when a proxy count or proxy list was configured and
matched.

#### Rightmost client

Some legacy networks put the client on the right: `proxy2, proxy1, client`. Use
`leftmost(false)` for them.

```rust
use ipware::{IpWare, IpWareConfig, IpWareProxy};

let ipware = IpWare::new(
    IpWareConfig::default().leftmost(false),
    IpWareProxy::default(),
);
```

Header entries may be IPv4 or IPv6 addresses, with or without a port. A header
with an entry that does not parse is skipped.

### 🔌 Framework integrations

- [axum-ipware](https://github.com/orhanbalci/axum-ipware): IP filtering
  middleware and a `ClientIp` extractor for axum.
- [actix-ip-filter](https://github.com/jhen0409/actix-ip-filter): IP filtering
  middleware for actix-web.

### 🙏 Credits

`IpWare` is ported from [python-ipware](https://github.com/un33k/python-ipware)
by [@un33k](https://github.com/un33k).

[`ClientIpResolver`]: https://docs.rs/ipware/latest/ipware/struct.ClientIpResolver.html
[`IpWare`]: https://docs.rs/ipware/latest/ipware/struct.IpWare.html
[`ResolvedIp`]: https://docs.rs/ipware/latest/ipware/struct.ResolvedIp.html
[`IpSource`]: https://docs.rs/ipware/latest/ipware/enum.IpSource.html
[`IpRanges`]: https://docs.rs/ipware/latest/ipware/struct.IpRanges.html
[`IpWareConfig::new`]: https://docs.rs/ipware/latest/ipware/struct.IpWareConfig.html#method.new
[`header::FORWARDED`]: https://docs.rs/ipware/latest/ipware/header/constant.FORWARDED.html
[`ClientIpResolver::platform`]: https://docs.rs/ipware/latest/ipware/struct.ClientIpResolver.html#method.platform

<!-- cargo-rdme end -->


### 📝 License

Licensed under MIT License ([LICENSE](LICENSE)).

### 🚧 Contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the MIT license, shall be licensed as above, without any additional terms or conditions.

