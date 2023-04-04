# ipware

[![Crates.io](https://img.shields.io/crates/v/ipware.svg)](https://crates.io/crates/ipware)
[![Documentation](https://docs.rs/ipware/badge.svg)](https://docs.rs/ipware)
[![License](https://img.shields.io/github/license/orhanbalci/ipware.svg)](https://github.com/orhanbalci/ipware/blob/master/LICENSE)

<!-- cargo-rdme start -->


This library aims to extract ip address of http request clients by using
different http-header values. Ported from [python-ipware](https://github.com/un33k/python-ipware)
developped by [@un33k](https://github.com/un33k)

### ⚠️ Warning
This library uses unstable rust API.
```rust ignore
![feature(ip)]
````

### 📦 Cargo.toml

```toml
[dependencies]
ipware = "0.1"
```

### 🔧 Example

```rust
use http::{HeaderMap, HeaderName};
use ipware::{IpWare, IpWareConfig, IpWareProxy};

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
println!("{} {}", ip_addr.unwrap(), trusted_route);
```


### 🖨️ Output

```text
177.139.233.139 false
```

### ⚙️ Configuration

|        Params   |  Description                                                                                                                                                                                                                                                                                                                                                     |
| --------------  | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `proxy_count`   |  Total number of expected proxies (pattern: `client, proxy1, ..., proxy2`)<br> if `proxy_count = 0` then `client`<br> if `proxy_count = 1` then `client, proxy1`<br> if `proxy_count = 2` then `client, proxy1, proxy2` <br> if `proxy_count = 3` then `client, proxy1, proxy2 proxy3`                                                                       |
|  `proxy_list`   |  List of trusted proxies (pattern: `client, proxy1, ..., proxy2`)<br> if `proxy_list = ['10.1.']` then `client, 10.1.1.1` OR `client, proxy1, 10.1.1.1`<br> if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1` OR `client, proxy1, 10.2.2.2`<br> if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1 10.2.2.2` OR `client, 10.1.1.1 10.2.2.2` |
|    `leftmost`   |  `leftmost = True` is default for de-facto standard.<br> `leftmost = False` for rare legacy networks that are configured with the `rightmost` pattern.<br> It converts `client, proxy1 proxy2` to `proxy2, proxy1, client`                                                                                                                                     |

|          Output   |  Description                                                                                 |
| ----------------  | -------------------------------------------------------------------------------------------  |
|            `ip`   |  Client IP address object of type IPv4Addr or IPv6Addr                                       |
| `trusted_route`   |  If proxy `proxy_count` and/or `proxy_list` were provided and matched, `true`, else `false`  |


#### 🔢 Http Header Precedence Order

The client IP address can be found in one or more request headers attributes. The lookup order is top to bottom and the default attributes are as follow.

```rust
pub use http::HeaderName;
let request_headers_precedence = vec![
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
];
```

You can customize the order by providing your own list using IpWareConfig.
```rust no_run
use ipware::IpWareConfig;
use http::HeaderName;
// specific header name
IpWareConfig::new(vec![HeaderName::from_static("http_x_forwarded_for")],true);

// multiple header names
IpWareConfig::new(
               vec![
                   HeaderName::from_static("http_x_forwarded_for"),
                   HeaderName::from_static("x_forwarded_for"),
               ],
               true,
           );
```

#### 🤝 Trusted Proxies

If your http server is behind one or more known proxy server(s), you can filter out unwanted requests
by providing a `trusted proxy list`, or a known proxy `count`.

You can customize the proxy IP prefixes by providing your own list by using IpWareProxy.
You can pass your custom list on every call, when calling the proxy-aware api to fetch the ip.

```rust no_run
// In the above scenario, use your load balancer IP address as a way to filter out unwanted requests.
use std::net::IpAddr;
use ipware::IpWare;
use ipware::IpWareConfig;
use ipware::IpWareProxy;
use http::HeaderMap;

let headers = HeaderMap::new(); // replace this with your own headers
let proxies = vec![
            "198.84.193.157".parse::<IpAddr>().unwrap(),
            "198.84.193.158".parse::<IpAddr>().unwrap(),
        ];
let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(0, &proxies));

// usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
// The request went through our <proxy1> and <proxy2>, then our server
// We choose the <client> ip address to the left our <proxy1> and ignore other ips
let (ip, trusted_route) = ipware.get_client_ip(&headers, false);

// usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
// The request went through our <proxy1> and <proxy2>, then our server
// Total ip address are total trusted proxies + client ip
// We don't allow far-end proxies, or fake addresses (exact or None)
let (ip, trusted_route) = ipware.get_client_ip(&headers, true);
```

#### Proxy Count

If your http server is behind a `known` number of proxies, but you deploy on multiple providers and don't want to track proxy IPs, you still can filter out unwanted requests by providing proxy `count`.

You can customize the proxy count by providing your `proxy_count` using IpWareProxy.
```rust no_run
use ipware::*;
use std::net::IpAddr;

// In the above scenario, the total number of proxies can be used as a way to filter out unwanted requests.
// enforce proxy count

let headers = HeaderMap::new(); // replace this with your own headers
let proxies = vec![];
let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));

// enforce proxy count and trusted proxies
let proxies = vec!["198.84.193.157".parse::<IpAddr>().unwrap()];
let ipware = IpWare::new(IpWareConfig::default(), IpWareProxy::new(1, &proxies));

// usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
// total number of ip addresses are greater than the total count
let (ip, trusted_route) = ipware.get_client_ip(&headers, false);

// usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
// total number of ip addresses are exactly equal to client ip + proxy_count
let (ip, trusted_route) = ipware.get_client_ip(&headers, true);
```

#### Support for IPv4, Ipv6, and IP:Port patterns and encapsulation
```text
- Library looks for an IpAddr in header values. If this fails algorithm tries to parse a SocketAddr (This on contains ports in addition to IpAddr)
- get_client_ip call returns an IpAddr enum. User can match for V4 or V6 variants. If a V6 ip is retrieved user can utilize `to_ipv4_mapped` to
   retrieve wrapped V4 address if available.
```

#### Originating Request
```test
Please note that the [de-facto](https:#developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) standard
for the originating client IP address is the `leftmost`as per`client, proxy1, proxy2`, and the `rightmost` proxy is the most
trusted proxy.
However, in rare cases your network has a `custom` configuration where the `rightmost` IP address is that of the originating client. If that is the case, then indicate it when creating:
```
```rust no_run
use ipware::*;
let ipware = IpWare::new(
    IpWareConfig::default().leftmost(false),
    IpWareProxy::default(),
);
```

<!-- cargo-rdme end -->


### 📝 License

Licensed under MIT License ([LICENSE](LICENSE)).

### 🚧 Contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the MIT license, shall be licensed as above, without any additional terms or conditions.

