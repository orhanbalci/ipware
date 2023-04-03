# ipware

[![Crates.io](https://img.shields.io/crates/v/ipware.svg)](https://crates.io/crates/ipware)
[![Documentation](https://docs.rs/ipware/badge.svg)](https://docs.rs/ipware)
[![License](https://img.shields.io/github/license/orhanbalci/ipware.svg)](https://github.com/orhanbalci/ipware/blob/master/LICENSE)

<!-- cargo-rdme start -->


This library aims to extract ip address of http request clients by using
different http-header values. Ported from [python-ipware](https://github.com/un33k/python-ipware)
developped by [@un33k](https://github.com/un33k)

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

### Configuration

|        Params   |  Description                                                                                                                                                                                                                                                                                                                                                     |
| --------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `proxy_count`   | : Total number of expected proxies (pattern: `client, proxy1, ..., proxy2`)<br>: if `proxy_count = 0` then `client`<br>: if `proxy_count = 1` then `client, proxy1`<br>: if `proxy_count = 2` then `client, proxy1, proxy2` <br>: if `proxy_count = 3` then `client, proxy1, proxy2 proxy3`                                                                       |
|  `proxy_list`   | : List of trusted proxies (pattern: `client, proxy1, ..., proxy2`)<br>: if `proxy_list = ['10.1.']` then `client, 10.1.1.1` OR `client, proxy1, 10.1.1.1`<br>: if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1` OR `client, proxy1, 10.2.2.2`<br>: if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1 10.2.2.2` OR `client, 10.1.1.1 10.2.2.2` |
|    `leftmost`   | : `leftmost = True` is default for de-facto standard.<br>: `leftmost = False` for rare legacy networks that are configured with the `rightmost` pattern.<br>: It converts `client, proxy1 proxy2` to `proxy2, proxy1, client`                                                                                                                                     |

|          Output   |  Description                                                                                 |
| ----------------: | :------------------------------------------------------------------------------------------- |
|            `ip`   | : Client IP address object of type IPv4Addr or IPv6Addr                                      |
| `trusted_route`   | : If proxy `proxy_count` and/or `proxy_list` were provided and matched, `true`, else `false` |

<!-- cargo-rdme end -->


## 📝 License

Licensed under MIT License ([LICENSE](LICENSE)).

### 🚧 Contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the MIT license, shall be licensed as above, without any additional terms or conditions.

