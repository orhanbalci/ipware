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

<!-- cargo-rdme end -->


## 📝 License

Licensed under MIT License ([LICENSE](LICENSE)).

### 🚧 Contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the MIT license, shall be licensed as above, without any additional terms or conditions.

