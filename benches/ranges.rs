//! Compares `IpRanges::contains` with a linear scan over `ipnet` ranges.
//!
//! Run with `cargo bench --bench ranges`.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use ipware::IpRanges;

const LOOKUPS: usize = 200_000;

fn main() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    println!(
        "{:>8}  {:>12}  {:>14}  {:>14}  {:>8}",
        "ranges", "build", "linear/lookup", "ipware/lookup", "speedup"
    );
    for size in [10, 100, 1_000, 10_000, 100_000] {
        // Blocklist-like data: mostly /24../32 IPv4 ranges spread over the space.
        let entries: Vec<String> = (0..size)
            .map(|_| {
                let ip = Ipv4Addr::from(rng.next() as u32);
                format!("{ip}/{}", 24 + rng.next() % 9)
            })
            .collect();
        let ips: Vec<IpAddr> = (0..LOOKUPS)
            .map(|_| IpAddr::from(Ipv4Addr::from(rng.next() as u32)))
            .collect();

        let start = Instant::now();
        let ranges = IpRanges::parse(&entries).unwrap();
        let build = start.elapsed();
        let nets: Vec<IpNet> = entries.iter().map(|entry| entry.parse().unwrap()).collect();

        // Fewer lookups for the slow linear scan on big lists.
        let linear_lookups = (LOOKUPS * 1_000 / size).clamp(1_000, LOOKUPS);
        let linear = time_per_lookup(&ips[..linear_lookups], |ip| {
            nets.iter().any(|net| net.contains(&ip))
        });
        let ipware = time_per_lookup(&ips, |ip| ranges.contains(ip));

        println!(
            "{size:>8}  {:>10.2?}  {:>12.1}ns  {:>12.1}ns  {:>7.0}x",
            build,
            nanos(linear),
            nanos(ipware),
            nanos(linear) / nanos(ipware),
        );
    }
}

fn time_per_lookup(ips: &[IpAddr], contains: impl Fn(IpAddr) -> bool) -> Duration {
    let start = Instant::now();
    let mut hits = 0usize;
    for &ip in ips {
        hits += usize::from(contains(black_box(ip)));
    }
    black_box(hits);
    start.elapsed() / ips.len() as u32
}

fn nanos(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e9
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}
