//! Repository tasks. Run with `cargo xtask <task>`.
//!
//! - `update-ranges`: fetch provider IP ranges and regenerate
//!   `src/providers/data.rs`.

use std::error::Error;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ipware::providers::parse;
use ipware::IpRanges;
use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Documented by Google rather than published as a list.
const GOOGLE_CLOUD_LOAD_BALANCERS: &[&str] = &["35.191.0.0/16", "130.211.0.0/22"];

struct Source {
    /// Constant name in the generated file.
    name: &'static str,
    url: &'static str,
    /// Extracts the range strings from the response body.
    extract: fn(&str) -> Result<Vec<String>>,
    /// The runtime parser for the same body, checked against `extract`.
    parse: fn(&str) -> std::result::Result<IpRanges, parse::ParseError>,
}

const SOURCES: &[Source] = &[
    Source {
        name: "CLOUDFLARE",
        url: "https://api.cloudflare.com/client/v4/ips",
        extract: |body| {
            let value: Value = serde_json::from_str(body)?;
            let mut ranges = strings(&value["result"]["ipv4_cidrs"])?;
            ranges.extend(strings(&value["result"]["ipv6_cidrs"])?);
            Ok(ranges)
        },
        parse: parse::cloudflare,
    },
    Source {
        name: "CLOUDFRONT_ORIGIN_FACING",
        url: "https://ip-ranges.amazonaws.com/ip-ranges.json",
        extract: |body| {
            let value: Value = serde_json::from_str(body)?;
            let mut ranges = Vec::new();
            for (list, key) in [("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")] {
                for prefix in value[list].as_array().ok_or("missing prefixes")? {
                    if prefix["service"] == "CLOUDFRONT_ORIGIN_FACING" {
                        ranges.push(prefix[key].as_str().ok_or("bad prefix")?.to_owned());
                    }
                }
            }
            Ok(ranges)
        },
        parse: |body| parse::aws(body, "CLOUDFRONT_ORIGIN_FACING"),
    },
    Source {
        name: "FASTLY",
        url: "https://api.fastly.com/public-ip-list",
        extract: |body| {
            let value: Value = serde_json::from_str(body)?;
            let mut ranges = strings(&value["addresses"])?;
            ranges.extend(strings(&value["ipv6_addresses"])?);
            Ok(ranges)
        },
        parse: parse::fastly,
    },
    Source {
        name: "GITHUB_HOOKS",
        url: "https://api.github.com/meta",
        extract: |body| {
            let value: Value = serde_json::from_str(body)?;
            strings(&value["hooks"])
        },
        parse: |body| parse::github_meta(body, "hooks"),
    },
    Source {
        name: "STRIPE_WEBHOOKS",
        url: "https://stripe.com/files/ips/ips_webhooks.json",
        extract: |body| {
            let value: Value = serde_json::from_str(body)?;
            strings(&value["WEBHOOKS"])
        },
        parse: |body| parse::stripe(body, "WEBHOOKS"),
    },
];

fn main() -> ExitCode {
    let result = match std::env::args().nth(1).as_deref() {
        Some("update-ranges") => update_ranges(),
        _ => {
            eprintln!("usage: cargo xtask update-ranges");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn update_ranges() -> Result<()> {
    let mut lists = Vec::new();
    for source in SOURCES {
        eprintln!("fetching {} from {}", source.name, source.url);
        let body = fetch(source.url)?;
        let mut ranges =
            (source.extract)(&body).map_err(|err| format!("{}: {err}", source.name))?;
        if ranges.is_empty() {
            return Err(format!("{}: no ranges in response", source.name).into());
        }
        let parsed = IpRanges::parse(&ranges).map_err(|err| format!("{}: {err}", source.name))?;
        let runtime = (source.parse)(&body).map_err(|err| format!("{}: {err}", source.name))?;
        if parsed != runtime {
            return Err(
                format!("{}: runtime parser disagrees with extraction", source.name).into(),
            );
        }
        ranges.sort();
        ranges.dedup();
        eprintln!("  {} ranges", ranges.len());
        lists.push((source.name, ranges));
    }
    lists.push((
        "GOOGLE_CLOUD_LOAD_BALANCERS",
        GOOGLE_CLOUD_LOAD_BALANCERS
            .iter()
            .map(|range| range.to_string())
            .collect(),
    ));
    lists.sort_by_key(|(name, _)| *name);

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../src/providers/data.rs");
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    let current_date = current
        .lines()
        .find_map(|line| line.strip_prefix("pub const SNAPSHOT_DATE: &str = \""))
        .and_then(|rest| rest.strip_suffix("\";"))
        .unwrap_or_default();
    if render(current_date, &lists) == current {
        eprintln!("ranges unchanged; {} left as is", path.display());
        return Ok(());
    }
    std::fs::write(&path, render(&today(), &lists))?;
    eprintln!("wrote {}", path.display());
    Ok(())
}

fn fetch(url: &str) -> Result<String> {
    let mut response = ureq::get(url)
        .header(
            "User-Agent",
            "ipware-xtask (https://github.com/orhanbalci/ipware)",
        )
        .call()?;
    Ok(response.body_mut().read_to_string()?)
}

fn strings(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or("expected an array")?
        .iter()
        .map(|item| Ok(item.as_str().ok_or("expected a string")?.to_owned()))
        .collect()
}

fn render(date: &str, lists: &[(&str, Vec<String>)]) -> String {
    let mut out = String::new();
    out.push_str("// @generated by `cargo xtask update-ranges`. Do not edit by hand.\n\n");
    out.push_str("/// The date the built-in provider ranges were fetched.\n");
    let _ = writeln!(out, "pub const SNAPSHOT_DATE: &str = \"{date}\";");
    for (name, ranges) in lists {
        let _ = writeln!(out, "\npub(super) const {name}: &[&str] = &[");
        for range in ranges {
            let _ = writeln!(out, "    \"{range}\",");
        }
        out.push_str("];\n");
    }
    out
}

/// Today's UTC date as `YYYY-MM-DD`.
fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
        / 86_400;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
