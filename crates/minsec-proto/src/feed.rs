//! Parsing the plain-text blocklist feed (`GET /v1/feed/{tier}/{family}`).
//!
//! ```text
//! # minsec-feed v1 full tier=basic family=4 snapshot=1234 generated=2026-08-23T12:00:00Z count=4821
//! 203.0.113.7
//! 198.51.100.0/24
//! ```
//!
//! A delta uses `from=`/`to=` in the header and `+`/`-` prefixed lines. A
//! bare address means a single host; prefixes are explicit.

use std::fmt;

const HEADER_PREFIX: &str = "# minsec-feed v1 ";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedHeader {
    pub kind: String,
    pub tier: String,
    pub family: u8,
    pub snapshot: i64,
    /// Delta only.
    pub from: i64,
    /// Delta only.
    pub to: i64,
    pub generated: String,
    pub count: usize,
}

#[derive(Debug)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "feed parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

pub fn parse_header(line: &str) -> Result<FeedHeader, ParseError> {
    let rest = line
        .trim()
        .strip_prefix(HEADER_PREFIX)
        .ok_or_else(|| ParseError(format!("not a minsec-feed v1 header: {line:?}")))?;
    let mut fields = rest.split_ascii_whitespace();
    let mut h = FeedHeader {
        kind: fields.next().unwrap_or_default().to_string(),
        ..Default::default()
    };
    if h.kind != "full" && h.kind != "delta" {
        return Err(ParseError(format!("unknown feed kind {:?}", h.kind)));
    }
    for kv in fields {
        let Some((k, v)) = kv.split_once('=') else { continue };
        match k {
            "tier" => h.tier = v.to_string(),
            "family" => h.family = v.parse().unwrap_or(0),
            "snapshot" => h.snapshot = v.parse().unwrap_or(0),
            "from" => h.from = v.parse().unwrap_or(0),
            "to" => h.to = v.parse().unwrap_or(0),
            "generated" => h.generated = v.to_string(),
            "count" => h.count = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    Ok(h)
}

/// A parsed feed body. For a full feed only `entries` is populated; for a
/// delta only `added`/`removed` are.
#[derive(Debug, Default)]
pub struct Feed {
    pub header: FeedHeader,
    pub entries: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl Feed {
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut lines = body.lines();
        let header = parse_header(lines.next().ok_or_else(|| ParseError("empty body".into()))?)?;
        let delta = header.kind == "delta";
        let mut feed = Feed {
            header,
            ..Default::default()
        };
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if delta {
                if let Some(net) = line.strip_prefix('+') {
                    feed.added.push(net.to_string());
                } else if let Some(net) = line.strip_prefix('-') {
                    feed.removed.push(net.to_string());
                } else {
                    return Err(ParseError(format!("delta line without +/-: {line:?}")));
                }
            } else {
                feed.entries.push(line.to_string());
            }
        }
        Ok(feed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full() {
        let body = "# minsec-feed v1 full tier=basic family=4 snapshot=1234 generated=2026-08-23T12:00:00Z count=2\n\
                    198.51.100.0/24\n203.0.113.7\n";
        let f = Feed::parse(body).unwrap();
        assert_eq!(f.header.kind, "full");
        assert_eq!(f.header.tier, "basic");
        assert_eq!(f.header.family, 4);
        assert_eq!(f.header.snapshot, 1234);
        assert_eq!(f.header.count, 2);
        assert_eq!(f.entries, vec!["198.51.100.0/24", "203.0.113.7"]);
        assert!(f.added.is_empty() && f.removed.is_empty());
    }

    #[test]
    fn delta() {
        let body = "# minsec-feed v1 delta tier=high family=6 from=1200 to=1234 count=2\n\
                    +2001:db8:1:2::/64\n-2001:db8:dead::/48\n";
        let f = Feed::parse(body).unwrap();
        assert_eq!(f.header.kind, "delta");
        assert_eq!((f.header.from, f.header.to), (1200, 1234));
        assert_eq!(f.added, vec!["2001:db8:1:2::/64"]);
        assert_eq!(f.removed, vec!["2001:db8:dead::/48"]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Feed::parse("").is_err());
        assert!(Feed::parse("# other-feed v1 full\n").is_err());
        assert!(Feed::parse("# minsec-feed v1 partial tier=basic\n").is_err());
        assert!(Feed::parse("# minsec-feed v1 delta tier=basic family=4 from=1 to=2 count=1\nnosign\n").is_err());
    }
}
