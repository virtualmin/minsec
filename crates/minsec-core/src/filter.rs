//! Filter definitions and the compiled matcher.
//!
//! A filter selects log sources and holds a list of patterns. Patterns are
//! regular expressions with fail2ban-compatible tokens so existing knowledge
//! carries over:
//!
//! * `<HOST>`, `<ADDR>`, `<IP>` — an IPv4 or IPv6 address (captured as `host`)
//! * `<IP4>`, `<IP6>` — address of one family only
//! * `<F-USER>…</F-USER>` (or any `<F-NAME>…</F-NAME>`) — a named capture
//!
//! Lines are matched anywhere (not anchored) so the same pattern works for
//! syslog-prefixed files and for raw journald messages.
//!
//! `\d`, `\s`, `\w` (and their negations) are rewritten to ASCII classes:
//! Unicode-aware classes cost ~25× more memory to compile and log lines never
//! need them.

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::ip;

const RE_IP4: &str = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}";
const RE_IP6: &str = r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:(?:\.[0-9]{1,3}){3})?";

/// Journal selectors. Every entry becomes a separate match expression, so an
/// entry matching any of them is selected.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalSelector {
    #[serde(default)]
    pub units: Vec<String>,
    #[serde(default)]
    pub identifiers: Vec<String>,
    #[serde(default)]
    pub comm: Vec<String>,
}

impl JournalSelector {
    pub fn is_empty(&self) -> bool {
        self.units.is_empty() && self.identifiers.is_empty() && self.comm.is_empty()
    }
    /// `FIELD=value` match expressions for sd_journal / journalctl.
    pub fn matches(&self) -> Vec<String> {
        let mut v = Vec::new();
        v.extend(self.units.iter().map(|u| format!("_SYSTEMD_UNIT={u}")));
        v.extend(self.identifiers.iter().map(|i| format!("SYSLOG_IDENTIFIER={i}")));
        v.extend(self.comm.iter().map(|c| format!("_COMM={c}")));
        v
    }
}

/// On-disk / embedded filter definition (TOML).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilterDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Log files to follow. Globs allowed. Missing files are watched for creation.
    #[serde(default)]
    pub files: Vec<String>,
    /// journald selectors. Used when the journal is available; the operator
    /// should pick either files or journal per filter to avoid double counting.
    #[serde(default)]
    pub journal: JournalSelector,
    /// Literal substrings, any of which must be present for a line to be
    /// considered. Cheap pre-check before the regex set. Optional.
    #[serde(default)]
    pub prefilter: Vec<String>,
    pub patterns: Vec<String>,
    /// Lines matching any of these are never counted, even if a pattern hits.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Ports this service listens on (used for per-filter port restriction).
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl FilterDef {
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(s)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub pattern: usize,
    pub ip: IpAddr,
    pub user: Option<String>,
}

/// Compiled form of a [`FilterDef`].
pub struct CompiledFilter {
    pub def: FilterDef,
    prefilter: Option<AhoCorasick>,
    /// All patterns as one alternation: `(?:p0)|(?:p1)|…`, with capture names
    /// suffixed by pattern index. One regex per filter keeps memory flat.
    re: Regex,
    /// Capture-group indices of `host{i}` / `user{i}` per pattern.
    groups: Vec<(usize, Option<usize>)>,
    ignore: Option<Regex>,
}

/// Expand fail2ban-style tokens into real regex syntax.
pub fn expand_tokens(pattern: &str) -> String {
    expand_tokens_n(pattern, "")
}

/// Like [`expand_tokens`] but suffixes every capture name with `suffix`, so
/// several patterns can live in one alternation without name clashes.
pub fn expand_tokens_n(pattern: &str, suffix: &str) -> String {
    let pattern = ascii_classes(pattern);
    let mut out = String::with_capacity(pattern.len() + 64);
    let mut rest = pattern.as_str();
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let Some(end) = tail.find('>') else {
            out.push_str(tail);
            rest = "";
            break;
        };
        let tok = &tail[1..end];
        let replacement = match tok {
            "HOST" | "ADDR" | "IP" => format!("(?P<host{suffix}>{RE_IP4}|{RE_IP6})"),
            "IP4" => format!("(?P<host{suffix}>{RE_IP4})"),
            "IP6" => format!("(?P<host{suffix}>{RE_IP6})"),
            t if t.starts_with("F-") => format!("(?P<{}{suffix}>", t[2..].to_ascii_lowercase()),
            t if t.starts_with("/F-") => ")".to_string(),
            _ => {
                // Not a token (e.g. a literal `<` in the pattern); keep verbatim.
                out.push('<');
                rest = &tail[1..];
                continue;
            }
        };
        out.push_str(&replacement);
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Rewrite Perl classes to ASCII equivalents. Nested classes (`[[0-9].]`) are
/// valid regex-crate syntax, so this is safe inside brackets too.
pub fn ascii_classes(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut it = pattern.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('d') => out.push_str("[0-9]"),
            Some('D') => out.push_str("[^0-9]"),
            Some('s') => out.push_str("[ \\t\\r\\n\\x0b\\x0c]"),
            Some('S') => out.push_str("[^ \\t\\r\\n\\x0b\\x0c]"),
            Some('w') => out.push_str("[0-9A-Za-z_]"),
            Some('W') => out.push_str("[^0-9A-Za-z_]"),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn build(patterns: &[String]) -> anyhow::Result<Regex> {
    let joined: Vec<String> = patterns
        .iter()
        .enumerate()
        .map(|(i, p)| format!("(?:{})", expand_tokens_n(p, &i.to_string())))
        .collect();
    regex::RegexBuilder::new(&joined.join("|"))
        .size_limit(4 << 20)
        .dfa_size_limit(1 << 18)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

impl CompiledFilter {
    pub fn compile(def: FilterDef) -> anyhow::Result<Self> {
        if def.patterns.is_empty() {
            anyhow::bail!("filter `{}` has no patterns", def.name);
        }
        // Validate each pattern on its own first so errors name the culprit.
        for p in &def.patterns {
            let r = regex::Regex::new(&expand_tokens(p)).map_err(|e| anyhow::anyhow!("pattern `{p}`: {e}"))?;
            if !r.capture_names().any(|n| n == Some("host")) {
                anyhow::bail!("pattern `{p}` has no <HOST> capture");
            }
        }
        let re = build(&def.patterns).map_err(|e| anyhow::anyhow!("filter `{}`: {e}", def.name))?;
        let names: Vec<Option<&str>> = re.capture_names().collect();
        let find = |n: &str| names.iter().position(|x| *x == Some(n));
        let groups = (0..def.patterns.len())
            .map(|i| {
                (
                    find(&format!("host{i}")).expect("host group present"),
                    find(&format!("user{i}")),
                )
            })
            .collect();
        let ignore = if def.ignore.is_empty() {
            None
        } else {
            let ig: Vec<String> = def.ignore.iter().map(|p| format!("(?:{})", expand_tokens(p))).collect();
            Some(Regex::new(&ig.join("|")).map_err(|e| anyhow::anyhow!("filter `{}` ignore: {e}", def.name))?)
        };
        let prefilter = if def.prefilter.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(&def.prefilter)?)
        };
        Ok(Self {
            def,
            prefilter,
            re,
            groups,
            ignore,
        })
    }

    pub fn name(&self) -> &str {
        &self.def.name
    }

    /// Match a single log line. Returns the first pattern (in definition order)
    /// that hits and yields a parseable IP.
    pub fn match_line(&self, line: &str) -> Option<Match> {
        self.match_line_opts(line, true)
    }

    /// `use_prefilter = false` skips the literal pre-check; used for journald
    /// entries, which are already selected by unit/identifier and lack the
    /// syslog program prefix the prefilter typically keys on.
    pub fn match_line_opts(&self, line: &str, use_prefilter: bool) -> Option<Match> {
        if use_prefilter {
            if let Some(pf) = &self.prefilter {
                if !pf.is_match(line) {
                    return None;
                }
            }
        }
        let caps = self.re.captures(line)?;
        if let Some(ig) = &self.ignore {
            if ig.is_match(line) {
                return None;
            }
        }
        for (idx, (h, u)) in self.groups.iter().enumerate() {
            let Some(host) = caps.get(*h) else { continue };
            let Some(ip) = ip::parse_log_ip(host.as_str()) else {
                continue;
            };
            let user = u.and_then(|g| caps.get(g)).map(|m| m.as_str().to_string());
            return Some(Match { pattern: idx, ip, user });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(patterns: &[&str]) -> FilterDef {
        FilterDef {
            name: "t".into(),
            description: String::new(),
            files: vec![],
            journal: Default::default(),
            prefilter: vec![],
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            ignore: vec![],
            ports: vec![],
        }
    }

    #[test]
    fn ascii() {
        assert_eq!(ascii_classes(r"a\d+\\d[\s\d]"), r"a[0-9]+\\d[[ \t\r\n\x0b\x0c][0-9]]");
        let r = Regex::new(&ascii_classes(r"^[^\d]\S+\s\w$")).unwrap();
        assert!(r.is_match("xab c"));
        assert!(!r.is_match("1ab c"));
    }

    #[test]
    fn expands() {
        assert_eq!(expand_tokens("a <F-USER>[^ ]+</F-USER> b"), "a (?P<user>[^ ]+) b");
        assert!(expand_tokens("x <HOST> y").contains("(?P<host>"));
        assert_eq!(expand_tokens("a < b"), "a < b");
    }

    #[test]
    fn matches_v4_v6_user() {
        let flt = CompiledFilter::compile(def(&[
            r"Failed password for (?:invalid user )?<F-USER>\S+</F-USER> from <HOST> port \d+",
        ]))
        .unwrap();
        let m = flt
            .match_line(
                "Jan  1 00:00:00 h sshd[1]: Failed password for invalid user bob from 203.0.113.9 port 2222 ssh2",
            )
            .unwrap();
        assert_eq!(m.ip, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(m.user.as_deref(), Some("bob"));
        let m = flt
            .match_line("Failed password for root from 2001:db8::5 port 1 ssh2")
            .unwrap();
        assert_eq!(m.ip, "2001:db8::5".parse::<IpAddr>().unwrap());
        let m = flt
            .match_line("Failed password for root from ::ffff:10.0.0.9 port 1 ssh2")
            .unwrap();
        assert_eq!(m.ip, "10.0.0.9".parse::<IpAddr>().unwrap());
        assert!(flt
            .match_line("Accepted password for root from 10.0.0.9 port 1")
            .is_none());
    }

    #[test]
    fn rejects_without_host() {
        assert!(CompiledFilter::compile(def(&["nothing"])).is_err());
    }
}
