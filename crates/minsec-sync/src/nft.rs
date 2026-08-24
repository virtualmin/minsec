//! Writing the crowd blocklist into nftables. The daemon owns the
//! `inet minsec` table, its chains, and the rules referencing `crowd4` /
//! `crowd6` (see minsec-core's setup script); minsec-sync only manages the
//! contents of those two sets. `ensure_sets` makes the sets themselves
//! idempotently so pulls work even before the daemon has restarted onto a
//! crowd-aware version — the sets are simply unreferenced until then.
//!
//! Every entry is parsed as an address/prefix of the right family before it
//! goes anywhere near a script: feed bytes are never interpolated raw.

use ipnet::IpNet;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

pub const TABLE: &str = "inet minsec";

pub struct Nft {
    bin: String,
    dry_run: bool,
}

pub fn set_name(family: u8) -> &'static str {
    if family == 4 {
        "crowd4"
    } else {
        "crowd6"
    }
}

/// Parse and validate one feed entry (bare address or CIDR) for a family.
pub fn parse_entry(entry: &str, family: u8) -> Option<IpNet> {
    let net = if let Ok(addr) = entry.parse::<IpAddr>() {
        IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok()?
    } else {
        entry.parse::<IpNet>().ok()?
    };
    let ok = match net {
        IpNet::V4(_) => family == 4,
        IpNet::V6(_) => family == 6,
    };
    ok.then_some(net)
}

impl Nft {
    pub fn new(bin: &str, dry_run: bool) -> Self {
        Self {
            bin: bin.to_string(),
            dry_run,
        }
    }

    fn run(&self, script: &str) -> anyhow::Result<()> {
        if self.dry_run {
            print!("{script}");
            return Ok(());
        }
        let mut child = Command::new(&self.bin)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("cannot run `{}`: {e}", self.bin))?;
        child.stdin.take().expect("piped").write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!(
                "nft failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    pub fn ensure_sets(&self) -> anyhow::Result<()> {
        let mut s = format!("add table {TABLE}\n");
        s.push_str(&format!(
            "add set {TABLE} crowd4 {{ type ipv4_addr; flags interval; }}\n"
        ));
        s.push_str(&format!(
            "add set {TABLE} crowd6 {{ type ipv6_addr; flags interval; }}\n"
        ));
        self.run(&s)
    }

    /// Atomically replace the whole set (flush + add in one transaction).
    pub fn replace(&self, family: u8, nets: &[IpNet]) -> anyhow::Result<()> {
        let set = set_name(family);
        let mut s = format!("flush set {TABLE} {set}\n");
        push_elements(&mut s, "add", set, nets);
        self.run(&s)
    }

    /// Apply a delta. Removals of entries nft no longer has must not fail
    /// the batch, so removals go one at a time with errors ignored;
    /// additions are transactional. On error the caller falls back to a
    /// full replace.
    pub fn apply_delta(&self, family: u8, added: &[IpNet], removed: &[IpNet]) -> anyhow::Result<()> {
        let set = set_name(family);
        for net in removed {
            let _ = self.run(&format!("delete element {TABLE} {set} {{ {} }}\n", fmt_net(net)));
        }
        if !added.is_empty() {
            let mut s = String::new();
            push_elements(&mut s, "add", set, added);
            self.run(&s)?;
        }
        Ok(())
    }
}

fn fmt_net(net: &IpNet) -> String {
    // Single hosts as bare addresses: nft normalizes /32 and /128 away, so
    // feeding them bare keeps our elements comparable with nft's output.
    if net.prefix_len() == net.max_prefix_len() {
        net.addr().to_string()
    } else {
        net.to_string()
    }
}

fn push_elements(s: &mut String, verb: &str, set: &str, nets: &[IpNet]) {
    for chunk in nets.chunks(500) {
        s.push_str(&format!("{verb} element {TABLE} {set} {{ "));
        for (i, net) in chunk.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&fmt_net(net));
        }
        s.push_str(" }\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_validation() {
        assert_eq!(parse_entry("203.0.113.7", 4).unwrap().to_string(), "203.0.113.7/32");
        assert_eq!(
            parse_entry("198.51.100.0/24", 4).unwrap().to_string(),
            "198.51.100.0/24"
        );
        assert_eq!(parse_entry("2001:db8::/64", 6).unwrap().to_string(), "2001:db8::/64");
        assert!(parse_entry("203.0.113.7", 6).is_none(), "family mismatch");
        assert!(parse_entry("2001:db8::1", 4).is_none(), "family mismatch");
        assert!(parse_entry("not-an-ip", 4).is_none());
        assert!(parse_entry("203.0.113.7; drop table", 4).is_none());
    }

    #[test]
    fn scripts() {
        let nets = vec![
            parse_entry("203.0.113.7", 4).unwrap(),
            parse_entry("198.51.100.0/24", 4).unwrap(),
        ];
        let mut s = String::new();
        push_elements(&mut s, "add", "crowd4", &nets);
        assert_eq!(s, "add element inet minsec crowd4 { 203.0.113.7, 198.51.100.0/24 }\n");
    }
}
