//! Dry-run backend: records bans in memory and logs them. Useful for
//! `minsec test`, for running alongside fail2ban to compare decisions, and for
//! tests.

use super::{Ban, Entry, Firewall};
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Null {
    bans: BTreeMap<IpNet, Instant>,
    pub allow: Vec<IpNet>,
}

impl Firewall for Null {
    fn name(&self) -> &'static str {
        "null"
    }
    fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn ban(&mut self, bans: &[Ban]) -> anyhow::Result<()> {
        let now = Instant::now();
        for b in bans {
            tracing::info!(target: "minsec::ban", net = %b.net, ttl = b.ttl.as_secs(), "ban (null backend)");
            self.bans.insert(b.net, now + b.ttl);
        }
        Ok(())
    }
    fn unban(&mut self, nets: &[IpNet]) -> anyhow::Result<()> {
        for n in nets {
            tracing::info!(target: "minsec::ban", net = %n, "unban (null backend)");
            self.bans.remove(n);
        }
        Ok(())
    }
    fn list(&mut self) -> anyhow::Result<Option<Vec<Entry>>> {
        let now = Instant::now();
        self.bans.retain(|_, until| *until > now);
        Ok(Some(
            self.bans
                .iter()
                .map(|(n, until)| Entry {
                    net: *n,
                    expires_in: Some(until.saturating_duration_since(now)),
                })
                .collect(),
        ))
    }
    fn set_allow(&mut self, nets: &[IpNet]) -> anyhow::Result<()> {
        self.allow = nets.to_vec();
        Ok(())
    }
}

impl Null {
    pub fn contains(&self, net: &IpNet) -> bool {
        self.bans.get(net).is_some_and(|u| *u > Instant::now())
    }
    pub fn remaining(&self, net: &IpNet) -> Option<Duration> {
        self.bans.get(net).map(|u| u.saturating_duration_since(Instant::now()))
    }
}
