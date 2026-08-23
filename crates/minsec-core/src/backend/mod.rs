//! Firewall backends. The kernel (or whatever the backend drives) owns the
//! authoritative ban list; the daemon only mirrors it for fast answers.

pub mod exec;
pub mod nft;
pub mod null;

use ipnet::IpNet;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    pub net: IpNet,
    pub ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub net: IpNet,
    /// Remaining lifetime when known.
    pub expires_in: Option<Duration>,
}

pub trait Firewall {
    fn name(&self) -> &'static str;
    /// Create tables/sets/chains idempotently. Must not disturb other rules.
    fn setup(&mut self) -> anyhow::Result<()>;
    fn ban(&mut self, bans: &[Ban]) -> anyhow::Result<()>;
    fn unban(&mut self, nets: &[IpNet]) -> anyhow::Result<()>;
    /// Currently active bans, if the backend can enumerate them.
    fn list(&mut self) -> anyhow::Result<Option<Vec<Entry>>>;
    /// Replace the allow list.
    fn set_allow(&mut self, nets: &[IpNet]) -> anyhow::Result<()>;
}

pub fn open(cfg: &crate::config::Defaults) -> anyhow::Result<Box<dyn Firewall>> {
    use crate::config::BackendKind::*;
    Ok(match cfg.backend {
        Nft => Box::new(nft::Nft::new()),
        Null => Box::new(null::Null::default()),
        Exec => Box::new(exec::Exec::new(cfg.exec_command.clone().expect("validated"))),
    })
}
