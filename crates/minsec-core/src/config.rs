//! Daemon configuration: `/etc/minsec/minsec.toml` plus `conf.d/*.toml` drop-ins.

use crate::duration::HumanDuration;
use crate::filter::{FilterDef, JournalSelector};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_CONFIG_DIR: &str = "/etc/minsec";
pub const DEFAULT_SOCKET: &str = "/run/minsec/minsec.sock";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/minsec";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Nft,
    Null,
    Exec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Escalate {
    /// Multiply bantime by this for each previous ban of the same key.
    #[serde(default = "default_factor")]
    pub factor: u32,
    /// Upper bound on escalated bantime.
    #[serde(default = "default_max_ban")]
    pub max: HumanDuration,
    /// Forget previous bans older than this.
    #[serde(default = "default_memory")]
    pub memory: HumanDuration,
}

fn default_factor() -> u32 {
    2
}
fn default_max_ban() -> HumanDuration {
    Duration::from_secs(7 * 86_400).into()
}
fn default_memory() -> HumanDuration {
    Duration::from_secs(30 * 86_400).into()
}

impl Default for Escalate {
    fn default() -> Self {
        Self {
            factor: default_factor(),
            max: default_max_ban(),
            memory: default_memory(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "d_bantime")]
    pub bantime: HumanDuration,
    #[serde(default = "d_findtime")]
    pub findtime: HumanDuration,
    #[serde(default = "d_maxretry")]
    pub maxretry: u32,
    /// `false` disables escalation entirely.
    #[serde(default = "d_true")]
    pub escalate_enabled: bool,
    #[serde(default)]
    pub escalate: Escalate,
    /// Never ban these networks. Loopback and the host's own addresses are
    /// always implied.
    #[serde(default)]
    pub allow: Vec<IpNet>,
    #[serde(default = "d_backend")]
    pub backend: BackendKind,
    /// Command for the `exec` backend: receives `ban|unban <ip> <ttl-secs>`.
    #[serde(default)]
    pub exec_command: Option<String>,
    /// IPv6 keys are truncated to this prefix length.
    #[serde(default = "d_v6_prefix")]
    pub ipv6_prefix: u8,
    /// Upper bound on tracked (filter, key) pairs across the daemon.
    #[serde(default = "d_max_tracked")]
    pub max_tracked: usize,
    /// Use journald (when present) for filters that declare journal selectors.
    #[serde(default = "d_true")]
    pub journal: bool,
}

fn d_bantime() -> HumanDuration {
    Duration::from_secs(3600).into()
}
fn d_findtime() -> HumanDuration {
    Duration::from_secs(600).into()
}
fn d_maxretry() -> u32 {
    5
}
fn d_true() -> bool {
    true
}
fn d_backend() -> BackendKind {
    BackendKind::Nft
}
fn d_v6_prefix() -> u8 {
    64
}
fn d_max_tracked() -> usize {
    50_000
}

impl Default for Defaults {
    fn default() -> Self {
        toml::from_str("").expect("defaults deserialize from empty table")
    }
}

/// Per-filter enablement and overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    #[serde(default)]
    pub enabled: bool,
    pub bantime: Option<HumanDuration>,
    pub findtime: Option<HumanDuration>,
    pub maxretry: Option<u32>,
    /// Replace the filter's default files.
    pub files: Option<Vec<String>>,
    /// Replace the filter's journal selectors.
    pub journal: Option<JournalSelector>,
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    #[serde(default = "d_socket")]
    pub socket: PathBuf,
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
}

fn d_socket() -> PathBuf {
    DEFAULT_SOCKET.into()
}
fn d_state_dir() -> PathBuf {
    DEFAULT_STATE_DIR.into()
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            socket: d_socket(),
            state_dir: d_state_dir(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub paths: Paths,
    #[serde(default)]
    pub filters: BTreeMap<String, FilterConfig>,
    /// Directory of the config file; custom filters live in `<dir>/filters/`.
    #[serde(skip)]
    pub config_dir: PathBuf,
}

/// Effective policy for one filter after merging defaults and overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub bantime: Duration,
    pub findtime: Duration,
    pub maxretry: u32,
    pub escalate: Option<Escalate>,
    pub ports: Vec<u16>,
}

impl Config {
    /// Load `<dir>/minsec.toml` and merge `<dir>/conf.d/*.toml` over it.
    /// A missing main file yields defaults (the daemon can run with nothing
    /// enabled; `minsec enable` writes drop-ins).
    pub fn load_dir(dir: &Path) -> anyhow::Result<Self> {
        let main = dir.join("minsec.toml");
        let mut merged: toml::Table = match std::fs::read_to_string(&main) {
            Ok(s) => toml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {e}", main.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
            Err(e) => anyhow::bail!("{}: {e}", main.display()),
        };
        let confd = dir.join("conf.d");
        if let Ok(rd) = std::fs::read_dir(&confd) {
            let mut entries: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "toml"))
                .collect();
            entries.sort();
            for p in entries {
                let s = std::fs::read_to_string(&p)?;
                let t: toml::Table = toml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
                merge(&mut merged, t);
            }
        }
        let mut cfg: Config = toml::Value::Table(merged)
            .try_into()
            .map_err(|e| anyhow::anyhow!("config: {e}"))?;
        cfg.config_dir = dir.to_path_buf();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = toml::from_str(s)?;
        cfg.config_dir = DEFAULT_CONFIG_DIR.into();
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let d = &self.defaults;
        if d.maxretry == 0 || d.maxretry > crate::tracker::MAX_RETRY_CAP {
            anyhow::bail!("defaults.maxretry must be 1..={}", crate::tracker::MAX_RETRY_CAP);
        }
        if d.findtime.secs() == 0 {
            anyhow::bail!("defaults.findtime must be > 0");
        }
        if d.ipv6_prefix == 0 || d.ipv6_prefix > 128 {
            anyhow::bail!("defaults.ipv6_prefix must be 1..=128");
        }
        if d.backend == BackendKind::Exec && d.exec_command.is_none() {
            anyhow::bail!("defaults.exec_command is required for the exec backend");
        }
        for (name, f) in &self.filters {
            if let Some(m) = f.maxretry {
                if m == 0 || m > crate::tracker::MAX_RETRY_CAP {
                    anyhow::bail!("filters.{name}.maxretry must be 1..={}", crate::tracker::MAX_RETRY_CAP);
                }
            }
        }
        Ok(())
    }

    /// Resolve a filter definition: `<config_dir>/filters/<name>.toml` wins
    /// over the built-in of the same name.
    pub fn filter_def(&self, name: &str) -> anyhow::Result<FilterDef> {
        let custom = self.config_dir.join("filters").join(format!("{name}.toml"));
        let mut def = match std::fs::read_to_string(&custom) {
            Ok(s) => FilterDef::from_toml(&s).map_err(|e| anyhow::anyhow!("{}: {e}", custom.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match crate::builtin::get(name) {
                Some(r) => r?,
                None => anyhow::bail!("unknown filter `{name}` (no built-in and no {})", custom.display()),
            },
            Err(e) => anyhow::bail!("{}: {e}", custom.display()),
        };
        if let Some(fc) = self.filters.get(name) {
            if let Some(files) = &fc.files {
                def.files = files.clone();
            }
            if let Some(j) = &fc.journal {
                def.journal = j.clone();
            }
            if let Some(p) = &fc.ports {
                def.ports = p.clone();
            }
        }
        Ok(def)
    }

    pub fn policy_for(&self, name: &str, def: &FilterDef) -> Policy {
        let d = &self.defaults;
        let fc = self.filters.get(name).cloned().unwrap_or_default();
        Policy {
            bantime: fc.bantime.unwrap_or(d.bantime).0,
            findtime: fc.findtime.unwrap_or(d.findtime).0,
            maxretry: fc.maxretry.unwrap_or(d.maxretry),
            escalate: d.escalate_enabled.then(|| d.escalate.clone()),
            ports: fc.ports.clone().unwrap_or_else(|| def.ports.clone()),
        }
    }

    pub fn enabled_filters(&self) -> impl Iterator<Item = &str> {
        self.filters.iter().filter(|(_, f)| f.enabled).map(|(n, _)| n.as_str())
    }
}

/// Deep-merge TOML tables: `over` wins; nested tables merge recursively.
fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let cfg = Config::parse(
            r#"
[defaults]
bantime = "2h"
allow = ["10.0.0.0/8"]
[filters.sshd]
enabled = true
maxretry = 3
"#,
        )
        .unwrap();
        assert_eq!(cfg.defaults.bantime.secs(), 7200);
        assert_eq!(cfg.defaults.findtime.secs(), 600);
        let def = cfg.filter_def("sshd").unwrap();
        let p = cfg.policy_for("sshd", &def);
        assert_eq!(p.maxretry, 3);
        assert_eq!(p.bantime, Duration::from_secs(7200));
        assert_eq!(cfg.enabled_filters().collect::<Vec<_>>(), vec!["sshd"]);
    }

    #[test]
    fn rejects_bad() {
        assert!(Config::parse("[defaults]\nmaxretry = 0").is_err());
        assert!(Config::parse("[defaults]\nbackend = \"exec\"").is_err());
        assert!(Config::parse("[nope]\nx = 1").is_err());
    }

    #[test]
    fn merge_tables() {
        let mut a: toml::Table = toml::from_str("[defaults]\nbantime='1h'\nmaxretry=5").unwrap();
        let b: toml::Table = toml::from_str("[defaults]\nmaxretry=9\n[filters.sshd]\nenabled=true").unwrap();
        merge(&mut a, b);
        let c: Config = toml::Value::Table(a).try_into().unwrap();
        assert_eq!(c.defaults.maxretry, 9);
        assert_eq!(c.defaults.bantime.secs(), 3600);
        assert!(c.filters["sshd"].enabled);
    }
}
