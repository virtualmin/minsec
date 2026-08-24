//! `/etc/minsec/sync.toml` — the multiplayer client's own config file,
//! deliberately separate from the daemon's (which rejects unknown keys).
//! Every field has a default; the file's existence is the opt-in switch for
//! the systemd timer (`run` exits quietly without it).

use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = "/etc/minsec/sync.toml";
pub const DEFAULT_SERVER: &str = "https://api.minsec.io";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/minsec/sync";
pub const DEFAULT_EVENTS: &str = "/var/lib/minsec/events.jsonl";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Backend base URL.
    pub server: String,
    /// Feed tier to pull: "basic" or "high".
    pub tier: String,
    /// Report local automatic bans to the crowd.
    pub report: bool,
    /// Pull the crowd blocklist into the crowd4/crowd6 nftables sets.
    pub pull: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub state_dir: PathBuf,
    /// The daemon's event log (source of reports).
    pub events: PathBuf,
    /// nft binary.
    pub nft: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: DEFAULT_SERVER.into(),
            tier: "basic".into(),
            report: true,
            pull: true,
            ipv4: true,
            ipv6: true,
            state_dir: DEFAULT_STATE_DIR.into(),
            events: DEFAULT_EVENTS.into(),
            nft: "nft".into(),
        }
    }
}

impl Config {
    /// Load the config file. `Ok(None)` when it does not exist (multiplayer
    /// not configured).
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
        };
        let cfg: Config = toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        if cfg.tier != "basic" && cfg.tier != "high" {
            anyhow::bail!("{}: tier must be \"basic\" or \"high\"", path.display());
        }
        if !cfg.server.starts_with("http://") && !cfg.server.starts_with("https://") {
            anyhow::bail!("{}: server must be an http(s) URL", path.display());
        }
        Ok(Some(cfg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let cfg: Config = toml::from_str("tier = \"high\"\nipv6 = false\n").unwrap();
        assert_eq!(cfg.tier, "high");
        assert!(!cfg.ipv6);
        assert_eq!(cfg.server, DEFAULT_SERVER);
        assert!(cfg.report && cfg.pull && cfg.ipv4);
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(toml::from_str::<Config>("serverr = \"x\"\n").is_err());
    }
}
