//! Control protocol: newline-delimited JSON over a unix socket.
//! One request per line, one response per line.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    Status,
    List,
    Ban {
        net: IpNet,
        #[serde(default)]
        ttl: Option<u64>,
        #[serde(default)]
        reason: Option<String>,
    },
    Unban {
        net: IpNet,
    },
    Filters,
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterStatus {
    pub name: String,
    pub files: Vec<String>,
    pub journal: bool,
    pub maxretry: u32,
    pub findtime: u64,
    pub bantime: u64,
    pub matched: u64,
    pub banned: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanInfo {
    pub net: IpNet,
    pub expires_in: Option<u64>,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub version: String,
    pub backend: String,
    pub uptime: u64,
    pub tracked: usize,
    pub lines: u64,
    pub bans_total: u64,
    pub active_bans: usize,
    pub filters: Vec<FilterStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bans: Option<Vec<BanInfo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<Vec<String>>,
}

impl Response {
    pub fn ok() -> Self {
        Self {
            ok: true,
            ..Default::default()
        }
    }
    pub fn message(m: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: Some(m.into()),
            ..Default::default()
        }
    }
    pub fn err(e: impl ToString) -> Self {
        Self {
            ok: false,
            error: Some(e.to_string()),
            ..Default::default()
        }
    }
}

/// Blocking client used by the CLI.
pub fn call(socket: &Path, req: &Request) -> anyhow::Result<Response> {
    use std::io::{BufRead, BufReader, Write};
    let mut s = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|e| anyhow::anyhow!("cannot connect to {} ({e}); is minsec running?", socket.display()))?;
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    s.write_all(line.as_bytes())?;
    let mut r = BufReader::new(s);
    let mut resp = String::new();
    r.read_line(&mut resp)?;
    if resp.is_empty() {
        anyhow::bail!("empty response from daemon");
    }
    Ok(serde_json::from_str(&resp)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let r: Request = serde_json::from_str(r#"{"cmd":"ban","net":"10.0.0.1/32","ttl":60}"#).unwrap();
        assert!(matches!(r, Request::Ban { ttl: Some(60), .. }));
        let s = serde_json::to_string(&Response::err("nope")).unwrap();
        assert_eq!(s, r#"{"ok":false,"error":"nope"}"#);
    }
}
