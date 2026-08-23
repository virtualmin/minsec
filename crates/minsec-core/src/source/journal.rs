//! journald source.
//!
//! Phase 0 implementation: one `journalctl --follow -o json` subprocess with
//! server-side match expressions, so we only receive entries for the units /
//! identifiers our filters care about. A `dlopen("libsystemd.so.0")` reader
//! using the same routing fields is planned to replace the subprocess.

use super::{Line, Origin};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub fn available() -> bool {
    std::path::Path::new("/run/systemd/journal").exists() && std::path::Path::new("/usr/bin/journalctl").exists()
}

/// `matches` are `FIELD=value` expressions; all are OR'd.
pub async fn run(matches: Vec<String>, tx: mpsc::Sender<Line>) -> anyhow::Result<()> {
    if matches.is_empty() {
        return Ok(());
    }
    let mut args: Vec<String> = vec![
        "--follow".into(),
        "--lines=0".into(),
        "--output=json".into(),
        "--no-pager".into(),
    ];
    for (i, m) in matches.iter().enumerate() {
        if i > 0 {
            args.push("+".into());
        }
        args.push(m.clone());
    }
    loop {
        tracing::info!(matches = matches.len(), "starting journalctl follower");
        let mut child = Command::new("journalctl")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| anyhow::anyhow!("cannot run journalctl: {e}"))?;
        let stdout = child.stdout.take().expect("piped");
        let mut lines = BufReader::with_capacity(64 * 1024, stdout).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if let Some(line) = parse_entry(&l) {
                if tx.send(line).await.is_err() {
                    return Ok(());
                }
            }
        }
        let st = child.wait().await?;
        tracing::warn!(status = %st, "journalctl exited; restarting in 5s");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

fn field(v: &serde_json::Value, k: &str) -> Option<Arc<str>> {
    v.get(k).and_then(|x| x.as_str()).map(Arc::from)
}

fn parse_entry(json: &str) -> Option<Line> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let text = match v.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        // Non-UTF-8 messages arrive as byte arrays.
        serde_json::Value::Array(bytes) => {
            let b: Vec<u8> = bytes.iter().filter_map(|x| x.as_u64()).map(|x| x as u8).collect();
            String::from_utf8_lossy(&b).into_owned()
        }
        _ => return None,
    };
    Some(Line {
        origin: Origin::Journal {
            unit: field(&v, "_SYSTEMD_UNIT"),
            identifier: field(&v, "SYSLOG_IDENTIFIER"),
            comm: field(&v, "_COMM"),
        },
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_json_entry() {
        let l = parse_entry(r#"{"MESSAGE":"Failed password for root from 1.2.3.4","SYSLOG_IDENTIFIER":"sshd","_SYSTEMD_UNIT":"sshd.service"}"#).unwrap();
        assert_eq!(l.text, "Failed password for root from 1.2.3.4");
        match l.origin {
            Origin::Journal { unit, identifier, .. } => {
                assert_eq!(unit.as_deref(), Some("sshd.service"));
                assert_eq!(identifier.as_deref(), Some("sshd"));
            }
            _ => panic!(),
        }
        let l = parse_entry(r#"{"MESSAGE":[104,105]}"#).unwrap();
        assert_eq!(l.text, "hi");
    }
}
