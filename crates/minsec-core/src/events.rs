//! Append-only JSONL event log: the daemon's only persistent state.
//! Consumed by `minsec events` and, later, by `minsec-sync`.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const ROTATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Event {
    Start {
        ts: u64,
        version: String,
    },
    Stop {
        ts: u64,
    },
    Ban {
        ts: u64,
        net: IpNet,
        filter: String,
        ttl: u64,
        hits: u32,
        escalation: u32,
        manual: bool,
    },
    Unban {
        ts: u64,
        net: IpNet,
        manual: bool,
    },
}

impl Event {
    pub fn ts(&self) -> u64 {
        match self {
            Event::Start { ts, .. } | Event::Stop { ts } | Event::Ban { ts, .. } | Event::Unban { ts, .. } => *ts,
        }
    }
}

pub struct EventLog {
    path: PathBuf,
    file: Option<File>,
    written: u64,
}

impl EventLog {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
            written,
        })
    }

    /// An event log that discards everything (tests, `minsec test`).
    pub fn sink() -> Self {
        Self {
            path: PathBuf::new(),
            file: None,
            written: 0,
        }
    }

    pub fn append(&mut self, ev: &Event) {
        let Some(f) = self.file.as_mut() else { return };
        let mut line = match serde_json::to_string(ev) {
            Ok(s) => s,
            Err(_) => return,
        };
        line.push('\n');
        if let Err(e) = f.write_all(line.as_bytes()) {
            tracing::warn!(path = %self.path.display(), "cannot write event: {e}");
            return;
        }
        self.written += line.len() as u64;
        if self.written >= ROTATE_BYTES {
            self.rotate();
        }
    }

    fn rotate(&mut self) {
        let old = self.path.with_extension("jsonl.1");
        if std::fs::rename(&self.path, &old).is_ok() {
            if let Ok(f) = OpenOptions::new().create(true).append(true).open(&self.path) {
                self.file = Some(f);
                self.written = 0;
            }
        }
    }

    /// Read all events (rotated file first), skipping malformed lines.
    pub fn read_all(path: &Path) -> Vec<Event> {
        let mut out = Vec::new();
        for p in [path.with_extension("jsonl.1"), path.to_path_buf()] {
            if let Ok(f) = File::open(&p) {
                for l in BufReader::new(f).lines().map_while(Result::ok) {
                    if let Ok(ev) = serde_json::from_str::<Event>(&l) {
                        out.push(ev);
                    }
                }
            }
        }
        out
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
