//! Reading new automatic-ban events from the daemon's append-only
//! `events.jsonl`, resuming from a byte cursor and following the daemon's
//! single-file rotation (`events.jsonl` → `events.jsonl.1`).
//!
//! Events are parsed loosely (unknown fields and kinds ignored) so the two
//! binaries can be upgraded independently.

use crate::state::Cursor;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

/// An automatic ban worth reporting. Mirrors `minsec_core::events::Event::Ban`.
#[derive(Debug, Clone, Deserialize)]
pub struct BanEvent {
    pub ts: u64,
    pub net: String,
    pub filter: String,
    pub ttl: u64,
    pub hits: u32,
    #[serde(default)]
    pub manual: bool,
}

#[derive(Debug, Deserialize)]
struct Tagged {
    kind: String,
}

#[derive(Debug, Default)]
pub struct NewEvents {
    pub bans: Vec<BanEvent>,
    pub cursor: Cursor,
}

fn inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.ino())
}

/// Read events past `cursor`. Returns the bans plus the cursor to persist
/// once (and only once) every returned event has been accepted upstream.
pub fn read_new(path: &Path, cursor: Option<Cursor>) -> anyhow::Result<NewEvents> {
    let rotated = path.with_extension("jsonl.1");
    let Some(cur_ino) = inode(path) else {
        // No events file (daemon never ran): nothing to report, keep cursor.
        return Ok(NewEvents {
            bans: Vec::new(),
            cursor: cursor.unwrap_or_default(),
        });
    };

    let mut bans = Vec::new();
    let mut start = 0u64;
    match cursor {
        Some(c) if c.ino == cur_ino => start = c.offset,
        // The file we were reading was rotated away; finish it first if it
        // is still around as .jsonl.1.
        Some(c) if inode(&rotated) == Some(c.ino) => {
            read_bans_from(&rotated, c.offset, &mut bans)?;
        }
        _ => {}
    }
    // A cursor offset past EOF means the file was truncated/replaced with
    // the same inode; start over rather than reading nothing forever.
    if start > std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) {
        start = 0;
    }
    let end = read_bans_from(path, start, &mut bans)?;
    Ok(NewEvents {
        bans,
        cursor: Cursor {
            ino: cur_ino,
            offset: end,
        },
    })
}

/// Append ban events from `path` starting at byte `offset`; returns the
/// offset after the last complete line. A trailing line without `\n` is a
/// partial write and is left for the next run.
fn read_bans_from(path: &Path, offset: u64, out: &mut Vec<BanEvent>) -> anyhow::Result<u64> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => BufReader::new(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(offset),
        Err(e) => return Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
    };
    f.seek(SeekFrom::Start(offset))?;
    let mut pos = offset;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = f.read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') {
            break;
        }
        pos += n as u64;
        let Ok(text) = std::str::from_utf8(&line) else { continue };
        let Ok(tag) = serde_json::from_str::<Tagged>(text) else {
            continue;
        };
        if tag.kind != "ban" {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<BanEvent>(text) {
            if !ev.manual {
                out.push(ev);
            }
        }
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("minsec-events-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const BAN: &str = r#"{"kind":"ban","ts":100,"net":"203.0.113.7/32","filter":"sshd","ttl":600,"hits":5,"escalation":0,"manual":false}"#;
    const MANUAL: &str = r#"{"kind":"ban","ts":101,"net":"198.51.100.1/32","filter":"sshd","ttl":600,"hits":1,"escalation":0,"manual":true}"#;
    const START: &str = r#"{"kind":"start","ts":99,"version":"0.1.4"}"#;

    #[test]
    fn skips_manual_and_other_kinds_and_partial_lines() {
        let dir = tmpdir("basic");
        let path = dir.join("events.jsonl");
        std::fs::write(
            &path,
            format!("{START}\n{BAN}\n{MANUAL}\n{{\"kind\":\"ban\",\"truncated"),
        )
        .unwrap();

        let got = read_new(&path, None).unwrap();
        assert_eq!(got.bans.len(), 1);
        assert_eq!(got.bans[0].net, "203.0.113.7/32");
        assert_eq!(got.bans[0].hits, 5);
        // Cursor stops before the partial line.
        let complete = format!("{START}\n{BAN}\n{MANUAL}\n").len() as u64;
        assert_eq!(got.cursor.offset, complete);

        // Nothing new: same cursor, no bans.
        let again = read_new(&path, Some(got.cursor)).unwrap();
        assert!(again.bans.is_empty());
        assert_eq!(again.cursor, got.cursor);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn follows_rotation() {
        let dir = tmpdir("rotate");
        let path = dir.join("events.jsonl");
        std::fs::write(&path, format!("{BAN}\n")).unwrap();
        let first = read_new(&path, None).unwrap();
        assert_eq!(first.bans.len(), 1);

        // Rotate: old file renamed to .1 (keeps its inode), new file gets a
        // late event in the old file plus one in the new.
        std::fs::rename(&path, dir.join("events.jsonl.1")).unwrap();
        let mut old = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("events.jsonl.1"))
            .unwrap();
        writeln!(old, "{}", BAN.replace("203.0.113.7", "203.0.113.8")).unwrap();
        std::fs::write(&path, format!("{}\n", BAN.replace("203.0.113.7", "203.0.113.9"))).unwrap();

        let got = read_new(&path, Some(first.cursor)).unwrap();
        let nets: Vec<_> = got.bans.iter().map(|b| b.net.as_str()).collect();
        assert_eq!(nets, vec!["203.0.113.8/32", "203.0.113.9/32"]);

        // And the cursor now tracks the new file.
        let done = read_new(&path, Some(got.cursor)).unwrap();
        assert!(done.bans.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncation_resets() {
        let dir = tmpdir("trunc");
        let path = dir.join("events.jsonl");
        std::fs::write(&path, format!("{BAN}\n{BAN}\n")).unwrap();
        let first = read_new(&path, None).unwrap();
        assert_eq!(first.bans.len(), 2);

        std::fs::write(&path, format!("{BAN}\n")).unwrap(); // same inode, shorter
        let got = read_new(&path, Some(first.cursor)).unwrap();
        assert_eq!(got.bans.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
