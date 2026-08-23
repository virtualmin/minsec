//! inotify-driven file follower with rotation handling.
//!
//! Watches the *parent directories* of configured paths (so files that do not
//! exist yet, and rotated-in replacements, are picked up), keeps one small
//! state per file, and never buffers more than one partial line per file.
//! A slow periodic poll backs up inotify for filesystems that do not deliver
//! events (NFS, some overlays) and for copytruncate rotation.

use super::{Line, Origin};
use futures_core::Stream;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::fs::File;
use std::future::poll_fn;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const READ_CHUNK: usize = 64 * 1024;
const MAX_LINE: usize = 16 * 1024;
/// Most bytes one `read_available` call consumes before handing what it has
/// to the channel. Without a budget a burst (or a large backlog on an inode we
/// are draining) would be materialised as one unbounded `Vec<Line>` before
/// backpressure applies. Files with more pending are re-polled immediately
/// after the flush.
const MAX_BATCH_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(2);

struct FileState {
    /// The configured pattern this file belongs to (used as routing key).
    pattern: Arc<str>,
    file: Option<File>,
    ino: u64,
    pos: u64,
    partial: Vec<u8>,
}

impl FileState {
    fn new(pattern: Arc<str>) -> Self {
        Self {
            pattern,
            file: None,
            ino: 0,
            pos: 0,
            partial: Vec::new(),
        }
    }
}

pub struct FileTailer {
    inotify: Option<Inotify>,
    dirs: HashMap<WatchDescriptor, PathBuf>,
    /// Configured patterns (may be globs) → parent dir.
    patterns: Vec<(Arc<str>, PathBuf)>,
    files: HashMap<PathBuf, FileState>,
    tx: mpsc::Sender<Line>,
    /// Start reading from the end of existing files (true) or the start.
    seek_end: bool,
    /// Set when a poll stopped at `MAX_BATCH_BYTES` with data still unread.
    backlog: bool,
}

impl FileTailer {
    pub fn new(
        patterns: impl IntoIterator<Item = String>,
        tx: mpsc::Sender<Line>,
        seek_end: bool,
    ) -> anyhow::Result<Self> {
        let inotify = Inotify::init()?;
        let mut t = Self {
            inotify: Some(inotify),
            dirs: HashMap::new(),
            patterns: Vec::new(),
            files: HashMap::new(),
            tx,
            seek_end,
            backlog: false,
        };
        for p in patterns {
            t.add_pattern(&p)?;
        }
        Ok(t)
    }

    fn add_pattern(&mut self, pattern: &str) -> anyhow::Result<()> {
        let path = Path::new(pattern);
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("/"))
            .to_path_buf();
        let key: Arc<str> = Arc::from(pattern);
        if !self.dirs.values().any(|d| *d == dir) {
            match self
                .inotify
                .as_ref()
                .expect("inotify present before run")
                .watches()
                .add(
                    &dir,
                    WatchMask::MODIFY
                        | WatchMask::CREATE
                        | WatchMask::MOVED_TO
                        | WatchMask::MOVED_FROM
                        | WatchMask::DELETE,
                ) {
                Ok(wd) => {
                    self.dirs.insert(wd, dir.clone());
                }
                Err(e) => tracing::warn!(dir = %dir.display(), "cannot watch directory ({e}); relying on polling"),
            }
        }
        self.patterns.push((key, dir));
        Ok(())
    }

    /// Expand globs and (re)open any files that now exist.
    fn rescan(&mut self) {
        let mut found: Vec<(PathBuf, Arc<str>)> = Vec::new();
        for (pat, _) in &self.patterns {
            if pat.contains(['*', '?', '[']) {
                if let Ok(paths) = glob::glob(pat) {
                    for p in paths.flatten() {
                        found.push((p, pat.clone()));
                    }
                }
            } else {
                found.push((PathBuf::from(&**pat), pat.clone()));
            }
        }
        for (path, pat) in found {
            self.files.entry(path).or_insert_with(|| FileState::new(pat));
        }
    }

    fn poll_all(&mut self, out: &mut Vec<Line>) {
        let paths: Vec<PathBuf> = self.files.keys().cloned().collect();
        for p in paths {
            self.poll_file(&p, out);
        }
    }

    fn poll_file(&mut self, path: &Path, out: &mut Vec<Line>) {
        let Some(st) = self.files.get_mut(path) else { return };
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => {
                if st.file.is_some() {
                    tracing::debug!(path = %path.display(), "file gone; waiting for it to reappear");
                    // Drain what remains of the old inode first.
                    while Self::read_available(st, path, out) {}
                }
                st.file = None;
                st.pos = 0;
                st.partial.clear();
                return;
            }
        };
        let rotated = st.file.is_some() && (meta.ino() != st.ino || meta.size() < st.pos);
        if rotated {
            tracing::debug!(path = %path.display(), "rotation detected");
            while Self::read_available(st, path, out) {}
            st.file = None;
            st.partial.clear();
        }
        if st.file.is_none() {
            match File::open(path) {
                Ok(mut f) => {
                    st.ino = meta.ino();
                    st.pos = if self.seek_end && !rotated {
                        f.seek(SeekFrom::End(0)).unwrap_or(0)
                    } else {
                        0
                    };
                    st.file = Some(f);
                    tracing::info!(path = %path.display(), offset = st.pos, "following");
                }
                Err(e) => {
                    tracing::debug!(path = %path.display(), "cannot open: {e}");
                    return;
                }
            }
        }
        if Self::read_available(st, path, out) {
            self.backlog = true;
        }
    }

    /// Read up to `MAX_BATCH_BYTES` of new data into `out`. Returns true if
    /// the budget was exhausted and more may be pending.
    fn read_available(st: &mut FileState, path: &Path, out: &mut Vec<Line>) -> bool {
        let Some(f) = st.file.as_mut() else { return false };
        let mut buf = vec![0u8; READ_CHUNK];
        let mut budget = MAX_BATCH_BYTES;
        loop {
            if budget == 0 {
                return true;
            }
            let want = budget.min(READ_CHUNK);
            let n = match f.read(&mut buf[..want]) {
                Ok(0) => return false,
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(path = %path.display(), "read error: {e}");
                    return false;
                }
            };
            budget -= n;
            st.pos += n as u64;
            let mut chunk = &buf[..n];
            while let Some(nl) = memchr::memchr(b'\n', chunk) {
                let line_bytes = &chunk[..nl];
                chunk = &chunk[nl + 1..];
                let text = if st.partial.is_empty() {
                    String::from_utf8_lossy(line_bytes).into_owned()
                } else {
                    st.partial.extend_from_slice(line_bytes);
                    let s = String::from_utf8_lossy(&st.partial).into_owned();
                    st.partial.clear();
                    s
                };
                out.push(Line {
                    origin: Origin::File(st.pattern.clone()),
                    text,
                });
            }
            if !chunk.is_empty() {
                if st.partial.len() + chunk.len() > MAX_LINE {
                    st.partial.clear(); // pathological line; drop it
                } else {
                    st.partial.extend_from_slice(chunk);
                }
            }
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut out: Vec<Line> = Vec::new();
        self.rescan();
        self.poll_all(&mut out);
        self.flush(&mut out).await?;
        let inotify = self.inotify.take().expect("run called once");
        let mut stream = inotify.into_event_stream([0u8; 4096])?;
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if std::mem::take(&mut self.backlog) {
                // A previous poll stopped at its byte budget; finish the
                // backlog before waiting for new events.
                self.poll_all(&mut out);
                self.flush(&mut out).await?;
                continue;
            }
            tokio::select! {
                ev = poll_fn(|cx| std::pin::Pin::new(&mut stream).poll_next(cx)) => {
                    let Some(ev) = ev else { anyhow::bail!("inotify stream ended") };
                    let ev = ev?;
                    let Some(dir) = self.dirs.get(&ev.wd).cloned() else { continue };
                    let Some(name) = ev.name.as_ref() else { continue };
                    let path = dir.join(name);
                    if ev.mask.intersects(EventMask::CREATE | EventMask::MOVED_TO) {
                        self.rescan();
                    }
                    if self.files.contains_key(&path) {
                        self.poll_file(&path, &mut out);
                    }
                }
                _ = tick.tick() => {
                    self.rescan();
                    self.poll_all(&mut out);
                }
            }
            self.flush(&mut out).await?;
        }
    }

    async fn flush(&self, out: &mut Vec<Line>) -> anyhow::Result<()> {
        for l in out.drain(..) {
            if self.tx.send(l).await.is_err() {
                anyhow::bail!("line channel closed");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A backlog larger than `MAX_BATCH_BYTES` is delivered in full, in order,
    /// through a small channel: the tailer must come back for the remainder
    /// on its own rather than waiting for another inotify event.
    #[test]
    fn large_backlog_is_delivered_in_bounded_batches() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let dir = tempdir("backlog");
            let log = dir.join("big.log");
            std::fs::write(&log, "").unwrap();
            let (tx, mut rx) = mpsc::channel(16);
            let tailer = FileTailer::new([log.to_string_lossy().into_owned()], tx, true).unwrap();
            tokio::task::spawn_local(tailer.run());
            tokio::time::sleep(Duration::from_millis(50)).await;

            // ~3 MiB in one burst: well over MAX_BATCH_BYTES.
            let total = 30_000;
            {
                let mut f = std::io::BufWriter::new(std::fs::OpenOptions::new().append(true).open(&log).unwrap());
                for i in 0..total {
                    writeln!(f, "line {i:06} {}", "x".repeat(90)).unwrap();
                }
            }
            for i in 0..total {
                let l = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                    .await
                    .expect("timed out waiting for backlog")
                    .unwrap();
                assert!(l.text.starts_with(&format!("line {i:06} ")), "got {:?}", &l.text[..12]);
            }
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn follows_appends_and_rotation_localset() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let dir = tempdir("rotate");
            let log = dir.join("test.log");
            std::fs::write(&log, "old line\n").unwrap();
            let (tx, mut rx) = mpsc::channel(64);
            let tailer = FileTailer::new([log.to_string_lossy().into_owned()], tx, true).unwrap();
            tokio::task::spawn_local(tailer.run());
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Append: partial then completed line.
            {
                let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
                f.write_all(b"first ").unwrap();
                f.write_all(b"line\nsecond line\n").unwrap();
            }
            let l1 = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(l1.text, "first line");
            let l2 = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(l2.text, "second line");

            // Rename rotation: new file read from the start.
            std::fs::rename(&log, dir.join("test.log.1")).unwrap();
            std::fs::write(&log, "after rotate\n").unwrap();
            let l3 = tokio::time::timeout(Duration::from_secs(4), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(l3.text, "after rotate");

            // copytruncate rotation: logrotate truncates, the writer appends later.
            std::fs::write(&log, "").unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            {
                let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
                f.write_all(b"after truncate\n").unwrap();
            }
            let l4 = tokio::time::timeout(Duration::from_secs(4), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(l4.text, "after truncate");
            std::fs::remove_dir_all(&dir).ok();
        });
    }

    fn tempdir(tag: &str) -> PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let d = base.join(format!("minsec-tail-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
