//! journald source.
//!
//! Preferred path: the `sd_journal` API from `libsystemd.so.0`, loaded with
//! `dlopen` at runtime so the binary has no link-time dependency on systemd
//! and still runs on hosts without it. Server-side matches mean we are only
//! woken for entries from the units/identifiers our filters declare, and the
//! journal's inotify fd plugs straight into the event loop.
//!
//! Fallback: a `journalctl --follow -o json` subprocess with the same matches
//! (for static builds, or if the library cannot be loaded).

use super::{Line, Origin};
use std::sync::Arc;
use tokio::sync::mpsc;

pub fn available() -> bool {
    std::path::Path::new("/run/systemd/journal").exists()
}

/// `matches` are `FIELD=value` expressions; all are OR'd.
pub async fn run(matches: Vec<String>, tx: mpsc::Sender<Line>) -> anyhow::Result<()> {
    if matches.is_empty() {
        return Ok(());
    }
    match native::Journal::open(&matches) {
        Ok(j) => {
            tracing::info!(matches = matches.len(), "following journal via libsystemd");
            native::run(j, tx).await
        }
        Err(e) => {
            tracing::warn!("libsystemd unavailable ({e}); falling back to journalctl");
            subprocess::run(matches, tx).await
        }
    }
}

fn field(v: &serde_json::Value, k: &str) -> Option<Arc<str>> {
    v.get(k).and_then(|x| x.as_str()).map(Arc::from)
}

mod native {
    use super::{Line, Origin};
    use libloading::{Library, Symbol};
    use std::ffi::{c_char, c_int, c_void};
    use std::os::fd::{BorrowedFd, RawFd};
    use std::sync::Arc;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    use tokio::sync::mpsc;

    const SD_JOURNAL_LOCAL_ONLY: c_int = 1 << 0;
    const SD_JOURNAL_INVALIDATE: c_int = 2;
    /// Entries per `drain` before handing the batch to the channel, so a
    /// journal burst is not materialised as one unbounded `Vec<Line>`.
    const MAX_BATCH: usize = 4096;

    type SdJournal = c_void;

    #[allow(non_snake_case)]
    struct Api {
        open: unsafe extern "C" fn(*mut *mut SdJournal, c_int) -> c_int,
        close: unsafe extern "C" fn(*mut SdJournal),
        add_match: unsafe extern "C" fn(*mut SdJournal, *const c_void, usize) -> c_int,
        add_disjunction: unsafe extern "C" fn(*mut SdJournal) -> c_int,
        seek_tail: unsafe extern "C" fn(*mut SdJournal) -> c_int,
        previous: unsafe extern "C" fn(*mut SdJournal) -> c_int,
        next: unsafe extern "C" fn(*mut SdJournal) -> c_int,
        get_data: unsafe extern "C" fn(*mut SdJournal, *const c_char, *mut *const c_void, *mut usize) -> c_int,
        get_fd: unsafe extern "C" fn(*mut SdJournal) -> c_int,
        get_events: unsafe extern "C" fn(*mut SdJournal) -> c_int,
        process: unsafe extern "C" fn(*mut SdJournal) -> c_int,
        _lib: Library,
    }

    impl Api {
        fn load() -> anyhow::Result<Self> {
            // SAFETY: loading libsystemd runs its constructors, which is what
            // any systemd-linked program does at startup.
            let lib = unsafe { Library::new("libsystemd.so.0") }
                .map_err(|e| anyhow::anyhow!("cannot load libsystemd.so.0: {e}"))?;
            macro_rules! sym {
                ($name:literal) => {{
                    // SAFETY: signatures match the documented sd-journal(3) API.
                    let s: Symbol<_> = unsafe { lib.get(concat!($name, "\0").as_bytes()) }
                        .map_err(|e| anyhow::anyhow!("{}: {e}", $name))?;
                    *s
                }};
            }
            Ok(Self {
                open: sym!("sd_journal_open"),
                close: sym!("sd_journal_close"),
                add_match: sym!("sd_journal_add_match"),
                add_disjunction: sym!("sd_journal_add_disjunction"),
                seek_tail: sym!("sd_journal_seek_tail"),
                previous: sym!("sd_journal_previous"),
                next: sym!("sd_journal_next"),
                get_data: sym!("sd_journal_get_data"),
                get_fd: sym!("sd_journal_get_fd"),
                get_events: sym!("sd_journal_get_events"),
                process: sym!("sd_journal_process"),
                _lib: lib,
            })
        }
    }

    pub struct Journal {
        api: Api,
        j: *mut SdJournal,
        fd: RawFd,
    }

    fn check(rc: c_int, what: &str) -> anyhow::Result<c_int> {
        if rc < 0 {
            anyhow::bail!("{what}: {}", std::io::Error::from_raw_os_error(-rc));
        }
        Ok(rc)
    }

    impl Journal {
        pub fn open(matches: &[String]) -> anyhow::Result<Self> {
            let api = Api::load()?;
            let mut j: *mut SdJournal = std::ptr::null_mut();
            // SAFETY: FFI calls with valid pointers; `j` is owned by this struct
            // and closed on drop.
            unsafe {
                check((api.open)(&mut j, SD_JOURNAL_LOCAL_ONLY), "sd_journal_open")?;
                let mut this = Self { api, j, fd: -1 };
                for m in matches {
                    check(
                        (this.api.add_match)(j, m.as_ptr() as *const c_void, m.len()),
                        "sd_journal_add_match",
                    )?;
                    // Matches on the same field OR, on different fields AND;
                    // a disjunction after each makes every selector an OR.
                    check((this.api.add_disjunction)(j), "sd_journal_add_disjunction")?;
                }
                check((this.api.seek_tail)(j), "sd_journal_seek_tail")?;
                // After seek_tail the cursor sits past the last entry; step
                // back onto it so the first `next` yields only new entries.
                (this.api.previous)(j);
                this.fd = check((this.api.get_fd)(j), "sd_journal_get_fd")?;
                Ok(this)
            }
        }

        fn get(&self, field: &'static str) -> Option<String> {
            let mut data: *const c_void = std::ptr::null();
            let mut len: usize = 0;
            // SAFETY: `field` is NUL-terminated; data/len are out-params valid
            // until the next cursor move, and we copy immediately.
            let rc = unsafe { (self.api.get_data)(self.j, field.as_ptr() as *const c_char, &mut data, &mut len) };
            if rc < 0 || data.is_null() {
                return None;
            }
            let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
            // Value is `FIELD=value`.
            let eq = bytes.iter().position(|&b| b == b'=')?;
            Some(String::from_utf8_lossy(&bytes[eq + 1..]).into_owned())
        }

        /// Drain up to `MAX_BATCH` new entries into `out`. Returns true if
        /// the batch filled up and more entries may be pending, so the caller
        /// should flush and drain again without waiting on the fd. Journal
        /// invalidation (files rotated) is just logged; the cursor stays valid.
        fn drain(&self, out: &mut Vec<Line>) -> anyhow::Result<bool> {
            let ev = unsafe { (self.api.process)(self.j) };
            check(ev, "sd_journal_process")?;
            if ev == SD_JOURNAL_INVALIDATE {
                tracing::debug!("journal files changed");
            }
            let mut n = 0;
            loop {
                if n >= MAX_BATCH {
                    return Ok(true);
                }
                let rc = check(unsafe { (self.api.next)(self.j) }, "sd_journal_next")?;
                if rc == 0 {
                    break;
                }
                n += 1;
                let Some(text) = self.get("MESSAGE\0") else { continue };
                out.push(Line {
                    origin: Origin::Journal {
                        unit: self.get("_SYSTEMD_UNIT\0").map(Arc::from),
                        identifier: self.get("SYSLOG_IDENTIFIER\0").map(Arc::from),
                        comm: self.get("_COMM\0").map(Arc::from),
                        uid: self.get("_UID\0").and_then(|u| u.parse().ok()),
                    },
                    text,
                });
            }
            Ok(false)
        }
    }

    impl Drop for Journal {
        fn drop(&mut self) {
            // SAFETY: `j` came from sd_journal_open and is closed exactly once.
            unsafe { (self.api.close)(self.j) }
        }
    }

    pub async fn run(j: Journal, tx: mpsc::Sender<Line>) -> anyhow::Result<()> {
        // SAFETY: the fd is owned by the journal object, which outlives the loop.
        let fd = unsafe { BorrowedFd::borrow_raw(j.fd) };
        let events = unsafe { (j.api.get_events)(j.j) };
        let interest = if events & (libc::POLLOUT as c_int) != 0 {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        let afd = AsyncFd::with_interest(fd, interest)?;
        let mut out = Vec::new();
        // Entries written between open and now.
        let mut more = j.drain(&mut out)?;
        loop {
            for l in out.drain(..) {
                if tx.send(l).await.is_err() {
                    return Ok(());
                }
            }
            if !more {
                let mut guard = afd.readable().await?;
                guard.clear_ready();
            }
            more = j.drain(&mut out)?;
        }
    }
}

mod subprocess {
    use super::{field, Line, Origin};
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;
    use tokio::sync::mpsc;

    pub async fn run(matches: Vec<String>, tx: mpsc::Sender<Line>) -> anyhow::Result<()> {
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

    pub(super) fn parse_entry(json: &str) -> Option<Line> {
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
                uid: v.get("_UID").and_then(|x| x.as_str()).and_then(|u| u.parse().ok()),
            },
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_json_entry() {
        let l = subprocess::parse_entry(
            r#"{"MESSAGE":"Failed password for root from 1.2.3.4","SYSLOG_IDENTIFIER":"sshd","_SYSTEMD_UNIT":"sshd.service","_UID":"0"}"#,
        )
        .unwrap();
        assert_eq!(l.text, "Failed password for root from 1.2.3.4");
        match l.origin {
            Origin::Journal {
                unit, identifier, uid, ..
            } => {
                assert_eq!(unit.as_deref(), Some("sshd.service"));
                assert_eq!(identifier.as_deref(), Some("sshd"));
                assert_eq!(uid, Some(0));
            }
            _ => panic!(),
        }
        let l = subprocess::parse_entry(r#"{"MESSAGE":[104,105]}"#).unwrap();
        assert_eq!(l.text, "hi");
    }

    /// Opens the real journal if this host has one (no entries expected).
    #[test]
    fn native_opens_when_available() {
        if !available() {
            return;
        }
        match native::Journal::open(&["SYSLOG_IDENTIFIER=minsec-test-nonexistent".into()]) {
            Ok(_) => {}
            Err(e) => eprintln!("native journal unavailable here: {e}"),
        }
    }
}
