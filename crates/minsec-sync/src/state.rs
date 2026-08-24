//! Persistent client state under the state dir: the Ed25519 key (`key`,
//! 0600, 32-byte seed) and `state.json` (host_id, report cursor, feed
//! cursors). State is written atomically (tmp + rename).

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// Inode of the events file the offset refers to.
    pub ino: u64,
    /// Byte offset of the first unconsumed line.
    pub offset: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedCursor {
    #[serde(default)]
    pub etag: String,
    #[serde(default)]
    pub snapshot: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub host_id: Option<String>,
    /// Next report batch sequence number (see report.rs for how this
    /// interacts with wall-clock time).
    #[serde(default)]
    pub next_seq: u64,
    #[serde(default)]
    pub cursor: Option<Cursor>,
    /// Keyed by "tier/family", e.g. "basic/v4".
    #[serde(default)]
    pub feeds: BTreeMap<String, FeedCursor>,
    #[serde(default)]
    pub min_report_interval: u64,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("cannot create {}: {e}", dir.display()))?;
        Ok(Self { dir: dir.to_path_buf() })
    }

    pub fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join("key")
    }

    pub fn load_state(&self) -> anyhow::Result<State> {
        match std::fs::read(self.state_path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("corrupt {}: {e}", self.state_path().display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(anyhow::anyhow!("cannot read {}: {e}", self.state_path().display())),
        }
    }

    pub fn save_state(&self, state: &State) -> anyhow::Result<()> {
        let tmp = self.dir.join("state.json.tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(state)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, self.state_path())?;
        Ok(())
    }

    /// Load the signing key, generating one on first use (file mode 0600).
    pub fn load_or_create_key(&self) -> anyhow::Result<SigningKey> {
        match std::fs::read(self.key_path()) {
            Ok(bytes) => {
                let seed: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("corrupt key file {}", self.key_path().display()))?;
                Ok(SigningKey::from_bytes(&seed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.create_key(),
            Err(e) => Err(anyhow::anyhow!("cannot read {}: {e}", self.key_path().display())),
        }
    }

    fn create_key(&self) -> anyhow::Result<SigningKey> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("cannot gather entropy: {e}"))?;
        self.write_key_file(&seed)?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Replace the key (used when the server knows the key but we lost the
    /// host_id). The old key is kept aside as `key.old`.
    pub fn rotate_key(&self) -> anyhow::Result<SigningKey> {
        let _ = std::fs::rename(self.key_path(), self.dir.join("key.old"));
        self.create_key()
    }

    fn write_key_file(&self, seed: &[u8; 32]) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = self.dir.join("key.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(seed)?;
        f.sync_all()?;
        std::fs::rename(&tmp, self.key_path())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip_and_key_persistence() {
        let dir = std::env::temp_dir().join(format!("minsec-sync-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();

        assert!(store.load_state().unwrap().host_id.is_none());
        let mut st = State {
            host_id: Some("abc".into()),
            next_seq: 7,
            ..Default::default()
        };
        st.feeds.insert(
            "basic/v4".into(),
            FeedCursor {
                etag: "\"s1\"".into(),
                snapshot: 1,
            },
        );
        store.save_state(&st).unwrap();
        let back = store.load_state().unwrap();
        assert_eq!(back.host_id.as_deref(), Some("abc"));
        assert_eq!(back.feeds["basic/v4"].snapshot, 1);

        let k1 = store.load_or_create_key().unwrap();
        let k2 = store.load_or_create_key().unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store.key_path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let k3 = store.rotate_key().unwrap();
        assert_ne!(k1.to_bytes(), k3.to_bytes());
        assert!(dir.join("key.old").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
