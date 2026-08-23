//! Escape-hatch backend: run a user command for every ban/unban.
//! Invoked as `<command> ban <net> <ttl-seconds>` / `<command> unban <net>`.

use super::{Ban, Entry, Firewall};
use ipnet::IpNet;
use std::process::Command;

pub struct Exec {
    command: String,
}

impl Exec {
    pub fn new(command: String) -> Self {
        Self { command }
    }
    fn run(&self, args: &[String]) -> anyhow::Result<()> {
        let st = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{} \"$@\"", self.command))
            .arg("minsec")
            .args(args)
            .status()?;
        if !st.success() {
            anyhow::bail!("exec backend `{}` failed: {st}", self.command);
        }
        Ok(())
    }
}

impl Firewall for Exec {
    fn name(&self) -> &'static str {
        "exec"
    }
    fn setup(&mut self) -> anyhow::Result<()> {
        self.run(&["setup".into()])
    }
    fn ban(&mut self, bans: &[Ban]) -> anyhow::Result<()> {
        for b in bans {
            self.run(&["ban".into(), crate::ip::key_to_nft(&b.net), b.ttl.as_secs().to_string()])?;
        }
        Ok(())
    }
    fn unban(&mut self, nets: &[IpNet]) -> anyhow::Result<()> {
        for n in nets {
            self.run(&["unban".into(), crate::ip::key_to_nft(n)])?;
        }
        Ok(())
    }
    fn list(&mut self) -> anyhow::Result<Option<Vec<Entry>>> {
        Ok(None)
    }
    fn set_allow(&mut self, _nets: &[IpNet]) -> anyhow::Result<()> {
        Ok(())
    }
}
