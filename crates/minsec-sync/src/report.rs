//! `minsec-sync report`: read new automatic bans from the events log,
//! normalize them to the wire rules, and submit signed batches.
//!
//! Sequence numbers: the server requires a strictly increasing `seq` per
//! agent and treats `seq <= last_seq` as an idempotent duplicate. We use
//! `max(stored next_seq, unix time)` so seq survives a lost or restored
//! state file without help from the server. If the server still reports a
//! duplicate (clock rollback), we jump a day ahead and retry once —
//! re-sending events is harmless (server-side votes are deduplicated per
//! reporter), losing them is not.
//!
//! The events cursor is only persisted after every batch was accepted, so
//! a failure mid-run re-sends from the old cursor next time.

use crate::client::{now_unix, Api};
use crate::config::Config;
use crate::events::{self, BanEvent};
use crate::state::{State, Store};
use ed25519_dalek::SigningKey;
use ipnet::IpNet;
use minsec_proto::types::{Report, ReportBatch};

/// Events older than this are dropped client-side; the server rejects at
/// 24 h and we leave an hour of margin.
const MAX_EVENT_AGE: u64 = 23 * 3600;
const SEQ_JUMP: u64 = 86_400;

fn agent_version() -> String {
    concat!("minsec-sync/", env!("CARGO_PKG_VERSION")).to_string()
}

fn valid_filter(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-')
}

/// Normalize one ban event to a wire report, or None if it is not
/// reportable. Mirrors the server's validation (internal/api/validate.go)
/// so nothing we send is rejected.
fn to_report(ev: &BanEvent, now: u64) -> Option<Report> {
    if ev.manual || ev.ts + MAX_EVENT_AGE < now || ev.ts > now + 60 {
        return None;
    }
    let net: IpNet = ev.net.parse().ok()?;
    let net = match net {
        IpNet::V4(v4) => {
            if v4.prefix_len() < 24 {
                return None;
            }
            IpNet::V4(v4)
        }
        IpNet::V6(v6) => {
            if v6.prefix_len() < 48 {
                return None;
            }
            if v6.prefix_len() > 64 {
                // Aggregate to /64: attackers rotate within allocations.
                IpNet::new(v6.addr().into(), 64).ok()?.trunc()
            } else {
                IpNet::V6(v6)
            }
        }
    };
    if !valid_filter(&ev.filter) {
        return None;
    }
    Some(Report {
        ts: ev.ts as i64,
        ip: net.trunc().to_string(),
        filter: ev.filter.clone(),
        count: ev.hits.max(1) as i64,
        ban_ttl: ev.ttl as i64,
    })
}

pub struct Outcome {
    pub sent: usize,
    pub skipped: usize,
    pub accepted: u64,
    pub rejected: u64,
}

pub fn run(cfg: &Config, api: &Api, store: &Store, state: &mut State, key: &SigningKey) -> anyhow::Result<Outcome> {
    let host_id = state.host_id.clone().ok_or_else(|| anyhow::anyhow!("not enrolled"))?;
    let new = events::read_new(&cfg.events, state.cursor)?;
    let now = now_unix();
    let reports: Vec<Report> = new.bans.iter().filter_map(|b| to_report(b, now)).collect();
    let mut out = Outcome {
        sent: reports.len(),
        skipped: new.bans.len() - reports.len(),
        accepted: 0,
        rejected: 0,
    };
    if reports.is_empty() {
        // Still advance past skipped/old events.
        state.cursor = Some(new.cursor);
        store.save_state(state)?;
        return Ok(out);
    }

    for chunk in reports.chunks(minsec_proto::MAX_BATCH_ITEMS) {
        let mut batch = ReportBatch {
            seq: state.next_seq.max(now_unix()),
            agent_version: agent_version(),
            reports: chunk.to_vec(),
        };
        let mut resp = api.submit(key, &host_id, &batch)?;
        if resp.duplicate {
            batch.seq += SEQ_JUMP;
            resp = api.submit(key, &host_id, &batch)?;
            if resp.duplicate {
                anyhow::bail!("server rejects our sequence numbers as duplicates; will retry next run");
            }
        }
        state.next_seq = batch.seq + 1;
        out.accepted += resp.accepted;
        out.rejected += resp.rejected;
        // Persist seq progress even though the cursor moves only at the
        // end: a crash between batches must not reuse a spent seq.
        store.save_state(state)?;
    }

    state.cursor = Some(new.cursor);
    store.save_state(state)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ban(ts: u64, net: &str, filter: &str) -> BanEvent {
        BanEvent {
            ts,
            net: net.into(),
            filter: filter.into(),
            ttl: 600,
            hits: 3,
            manual: false,
        }
    }

    #[test]
    fn normalization() {
        let now = 1_000_000_000;
        assert_eq!(
            to_report(&ban(now, "203.0.113.7/32", "sshd"), now).unwrap().ip,
            "203.0.113.7/32"
        );
        // v6 narrower than /64 aggregates to /64.
        let r = to_report(&ban(now, "2001:db8:1:2:3:4:5:6/128", "sshd"), now).unwrap();
        assert_eq!(r.ip, "2001:db8:1:2::/64");
        // Out-of-bounds prefixes are dropped.
        assert!(to_report(&ban(now, "10.0.0.0/8", "sshd"), now).is_none());
        assert!(to_report(&ban(now, "2001:db8::/32", "sshd"), now).is_none());
        // Old events and bad filters are dropped.
        assert!(to_report(&ban(now - MAX_EVENT_AGE - 1, "203.0.113.7/32", "sshd"), now).is_none());
        assert!(to_report(&ban(now, "203.0.113.7/32", "SSHD!"), now).is_none());
        assert!(to_report(&ban(now, "203.0.113.7/32", "postfix-sasl"), now).is_some());
    }
}
