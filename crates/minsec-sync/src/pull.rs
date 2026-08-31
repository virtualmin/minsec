//! `minsec-sync pull`: fetch the crowd blocklist (ETag + delta aware) and
//! write it into the crowd4/crowd6 nftables sets.

use crate::client::{now_unix, Api, FeedFetch};
use crate::config::Config;
use crate::nft::{self, Nft};
use crate::state::{FeedCursor, State, Store};
use minsec_proto::feed::Feed;

pub struct Outcome {
    pub family: u8,
    /// "unchanged" | "full" | "delta"
    pub action: &'static str,
    pub entries: usize,
    pub invalid: usize,
    /// The full replace was forced to refresh the kernel timeout rather
    /// than because the server had something new.
    pub refresh: bool,
}

pub fn run(cfg: &Config, api: &Api, store: &Store, state: &mut State, nft: &Nft) -> anyhow::Result<Vec<Outcome>> {
    nft.ensure_sets()?;
    let mut outcomes = Vec::new();
    for family in [4u8, 6u8] {
        if (family == 4 && !cfg.ipv4) || (family == 6 && !cfg.ipv6) {
            continue;
        }
        outcomes.push(pull_family(cfg, api, store, state, nft, family)?);
    }
    state.last_pull_ok = now_unix();
    store.save_state(state)?;
    Ok(outcomes)
}

fn pull_family(
    cfg: &Config,
    api: &Api,
    store: &Store,
    state: &mut State,
    nft: &Nft,
    family: u8,
) -> anyhow::Result<Outcome> {
    let key = format!("{}/v{family}", cfg.tier);
    let fam = if family == 4 { "v4" } else { "v6" };
    let cur = state.feeds.get(&key).cloned().unwrap_or_default();
    let now = now_unix();

    // Crowd elements carry a kernel timeout (nft::CROWD_TIMEOUT) so that a
    // sync which stops running cannot enforce its last snapshot forever.
    // Only a full replace re-adds every element and so restarts that clock:
    // deltas touch what changed, and an unchanged feed touches nothing at
    // all. Once the refresh deadline passes, ask unconditionally so the
    // server cannot answer 304 and leave the set ageing out under us.
    if now.saturating_sub(cur.last_full) >= nft::FULL_REFRESH_SECS {
        // A first pull takes this path too, with nothing to refresh yet.
        let refresh = cur.last_full != 0;
        return fetch_full(cfg, api, store, state, nft, family, &key, fam, refresh);
    }

    match api.pull_feed(&cfg.tier, fam, &cur.etag, cur.snapshot)? {
        FeedFetch::NotModified => Ok(Outcome {
            family,
            action: "unchanged",
            entries: 0,
            invalid: 0,
            refresh: false,
        }),
        FeedFetch::Body { text, etag } => {
            let feed = Feed::parse(&text)?;
            if feed.header.family != family {
                anyhow::bail!("server sent family {} for a v{family} request", feed.header.family);
            }
            let outcome = if feed.header.kind == "delta" {
                match apply_delta(nft, family, &feed) {
                    Ok(o) => o,
                    Err(e) => {
                        // A delta that no longer matches our set contents
                        // (missed pull, manual edits): resync from a full
                        // fetch instead of failing.
                        eprintln!("minsec-sync: delta for v{family} failed ({e:#}); refetching full feed");
                        return fetch_full(cfg, api, store, state, nft, family, &key, fam, false);
                    }
                }
            } else {
                apply_full(nft, family, &feed)?
            };
            let snapshot = if feed.header.kind == "delta" {
                feed.header.to
            } else {
                feed.header.snapshot
            };
            // A full listing arriving through the conditional path replaces
            // the set just the same, so it restarts the timeout clock too.
            let last_full = if outcome.action == "full" { now } else { cur.last_full };
            state.feeds.insert(
                key,
                FeedCursor {
                    etag,
                    snapshot,
                    last_full,
                },
            );
            store.save_state(state)?;
            Ok(outcome)
        }
    }
}

/// Fetch the whole listing unconditionally and replace the set with it.
#[allow(clippy::too_many_arguments)]
fn fetch_full(
    cfg: &Config,
    api: &Api,
    store: &Store,
    state: &mut State,
    nft: &Nft,
    family: u8,
    key: &str,
    fam: &str,
    refresh: bool,
) -> anyhow::Result<Outcome> {
    let FeedFetch::Body { text, etag } = api.pull_feed(&cfg.tier, fam, "", 0)? else {
        anyhow::bail!("server returned 304 to an unconditional feed request");
    };
    let feed = Feed::parse(&text)?;
    if feed.header.family != family {
        anyhow::bail!("server sent family {} for a v{family} request", feed.header.family);
    }
    let mut o = apply_full(nft, family, &feed)?;
    o.refresh = refresh;
    state.feeds.insert(
        key.to_string(),
        FeedCursor {
            etag,
            snapshot: feed.header.snapshot,
            last_full: now_unix(),
        },
    );
    store.save_state(state)?;
    Ok(o)
}

fn apply_full(nft: &Nft, family: u8, feed: &Feed) -> anyhow::Result<Outcome> {
    let mut invalid = 0usize;
    let nets: Vec<_> = feed
        .entries
        .iter()
        .filter_map(|e| {
            let net = nft::parse_entry(e, family);
            if net.is_none() {
                invalid += 1;
            }
            net
        })
        .collect();
    nft.replace(family, &nets)?;
    Ok(Outcome {
        family,
        action: "full",
        entries: nets.len(),
        invalid,
        refresh: false,
    })
}

fn apply_delta(nft: &Nft, family: u8, feed: &Feed) -> anyhow::Result<Outcome> {
    let mut invalid = 0usize;
    let mut parse = |entries: &[String]| -> Vec<_> {
        entries
            .iter()
            .filter_map(|e| {
                let net = nft::parse_entry(e, family);
                if net.is_none() {
                    invalid += 1;
                }
                net
            })
            .collect()
    };
    let added = parse(&feed.added);
    let removed = parse(&feed.removed);
    nft.apply_delta(family, &added, &removed)?;
    Ok(Outcome {
        family,
        action: "delta",
        entries: added.len() + removed.len(),
        invalid,
        refresh: false,
    })
}
