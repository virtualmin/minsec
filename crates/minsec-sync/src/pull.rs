//! `minsec-sync pull`: fetch the crowd blocklist (ETag + delta aware) and
//! write it into the crowd4/crowd6 nftables sets.

use crate::client::{Api, FeedFetch};
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

    match api.pull_feed(&cfg.tier, fam, &cur.etag, cur.snapshot)? {
        FeedFetch::NotModified => Ok(Outcome {
            family,
            action: "unchanged",
            entries: 0,
            invalid: 0,
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
                        let FeedFetch::Body { text, etag: full_etag } = api.pull_feed(&cfg.tier, fam, "", 0)? else {
                            anyhow::bail!("server returned 304 to an unconditional feed request");
                        };
                        let full = Feed::parse(&text)?;
                        let o = apply_full(nft, family, &full)?;
                        state.feeds.insert(
                            key,
                            FeedCursor {
                                etag: full_etag,
                                snapshot: full.header.snapshot,
                            },
                        );
                        store.save_state(state)?;
                        return Ok(o);
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
            state.feeds.insert(key, FeedCursor { etag, snapshot });
            store.save_state(state)?;
            Ok(outcome)
        }
    }
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
    })
}
