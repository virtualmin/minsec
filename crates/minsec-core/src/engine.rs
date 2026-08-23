//! The engine: routes lines to filters, tracks failures, applies policy, and
//! drives the firewall backend. Single-threaded; no log text is retained.

use crate::backend::{Ban, Firewall};
use crate::config::{Config, Policy};
use crate::control::{BanInfo, FilterStatus, Status};
use crate::events::{Event, EventLog};
use crate::filter::{CompiledFilter, JournalSelector};
use crate::source::{Line, Origin};
use crate::tracker::{TrackKey, Tracker, Verdict};
use ipnet::IpNet;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// Highest UID treated as a system account for journal provenance. Matches
/// the `SYS_UID_MAX` default on every major distribution (`login.defs`).
const SYSTEM_UID_MAX: u32 = 999;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct LoadedFilter {
    pub filter: CompiledFilter,
    pub policy: Policy,
    pub via_journal: bool,
    pub matched: u64,
    pub banned: u64,
}

#[derive(Clone, Copy)]
struct BanHistory {
    count: u32,
    last: u32,
}

#[derive(Clone)]
struct ActiveBan {
    until: u32,
    filter: Option<u16>,
}

pub struct Engine {
    pub cfg: Config,
    pub filters: Vec<LoadedFilter>,
    routes_file: HashMap<Arc<str>, Vec<u16>>,
    routes_journal: Vec<(JournalSelector, u16)>,
    tracker: Tracker,
    history: HashMap<IpNet, BanHistory>,
    active: BTreeMap<IpNet, ActiveBan>,
    backend: Box<dyn Firewall>,
    allow: Vec<IpNet>,
    events: EventLog,
    started: Instant,
    pub lines: u64,
    pub bans_total: u64,
    last_sweep: u32,
}

pub struct Decision {
    pub filter: u16,
    pub net: IpNet,
    pub banned: bool,
    pub hits: u32,
}

/// True if the two networks share any address.
fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(b) || b.contains(a)
}

impl Engine {
    pub fn new(cfg: Config, backend: Box<dyn Firewall>, events: EventLog) -> anyhow::Result<Self> {
        let mut filters = Vec::new();
        let mut routes_file: HashMap<Arc<str>, Vec<u16>> = HashMap::new();
        let mut routes_journal = Vec::new();
        let use_journal = cfg.defaults.journal && crate::source::journal::available();
        for name in cfg.enabled_filters() {
            let def = cfg.filter_def(name)?;
            let policy = cfg.policy_for(name, &def);
            let idx = filters.len() as u16;
            let journal_selected = use_journal && !def.journal.is_empty();
            if journal_selected {
                routes_journal.push((def.journal.clone(), idx));
            } else {
                for f in &def.files {
                    routes_file.entry(Arc::from(f.as_str())).or_default().push(idx);
                }
                if def.files.is_empty() {
                    tracing::warn!(
                        filter = name,
                        "no log files and journald not available; filter is inert"
                    );
                }
            }
            let filter = CompiledFilter::compile(def)?;
            filters.push(LoadedFilter {
                filter,
                policy,
                via_journal: journal_selected,
                matched: 0,
                banned: 0,
            });
        }
        let mut allow: Vec<IpNet> = cfg.defaults.allow.clone();
        allow.extend(
            crate::ip::local_addresses()
                .into_iter()
                .filter(|ip| !ip.is_unspecified())
                .map(IpNet::from),
        );
        allow.sort();
        allow.dedup();
        let tracker = Tracker::new(cfg.defaults.max_tracked);
        Ok(Self {
            cfg,
            filters,
            routes_file,
            routes_journal,
            tracker,
            history: HashMap::new(),
            active: BTreeMap::new(),
            backend,
            allow,
            events,
            started: Instant::now(),
            lines: 0,
            bans_total: 0,
            last_sweep: 0,
        })
    }

    pub fn file_patterns(&self) -> Vec<String> {
        self.routes_file.keys().map(|k| k.to_string()).collect()
    }

    pub fn journal_matches(&self) -> Vec<String> {
        let mut v: Vec<String> = self.routes_journal.iter().flat_map(|(s, _)| s.matches()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Prepare the backend and reconcile our mirror with what it already holds.
    pub fn start(&mut self, now: u32) -> anyhow::Result<()> {
        self.backend.setup()?;
        self.backend.set_allow(&self.allow)?;
        if let Some(existing) = self.backend.list()? {
            for e in existing {
                let until = now.saturating_add(e.expires_in.map(|d| d.as_secs() as u32).unwrap_or(u32::MAX - now));
                self.active.insert(e.net, ActiveBan { until, filter: None });
            }
        }
        // Rebuild escalation history from the event log.
        let memory = self.cfg.defaults.escalate.memory.secs();
        let cutoff = (now as u64).saturating_sub(memory);
        let path = self.cfg.paths.state_dir.join("events.jsonl");
        for ev in EventLog::read_all(&path) {
            if let Event::Ban {
                ts, net, manual: false, ..
            } = ev
            {
                if ts >= cutoff {
                    let h = self.history.entry(net).or_insert(BanHistory { count: 0, last: 0 });
                    h.count += 1;
                    h.last = ts as u32;
                }
            }
        }
        tracing::info!(
            backend = self.backend.name(),
            filters = self.filters.len(),
            active_bans = self.active.len(),
            history = self.history.len(),
            "engine started"
        );
        self.events.append(&Event::Start {
            ts: now as u64,
            version: VERSION.into(),
        });
        Ok(())
    }

    pub fn stop(&mut self, now: u32) {
        self.events.append(&Event::Stop { ts: now as u64 });
    }

    fn is_allowed(&self, ip: IpAddr) -> bool {
        crate::ip::is_loopback_or_unspecified(ip) || self.allow.iter().any(|n| n.contains(&ip))
    }

    fn filters_for(&self, origin: &Origin) -> Vec<u16> {
        match origin {
            Origin::File(p) => self.routes_file.get(p).cloned().unwrap_or_default(),
            Origin::Journal {
                unit,
                identifier,
                comm,
                uid,
            } => self
                .routes_journal
                .iter()
                .filter(|(sel, _)| {
                    // `_SYSTEMD_UNIT` is assigned by journald from the sender's
                    // cgroup and cannot be forged, so it is sufficient alone.
                    if unit.as_deref().is_some_and(|u| sel.units.iter().any(|x| x == u)) {
                        return true;
                    }
                    // `SYSLOG_IDENTIFIER` and `_COMM` are sender-chosen: any
                    // local user can `logger -t sshd 'Failed password ...'`
                    // and have a victim address banned. Only honour them from
                    // system accounts (the services we watch all run as
                    // root or a dedicated daemon user); fail closed when
                    // journald did not record a sender UID.
                    let trusted = uid.is_some_and(|u| u <= SYSTEM_UID_MAX);
                    trusted
                        && (identifier
                            .as_deref()
                            .is_some_and(|i| sel.identifiers.iter().any(|x| x == i))
                            || comm.as_deref().is_some_and(|c| sel.comm.iter().any(|x| x == c)))
                })
                .map(|(_, i)| *i)
                .collect(),
        }
    }

    /// Process one line. Returns decisions for every filter that matched.
    pub fn handle_line(&mut self, line: &Line, now: u32) -> Vec<Decision> {
        self.lines += 1;
        let mut out = Vec::new();
        let from_file = matches!(line.origin, Origin::File(_));
        for idx in self.filters_for(&line.origin) {
            let Some(m) = self.filters[idx as usize].filter.match_line_opts(&line.text, from_file) else {
                continue;
            };
            if let Some(d) = self.record_hit(idx, m.ip, now) {
                out.push(d);
            }
        }
        if now.saturating_sub(self.last_sweep) >= 60 {
            self.tick(now);
        }
        out
    }

    fn record_hit(&mut self, idx: u16, ip: IpAddr, now: u32) -> Option<Decision> {
        if self.is_allowed(ip) {
            tracing::debug!(%ip, "hit from allowed address ignored");
            return None;
        }
        let net = crate::ip::to_key(ip, self.cfg.defaults.ipv6_prefix);
        // IPv6 hosts are widened to `ipv6_prefix` (a /64 by default) and the
        // *network* is what the backend bans. Checking only the host above
        // would let an attacker sharing a /64 with an allowlisted address get
        // that whole prefix dropped on backends that have no allow set of
        // their own (`exec`). Never ban a network that overlaps the allowlist.
        if self.allow.iter().any(|a| overlaps(a, &net)) {
            tracing::debug!(%ip, %net, "ban network overlaps allowlist; ignored");
            return None;
        }
        let lf = &mut self.filters[idx as usize];
        lf.matched += 1;
        if self.active.get(&net).is_some_and(|b| b.until > now) {
            // Already banned (traffic that slipped through before the drop took
            // effect, or a port we do not cover). Nothing to do.
            return Some(Decision {
                filter: idx,
                net,
                banned: false,
                hits: 0,
            });
        }
        let (findtime, maxretry) = (lf.policy.findtime, lf.policy.maxretry);
        match self.tracker.hit(TrackKey { filter: idx, net }, now, findtime, maxretry) {
            Verdict::Below { hits } => Some(Decision {
                filter: idx,
                net,
                banned: false,
                hits,
            }),
            Verdict::Ban { hits } => {
                self.apply_ban(idx, net, hits, now);
                Some(Decision {
                    filter: idx,
                    net,
                    banned: true,
                    hits,
                })
            }
        }
    }

    fn escalated_ttl(&self, base: Duration, net: &IpNet, now: u32) -> (Duration, u32) {
        let Some(esc) = self
            .cfg
            .defaults
            .escalate_enabled
            .then_some(&self.cfg.defaults.escalate)
        else {
            return (base, 0);
        };
        let Some(h) = self.history.get(net) else {
            return (base, 0);
        };
        if (now.saturating_sub(h.last) as u64) > esc.memory.secs() {
            return (base, 0);
        }
        let mut secs = base.as_secs();
        for _ in 0..h.count.min(32) {
            secs = secs.saturating_mul(esc.factor as u64);
            if secs >= esc.max.secs() {
                secs = esc.max.secs();
                break;
            }
        }
        (Duration::from_secs(secs.max(base.as_secs())), h.count)
    }

    fn apply_ban(&mut self, idx: u16, net: IpNet, hits: u32, now: u32) {
        let base = self.filters[idx as usize].policy.bantime;
        let (ttl, escalation) = self.escalated_ttl(base, &net, now);
        let name = self.filters[idx as usize].filter.name().to_string();
        if let Err(e) = self.backend.ban(&[Ban { net, ttl }]) {
            tracing::error!(%net, filter = %name, "backend ban failed: {e}");
            return;
        }
        self.filters[idx as usize].banned += 1;
        self.bans_total += 1;
        self.active.insert(
            net,
            ActiveBan {
                until: now.saturating_add(ttl.as_secs() as u32),
                filter: Some(idx),
            },
        );
        if !self.history.contains_key(&net) {
            self.trim_history();
        }
        let h = self.history.entry(net).or_insert(BanHistory { count: 0, last: now });
        h.count += 1;
        h.last = now;
        tracing::info!(target: "minsec::ban", %net, filter = %name, hits, ttl = %crate::duration::format(ttl), escalation, "ban");
        self.events.append(&Event::Ban {
            ts: now as u64,
            net,
            filter: name,
            ttl: ttl.as_secs(),
            hits,
            escalation,
            manual: false,
        });
    }

    pub fn manual_ban(&mut self, net: IpNet, ttl: Option<Duration>, now: u32) -> anyhow::Result<()> {
        if self.allow.iter().any(|a| overlaps(a, &net)) || crate::ip::is_loopback_or_unspecified(net.addr()) {
            anyhow::bail!("{net} is on the allow list (or local); refusing to ban");
        }
        let ttl = ttl.unwrap_or(self.cfg.defaults.bantime.0);
        self.backend.ban(&[Ban { net, ttl }])?;
        self.bans_total += 1;
        self.active.insert(
            net,
            ActiveBan {
                until: now.saturating_add(ttl.as_secs() as u32),
                filter: None,
            },
        );
        tracing::info!(target: "minsec::ban", %net, ttl = %crate::duration::format(ttl), "manual ban");
        self.events.append(&Event::Ban {
            ts: now as u64,
            net,
            filter: "manual".into(),
            ttl: ttl.as_secs(),
            hits: 0,
            escalation: 0,
            manual: true,
        });
        Ok(())
    }

    pub fn unban(&mut self, net: IpNet, now: u32) -> anyhow::Result<()> {
        self.backend.unban(&[net])?;
        self.active.remove(&net);
        for i in 0..self.filters.len() {
            self.tracker.forget(&TrackKey { filter: i as u16, net });
        }
        tracing::info!(target: "minsec::ban", %net, "unban");
        self.events.append(&Event::Unban {
            ts: now as u64,
            net,
            manual: true,
        });
        Ok(())
    }

    /// Periodic housekeeping: expire mirror entries, sweep idle trackers,
    /// forget stale ban history.
    pub fn tick(&mut self, now: u32) {
        self.last_sweep = now;
        self.active.retain(|_, b| b.until > now);
        let idle = self
            .filters
            .iter()
            .map(|f| f.policy.findtime)
            .max()
            .unwrap_or(Duration::from_secs(600));
        let dropped = self.tracker.sweep(now, idle);
        let memory = self.cfg.defaults.escalate.memory.secs() as u32;
        self.history.retain(|_, h| now.saturating_sub(h.last) <= memory);
        self.trim_history();
        if dropped > 0 {
            tracing::debug!(dropped, tracked = self.tracker.len(), "tracker sweep");
        }
        if self.active.len() > self.cfg.defaults.max_tracked {
            // Not capped: every entry is a live ban and dropping it would
            // silently unprotect the host. Make saturation visible instead.
            tracing::warn!(
                active = self.active.len(),
                max_tracked = self.cfg.defaults.max_tracked,
                "active bans exceed max_tracked; consider a shorter bantime or wider ipv6_prefix"
            );
        }
    }

    /// Keep escalation history within `max_tracked` entries so a long
    /// `escalate.memory` window cannot turn high-cardinality bans into
    /// unbounded daemon memory. Oldest entries go first, in a batch, so the
    /// O(n) scan is amortised the same way as [`Tracker`] eviction.
    fn trim_history(&mut self) {
        let cap = self.cfg.defaults.max_tracked.max(16);
        if self.history.len() < cap {
            return;
        }
        let keep = cap - (cap / 32).max(1);
        let drop = self.history.len() - keep;
        let mut all: Vec<(u32, IpNet)> = self.history.iter().map(|(n, h)| (h.last, *n)).collect();
        all.select_nth_unstable_by_key(drop - 1, |e| e.0);
        for (_, n) in &all[..drop] {
            self.history.remove(n);
        }
        tracing::debug!(
            dropped = drop,
            history = self.history.len(),
            "escalation history trimmed"
        );
    }

    pub fn status(&mut self, now: u32) -> Status {
        self.active.retain(|_, b| b.until > now);
        Status {
            version: VERSION.into(),
            backend: self.backend.name().into(),
            uptime: self.started.elapsed().as_secs(),
            tracked: self.tracker.len(),
            lines: self.lines,
            bans_total: self.bans_total,
            active_bans: self.active.len(),
            filters: self
                .filters
                .iter()
                .map(|f| FilterStatus {
                    name: f.filter.name().into(),
                    files: f.filter.def.files.clone(),
                    journal: f.via_journal,
                    maxretry: f.policy.maxretry,
                    findtime: f.policy.findtime.as_secs(),
                    bantime: f.policy.bantime.as_secs(),
                    matched: f.matched,
                    banned: f.banned,
                })
                .collect(),
        }
    }

    /// Active bans. Asks the backend (kernel truth) when it can enumerate,
    /// enriched with the filter name from our mirror.
    pub fn list(&mut self, now: u32) -> anyhow::Result<Vec<BanInfo>> {
        let filter_name = |e: &Engine, net: &IpNet| {
            e.active
                .get(net)
                .and_then(|b| b.filter)
                .map(|i| e.filters[i as usize].filter.name().to_string())
        };
        if let Some(entries) = self.backend.list()? {
            let mut out: Vec<BanInfo> = entries
                .iter()
                .map(|e| BanInfo {
                    net: e.net,
                    expires_in: e.expires_in.map(|d| d.as_secs()),
                    filter: filter_name(self, &e.net),
                })
                .collect();
            out.sort_by_key(|b| b.net);
            // Kernel truth: drop mirror entries the kernel no longer has.
            let kernel: std::collections::HashSet<IpNet> = entries.iter().map(|e| e.net).collect();
            self.active.retain(|n, _| kernel.contains(n));
            return Ok(out);
        }
        self.active.retain(|_, b| b.until > now);
        Ok(self
            .active
            .iter()
            .map(|(net, b)| BanInfo {
                net: *net,
                expires_in: Some((b.until - now) as u64),
                filter: b.filter.map(|i| self.filters[i as usize].filter.name().to_string()),
            })
            .collect())
    }

    pub fn filter_names(&self) -> Vec<String> {
        self.filters.iter().map(|f| f.filter.name().to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::null::Null;

    fn engine(extra: &str) -> Engine {
        let cfg = Config::parse(&format!(
            "[defaults]\nbackend = \"null\"\njournal = false\nmaxretry = 3\nfindtime = \"1m\"\nbantime = \"10m\"\n{extra}\n[filters.sshd]\nenabled = true\n"
        ))
        .unwrap();
        let mut e = Engine::new(cfg, Box::new(Null::default()), EventLog::sink()).unwrap();
        e.start(1000).unwrap();
        e
    }

    fn line(text: &str) -> Line {
        Line {
            origin: Origin::File(Arc::from("/var/log/secure")),
            text: text.into(),
        }
    }

    #[test]
    fn bans_after_maxretry() {
        let mut e = engine("");
        let l = line("Jan 1 00:00:00 h sshd[1]: Failed password for root from 198.51.100.7 port 1 ssh2");
        assert!(!e.handle_line(&l, 1000)[0].banned);
        assert!(!e.handle_line(&l, 1001)[0].banned);
        let d = e.handle_line(&l, 1002);
        assert!(d[0].banned);
        assert_eq!(d[0].hits, 3);
        assert_eq!(e.list(1003).unwrap().len(), 1);
        assert_eq!(e.status(1003).filters[0].banned, 1);
        // Further hits while banned do not re-ban.
        assert!(!e.handle_line(&l, 1004)[0].banned);
    }

    #[test]
    fn allowlist_wins() {
        let mut e = engine("allow = [\"198.51.100.0/24\"]");
        let l = line("sshd[1]: Failed password for root from 198.51.100.7 port 1 ssh2");
        for t in 0..10 {
            assert!(e.handle_line(&l, 1000 + t).is_empty());
        }
        assert!(e.manual_ban("198.51.100.9/32".parse().unwrap(), None, 1000).is_err());
    }

    #[test]
    fn escalation_grows() {
        let mut e = engine("");
        let net: IpNet = "198.51.100.7/32".parse().unwrap();
        assert_eq!(e.escalated_ttl(Duration::from_secs(600), &net, 1000).0.as_secs(), 600);
        e.history.insert(net, BanHistory { count: 2, last: 999 });
        assert_eq!(e.escalated_ttl(Duration::from_secs(600), &net, 1000).0.as_secs(), 2400);
        e.history.insert(net, BanHistory { count: 30, last: 999 });
        assert_eq!(
            e.escalated_ttl(Duration::from_secs(600), &net, 1000).0.as_secs(),
            7 * 86_400
        );
    }

    #[test]
    fn journal_identifier_requires_system_uid() {
        let mut e = engine("");
        e.routes_journal.push((
            JournalSelector {
                units: vec!["sshd.service".into()],
                identifiers: vec!["sshd".into()],
                comm: vec!["sshd".into()],
            },
            0,
        ));
        let origin = |unit: Option<&str>, ident: Option<&str>, comm: Option<&str>, uid: Option<u32>| Origin::Journal {
            unit: unit.map(Arc::from),
            identifier: ident.map(Arc::from),
            comm: comm.map(Arc::from),
            uid,
        };
        // Genuine sshd: unit matches, regardless of anything else.
        assert_eq!(
            e.filters_for(&origin(Some("sshd.service"), Some("sshd"), None, Some(0))),
            vec![0]
        );
        assert_eq!(e.filters_for(&origin(Some("sshd.service"), None, None, None)), vec![0]);
        // Identifier / comm from a system account (e.g. a non-unit sshd spawn).
        assert_eq!(e.filters_for(&origin(None, Some("sshd"), None, Some(0))), vec![0]);
        assert_eq!(e.filters_for(&origin(None, None, Some("sshd"), Some(999))), vec![0]);
        // `logger -t sshd` from an ordinary user: spoofable fields, untrusted uid.
        assert!(e
            .filters_for(&origin(Some("session-2.scope"), Some("sshd"), None, Some(1000)))
            .is_empty());
        assert!(e
            .filters_for(&origin(None, Some("sshd"), Some("sshd"), Some(1000)))
            .is_empty());
        // No recorded sender uid: fail closed.
        assert!(e.filters_for(&origin(None, Some("sshd"), None, None)).is_empty());
    }

    #[test]
    fn ipv6_prefix_overlapping_allowlist_is_never_banned() {
        // Allow one host; an attacker in the same /64 must not get the /64
        // banned, since the exec backend has no allow set to protect it.
        let mut e = engine("allow = [\"2001:db8:1:2::5/128\"]");
        let l = line("sshd[1]: Failed password for root from 2001:db8:1:2::bad port 1 ssh2");
        for t in 0..10 {
            assert!(e.handle_line(&l, 1000 + t).is_empty());
        }
        // A different /64 is still banned normally.
        let l = line("sshd[1]: Failed password for root from 2001:db8:1:3::bad port 1 ssh2");
        e.handle_line(&l, 1000);
        e.handle_line(&l, 1000);
        assert!(e.handle_line(&l, 1000)[0].banned);
    }

    #[test]
    fn history_is_capped_at_max_tracked() {
        let mut e = engine("max_tracked = 100");
        for i in 0..100u32 {
            let net: IpNet = format!("10.{}.{}.0/32", i / 256, i % 256).parse().unwrap();
            e.history.insert(
                net,
                BanHistory {
                    count: 1,
                    last: 1000 + i,
                },
            );
        }
        // Inserting a new net at the cap trims a batch of the oldest first.
        let hit = |e: &mut Engine, s: &str, t: u32| {
            let l = line(&format!("sshd[1]: Failed password for root from {s} port 1 ssh2"));
            for _ in 0..3 {
                e.handle_line(&l, t);
            }
        };
        hit(&mut e, "198.51.100.7", 5000);
        assert!(e.history.len() <= 100);
        assert!(e.history.contains_key(&"198.51.100.7/32".parse::<IpNet>().unwrap()));
        assert!(
            !e.history.contains_key(&"10.0.0.0/32".parse::<IpNet>().unwrap()),
            "oldest evicted"
        );
        assert!(
            e.history.contains_key(&"10.0.99.0/32".parse::<IpNet>().unwrap()),
            "newest kept"
        );
    }

    #[test]
    fn ipv6_keys_by_prefix() {
        let mut e = engine("");
        let mk = |h: &str| {
            line(&format!(
                "sshd[1]: Failed password for root from 2001:db8:1:2::{h} port 1 ssh2"
            ))
        };
        e.handle_line(&mk("1"), 1000);
        e.handle_line(&mk("2"), 1000);
        let d = e.handle_line(&mk("3"), 1000);
        assert!(d[0].banned, "three hosts in one /64 count together");
        assert_eq!(d[0].net.to_string(), "2001:db8:1:2::/64");
    }
}
