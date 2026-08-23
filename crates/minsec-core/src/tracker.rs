//! Bounded, allocation-free failure tracking.
//!
//! For every (filter, key) we keep a small fixed ring of hit timestamps
//! (seconds). A key is "over the line" when `maxretry` hits fall inside the
//! last `findtime`. Entries are evicted when idle or when the global cap is
//! reached (oldest first), so memory is bounded by configuration, not by
//! traffic volume.

use ipnet::IpNet;
use std::collections::HashMap;
use std::time::Duration;

/// Upper bound on `maxretry`; also the ring size.
pub const MAX_RETRY_CAP: u32 = 32;

/// At the cap, evict `len / EVICT_DIVISOR` entries per scan.
const EVICT_DIVISOR: usize = 32;

#[derive(Clone, Copy)]
struct Window {
    ts: [u32; MAX_RETRY_CAP as usize],
    head: u8,
    len: u8,
}

impl Window {
    fn new() -> Self {
        Self {
            ts: [0; MAX_RETRY_CAP as usize],
            head: 0,
            len: 0,
        }
    }
    fn push(&mut self, now: u32, cap: u8) {
        let cap = cap.max(1) as usize;
        if (self.len as usize) < cap {
            let idx = (self.head as usize + self.len as usize) % cap;
            self.ts[idx] = now;
            self.len += 1;
        } else {
            self.ts[self.head as usize] = now;
            self.head = ((self.head as usize + 1) % cap) as u8;
        }
    }
    fn count_since(&self, since: u32, cap: u8) -> u32 {
        let cap = cap.max(1) as usize;
        (0..self.len as usize)
            .map(|i| self.ts[(self.head as usize + i) % cap])
            .filter(|&t| t >= since)
            .count() as u32
    }
    fn last(&self, cap: u8) -> u32 {
        if self.len == 0 {
            return 0;
        }
        let cap = cap.max(1) as usize;
        self.ts[(self.head as usize + self.len as usize - 1) % cap]
    }
    fn clear(&mut self) {
        self.len = 0;
        self.head = 0;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TrackKey {
    pub filter: u16,
    pub net: IpNet,
}

pub struct Tracker {
    map: HashMap<TrackKey, Window>,
    max_entries: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Below threshold; `hits` in window so far.
    Below { hits: u32 },
    /// Threshold reached; the window has been reset.
    Ban { hits: u32 },
}

impl Tracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::new(),
            max_entries: max_entries.max(16),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Record a hit at `now` (unix seconds) and decide.
    pub fn hit(&mut self, key: TrackKey, now: u32, findtime: Duration, maxretry: u32) -> Verdict {
        let cap = maxretry.clamp(1, MAX_RETRY_CAP) as u8;
        if !self.map.contains_key(&key) && self.map.len() >= self.max_entries {
            self.evict_batch();
        }
        let w = self.map.entry(key).or_insert_with(Window::new);
        w.push(now, cap);
        let since = now.saturating_sub(findtime.as_secs().min(u32::MAX as u64) as u32);
        let hits = w.count_since(since, cap);
        if hits >= maxretry {
            w.clear();
            self.map.remove(&key);
            Verdict::Ban { hits }
        } else {
            Verdict::Below { hits }
        }
    }

    pub fn forget(&mut self, key: &TrackKey) {
        self.map.remove(key);
    }

    /// Drop entries whose newest hit is older than `idle`.
    pub fn sweep(&mut self, now: u32, idle: Duration) -> usize {
        let cutoff = now.saturating_sub(idle.as_secs().min(u32::MAX as u64) as u32);
        let before = self.map.len();
        self.map.retain(|_, w| w.last(MAX_RETRY_CAP as u8) >= cutoff);
        if self.map.capacity() > self.map.len() * 4 + 64 {
            self.map.shrink_to_fit();
        }
        before - self.map.len()
    }

    /// Make room for one new key: drop the oldest ~1/32 of entries (by last
    /// hit). Finding the oldest is O(n), so evicting one at a time would let a
    /// steady stream of fresh addresses at the cap cost a full scan per line.
    /// Evicting a batch amortises that to O(32) per insertion.
    fn evict_batch(&mut self) {
        let n = (self.map.len() / EVICT_DIVISOR).max(1);
        let mut all: Vec<(u32, TrackKey)> = self
            .map
            .iter()
            .map(|(k, w)| (w.last(MAX_RETRY_CAP as u8), *k))
            .collect();
        if n < all.len() {
            all.select_nth_unstable_by_key(n - 1, |e| e.0);
            all.truncate(n);
        }
        for (_, k) in all {
            self.map.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> TrackKey {
        TrackKey {
            filter: 0,
            net: format!("10.0.0.{n}/32").parse().unwrap(),
        }
    }

    #[test]
    fn bans_at_threshold_within_window() {
        let mut t = Tracker::new(100);
        let ft = Duration::from_secs(600);
        for i in 0..4 {
            assert_eq!(t.hit(key(1), 1000 + i, ft, 5), Verdict::Below { hits: i + 1 });
        }
        assert_eq!(t.hit(key(1), 1004, ft, 5), Verdict::Ban { hits: 5 });
        assert!(t.is_empty(), "ban resets the window");
    }

    #[test]
    fn old_hits_age_out() {
        let mut t = Tracker::new(100);
        let ft = Duration::from_secs(60);
        for i in 0..4 {
            t.hit(key(1), 1000 + i, ft, 5);
        }
        assert_eq!(t.hit(key(1), 2000, ft, 5), Verdict::Below { hits: 1 });
    }

    #[test]
    fn ring_wraps_with_small_maxretry() {
        let mut t = Tracker::new(100);
        let ft = Duration::from_secs(600);
        assert_eq!(t.hit(key(1), 1, ft, 1), Verdict::Ban { hits: 1 });
        assert_eq!(t.hit(key(2), 1, ft, 2), Verdict::Below { hits: 1 });
        assert_eq!(t.hit(key(2), 2, ft, 2), Verdict::Ban { hits: 2 });
    }

    #[test]
    fn cap_and_sweep() {
        let mut t = Tracker::new(16);
        let ft = Duration::from_secs(600);
        for n in 0..40u8 {
            t.hit(key(n), 1000 + n as u32, ft, 5);
        }
        assert!(t.len() <= 16);
        let n = t.len();
        assert_eq!(t.sweep(5000, Duration::from_secs(10)), n);
        assert!(t.is_empty());
    }

    #[test]
    fn cap_evicts_oldest_in_batches() {
        let mut t = Tracker::new(64);
        let ft = Duration::from_secs(6000);
        for n in 0..64u8 {
            t.hit(key(n), 1000 + n as u32, ft, 5);
        }
        assert_eq!(t.len(), 64);
        // One new key at the cap evicts a batch (64/32 = 2) of the oldest,
        // so the next new key fits without another scan.
        t.hit(key(100), 2000, ft, 5);
        assert_eq!(t.len(), 63);
        t.hit(key(101), 2000, ft, 5);
        assert_eq!(t.len(), 64);
        // The oldest two went; the newest survivors did not.
        assert_eq!(t.hit(key(0), 2001, ft, 5), Verdict::Below { hits: 1 });
        assert_eq!(t.hit(key(63), 2001, ft, 5), Verdict::Below { hits: 2 });
    }

    #[test]
    fn sweep_removes_idle() {
        let mut t = Tracker::new(16);
        let ft = Duration::from_secs(600);
        t.hit(key(1), 1000, ft, 5);
        t.hit(key(2), 4000, ft, 5);
        assert_eq!(t.sweep(4100, Duration::from_secs(600)), 1);
        assert_eq!(t.len(), 1);
    }
}
