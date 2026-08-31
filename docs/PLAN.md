# minsec — plan and recommendations

## Context

Virtualmin ships fail2ban as its dynamic firewall. It works, but it is a Python
daemon that routinely sits at 50–150 MB RSS, keeps far too much state in memory,
and has a configuration/UX model (jail.conf → jail.local → jail.d, filter.d,
action.d, `<HOST>` regex soup) that users and support staff dislike. Alternatives
were evaluated — sshguard (tiny, C, limited, under-documented), Reaction (Rust,
new, small community), CrowdSec (feature-rich, but heavy, Go, and awkward to
redistribute inside a commercial hosting product) — and rejected in favour of
building our own.

**MVP goal:** a drop-in functional replacement for fail2ban in the Virtualmin
stack: tiny (≤10 MB RSS hard ceiling, target ≤5 MB), fast, Rust, nftables-first,
with built-in filters for everything Virtualmin installs, and a CLI/socket API
clean enough that Virtualmin's Perl UI can drive it without screen-scraping.

**Long-term goal ("multiplayer mode"):** opt-in crowd-sourced abuse reporting
from ~150k Virtualmin systems, a curated blocklist feed, and later CrowdSec-like
extras (reputation lookups, dynamic WAF, subscription services). The MVP must be
designed so this bolts on without growing the core daemon.

This document is the recommended design; it is not an exhaustive survey.

---

## 1. Key recommendations (summary)

| Decision | Recommendation | Why |
|---|---|---|
| Language | **Rust**, stable toolchain, MSRV pinned | Memory safety, small static-ish binaries, good ecosystem for netlink/regex/async. Zig/C rejected for safety; Go rejected for RSS floor (~10 MB+) and GC. |
| Runtime | **tokio, `current_thread`**, minimal feature set (`rt`, `net`, `time`, `signal`, `io-util`, `sync`) | Single-threaded is plenty for 100k+ lines/s; saves per-thread stacks and allocator arenas. Easy escape hatch to `mio` if tokio's footprint ever matters (it shouldn't: ~300 KB code, negligible heap). |
| Allocator | system malloc, `MALLOC_ARENA_MAX=1` set in the unit file (glibc) | jemalloc/mimalloc add 300 KB–1 MB and arena overhead. |
| Binary | `opt-level="s"`, `lto="fat"`, `codegen-units=1`, `panic="abort"`, `strip=true` | Expect 2.5–4.5 MB dynamic glibc binary. |
| Linking | **dynamic glibc, per-distro packages** (we already run per-distro repos). musl static as a secondary "portable" build with journal support degraded to the `journalctl` subprocess backend. | musl static cannot `dlopen(libsystemd)`; see §4.2. |
| Log sources | inotify-driven file tailer + journald via `dlopen("libsystemd.so.0")` (no hard link dependency) with `journalctl -o export -f` subprocess fallback | Journald native API supports server-side match filters (`_SYSTEMD_UNIT=sshd.service`) so we only wake for relevant entries. |
| Matching | `regex` crate (`RegexSet` + literal prefilter via `aho-corasick`), fail2ban-compatible `<HOST>`/`<ADDR>` tokens, DFA size caps | Reuse of existing filter knowledge and easy migration; the regex crate's memory is bounded by config, not by traffic. |
| State model | Streaming: no log lines retained. Per-(filter, ip) compact sliding-window counters in a bounded map with LRU eviction. Kernel nft set **with element timeouts** is the source of truth for active bans. | This is the single biggest departure from fail2ban's memory model. |
| Firewall MVP | **nftables**, own `inet minsec` table, sets `ban4`/`ban6` with `flags timeout,interval`, hook `input`/`forward` at priority `-10` (before firewalld/iptables-nft filter chains) | Kernel expires bans itself; bans survive daemon restarts; coexists with firewalld and iptables-nft without touching their rules. |
| Firewall later | ipset+iptables (legacy EL/older Debian), firewalld-via-nft (already covered), pf (FreeBSD/OpenBSD), ipfw, `exec` (script escape hatch), `null` (dry-run/log-only) | |
| Config | TOML: `/etc/minsec/minsec.toml` + `/etc/minsec/conf.d/*.toml`; built-in filter library compiled into the binary, overridable by files | One format, one directory, `minsec enable sshd` style UX. |
| Control | Unix socket at `/run/minsec/minsec.sock`, newline-delimited JSON request/response; CLI is a thin client with `--json` | Virtualmin's Perl side speaks JSON over a socket trivially; no scraping. |
| Privileges | Run as `minsec` user with `AmbientCapabilities=CAP_NET_ADMIN` + groups `adm,systemd-journal`; systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges`, etc.) | fail2ban runs as root; we shouldn't. |
| Crowd / network features | **Separate binary `minsec-sync`** (reporter + blocklist puller) run by a systemd timer or on demand; core daemon has **no TLS/HTTP stack** | Keeps rustls/HTTP (~1.5–2 MB + heap) out of the resident daemon; sync is short-lived. |
| License | GPLv3 (already chosen). Consider MIT/Apache for the wire-protocol/report schema crates so third parties can integrate. | |

---

## 2. Architecture

```
                 ┌─────────────────────────────────────────────────┐
 /var/log/*.log ─┤ sources  │ filters  │ tracker  │ policy │ backend ├─ nftables set
 journald ───────┤ (tail,   │ (regex   │ (sliding │ (ban   │ (nft,   │  (kernel expires)
                 │  journal)│  sets)   │  window) │  time, │  ipset, │
                 │          │          │          │ escal.)│  pf...) │
                 └────┬─────┴──────────┴─────┬────┴────────┴─────────┘
                      │                      │
                 event log (jsonl, rotated)  control socket (JSON) ◄── minsec CLI / Virtualmin
                      │
                 minsec-sync (separate process, timer-driven) ──► report API / blocklist feed
```

### 2.1 Crate layout (Cargo workspace)

```
minsec/
  Cargo.toml                 # workspace
  crates/
    minsec-core/             # lib: config, sources, filters, tracker, policy, backends, protocol
    minsec/                  # bin: daemon (`minsec daemon`) + CLI subcommands, one binary
    minsec-sync/             # bin (later): reporter + blocklist fetch; optional package
    minsec-proto/            # tiny lib: control-socket + report JSON schemas (serde), MIT/Apache
  filters/                   # built-in filter library (TOML), embedded via include_str!/build.rs
  packaging/                 # systemd unit, tmpfiles, sysusers, rpm/deb metadata
  tests/corpus/              # golden log lines per filter (match / must-not-match)
  docs/
```

One binary for daemon + CLI (`minsec daemon`, `minsec status`, …) keeps the
package simple and avoids duplicated code; the CLI path never initialises the
daemon's state so it stays fast.

### 2.2 Modules in `minsec-core`

- `config` — TOML loading, drop-in merge, validation, `minsec check` (like `nft -c`).
- `source::file` — inotify tailer. Handles rotation by inode/size change (copytruncate and rename), reads in 64 KB chunks, splits on `\n`, never buffers more than one partial line per file. Globs (`/var/log/virtualmin/*_access_log`) re-scanned on directory inotify events.
- `source::journal` — `sd_journal_*` via `dlopen` (libloading crate). Adds matches per filter (`_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `_COMM`), uses `sd_journal_get_fd` + `sd_journal_process` so it is edge-triggered in the same event loop. Fallback: `journalctl -o export -f --since=now` subprocess with the same match args.
- `filter` — a filter = source selector + list of patterns + extraction of `ip` (+ optional `user`, `port`). Patterns support fail2ban tokens (`<HOST>`, `<ADDR>`, `<F-USER>`) compiled to named captures. Each filter builds a literal prefilter (`aho-corasick` of required substrings) so the regex set only runs on candidate lines. Optional "ignore regex" list.
- `tracker` — per-filter `HashMap<IpKey, Window>`. `IpKey` = IPv4 /32 or IPv6 /64 (configurable prefix), stored as `u128` + prefix byte. `Window` = fixed ring of `N ≤ 32` `u32` second-offsets (maxretry cap) — 8 + 4N bytes, no `Vec`, no per-hit allocation. Global cap on tracked keys (default 100k ≈ ~8 MB worst case; default tuned to ~2 MB) with LRU/idle eviction sweep every `findtime`.
- `policy` — bantime, findtime, maxretry, escalation (`bantime.increment`-style: multiplier, max, based on the ban count in the event log), allowlist (CIDRs, plus auto-allow of the daemon host's own addresses and SSH client of the current admin session — the latter optional), "recidive" as a first-class policy (`N bans in window → long ban`) rather than a meta-filter parsing our own log.
- `backend` — trait `Firewall { ban(ip, ttl), unban(ip), list(), sync(expected) }`. Implementations: `nft` (MVP), `ipset`, `pf`, `exec`, `null`. Backends are batched: bans within 100 ms are coalesced into one `nft` transaction.
- `control` — unix socket, NDJSON; commands: `status`, `list [filter]`, `ban ip [--ttl] [--reason]`, `unban ip`, `allow ip`, `reload`, `test-filter`, `stats`, `events --follow`.
- `events` — append-only JSONL at `/var/lib/minsec/events.jsonl` (ban/unban/manual/start/stop), size-rotated, with a cursor file used by `minsec-sync`. This is the only persistence; no SQLite in the core.
- `notify` — optional hooks on ban/unban: `exec` command (templated), `sendmail` pipe, webhook handled by `exec curl` rather than an in-process HTTP client.

### 2.3 nftables layout (MVP)

```
table inet minsec {
  set ban4 { type ipv4_addr; flags timeout,interval; }
  set ban6 { type ipv6_addr; flags timeout,interval; }
  set allow4 { type ipv4_addr; flags interval; }
  set allow6 { type ipv6_addr; flags interval; }
  chain input   { type filter hook input   priority -10; policy accept;
                  ip  saddr @allow4 accept; ip6 saddr @allow6 accept;
                  ip  saddr @ban4 counter drop; ip6 saddr @ban6 counter drop; }
  chain forward { type filter hook forward priority -10; policy accept; ... same ... }
}
```

- Per-filter `ports = [...]` option adds `tcp dport { … }` qualifiers via a
  verdict map; default is "ban everywhere" (users overwhelmingly want this).
- Invocation: MVP drives `nft -j -f -` with JSON batches (the `nft` binary is
  present wherever nftables is). Native netlink (`nftnl`/`rustables`) is a
  Phase-3 optimisation, gated behind a feature flag — it removes the fork but
  adds a maintenance surface.
- On startup: create table if missing, reconcile set contents with our event
  log (kernel wins), never flush other tables. On shutdown: leave the table in
  place (bans keep expiring in-kernel).
- firewalld: works alongside because we own a separate table; document that
  `firewall-cmd --reload` does not touch it. iptables-legacy hosts get the
  `ipset` backend (detect via `iptables -V` / presence of `nft`).

### 2.4 Config UX (illustrative)

```toml
# /etc/minsec/minsec.toml
[defaults]
bantime  = "1h"
findtime = "10m"
maxretry = 5
escalate = { factor = 2, max = "1w" }
allow    = ["127.0.0.0/8", "::1", "203.0.113.0/24"]
backend  = "nft"         # nft | ipset | pf | exec | null

[filters.sshd]            # built-in; enabling is one line
enabled = true

[filters.postfix-sasl]
enabled = true
maxretry = 3

[filters.wordpress-login]  # built-in, matches Virtualmin per-domain access logs
enabled = true
paths = ["/var/log/virtualmin/*_access_log"]
```

CLI: `minsec enable sshd`, `minsec status`, `minsec list`, `minsec ban 1.2.3.4 --ttl 1d`,
`minsec unban 1.2.3.4`, `minsec test sshd /var/log/secure` (shows matches + extracted
IPs, the thing everyone needs when writing filters), `minsec check`,
`minsec import-fail2ban` (best-effort translation of jail.local/jail.d to TOML).

### 2.5 Built-in filter library (MVP set)

sshd (incl. "Invalid user", "Failed password", "Connection closed by authenticating
user", PAM, MaxAuthTries), postfix (smtpd reject, sasl auth failed, rbl),
dovecot (imap/pop/managesieve auth), exim, proftpd, pure-ftpd, vsftpd, webmin /
usermin / virtualmin (miniserv.log), apache & nginx (auth 401, bad-bots, 4xx
floods), roundcube, wordpress (wp-login / xmlrpc brute force), bind named
(refused queries — optional), mysql/mariadb auth, nextcloud. Each ships with a
golden test corpus.

---

## 3. Memory and performance budget

| Item | Budget |
|---|---|
| Binary on disk | ≤ 5 MB (target 3 MB) |
| Anonymous RSS, idle, 10 filters, 5 files + journal | ≤ 4 MB |
| Anonymous RSS, 50k tracked IPs | ≤ 10 MB (hard ceiling; cap enforced by eviction) |
| Throughput | ≥ 300k lines/s single core on a non-matching corpus (prefilter), ≥ 50k/s matching |
| Ban latency | < 50 ms from log line to kernel drop |

Notes:
- `sd_journal` mmaps journal files; measure **PSS/anon RSS** (`/proc/<pid>/smaps_rollup` → `Anonymous:`), not plain `VmRSS`, and document this for users comparing to fail2ban.
- CI gates: binary size and an idle-RSS test (`systemd-run` + sample after 30 s) fail the build on regression beyond 10 %.
- Regex: set `size_limit`/`dfa_size_limit` per filter; reject filters at `minsec check` time if compiled size > 1 MB.

---

## 4. Risks and design notes

### 4.1 Things fail2ban does that we intentionally drop
- DNS resolution of hostnames in logs (`usedns`) — IPs only.
- Per-jail action scripts in shell (`action.d`) — replaced by backends + one `exec` hook.
- SQLite database — replaced by kernel set + JSONL event log.
- Per-jail threads — single event loop.
- `recidive` via parsing our own log — first-class policy instead.

### 4.2 journald access vs. static linking
Linking libsystemd hard makes the package depend on it (bad for Alpine/BSD);
musl static cannot `dlopen`. Recommendation: glibc dynamic builds per distro
(EL8/9/10, Debian 11/12/13, Ubuntu 22.04/24.04) with `dlopen` of libsystemd at
runtime; a musl "portable" build where journald is reached via the `journalctl`
subprocess. A native read-only parser for the journal file format is a
plausible Phase-3 item (format is documented and stable) but is not worth MVP risk.

### 4.3 IPv6
Ban by /64 by default (attackers rotate within their allocation); configurable
per filter. Sets use `interval` flag so prefixes are native.

### 4.4 Log rotation and bursts
inotify + inode tracking covers `logrotate` rename and copytruncate. On startup
we seek to end (no replay) unless `--replay=10m` is given. Back-pressure: if a
source outruns matching (unlikely), we skip prefilter-negative chunks; we never
grow an unbounded queue.

### 4.5 Self-lockout protection
Auto-allow: loopback, addresses on local interfaces, and (optionally) the source
address of the admin's current SSH session when `minsec enable` is run
interactively. `minsec ban` refuses the client's own address without `--force`.

### 4.6 Multiplayer (Phase 4) — designed in now, built later
- Report schema (`minsec-proto`): `{ts, ip, filter, count, ban_ttl, host_id(anon), version}`; no log lines, no usernames by default (privacy + GDPR posture: IP + category only, explicit opt-in, documented retention).
- `minsec-sync report` reads the events cursor, batches, signs with a per-install key (Ed25519, generated at first run), POSTs.
- `minsec-sync pull` fetches a delta feed (plain text / compact binary, ETag), writes it into dedicated sets `crowd4`/`crowd6` (separate from local bans so users can disable or audit it), and optionally only for "high-confidence" tiers — the free/paid split lives here.
- Abuse-resistance of the feed is a server-side problem (reporter reputation, quorum across N independent reporters, allowlists of major providers) and a separate repo; noting it so the report schema includes what that needs (host_id, version, filter).
- WAF / reputation lookups / per-request decisions are **not** in the daemon; they'd be an nginx/apache module or a separate service consuming the same sets.

---

## 5. Phased plan

**Phase 0 — Skeleton (≈1 week)**
Workspace, CI (fmt, clippy, tests, size/RSS gate), release profile, packaging
stubs (systemd unit with hardening, sysusers/tmpfiles, cargo-deb / cargo-generate-rpm),
`null` backend, file tailer, sshd filter, `minsec test`. Proves the size budget early.

**Phase 1 — MVP core (≈3–4 weeks)**
Config + drop-ins, filter library + golden corpus, tracker/policy (findtime,
maxretry, bantime, escalation, allowlist, recidive), nft backend with
reconciliation, journald source (dlopen + subprocess fallback), control socket +
CLI, event log, notify hooks, `minsec import-fail2ban`. Fuzz targets for the line
splitter, filter tokens, and the control protocol.

**Phase 2 — Virtualmin integration & release (≈2 weeks)**
Perl module over the socket (status, enable/disable filters, ban/unban, list,
settings) replacing the fail2ban page; installer selects minsec by default,
fail2ban remains selectable; migration path (`import-fail2ban`, disable
fail2ban, keep its jail files). Docs. Beta on Virtualmin forums.

**Phase 3 — Breadth**
`ipset` backend, pf backend + kqueue tailer (FreeBSD), per-filter ports/verdict
maps, native netlink nft backend (feature-gated), native journal parser
evaluation, more filters from community PRs.

**Phase 4 — Multiplayer**
`minsec-sync`, report API + feed server (separate repo), opt-in flow in
Virtualmin, curated feed, then paid tiers / reputation API / WAF integrations.

**Phase 5 — Intelligence**
Turn the crowd dataset into products beyond the nftables feed. The backend
roadmap for this lives in `docs/PLAN.md` in the minsec.io repo; the
agent-side work it implies is listed below.

---

## 5a. Agent-side work for the intelligence roadmap

The crowd backend now maps each reported filter name through a signature
registry to an abuse category (`mail-auth`, `mail-mx`, `web-auth`,
`web-exploit`, `infra`), and publishes the result as a categorised DNSBL for
mail filtering as well as the existing firewall feed. That machinery is
entirely server-side — the wire format still has only an address, a rule
name, and counters. What it asks of the agent:

- **Exploit-probe filters.** The filter engine already matches on full
  access-log lines including the request path (`filters/wordpress.toml` is a
  path rule, not an auth-failure rule). Rules named for what they detect —
  `cve-2024-4577-php-cgi`, `wp-file-manager-rce` — make the *rule name* the
  signature id, which turns existing reports into CVE-attributed telemetry
  with no new fields and nothing new collected. This is the highest-value
  agent-side item on the list.
- **Filter metadata.** A `category` hint in the filter TOML would let a
  custom filter declare what it detects instead of landing in the backend's
  `unclassified` queue. Advisory only: the server must keep deciding, since
  a reported hint is attacker-influenced input.
- **Targeting feedback.** The backend knows whether an address is hitting
  only this host or thousands. Surfacing that in `minsec status` and the
  Virtualmin UI is the most useful thing the crowd can give an individual
  operator, and needs a small agent-facing lookup in `minsec-sync`.
- **Reporting granularity.** `escalation` now rides along (0 on a first ban,
  incrementing per re-ban). If per-filter report suppression is ever wanted
  for privacy-conscious operators, a `report = false` key on a filter is the
  natural shape.

---

## 6. Verification

- Unit: golden corpus per filter (must-match with expected IP, must-not-match),
  tracker window math with simulated clocks, escalation, allowlist precedence.
- Fuzz: `cargo fuzz` on line splitter, filter pattern compiler, NDJSON control parser.
- Integration (privileged CI job or Vagrant/VM): real nftables — start daemon,
  append attack lines to a temp log, assert set membership and timeout via
  `nft -j list set`, restart daemon and assert reconciliation, rotate log and
  assert continued tailing; journald path via `systemd-cat` on a systemd VM.
- Performance: `minsec bench <corpus>` subcommand; CI records lines/s and
  anon-RSS; thresholds from §3.
- Packaging smoke: install rpm/deb on each supported distro in containers/VMs,
  `systemctl start minsec`, `minsec status --json`, with firewalld present and absent.
- Manual: run alongside fail2ban in `null` backend mode on a real Virtualmin
  host for a week and diff the ban decisions.

---

## 7. Current defaults (subject to change)

- Ban-all-ports by default; per-filter port restriction opt-in.
- IPv6 aggregated to /64 by default.
- GPLv3 for the daemon; permissive license for `minsec-proto`.
- Supported MVP platforms = Virtualmin's supported list (EL8/9/10 family,
  Debian 11–13, Ubuntu 22.04/24.04); BSDs in Phase 3.
- Escalation on by default (2× per repeat ban, max 1 week), matching what most
  users set `bantime.increment` to anyway.
