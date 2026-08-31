# minsec

Minimalist security daemon with multiplayer mode.

`minsec` watches log files and the systemd journal for authentication failures
and abuse, and blocks offending addresses with the kernel firewall. It is a
replacement for fail2ban built for the Virtualmin stack, designed around three
constraints fail2ban does not meet:

* **Tiny.** One ~2.5 MB binary; ~2 MB anonymous RSS with ten filters enabled.
  No log text is retained, per-address state is a fixed-size ring, and the
  kernel — not the daemon — owns the ban list (nftables set elements with
  timeouts), so bans expire on their own and survive restarts. (2MB not
  counting linked ~30MB systemd lib, which is shared with all other journal
  users. It's free real estate.)
* **Fast.** Single-threaded streaming parser: one combined regex per filter
  behind a literal prefilter; ~5M lines/s on a laptop core.
* **Simple to operate.** One TOML file plus drop-ins, built-in filters for the
  services Virtualmin installs, `minsec enable sshd`, `minsec test sshd
  /var/log/secure` to see exactly what would match, and a JSON control socket
  so UIs don't have to scrape CLI output.

"Multiplayer mode" — opt-in crowd-sourced abuse reporting and a curated
blocklist feed — lives in the separate `minsec-sync` helper so the resident
daemon is minimalist and auditable; it reports automatic bans (attacker network
and abuse category only) and pulls the crowd blocklist into dedicated
`crowd4`/`crowd6` nftables sets. See [docs/MULTIPLAYER.md](docs/MULTIPLAYER.md)
to opt in, and [docs/PLAN.md](docs/PLAN.md) for the full design and roadmap.

## Status

Early. The core works end to end against real nftables (see
`tests/e2e-nft.sh`), but it has not yet shipped in a Virtualmin release.

## Quick start

```sh
cargo build --release
sudo install -m 0755 target/release/minsec /usr/bin/minsec
sudo install -d /etc/minsec && sudo install -m 0644 packaging/minsec.toml /etc/minsec/
sudo install -d /usr/share/man/man1 /usr/share/man/man5
sudo install -m 0644 docs/man/*.1 /usr/share/man/man1/
sudo install -m 0644 docs/man/*.5 /usr/share/man/man5/
sudo install -m 0644 packaging/minsec.service /etc/systemd/system/
sudo install -m 0644 packaging/minsec.sysusers.conf /usr/lib/sysusers.d/minsec.conf
sudo install -m 0644 packaging/minsec.tmpfiles.conf /usr/lib/tmpfiles.d/minsec.conf
sudo systemd-sysusers && sudo systemd-tmpfiles --create
sudo minsec enable sshd
sudo minsec check
sudo systemctl enable --now minsec
minsec status
```

Try it without touching the firewall first:

```sh
sudo minsec daemon --backend null      # logs what it would ban
minsec test sshd /var/log/secure       # show matches and extracted addresses
```

## Configuration

`/etc/minsec/minsec.toml`, merged with `/etc/minsec/conf.d/*.toml`:

```toml
[defaults]
bantime  = "1h"
findtime = "10m"
maxretry = 5
backend  = "nft"                 # nft | null | exec
escalate = { factor = 2, max = "1w", memory = "30d" }
allow    = ["203.0.113.0/24"]    # loopback and local addresses are implied
ipv6_prefix = 64                 # IPv6 is tracked and banned per /64

[filters.sshd]
enabled = true
maxretry = 3

[filters.wordpress]
enabled = true
files = ["/var/log/virtualmin/*_access_log"]
```

Built-in filters: `minsec filters`. A custom or overriding filter is a TOML
file in `/etc/minsec/filters/<name>.toml`:

```toml
name = "myapp"
files = ["/var/log/myapp.log"]
journal = { identifiers = ["myapp"] }
prefilter = ["login failed"]          # cheap literal check before the regex
patterns = ['login failed for <F-USER>\S+</F-USER> from <HOST>']
```

Patterns are regular expressions with fail2ban-style `<HOST>` and
`<F-USER>…</F-USER>` tokens. They are matched anywhere in the line, so they
work on syslog files and raw journal messages alike. `\d`, `\s` and `\w` are
ASCII.

## CLI

| Command | |
|---|---|
| `minsec status` | daemon and per-filter counters |
| `minsec list` | active bans, from the kernel |
| `minsec ban 198.51.100.7 --ttl 1d` / `minsec unban …` | manual bans (CIDRs allowed) |
| `minsec enable <filter>` / `disable` | writes `conf.d/<filter>.toml` |
| `minsec test <filter> [file]` | run a filter over a file or stdin |
| `minsec check` | validate config and compile filters |
| `minsec events` | recent ban/unban events (JSONL) |

Add `--json` to any command for machine-readable output; the same JSON is
available directly on the control socket (`/run/minsec/minsec.sock`,
newline-delimited requests such as `{"cmd":"status"}`).

Complete command and configuration references are installed as
`minsec(1)`, `minsec-sync(1)`, `minsec.toml(5)`,
`minsec-filter.toml(5)`, and `minsec-sync.toml(5)`.

## Firewall

The nftables backend owns `table inet minsec` and nothing else: sets `ban4`,
`ban6`, `allow4`, `allow6` and `input`/`forward` chains at priority -10, so it
composes with firewalld or iptables-nft without modifying their rules. The
`exec` backend runs a script (`<cmd> ban <net> <ttl>` / `<cmd> unban <net>`)
for anything else; ipset and pf backends are on the roadmap.

## Packages

Tagging `v*` runs `.github/workflows/release.yml`, which builds x86_64 and
aarch64 binaries against glibc 2.28 (`cargo-zigbuild`), packages them with
`cargo-deb` and `cargo-generate-rpm`, installs them in EL8/9/10, Debian 11/12
and Ubuntu 22.04/24.04 containers, and attaches the `.rpm`/`.deb` files to the
GitHub release. One package per architecture serves every supported distro;
`scripts/check-glibc.sh` enforces the floor.

To build packages locally:

```sh
cargo install cargo-zigbuild cargo-deb cargo-generate-rpm && pip install ziglang
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.28 -p minsec
mkdir -p target/release && cp target/x86_64-unknown-linux-gnu/release/minsec target/release/
cargo deb -p minsec --no-build --no-strip --target x86_64-unknown-linux-gnu
cargo generate-rpm -p crates/minsec --target x86_64-unknown-linux-gnu
```

## Development

```sh
cargo test                                   # unit + golden corpus (tests/corpus)
unshare -rn tests/e2e-nft.sh target/debug/minsec   # real nftables in a private netns
cargo run --release -p minsec-core --example regex_mem   # heap cost per filter
```

## License

GPL-3.0-or-later.

### Cutting a release

Versions live in `Cargo.toml` (`[workspace.package] version`) and are the
source of truth; a tag must match it or the release workflow fails.

```sh
scripts/release.sh 0.1.1        # bump, commit "Release v0.1.1", tag v0.1.1, push
```

The tag push triggers `.github/workflows/release.yml`, which builds the
glibc-2.28 packages for x86_64 and aarch64, smoke-installs them, and attaches
them to the GitHub release.
