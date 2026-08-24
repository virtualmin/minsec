# minsec multiplayer mode

Multiplayer mode connects a minsec system to the crowd: it reports the
automatic bans your daemon already makes, and in return pulls a blocklist
built from what every participating system is seeing — attackers blocked
*before* they reach your login prompts.

It is **opt-in**, handled entirely by the small `minsec-sync` binary (the
resident daemon carries no TLS or HTTP stack), and designed so you can
audit exactly what leaves the machine.

## What is sent

One record per **automatic** ban: the attacker's network (IPv6 aggregated
to /64), the filter name (`sshd`, `postfix-sasl`, …), the hit count, when
it happened, the local ban length, and how many times that address has
already been re-banned here. That's all. Never log lines, never usernames,
never hostnames, never anything about your users or traffic. Manual bans
and unbans are never reported.

The filter name is the only field that says anything about *what* the
attacker did, and it names a detection rule — never the traffic that
matched it. The server maps it to an abuse category (mail credential abuse,
web application brute force, generic infrastructure abuse, …), which is
what the crowd blocklist and the mail-facing outputs are built from. If you
write a custom filter, its name is sent as-is; names the server does not
recognise are counted but never published. Retention and the full privacy
posture are documented in the backend repo (`docs/PRIVACY.md` on
minsec.io).

Reports are signed with a per-install Ed25519 key generated on first
enrollment; the server identifies the installation by a random UUID, not
by anything derived from your hardware or network.

## Opting in

```sh
sudo install -m 0644 /usr/share/doc/minsec/sync.toml.example /etc/minsec/sync.toml
sudo systemctl enable --now minsec-sync.timer
```

The config file's presence is the switch: the timer runs `minsec-sync run`
every 5 minutes, which enrolls automatically on the first run (solving a
small proof-of-work), then reports new bans and refreshes the blocklist.
Remove the file to opt out; `nft flush set inet minsec crowd4` (and
`crowd6`) clears the pulled list immediately.

`report` and `pull` can be toggled independently in `sync.toml` — you can
pull the crowd blocklist without contributing, or vice versa.

## Where the blocklist lands

The daemon's nftables setup creates two extra sets in the `inet minsec`
table, `crowd4` and `crowd6`, enforced after your allowlist and local
bans. `minsec-sync pull` maintains their contents (full replaces are one
atomic nft transaction; most refreshes are deltas or `304 Not Modified`).
They are separate from the local `ban4`/`ban6` sets so you can always see
which blocks came from the crowd:

```sh
nft list set inet minsec crowd4
```

## Commands

```sh
minsec-sync enroll          # generate key + enroll (run does this automatically)
minsec-sync report          # submit new automatic bans from the events log
minsec-sync pull            # refresh crowd4/crowd6
minsec-sync pull --dry-run  # print the nft script instead of applying it
minsec-sync run             # report + pull; what the timer runs
minsec-sync status          # enrollment, cursor, and feed state
```

State (key, host id, events-log cursor, feed cursors) lives in
`/var/lib/minsec/sync/`.

## Protocol

The wire protocol — request signing, enrollment proof-of-work, feed format
— is defined by the backend repo (minsec.io, `docs/API.md`) and
implemented here in the `minsec-proto` crate. The two implementations are
pinned together by shared signing vectors
(`crates/minsec-proto/testdata/vectors.json`, copied verbatim from the
backend repo).

Testing: `cargo test -p minsec-proto -p minsec-sync` covers the protocol
and a full client cycle against a mock backend; `tests/e2e-multiplayer.sh`
runs the real Go backend and drives three enrolled agents to quorum
(needs the minsec.io checkout and a disposable PostgreSQL database).
