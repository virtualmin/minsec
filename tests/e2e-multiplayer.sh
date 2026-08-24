#!/usr/bin/env bash
# Cross-implementation end-to-end test: the Rust multiplayer client
# (minsec-sync) against the real Go backend (minsecd, from the minsec.io
# repo). Three agents enroll (solving real proof-of-work), report the same
# attacker, the backend scores it to quorum, and the feed pull must deliver
# it back as an nft crowd4 update.
#
# Requirements: cargo, go, and a PostgreSQL database this script may ruin.
#
#   MINSEC_IO_REPO=$HOME/src/minsec.io \
#   MINSEC_E2E_DATABASE_URL=postgres://postgres:minsec@127.0.0.1:5433/minsec_e2e \
#   tests/e2e-multiplayer.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IO_REPO="${MINSEC_IO_REPO:-$HOME/src/minsec.io}"
DB_URL="${MINSEC_E2E_DATABASE_URL:?set MINSEC_E2E_DATABASE_URL to a disposable database}"
ADDR="127.0.0.1:18081"
ATTACKER="185.220.101.99"

[ -d "$IO_REPO/cmd/minsecd" ] || { echo "minsec.io repo not found at $IO_REPO (set MINSEC_IO_REPO)"; exit 1; }

TMP="$(mktemp -d)"
MINSECD_PID=""
cleanup() {
    [ -n "$MINSECD_PID" ] && kill "$MINSECD_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

echo "== building minsec-sync (rust) and minsecd (go)"
cargo build -q -p minsec-sync
(cd "$IO_REPO" && go build -o "$TMP/minsecd" ./cmd/minsecd)
SYNC="$REPO/target/debug/minsec-sync"

echo "== starting minsecd on $ADDR"
export MINSEC_DATABASE_URL="$DB_URL"
export MINSEC_ENROLL_SECRET="e2e-test-secret-0123456789abcdef"
export MINSEC_LISTEN_ADDR="$ADDR"
export MINSEC_METRICS_ADDR="127.0.0.1:19091"
export MINSEC_POW_DIFFICULTY=8
export MINSEC_PROBATION_PERIOD=0s
export MINSEC_TRUST_PROXY=false
export MINSEC_ENROLL_PER_IP_HOUR=100
export MINSEC_SCORE_INTERVAL=1h   # scoring is forced via `admin snapshot`
"$TMP/minsecd" serve >"$TMP/minsecd.log" 2>&1 &
MINSECD_PID=$!
for i in $(seq 1 50); do
    curl -fsS "http://$ADDR/readyz" >/dev/null 2>&1 && break
    [ "$i" = 50 ] && { echo "minsecd never became ready"; cat "$TMP/minsecd.log"; exit 1; }
    sleep 0.2
done

agent_conf() { # $1 = agent number
    local dir="$TMP/agent$1"
    mkdir -p "$dir"
    cat >"$dir/sync.toml" <<EOF
server = "http://$ADDR"
state_dir = "$dir/state"
events = "$dir/events.jsonl"
EOF
    echo "$dir"
}

echo "== three agents enroll and report $ATTACKER"
NOW="$(date +%s)"
for i in 1 2 3; do
    dir="$(agent_conf "$i")"
    printf '{"kind":"ban","ts":%s,"net":"%s/32","filter":"sshd","ttl":600,"hits":5,"escalation":0,"manual":false}\n' \
        "$NOW" "$ATTACKER" >"$dir/events.jsonl"
    "$SYNC" --config "$dir/sync.toml" enroll | grep -q "enrolled as " || { echo "agent $i enroll failed"; exit 1; }
    "$SYNC" --config "$dir/sync.toml" report | grep -q "1 accepted" || { echo "agent $i report failed"; exit 1; }
done

echo "== forcing a scoring tick"
"$TMP/minsecd" admin snapshot >/dev/null

echo "== pulling the feed back"
out="$("$SYNC" --config "$TMP/agent1/sync.toml" pull --dry-run)"
echo "$out" | grep -q "flush set inet minsec crowd4" || { echo "no crowd4 update:"; echo "$out"; exit 1; }
echo "$out" | grep -q "$ATTACKER" || { echo "attacker missing from feed:"; echo "$out"; exit 1; }

out="$("$SYNC" --config "$TMP/agent1/sync.toml" pull --dry-run)"
echo "$out" | grep -q "feed v4: unchanged" || { echo "expected 304 on re-pull:"; echo "$out"; exit 1; }

echo "== idempotent re-report is a no-op"
"$SYNC" --config "$TMP/agent1/sync.toml" report | grep -q "reported 0 events" || { echo "cursor did not hold"; exit 1; }

echo "PASS: enroll -> signed report -> quorum -> feed -> 304, Rust client against Go backend"
