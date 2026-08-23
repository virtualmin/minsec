#!/bin/bash
# End-to-end test against real nftables inside a private network namespace.
# Usage: sudo tests/e2e-nft.sh /path/to/minsec   (or: unshare -rn tests/e2e-nft.sh ...)
set -euo pipefail
B=${1:-target/release/minsec}
W=$(mktemp -d)
trap 'kill $DPID 2>/dev/null; rm -rf "$W"' EXIT
mkdir -p "$W/etc" "$W/state"; : > "$W/secure"
cat > "$W/etc/minsec.toml" <<CFG
[defaults]
backend = "nft"
journal = false
maxretry = 3
findtime = "1m"
bantime = "5m"
[paths]
socket = "$W/minsec.sock"
state_dir = "$W/state"
[filters.sshd]
enabled = true
files = ["$W/secure"]
CFG
run() { if [ "$(id -u)" = 0 ] && [ -z "${IN_NS:-}" ]; then IN_NS=1 exec unshare -n "$0" "$B"; fi; }
run
"$B" -c "$W/etc" daemon & DPID=$!
sleep 0.5
for i in 1 2 3; do echo "sshd[1]: Failed password for root from 198.51.100.7 port 1 ssh2" >> "$W/secure"; done
sleep 0.7
nft list set inet minsec ban4 | grep -q 198.51.100.7 || { echo "FAIL: kernel set missing ban"; exit 1; }
"$B" -c "$W/etc" list | grep -q 198.51.100.7 || { echo "FAIL: list"; exit 1; }
kill $DPID; wait $DPID || true
"$B" -c "$W/etc" daemon & DPID=$!
sleep 0.5
"$B" -c "$W/etc" list | grep -q 198.51.100.7 || { echo "FAIL: ban lost across restart"; exit 1; }
"$B" -c "$W/etc" unban 198.51.100.7
nft list set inet minsec ban4 | grep -q 198.51.100.7 && { echo "FAIL: unban"; exit 1; }
echo "e2e-nft: ok"
