#!/usr/bin/env bash
# Cut a release: bump the workspace version, commit, tag, push.
# The tag push triggers .github/workflows/release.yml, which builds the
# packages and refuses to run if the tag and Cargo.toml version disagree.
#
# usage: scripts/release.sh 0.1.1 [--no-push]
set -euo pipefail

ver=${1:-}
push=1
[[ "${2:-}" == "--no-push" ]] && push=0
if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "usage: $0 X.Y.Z[-pre] [--no-push]" >&2; exit 2
fi

cd "$(dirname "$0")/.."

branch=$(git rev-parse --abbrev-ref HEAD)
[[ "$branch" == "main" ]] || { echo "not on main (on $branch)" >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "working tree not clean" >&2; exit 1; }
git fetch -q origin main
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || { echo "main is not in sync with origin/main" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/v$ver" >/dev/null && { echo "tag v$ver already exists" >&2; exit 1; }

cur=$(grep -m1 -E '^version = "' Cargo.toml | sed -E 's/version = "(.*)"/\1/')
echo "bumping $cur -> $ver"
sed -i -E "0,/^version = \"$cur\"/s//version = \"$ver\"/" Cargo.toml
cargo check -q --workspace            # refresh Cargo.lock
git add Cargo.toml Cargo.lock
git commit -q -m "Release v$ver"
git tag -a "v$ver" -m "minsec $ver"

if (( push )); then
    git push origin main "v$ver"
    echo "pushed; release workflow running: $(gh repo view --json url -q .url 2>/dev/null)/actions"
else
    echo "created commit and tag v$ver locally; push with: git push origin main v$ver"
fi
