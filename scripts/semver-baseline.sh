#!/usr/bin/env bash
# Print the git rev `cargo semver-checks --baseline-rev` should compare
# against: the newest stable release tag (`vX.Y.Z`, no pre-release suffix)
# reachable from HEAD. Falls back to `origin/main` when no tag exists.
#
# Comparing against the last *release* instead of `origin/main` means the
# public API only has to be versioned once per release cycle: the first
# breaking PR after vX.Y.Z bumps Cargo.toml to the next minor (0.x) and
# later breaking PRs pass without bumping again. Using `origin/main` made
# every breaking PR demand its own bump, walking the version far past the
# next actual release.
set -euo pipefail

tag="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --merged HEAD --sort=-v:refname \
    | grep -Ev -- '-' | head -n 1 || true)"

if [[ -n "$tag" ]]; then
    echo "$tag"
else
    echo "origin/main"
fi
