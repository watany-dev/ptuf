#!/usr/bin/env bash
# Reproducible build verification for ptuf.
#
# Builds the release binary twice with SOURCE_DATE_EPOCH and stripped
# build paths, then compares the SHA256 of both artifacts. If they
# differ, the toolchain or build graph is leaking host-side state
# (build timestamps, absolute paths, hostname, randomized symbols).
#
# This is run from the `make verify-reproducible` target and from
# `.github/workflows/release.yml` as a release-gate job. Linux-only
# (musl target for cross-distro determinism). Bound to threat-model
# entry E-4 in docs/design/threat-model.md.
#
# Exit codes:
#   0  - the two SHA256 hashes match (reproducible)
#   1  - hashes differ (NOT reproducible — fail the release)
#   2  - usage / environment error (cargo missing, etc.)
set -euo pipefail

# Pinned epoch so SOURCE_DATE_EPOCH-aware tools embed a deterministic
# timestamp. The value is arbitrary but must be stable across both
# builds. The 2024 cutoff matches the dist-workspace.toml pin.
PIN_EPOCH="1704067200" # 2024-01-01T00:00:00Z

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH" >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum not found in PATH" >&2
  exit 2
fi

WORK="$(mktemp -d -t ptuf-reproducible-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

build_once() {
  local label="$1"
  local dest="$WORK/$label"
  # Each build uses an isolated CARGO_TARGET_DIR so debug paths,
  # incremental cache and timestamp metadata cannot leak between runs.
  # `--remap-path-prefix` strips the absolute working directory from
  # the embedded debug info so two checkouts in different paths still
  # produce identical bytes.
  CARGO_TARGET_DIR="$dest/target" \
    SOURCE_DATE_EPOCH="$PIN_EPOCH" \
    RUSTFLAGS="--remap-path-prefix=$ROOT=. --remap-path-prefix=$dest=." \
    cargo build --release --locked --bin ptuf
  cp "$dest/target/release/ptuf" "$WORK/ptuf-$label"
}

echo "==> build 1/2"
build_once a
echo "==> build 2/2"
build_once b

HASH_A="$(sha256sum "$WORK/ptuf-a" | awk '{print $1}')"
HASH_B="$(sha256sum "$WORK/ptuf-b" | awk '{print $1}')"

echo "SHA256 build A: $HASH_A"
echo "SHA256 build B: $HASH_B"

if [ "$HASH_A" = "$HASH_B" ]; then
  echo "OK: build is reproducible"
  exit 0
fi

echo "FAIL: build is NOT reproducible — bytes differ" >&2
# Surface the first differing offset for a head-start on debugging.
cmp "$WORK/ptuf-a" "$WORK/ptuf-b" || true
exit 1
