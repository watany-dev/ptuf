#!/usr/bin/env bash
# Point this clone's git hooks at the tracked scripts/hooks/ directory.
# Re-run is idempotent.
set -euo pipefail

target="scripts/hooks"
current="$(git config --get core.hooksPath || true)"

if [[ -n "$current" && "$current" != "$target" ]]; then
    echo "warning: overwriting existing core.hooksPath ($current -> $target)" >&2
fi

git config core.hooksPath "$target"
echo "core.hooksPath set to $target"
