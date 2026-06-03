#!/usr/bin/env bash
set -euo pipefail

if [ -x "${HOME}/.cargo/bin/ptuf" ]; then
  PTUF="${HOME}/.cargo/bin/ptuf"
elif PTUF="$(command -v ptuf 2>/dev/null)"; then
  :
else
  echo "ptuf is missing for Cursor hooks; run 'bash scripts/bootstrap-cloud.sh' before the agent loop starts." >&2
  exit 1
fi

exec "${PTUF}" hook cursor
