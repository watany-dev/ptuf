#!/usr/bin/env bash

set -euo pipefail

runtime_root="${CLINE_WRITABLE_ROOT:-/tmp/cline-runtime}"
original_home="${HOME:-}"
runtime_home="${CLINE_RUNTIME_HOME:-$runtime_root/home}"

seed_dir() {
  local source="$1"
  local target="$2"

  if [[ ! -e "$source" || -e "$target" ]]; then
    return
  fi

  mkdir -p "$(dirname "$target")"
  cp -R "$source" "$target"
}

export HOME="$runtime_home"

if [[ $# -gt 0 ]]; then
  case "$1" in
    cline|kanban)
      command="$1"
      shift
      ;;
    *)
      command="cline"
      ;;
  esac
else
  command="cline"
fi

export CLINE_DIR="${CLINE_DIR:-$HOME/.cline}"
export CLINE_DATA_DIR="${CLINE_DATA_DIR:-$CLINE_DIR/data}"
export CLINE_SESSION_DATA_DIR="${CLINE_SESSION_DATA_DIR:-$CLINE_DATA_DIR/sessions}"
export CLINE_TEAM_DATA_DIR="${CLINE_TEAM_DATA_DIR:-$CLINE_DATA_DIR/teams}"
export CLINE_DB_DATA_DIR="${CLINE_DB_DATA_DIR:-$CLINE_DATA_DIR/db}"

if [[ -n "$original_home" && "$original_home" != "$HOME" ]]; then
  original_cline_dir="${original_home%/}/.cline"
  seed_dir "$original_cline_dir/data" "$CLINE_DIR/data"
  seed_dir "$original_cline_dir/kanban" "$CLINE_DIR/kanban"
fi

mkdir -p \
  "$HOME" \
  "$CLINE_DIR/kanban/workspaces" \
  "$CLINE_DATA_DIR/settings" \
  "$CLINE_SESSION_DATA_DIR" \
  "$CLINE_TEAM_DATA_DIR" \
  "$CLINE_DB_DATA_DIR"

exec "$command" "$@"
