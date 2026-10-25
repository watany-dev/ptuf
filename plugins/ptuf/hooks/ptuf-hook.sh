#!/bin/sh
# Claude Code plugin entry point: hand the PreToolUse payload on stdin to
# `ptuf hook claude-code`. The plugin ships no binary, so look on PATH
# first and then in the installer's default directory (Claude Code may
# start without ~/.cargo/bin on PATH).
#
# A missing binary fails closed: exit 2 makes Claude Code block the call
# and show stderr, instead of silently running the agent unguarded.

if command -v ptuf >/dev/null 2>&1; then
    exec ptuf hook claude-code
fi

fallback="${CARGO_HOME:-$HOME/.cargo}/bin/ptuf"
if [ -x "$fallback" ]; then
    exec "$fallback" hook claude-code
fi

echo "ptuf plugin is enabled but the ptuf binary was not found on PATH or at $fallback." >&2
echo "Install it from a terminal (https://github.com/watany-dev/ptuf#install), e.g. 'brew install watany-dev/tap/ptuf' or 'npm install -g @watany-dev/ptuf', then retry." >&2
exit 2
