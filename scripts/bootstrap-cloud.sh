#!/usr/bin/env bash
set -euo pipefail

PTUF_VERSION="${PTUF_VERSION:-v0.3.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
PROFILE_FILE="${HOME}/.profile"
PROFILE_MARKER="# ptuf bootstrap-cloud PATH"
PATH_EXPORT='export PATH="$HOME/.cargo/bin:$PATH"'

export PATH="${CARGO_BIN_DIR}:${PATH}"

if [ ! -f "${PROFILE_FILE}" ] || ! grep -Fq "${PROFILE_MARKER}" "${PROFILE_FILE}"; then
  {
    printf '\n%s\n' "${PROFILE_MARKER}"
    printf '%s\n' "${PATH_EXPORT}"
  } >> "${PROFILE_FILE}"
fi

if [ -f "${REPO_ROOT}/Cargo.toml" ] && grep -Fq 'name = "ptuf"' "${REPO_ROOT}/Cargo.toml"; then
  cargo install --path "${REPO_ROOT}" --locked
else
  curl -LsSf "https://github.com/watany-dev/ptuf/releases/download/${PTUF_VERSION}/ptuf-installer.sh" | sh
fi

ptuf --version || {
  echo "ptuf bootstrap failed; refusing to start unguarded" >&2
  exit 1
}
