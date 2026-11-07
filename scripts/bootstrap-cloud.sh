#!/usr/bin/env bash
set -euo pipefail

PTUF_VERSION="${PTUF_VERSION:-v0.6.0}"
# The release installer runs only if its SHA256 matches this pin. It embeds
# the SHA256 of every release archive and checks it before unpacking, so
# pinning the installer pins the ptuf binary too. To bump, set PTUF_VERSION
# and this to the new release's ptuf-installer.sh (`curl -LsSf <url> | sha256sum`).
PTUF_INSTALLER_SHA256="${PTUF_INSTALLER_SHA256:-13fbf4011db16d5906f76a0040fdd3a060a9b97879a961e446531dc791200996}"
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
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  installer="${tmp}/ptuf-installer.sh"
  curl --proto '=https' --tlsv1.2 -LsSf -o "${installer}" \
    "https://github.com/watany-dev/ptuf/releases/download/${PTUF_VERSION}/ptuf-installer.sh"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${installer}" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "${installer}" | awk '{print $1}')"
  fi
  if [ "${actual}" != "${PTUF_INSTALLER_SHA256}" ]; then
    echo "ptuf-installer.sh SHA256 mismatch (expected ${PTUF_INSTALLER_SHA256}, got ${actual}); refusing to install" >&2
    exit 1
  fi
  sh "${installer}"
fi

ptuf --version || {
  echo "ptuf bootstrap failed; refusing to start unguarded" >&2
  exit 1
}
