# Installing ptuf

For most users the fastest path is the one-line installer script — it
downloads the same prebuilt binary cargo-dist publishes to GitHub
Releases, no Rust toolchain required. The verified-install path below
adds SHA-256 and GitHub artifact attestation checks for pinned or
shared-environment deployments.

## Requirements

Quick install needs only `curl` (Unix) or `irm` (PowerShell). The
following are required only when building from source:

- Rust `1.93.0` or newer
- `lld` for the default Linux build profile
- `cargo-deny` and `cargo-tarpaulin` for the full local quality
  pipeline (developers only)

## Quick install

Pin `PTUF_VERSION` so CI and Docker builds are reproducible.

### Linux / macOS

```bash
PTUF_VERSION=v0.1.0
curl -LsSf "https://github.com/watany-dev/ptuf/releases/download/$PTUF_VERSION/ptuf-installer.sh" | sh
```

### Windows (PowerShell)

```powershell
$env:PTUF_VERSION = "v0.1.0"
powershell -ExecutionPolicy Bypass -c "irm https://github.com/watany-dev/ptuf/releases/download/$env:PTUF_VERSION/ptuf-installer.ps1 | iex"
```

The installer is the official cargo-dist script published alongside
each release. It installs `ptuf` into `$CARGO_HOME/bin` (default
`~/.cargo/bin`).

For a developer machine where you always want the newest release, the
GitHub `latest` redirect also works (not recommended for CI / Docker
because the resolved version drifts):

```bash
curl -LsSf https://github.com/watany-dev/ptuf/releases/latest/download/ptuf-installer.sh | sh
```

The Quick install path does not verify the SHA-256 sum or the GitHub
artifact attestation. For pinned or shared-environment deployments,
use the [Verified install](#verified-install-recommended-for-pinned-deployments)
path below instead.

## Verified install (recommended for pinned deployments)

Set the exact version and target you want, download the canonical
archive, verify its checksum, and verify the GitHub artifact
attestation before extracting.

### Linux

```bash
VERSION=v0.1.0
TARGET=x86_64-unknown-linux-musl
ARCHIVE=ptuf-$TARGET.tar.gz
BASE=https://github.com/watany-dev/ptuf/releases/download/$VERSION

curl -LO "$BASE/$ARCHIVE"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "$ARCHIVE" \
  --repo watany-dev/ptuf \
  --source-ref refs/tags/$VERSION
tar -xzf "$ARCHIVE" --strip-components=1
install -m 0755 ptuf ~/.cargo/bin/ptuf
```

### macOS

```bash
VERSION=v0.1.0
TARGET=aarch64-apple-darwin
ARCHIVE=ptuf-$TARGET.tar.gz
BASE=https://github.com/watany-dev/ptuf/releases/download/$VERSION

curl -LO "$BASE/$ARCHIVE"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "$ARCHIVE" \
  --repo watany-dev/ptuf \
  --source-ref refs/tags/$VERSION
tar -xzf "$ARCHIVE" --strip-components=1
install -m 0755 ptuf ~/.cargo/bin/ptuf
```

### Windows (PowerShell)

```powershell
$Version = "v0.1.0"
$Target = "x86_64-pc-windows-msvc"
$Archive = "ptuf-$Target.zip"
$Base = "https://github.com/watany-dev/ptuf/releases/download/$Version"

curl.exe -LO "$Base/$Archive"
curl.exe -LO "$Base/SHA256SUMS"
$Expected = (Get-Content SHA256SUMS | Where-Object { $_ -match ([regex]::Escape($Archive) + "$") } | ForEach-Object { ($_ -split "\s+")[0] })
$Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "checksum mismatch for $Archive" }
gh attestation verify $Archive `
  --repo watany-dev/ptuf `
  --source-ref refs/tags/$Version
Expand-Archive $Archive -DestinationPath .
```

## With cargo-binstall (Rust users, no compilation)

If you have [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)
installed, it downloads the same prebuilt archive cargo-dist publishes
and skips compilation:

```bash
cargo binstall ptuf
```

cargo-binstall does not verify the SHA-256 sum or the GitHub artifact
attestation. For pinned or shared-environment deployments, use the
[Verified install](#verified-install-recommended-for-pinned-deployments)
path above instead.

## From crates.io

```bash
cargo install ptuf
```

## From source

```bash
make build
cargo install --path .
```

## Updating

`ptuf update` upgrades the installed binary in place. It auto-detects
the install path and dispatches to the matching updater:

- if `ptuf` lives under `$CARGO_HOME/bin` (or `~/.cargo/bin`) and `cargo`
  is on PATH, it runs `cargo install ptuf --locked --force` (the
  `--locked` flag pins transitive deps to the published `Cargo.lock` so
  the installed binary matches the audited release tree);
- otherwise it downloads the cargo-dist installer
  (`ptuf-installer.sh` on Unix, `ptuf-installer.ps1` on Windows) to a
  process-scoped tmp file, verifies its GitHub artifact attestation with
  `gh attestation verify <file> --repo watany-dev/ptuf`, and only then
  executes it.

The prebuilt path therefore runs three sub-processes in order:

| step | command (Unix) | command (Windows) |
| ---- | -------------- | ----------------- |
| download | `curl --proto =https --tlsv1.2 -fLsS -o <tmp>/installer.sh <url>` | `powershell ... iwr -useb <url> -OutFile <tmp>` |
| verify | `gh attestation verify <tmp>/installer.sh --repo watany-dev/ptuf` | same |
| execute | `sh <tmp>/installer.sh` | `powershell -ExecutionPolicy Bypass -File <tmp>` |

If `gh` is missing on PATH, ptuf exits `1` and leaves the downloaded
script on disk so you can install GitHub CLI and re-verify it manually.
Pass `--skip-attestation` (or set `PTUF_UPDATE_SKIP_ATTESTATION=1`) to
bypass the check on hosts where `gh` cannot be installed; the bypass
emits a `WARNING` line to stderr so the unverified install is auditable.

When `--version` pins an older tag, `ptuf update` refuses by default and
prints "refusing to downgrade — installed X is newer than the requested
Y; pass --force to override". Pre-release tags (e.g. `v0.2.0-rc.1`)
cannot be ordered against bare semver, so the guard is skipped with a
single advisory line on stderr to keep the skip auditable.

Common flags:

```bash
ptuf update                        # upgrade to the latest GitHub release
ptuf update --check                # only print current vs. latest, no write
ptuf update --version v0.2.0       # pin to a specific tag
ptuf update --force                # reinstall even if already up to date (also
                                   # required to roll back to an older tag)
ptuf update --skip-attestation     # skip `gh attestation verify` (CI/sandbox)
```

`ptuf update` shells out to `curl` (for the latest-release lookup and
the prebuilt download) and to either `cargo`, `gh`, `sh`, or
`powershell` for the verify / swap steps. It does not embed an HTTP
client. The verify step is the same one documented under
[Verified install](#verified-install-recommended-for-pinned-deployments),
so the auto-update path now matches the manual recommendation by
default.
